"""Durable ownership of stopped resources. Primary: ADRL-OPS-001.

Secondary: ADRL-MEM-001/002/005/010, ADRL-SAF-007, ADRL-TRU-001.
Internal create/inspect/non-force-remove only. Issued-but-unbound creates stay uncertain;
no resource adoption, start, kill, workspace release, task outcome or learning authority.
"""

from __future__ import annotations

import asyncio
import contextvars
import hmac
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

from adrl.api.auth import Principal
from adrl.core.container_control import (
    ContainerControl,
    ContainerRequest,
    EngineError,
    ResourceError,
    ResourcePolicy,
    canonical,
)
from adrl.ledger import crypto
from adrl.ledger.attempts import AttemptJournal, AttemptPolicy, check_execution_fence

PHASES = ("intent", "create_issued", "bound", "remove_issued", "removed")
Phase = Literal["intent", "create_issued", "bound", "remove_issued", "removed"]


class ResourceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["stopped-resource-event-v1"] = "stopped-resource-event-v1"
    operation_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    workspace_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    session_hmac: str = Field(pattern=r"^[a-f0-9]{64}$")
    attempt_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    start_event_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    host_key_id: str = Field(min_length=1, max_length=128)
    engine_ref: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_ref: str = Field(pattern=r"^[a-f0-9]{64}$")
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    seccomp_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy: ResourcePolicy
    sequence: int = Field(strict=True, ge=0, le=4)
    phase: Phase
    recorded_at: AwareDatetime
    resource_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    resource_created: str | None = Field(default=None, min_length=1, max_length=64)
    configuration_ref: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    workspace_state: Literal["blocked"] = "blocked"
    exact_close_eligible: Literal[False] = False
    eligible_for_learning: Literal[False] = False

    @model_validator(mode="after")
    def binding(self) -> ResourceEvent:
        if PHASES[self.sequence] != self.phase:
            raise ValueError("resource_phase_mismatch")
        values = (self.resource_id, self.resource_created, self.configuration_ref)
        if self.sequence < 2 and any(value is not None for value in values):
            raise ValueError("premature_resource_binding")
        if self.sequence >= 2 and any(value is None for value in values):
            raise ValueError("missing_resource_binding")
        if self.resource_created is not None:
            created = datetime.fromisoformat(self.resource_created.replace("Z", "+00:00"))
            if created.tzinfo is None:
                raise ValueError("resource_creation_time_required")
        return self


class StoppedResourceOwner:
    """Trusted local operator API; erasure-compatible cleanup never adopts a missing ID."""

    def __init__(self, journal: AttemptJournal, control: ContainerControl) -> None:
        self.journal = journal
        self.control = control
        self.policy = control.policy
        self.last_event: ResourceEvent | None = None

    def _reference(self, purpose: str, value: Any) -> str:
        return crypto.keyed_hash(
            self.journal.data.keys.hmac_key(), purpose + ":" + canonical(value).decode()
        )

    def _operation(self, operation_id: UUID) -> str:
        return self._reference("resource-operation-v1", str(operation_id))

    def _engine(self) -> str:
        try:
            return self._reference("resource-engine-v1", self.control.engine())
        except EngineError:
            # A missing /info endpoint is never an exact resource-absence receipt.
            raise ResourceError("resource_engine_unavailable") from None

    def _mac(self, previous: str, payload: str) -> str:
        return crypto.keyed_hash(
            self.journal.data.keys.hmac_key(), "resource-event-v1:" + previous + ":" + payload
        )

    def _history(
        self, operation: str, conn: sqlite3.Connection | None = None
    ) -> tuple[ResourceEvent, ...]:
        sql = "SELECT * FROM product_resource_events WHERE operation_key=? ORDER BY event_seq"
        rows = (
            list(conn.execute(sql, (operation,)))
            if conn
            else self.journal.data.ledger.read(sql, (operation,))
        )
        events: list[ResourceEvent] = []
        previous = "0" * 64
        for sequence, row in enumerate(rows):
            try:
                event = ResourceEvent.model_validate_json(row["payload_json"])
                if (
                    event.sequence != sequence
                    or row["event_seq"] != sequence
                    or event.phase != row["event_type"]
                    or event.operation_key != operation
                    or event.workspace_key != row["workspace_key"]
                    or event.host_key_id != self.journal.data.keys.hmac_key_id()
                    or row["prev_mac"] != previous
                    or not hmac.compare_digest(row["mac"], self._mac(previous, row["payload_json"]))
                ):
                    raise ResourceError("resource_integrity_failure")
                if events:
                    exclude = {
                        "phase",
                        "sequence",
                        "recorded_at",
                        "resource_id",
                        "resource_created",
                        "configuration_ref",
                    }
                    if event.model_dump(exclude=exclude) != events[0].model_dump(exclude=exclude):
                        raise ResourceError("resource_integrity_failure")
                    if sequence > 2 and any(
                        getattr(event, name) != getattr(events[2], name)
                        for name in ("resource_id", "resource_created", "configuration_ref")
                    ):
                        raise ResourceError("resource_integrity_failure")
                previous = row["mac"]
                events.append(event)
            except (ValueError, ValidationError, TypeError):
                raise ResourceError("resource_integrity_failure") from None
        if events:
            sql = "SELECT * FROM product_execution_fences WHERE workspace_key=?"
            fences = (
                list(conn.execute(sql, (events[0].workspace_key,)))
                if conn
                else self.journal.data.ledger.read(sql, (events[0].workspace_key,))
            )
            if (
                len(fences) != 1
                or any(
                    fences[0][field] != getattr(events[0], field)
                    for field in (
                        "workspace_key",
                        "session_hmac",
                        "attempt_key",
                        "start_event_key",
                        "host_key_id",
                    )
                )
                or fences[0]["policy_json"] != events[0].policy.model_dump_json()
            ):
                raise ResourceError("resource_fence_integrity_failure")
        return tuple(events)

    def read(self, operation_id: UUID) -> tuple[ResourceEvent, ...]:
        events = self._history(self._operation(operation_id))
        if not events:
            raise ResourceError("resource_operation_unavailable")
        return events

    def _insert(self, conn: sqlite3.Connection, event: ResourceEvent, previous: str) -> None:
        payload = event.model_dump_json()
        if len(payload.encode()) > event.policy.max_event_bytes:
            raise ResourceError("resource_event_limit")
        conn.execute(
            "INSERT INTO product_resource_events "
            "(operation_key,workspace_key,event_seq,event_type,payload_json,prev_mac,mac) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                event.operation_key,
                event.workspace_key,
                event.sequence,
                event.phase,
                payload,
                previous,
                self._mac(previous, payload),
            ),
        )

    def _advance(
        self,
        operation: str,
        phase: Phase,
        *,
        principal: Principal | None = None,
        **binding: str,
    ) -> tuple[ResourceEvent, bool]:
        def write(conn: sqlite3.Connection) -> tuple[ResourceEvent, bool]:
            history = self._history(operation, conn)
            if not history:
                raise ResourceError("resource_operation_unavailable")
            last = history[-1]
            sequence = PHASES.index(phase)
            if last.sequence == sequence and all(getattr(last, k) == v for k, v in binding.items()):
                return last, False
            if last.sequence + 1 != sequence:
                raise ResourceError("resource_transition_conflict")
            if phase == "create_issued":
                if principal is None:
                    raise ResourceError("resource_create_authority_required")
                self._check_started(conn, principal, last)
            event = ResourceEvent.model_validate(
                last.model_dump()
                | binding
                | {
                    "phase": phase,
                    "sequence": sequence,
                    "recorded_at": datetime.now(UTC),
                }
            )
            previous = conn.execute(
                "SELECT mac FROM product_resource_events WHERE operation_key=? AND event_seq=?",
                (operation, last.sequence),
            ).fetchone()[0]
            self._insert(conn, event, previous)
            return event, True

        return cast(
            tuple[ResourceEvent, bool], self.journal.data.ledger.submit(write).result(timeout=15)
        )

    def _check_started(
        self, conn: sqlite3.Connection, principal: Principal, event: ResourceEvent
    ) -> None:
        key = self.journal.captures._key(principal)
        if principal.session_hmac != event.session_hmac:
            raise ResourceError("resource_session_mismatch")
        rows = [
            dict(row)
            for row in conn.execute(
                "SELECT * FROM product_attempt_events WHERE session_hmac=? AND attempt_key=? "
                "ORDER BY attempt_seq",
                (event.session_hmac, event.attempt_key),
            )
        ]
        history = self.journal._history(principal, key, rows)
        grant = conn.execute(
            "SELECT * FROM product_attempt_capacity WHERE session_hmac=? AND attempt_key=?",
            (event.session_hmac, event.attempt_key),
        ).fetchone()
        self.journal._check_grant(history, rows[0], dict(grant) if grant else None)
        if (
            history[-1].phase != "started"
            or rows[0]["event_key"] != event.start_event_key
            or history[0].workspace_ref != "hmac:" + event.workspace_key
        ):
            raise ResourceError("resource_requires_bound_v2_start")

    def _begin(
        self,
        principal: Principal,
        operation_id: UUID,
        attempt_id: UUID,
        request: ContainerRequest,
        engine: str,
        stop: threading.Event,
    ) -> ResourceEvent:
        key = self.journal.captures._key(principal)
        _, workspace = self.journal._workspace(
            principal, Path(principal.assertion.inventory.root), strict=True
        )
        operation = self._operation(operation_id)
        attempt = crypto.keyed_hash(key, "attempt:" + str(attempt_id))
        ref = self._reference(
            "resource-request-v1",
            {
                "request": request.model_dump(),
                "policy": self.policy.model_dump(),
                "profile": self.control.profile_sha256,
                "engine": engine,
            },
        )

        def write(conn: sqlite3.Connection) -> ResourceEvent:
            if stop.is_set():
                raise ResourceError("resource_admission_cancelled")
            if self.journal.captures._key(principal) != key:
                raise ResourceError("resource_key_unavailable")
            prior = self._history(operation, conn)
            if prior:
                if (
                    prior[0].request_ref != ref
                    or prior[0].workspace_key != workspace
                    or prior[0].session_hmac != principal.session_hmac
                    or prior[0].attempt_key != attempt
                ):
                    raise ResourceError("resource_operation_conflict")
                return prior[-1]
            check_execution_fence(conn, workspace, self.journal.data.keys.hmac_key_id())
            rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM product_attempt_events WHERE session_hmac=? AND attempt_key=? "
                    "ORDER BY attempt_seq",
                    (principal.session_hmac, attempt),
                )
            ]
            history = self.journal._history(principal, key, rows)
            grant = conn.execute(
                "SELECT * FROM product_attempt_capacity WHERE session_hmac=? AND attempt_key=?",
                (principal.session_hmac, attempt),
            ).fetchone()
            self.journal._check_grant(history, rows[0], dict(grant) if grant else None)
            if (
                history[-1].phase != "started"
                or not isinstance(history[0].policy, AttemptPolicy)
                or history[0].workspace_ref != "hmac:" + workspace
            ):
                raise ResourceError("resource_requires_bound_v2_start")
            if (
                conn.execute(
                    "SELECT COUNT(*) FROM product_resource_events WHERE event_seq=0"
                ).fetchone()[0]
                >= self.policy.max_resources
            ):
                raise ResourceError("resource_admission_limit")
            event = ResourceEvent(
                operation_key=operation,
                workspace_key=workspace,
                session_hmac=principal.session_hmac,
                attempt_key=attempt,
                host_key_id=self.journal.data.keys.hmac_key_id(),
                start_event_key=rows[0]["event_key"],
                engine_ref=engine,
                request_ref=ref,
                image_id=request.image_id,
                seccomp_sha256=self.control.profile_sha256,
                policy=self.policy,
                sequence=0,
                phase="intent",
                recorded_at=datetime.now(UTC),
            )
            # Size the largest later event before admission, including its complete binding.
            largest = ResourceEvent.model_validate(
                event.model_dump()
                | {
                    "sequence": 4,
                    "phase": "removed",
                    "resource_id": "f" * 64,
                    "configuration_ref": "f" * 64,
                    "resource_created": "9999-12-31T23:59:59.999999999Z",
                }
            )
            if len(largest.model_dump_json().encode()) > self.policy.max_event_bytes:
                raise ResourceError("resource_future_event_limit")
            conn.execute(
                "INSERT INTO product_execution_fences "
                "(workspace_key,session_hmac,attempt_key,start_event_key,"
                "host_key_id,policy_json,ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    workspace,
                    principal.session_hmac,
                    attempt,
                    rows[0]["event_key"],
                    event.host_key_id,
                    self.policy.model_dump_json(),
                    event.recorded_at.isoformat(),
                ),
            )
            self._insert(conn, event, "0" * 64)
            return event

        return cast(ResourceEvent, self.journal.data.ledger.submit(write).result(timeout=15))

    def _inspect_bound(self, event: ResourceEvent) -> dict[str, Any]:
        if not event.resource_id or self._engine() != event.engine_ref:
            raise ResourceError("resource_engine_or_binding_mismatch")
        value = self.control.inspect(event.resource_id)
        self.control.never_started(value)
        ref = self._reference("resource-configuration-v1", self.control.configuration(value))
        if ref != event.configuration_ref or value["Created"] != event.resource_created:
            raise ResourceError("resource_bound_configuration_mismatch")
        return value

    def inspect_owned(self, operation_id: UUID) -> ResourceEvent:
        event = self.read(operation_id)[-1]
        if event.phase not in {"bound", "remove_issued"}:
            raise ResourceError("resource_not_bound")
        self._inspect_bound(event)
        return event

    def _create(
        self,
        principal: Principal,
        operation_id: UUID,
        attempt_id: UUID,
        request: ContainerRequest,
        stop: threading.Event,
    ) -> ResourceEvent:
        self.journal.captures._key(principal)
        engine = self._engine()
        event = self._begin(principal, operation_id, attempt_id, request, engine, stop)
        if event.phase == "bound":
            self._inspect_bound(event)
            return event
        if event.phase != "intent":
            raise ResourceError("resource_create_already_issued")
        name, body = self.control.prepare(request, event.operation_key)
        if stop.is_set():
            raise ResourceError("resource_admission_cancelled")
        self.journal.captures._key(principal)
        if self._engine() != engine:
            raise ResourceError("resource_engine_changed")
        _, claimed = self._advance(event.operation_key, "create_issued", principal=principal)
        if not claimed:
            raise ResourceError("resource_create_already_issued")
        try:
            # After the durable claim, any lost reply leaves uncertainty. Never adopt by name
            # or repeat create. Cancellation may still leave a fully bound stopped object.
            identity = self.control.create(name, body)
            if self._engine() != engine:
                raise ResourceError("resource_engine_changed")
            value = self.control.inspect(identity)
            self.control.verify_created(value, name, body)
            event, _ = self._advance(
                event.operation_key,
                "bound",
                resource_id=identity,
                resource_created=value["Created"],
                configuration_ref=self._reference(
                    "resource-configuration-v1", self.control.configuration(value)
                ),
            )
            return event
        except Exception:
            raise ResourceError("resource_create_uncertain") from None

    async def create(
        self, principal: Principal, operation_id: UUID, attempt_id: UUID, request: ContainerRequest
    ) -> ResourceEvent:
        self.last_event = None
        copied = ContainerRequest.model_validate(request.model_dump())
        stop = threading.Event()
        context = contextvars.copy_context()
        worker = asyncio.get_running_loop().run_in_executor(
            None, context.run, self._create, principal, operation_id, attempt_id, copied, stop
        )
        try:
            event = await asyncio.shield(worker)
            self.last_event = event
            return event
        except asyncio.CancelledError:
            stop.set()
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    stop.set()
                except Exception:
                    break
            if not worker.cancelled():
                if worker.exception() is None:
                    self.last_event = worker.result()
            raise

    def remove(self, operation_id: UUID) -> ResourceEvent:
        self.last_event = None
        event = self.read(operation_id)[-1]
        if event.phase == "removed":
            return event
        if event.phase == "bound":
            self._inspect_bound(event)
            event, _ = self._advance(event.operation_key, "remove_issued")
        if event.phase != "remove_issued" or event.resource_id is None:
            raise ResourceError("resource_not_bound")
        try:
            self._inspect_bound(event)
        except EngineError as exc:
            if exc.status != 404:
                raise
        else:
            try:
                self.control.remove(event.resource_id)
            except EngineError as exc:
                if exc.status != 404:
                    raise
            try:
                self.control.inspect(event.resource_id)
            except EngineError as exc:
                if exc.status != 404:
                    raise
            else:
                raise ResourceError("resource_removal_unconfirmed")
        event, _ = self._advance(event.operation_key, "removed")
        self.last_event = event
        return event
