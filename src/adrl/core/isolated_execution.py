"""One-shot isolated fixture execution. Primary: ADRL-OPS-001.

Secondary: ADRL-MEM-001/002/003/005/010, ADRL-SAF-007, ADRL-TRU-001.
No public start API, successful close, workspace release or learning eligibility.
"""

from __future__ import annotations

import asyncio
import contextvars
import hmac
import sqlite3
import threading
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, cast
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from adrl.api.auth import Principal
from adrl.core.container_control import EngineError, ResourceError
from adrl.core.execution_control import ExecutionControl, ExecutionPolicy
from adrl.core.launch_markers import LaunchMarkers
from adrl.core.resource_owner import ResourceEvent, StoppedResourceOwner

Ref = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Phase = Literal["claim", "acknowledged", "sealed", "stopped", "discard_issued", "discarded"]
TRANSITIONS: dict[str, set[str]] = {
    "claim": {"acknowledged", "sealed"},
    "acknowledged": {"sealed"},
    "sealed": {"stopped", "discard_issued"},
    "stopped": {"discard_issued"},
    "discard_issued": {"discarded"},
    "discarded": set(),
}


class LaunchEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["isolated-launch-event-v1"] = "isolated-launch-event-v1"
    operation_key: Ref
    workspace_key: Ref
    host_key_id: str = Field(min_length=1, max_length=128)
    resource_id: Ref
    resource_created: str = Field(min_length=1, max_length=64)
    resource_mac: Ref
    engine_ref: Ref
    configuration_ref: Ref
    fixture_ref: Ref
    policy: ExecutionPolicy
    sequence: int = Field(strict=True, ge=0, le=7)
    phase: Phase
    recorded_at: AwareDatetime
    started_at: str | None = Field(default=None, min_length=1, max_length=64)
    workspace_state: Literal["blocked"] = "blocked"
    exact_close_eligible: Literal[False] = False
    eligible_for_learning: Literal[False] = False

    @model_validator(mode="after")
    def launch(self) -> LaunchEvent:
        if (self.phase == "claim" and (self.sequence != 0 or self.started_at is not None)) or (
            self.phase in {"acknowledged", "stopped"} and self.started_at is None
        ):
            raise ValueError("launch_phase_fields_invalid")
        return self


class ExecutionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    resource_state: Literal["not_launched", "stopped", "absent", "uncertain"]
    audit_failed: bool
    execution_failed: bool = False
    last_event: LaunchEvent | None
    workspace_state: Literal["blocked"] = "blocked"
    exact_close_eligible: Literal[False] = False
    eligible_for_learning: Literal[False] = False


class IsolatedExecution:
    """Original caller dispatches once; reopened recovery only seals and discards.

    The worker runs outside the caller event loop. Cancellation drains it. The pinned fixture
    has its own lifetime; owner/host death does not magically stop a daemon-owned workload.
    """

    def __init__(self, owner: StoppedResourceOwner, policy: ExecutionPolicy | None = None) -> None:
        self.owner = owner
        self.policy = ExecutionPolicy.model_validate((policy or ExecutionPolicy()).model_dump())
        self.control = ExecutionControl(owner.control, self.policy)
        self.markers = LaunchMarkers(owner.journal.data.keys.root, self.policy)
        self._active = threading.Lock()
        self.last_report: ExecutionReport | None = None

    def _ref(self, purpose: str, value: Any) -> str:
        return self.owner._reference("launch-v1:" + purpose, value)

    def _binding(
        self, operation: str, conn: sqlite3.Connection | None = None
    ) -> tuple[ResourceEvent, str]:
        history = self.owner._history(operation, conn)
        if len(history) < 3:
            raise ResourceError("launch_original_binding_required")
        query = "SELECT mac FROM product_resource_events WHERE operation_key=? AND event_seq=2"
        rows = (
            list(conn.execute(query, (operation,)))
            if conn
            else self.owner.journal.data.ledger.read(query, (operation,))
        )
        return history[2], cast(str, rows[0]["mac"])

    def _history(
        self, operation: str, conn: sqlite3.Connection | None = None
    ) -> tuple[LaunchEvent, ...]:
        bound, bound_mac = self._binding(operation, conn)
        query = "SELECT * FROM product_launch_events WHERE operation_key=? ORDER BY event_seq"
        rows = (
            list(conn.execute(query, (operation,)))
            if conn
            else self.owner.journal.data.ledger.read(query, (operation,))
        )
        events: list[LaunchEvent] = []
        previous = bound_mac
        mutable = {"sequence", "phase", "recorded_at", "started_at"}
        for sequence, row in enumerate(rows):
            try:
                event = LaunchEvent.model_validate_json(row["payload_json"])
                if (
                    row["event_seq"] != sequence
                    or event.sequence != sequence
                    or row["event_type"] != event.phase
                    or event.operation_key != operation
                    or event.workspace_key != bound.workspace_key
                    or event.resource_id != bound.resource_id
                    or event.resource_created != bound.resource_created
                    or event.resource_mac != bound_mac
                    or event.host_key_id != bound.host_key_id
                    or row["prev_mac"] != previous
                    or not hmac.compare_digest(
                        row["mac"], self._ref("event", [previous, row["payload_json"]])
                    )
                    or len(row["payload_json"].encode()) > event.policy.max_event_bytes
                ):
                    raise ValueError("launch_record_mismatch")
                if not events:
                    if event.phase != "claim":
                        raise ValueError("launch_claim_missing")
                else:
                    last = events[-1]
                    if (
                        event.phase not in TRANSITIONS[last.phase]
                        or event.model_dump(exclude=mutable) != last.model_dump(exclude=mutable)
                        or (event.phase != "acknowledged" and event.started_at != last.started_at)
                    ):
                        raise ValueError("launch_history_changed")
                events.append(event)
                previous = row["mac"]
            except (ValueError, TypeError):
                raise ResourceError("launch_history_integrity_failure") from None
        return tuple(events)

    def read(self, operation_id: UUID) -> tuple[LaunchEvent, ...]:
        return self._history(self.owner._operation(operation_id))

    def _insert(self, conn: sqlite3.Connection, event: LaunchEvent, previous: str) -> None:
        payload = event.model_dump_json()
        if len(payload.encode()) > event.policy.max_event_bytes:
            raise ResourceError("launch_event_limit")
        conn.execute(
            "INSERT INTO product_launch_events "
            "(operation_key,event_seq,event_type,payload_json,prev_mac,mac) VALUES (?,?,?,?,?,?)",
            (
                event.operation_key,
                event.sequence,
                event.phase,
                payload,
                previous,
                self._ref("event", [previous, payload]),
            ),
        )

    def _authority(self, principal: Principal, operation: str) -> None:
        def check(conn: sqlite3.Connection) -> None:
            bound, _ = self._binding(operation, conn)
            self.owner._check_started(conn, principal, bound)

        self.owner.journal.data.ledger.submit(check).result(timeout=self.policy.ledger_seconds)

    def _prepare(self, principal: Principal, operation_id: UUID) -> LaunchEvent:
        history = self.owner.read(operation_id)
        bound = history[-1]
        if bound.phase != "bound":
            raise ResourceError("launch_stopped_binding_required")
        self._authority(principal, bound.operation_key)
        if self._history(bound.operation_key):
            raise ResourceError("launch_already_claimed")
        original = self.owner._inspect_bound(bound)
        engine = self.control.profile()
        fixture = self.control.fixture(original)
        projected = self.control.projection(original, original=True)
        _, bound_mac = self._binding(bound.operation_key)
        event = LaunchEvent(
            operation_key=bound.operation_key,
            workspace_key=bound.workspace_key,
            host_key_id=bound.host_key_id,
            resource_id=cast(str, bound.resource_id),
            resource_created=cast(str, bound.resource_created),
            resource_mac=bound_mac,
            engine_ref=self._ref("engine", engine),
            configuration_ref=self._ref("configuration", projected),
            fixture_ref=self._ref("fixture", fixture),
            policy=self.policy,
            sequence=0,
            phase="claim",
            recorded_at=datetime.now(UTC),
        )
        largest = LaunchEvent.model_validate(
            event.model_dump()
            | {
                "phase": "stopped",
                "sequence": 7,
                "started_at": "9" * 64,
            }
        )
        if len(largest.model_dump_json().encode()) > self.policy.max_event_bytes:
            raise ResourceError("launch_future_event_limit")
        return event

    def _claim(self, principal: Principal, event: LaunchEvent) -> LaunchEvent:
        def write(conn: sqlite3.Connection) -> LaunchEvent:
            bound, mac = self._binding(event.operation_key, conn)
            if (
                self.owner._history(event.operation_key, conn)[-1].phase != "bound"
                or mac != event.resource_mac
            ):
                raise ResourceError("launch_binding_changed")
            self.owner._check_started(conn, principal, bound)
            if self._history(event.operation_key, conn):
                raise ResourceError("launch_already_claimed")
            count = conn.execute(
                "SELECT COUNT(*) FROM product_launch_events WHERE event_seq=0"
            ).fetchone()[0]
            if count >= event.policy.max_histories:
                raise ResourceError("launch_history_capacity")
            self._insert(conn, event, event.resource_mac)
            return event

        return cast(
            LaunchEvent,
            self.owner.journal.data.ledger.submit(write).result(timeout=self.policy.ledger_seconds),
        )

    def _append(
        self, operation: str, phase: Phase, *, started_at: str | None = None
    ) -> LaunchEvent:
        def write(conn: sqlite3.Connection) -> LaunchEvent:
            history = self._history(operation, conn)
            if not history:
                raise ResourceError("launch_claim_unavailable")
            last = history[-1]
            if phase == last.phase and (started_at is None or started_at == last.started_at):
                return last
            if phase not in TRANSITIONS[last.phase] or last.sequence + 1 >= last.policy.max_events:
                raise ResourceError("launch_transition_refused")
            value = last.model_dump() | {
                "phase": phase,
                "sequence": last.sequence + 1,
                "recorded_at": datetime.now(UTC),
            }
            if started_at is not None:
                if phase != "acknowledged":
                    raise ResourceError("launch_timestamp_transition_refused")
                value["started_at"] = started_at
            event = LaunchEvent.model_validate(value)
            previous = conn.execute(
                "SELECT mac FROM product_launch_events WHERE operation_key=? AND event_seq=?",
                (operation, last.sequence),
            ).fetchone()[0]
            self._insert(conn, event, previous)
            return event

        return cast(
            LaunchEvent,
            self.owner.journal.data.ledger.submit(write).result(timeout=self.policy.ledger_seconds),
        )

    def _execution(self, event: LaunchEvent) -> ExecutionControl:
        if event.policy == self.control.policy:
            return self.control
        return ExecutionControl(self.owner.control, event.policy)

    def _engine(self, event: LaunchEvent) -> ExecutionControl:
        control = self._execution(event)
        if self._ref("engine", control.profile()) != event.engine_ref:
            raise ResourceError("launch_engine_changed")
        return control

    def _value(self, event: LaunchEvent, value: dict[str, Any]) -> dict[str, Any]:
        control = self._execution(event)
        if self._ref("configuration", control.projection(value)) != event.configuration_ref:
            raise ResourceError("launch_configuration_changed")
        if event.started_at is not None:
            control.started(value, event.started_at)
        return value

    def _inspect(self, event: LaunchEvent) -> dict[str, Any]:
        control = self._engine(event)
        return self._value(event, control.control.inspect(event.resource_id))

    def _absent(self, event: LaunchEvent) -> bool:
        # Only the exact container inspection's 404 can confirm absence, never /info,
        # /version, image validation, or another intermediate request's error.
        control = self._engine(event)
        try:
            value = control.control.inspect(event.resource_id)
        except EngineError as exc:
            if exc.status == 404:
                return True
            raise
        self._value(event, value)
        return False

    def _report(
        self,
        state: Literal["not_launched", "stopped", "absent", "uncertain"],
        failed: bool,
        event: LaunchEvent | None,
    ) -> ExecutionReport:
        report = ExecutionReport(resource_state=state, audit_failed=failed, last_event=event)
        self.last_report = report
        return report

    def recover(self, operation_id: UUID) -> ExecutionReport:
        """Trusted local operator cleanup. Never dispatch, adopt or infer a successful task."""
        self.last_report = None
        try:
            # Authenticate before making a bounded, operation-specific cleanup lock file.
            if not self.read(operation_id):
                return self._report("not_launched", False, None)
            with self.markers.recovery(self.owner._operation(operation_id)):
                return self._recover(operation_id)
        except Exception:
            return self._report("uncertain", True, None)

    def _recover(self, operation_id: UUID) -> ExecutionReport:
        try:
            history = self.read(operation_id)
            if not history:
                return self._report("not_launched", False, None)
            event = history[-1]
        except Exception:
            return self._report("uncertain", True, None)
        failed = False
        if event.phase == "discarded":
            try:
                return self._report("absent" if self._absent(event) else "uncertain", False, event)
            except Exception:
                return self._report("uncertain", False, event)
        if event.phase == "discard_issued":
            # A prior caller may have sent a request that is still in flight. Reconcile
            # only exact absence; never turn an issued history into another DELETE.
            try:
                if not self._absent(event):
                    return self._report("uncertain", False, event)
                event = self._append(event.operation_key, "discarded")
                return self._report("absent", False, event)
            except Exception:
                return self._report("uncertain", True, event)
        for phase in ("sealed", "discard_issued"):
            if phase == "sealed" and event.phase not in {"claim", "acknowledged"}:
                continue
            try:
                event = self._append(event.operation_key, phase)
            except Exception:
                # Audit acknowledgement may be lost. Authenticated ownership is independent.
                failed = True
        try:
            if not self._absent(event):
                try:
                    self._execution(event).discard(event.resource_id)
                except Exception:
                    # No reissue: only exact-ID absence may reconcile a lost deletion reply.
                    if not self._absent(event):
                        raise
            if not self._absent(event):
                return self._report("uncertain", failed, event)
        except Exception:
            return self._report("uncertain", failed, event)
        if not failed:
            try:
                event = self._append(event.operation_key, "discarded")
            except Exception:
                failed = True
        return self._report("absent", failed, event)

    def _stop(self, event: LaunchEvent) -> LaunchEvent:
        value = self._inspect(event)
        if value["State"]["Running"]:
            try:
                self._execution(event).kill(event.resource_id)
            except EngineError as exc:
                if exc.status != 409:
                    raise
        deadline = time.monotonic() + event.policy.stop_seconds
        while time.monotonic() < deadline:
            value = self._inspect(event)
            if value["State"]["Status"] == "exited":
                return self._append(event.operation_key, "stopped")
            time.sleep(event.policy.poll_seconds)
        raise ResourceError("launch_stop_unconfirmed")

    def _run(
        self, principal: Principal, operation_id: UUID, stop: threading.Event
    ) -> ExecutionReport:
        event = self._prepare(principal, operation_id)
        if stop.is_set():
            raise ResourceError("launch_cancelled_before_admission")
        # Competing/recovery callers cannot reach the cleanup block by finding a marker.
        self.markers.publish(event.operation_key)
        try:
            event = self._claim(principal, event)
            self._authority(principal, event.operation_key)
            self.owner.control.never_started(self._inspect(event))
            if stop.is_set():
                return self.recover(operation_id)
            self.control.start(event.resource_id)
            value = self._inspect(event)
            started = self.control.started(value)
            event = self._append(event.operation_key, "acknowledged", started_at=started)
            event = self._append(event.operation_key, "sealed")
            deadline = time.monotonic() + event.policy.max_run_seconds
            while True:
                self._authority(principal, event.operation_key)
                value = self._inspect(event)
                if (
                    stop.is_set()
                    or time.monotonic() >= deadline
                    or value["State"]["Status"] == "exited"
                ):
                    break
                stop.wait(event.policy.poll_seconds)
            event = self._stop(event)
            # Erasure can race the final audit. Recheck before reporting retained output.
            self._authority(principal, event.operation_key)
            return self._report("stopped", False, event)
        except Exception:
            recovered = self.recover(operation_id)
            report = recovered.model_copy(update={"execution_failed": True})
            self.last_report = report
            return report

    async def run(
        self, principal: Principal, operation_id: UUID, *, stop: threading.Event | None = None
    ) -> ExecutionReport:
        if not self._active.acquire(blocking=False):
            raise ResourceError("launch_worker_already_active")
        self.last_report = None
        stopping = stop if stop is not None else threading.Event()
        context = contextvars.copy_context()
        worker = asyncio.get_running_loop().run_in_executor(
            None, context.run, self._run, principal, operation_id, stopping
        )
        try:
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                stopping.set()
                while not worker.done():
                    try:
                        await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        stopping.set()
                    except Exception:
                        break
                if not worker.cancelled():
                    worker.exception()
                raise
        finally:
            self._active.release()
