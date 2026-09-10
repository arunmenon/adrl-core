"""Append-only operator attempt lifecycle. Primary: ADRL-MEM-002.

Secondary: ADRL-MEM-001/003/005/010, ADRL-SEM-002/007, ADRL-TRU-001, ADRL-OPS-001.
Records intent and interruption only. No successful close, process supervision, capture
association or learning authority is implemented by this internal journal.
"""

from __future__ import annotations

import asyncio
import re
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, cast
from uuid import UUID

from cryptography.exceptions import InvalidTag
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

from adrl.api.auth import Principal
from adrl.api.contracts import OpaqueId
from adrl.api.store import ProductStore
from adrl.ledger import crypto
from adrl.ledger.capture import CaptureArchive, CaptureEntry, CapturePolicy, _manifest
from adrl.ledger.session_verification import _tree_ref

PHASES = {
    "start": "started",
    "request_close": "close_requested",
    "cancel": "cancelled",
    "mark_incomplete": "incomplete",
}
TERMINAL = frozenset({"cancelled", "incomplete"})


def check_execution_fence(conn: sqlite3.Connection, workspace: str, host_key_id: str) -> None:
    """A journal terminal event cannot release a supervised workspace block."""
    if conn.execute(
        "SELECT 1 FROM product_execution_fences WHERE host_key_id!=? LIMIT 1", (host_key_id,)
    ).fetchone():
        raise AttemptError("execution_fence_key_changed")
    if conn.execute(
        "SELECT 1 FROM product_execution_fences WHERE workspace_key=?", (workspace,)
    ).fetchone():
        raise AttemptError("workspace_execution_blocked")


class AttemptError(ValueError):
    """An attempt command conflicts with its identity, history or resource bounds."""


class _AttemptBounds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    snapshot: CapturePolicy = Field(default_factory=CapturePolicy)
    max_session_attempts: int = Field(default=3, ge=1, le=3)
    max_event_bytes: int = Field(default=8_000_000, ge=1, le=8_000_000)
    max_history_bytes: int = Field(default=32_000_000, ge=1, le=32_000_000)


class LegacyAttemptPolicy(_AttemptBounds):
    """Read/retry/continue historical v1 attempts; new v1 admission is refused."""

    schema_version: Literal["operator-attempt-policy-v1"] = "operator-attempt-policy-v1"
    max_events_per_attempt: int = Field(default=8, ge=1, le=8)


class AttemptPolicy(_AttemptBounds):
    schema_version: Literal["operator-attempt-policy-v2"] = "operator-attempt-policy-v2"
    max_events_per_attempt: int = Field(default=8, ge=2, le=8)
    terminal_reserve_bytes: int = Field(default=1024, ge=1024, le=4096)


JournalPolicy = Annotated[
    AttemptPolicy | LegacyAttemptPolicy, Field(discriminator="schema_version")
]


class StartAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["start"] = "start"
    event_id: UUID
    attempt_id: UUID
    task_ref: OpaqueId
    capture_id: UUID
    parent_attempt_id: UUID | None = None

    @model_validator(mode="after")
    def distinct_parent(self) -> StartAttempt:
        if self.parent_attempt_id == self.attempt_id:
            raise ValueError("An attempt cannot parent itself.")
        return self


class AttemptTransition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["request_close", "cancel", "mark_incomplete"]
    event_id: UUID
    attempt_id: UUID
    reason: (
        Literal[
            "operator_cancelled",
            "operator_interrupted",
            "supervisor_lost",
            "capture_unavailable",
            "quiescence_unavailable",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def meaningful_reason(self) -> AttemptTransition:
        if self.kind == "request_close" and self.reason is not None:
            raise ValueError("Close requests carry no terminal reason.")
        if self.kind == "cancel" and self.reason != "operator_cancelled":
            raise ValueError("Cancellation needs its explicit operator reason.")
        if self.kind == "mark_incomplete" and self.reason in {None, "operator_cancelled"}:
            raise ValueError("Incomplete attempts need an interruption reason.")
        return self


AttemptCommand = Annotated[StartAttempt | AttemptTransition, Field(discriminator="kind")]


class AttemptEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["operator-attempt-event-v1"] = "operator-attempt-event-v1"
    authority: Literal["local_operator"] = "local_operator"
    attribution: Literal["unestablished"] = "unestablished"
    eligible_for_learning: Literal[False] = False
    command: AttemptCommand
    sequence: int = Field(strict=True, ge=0, le=7)
    recorded_at: AwareDatetime
    workspace_ref: str = Field(pattern=r"^hmac:[a-f0-9]{64}$")
    policy: JournalPolicy | None = None
    initial_manifest: tuple[tuple[str, str], ...] | None = None
    initial_source_ref: str | None = Field(default=None, pattern=r"^hmac:[a-f0-9]{64}$")

    @property
    def phase(self) -> str:
        return PHASES[self.command.kind]

    @model_validator(mode="after")
    def initial_state(self) -> AttemptEvent:
        if not isinstance(self.command, StartAttempt):
            if (
                self.policy is not None
                or self.initial_manifest is not None
                or self.initial_source_ref is not None
            ):
                raise ValueError("Only the start event carries initial state.")
            return self
        if (
            self.sequence != 0
            or self.policy is None
            or self.initial_manifest is None
            or self.initial_source_ref is None
        ):
            raise ValueError("A start requires sequence zero and its initial provenance.")
        manifest = dict(self.initial_manifest)
        if (
            len(manifest) != len(self.initial_manifest)
            or len(manifest) > self.policy.snapshot.max_files
        ):
            raise ValueError("Duplicate or excessive manifest entries.")
        paths: set[str] = set()
        for name, signature in self.initial_manifest:
            directory = signature == "directory"
            if directory and not name.endswith("/"):
                raise ValueError("Directory manifest key must end in slash.")
            if not directory and not re.fullmatch(r"[01]:[a-f0-9]{64}", signature):
                raise ValueError("Invalid manifest signature.")
            path = name[:-1] if directory else name
            CaptureEntry(
                path=path,
                kind="directory" if directory else "file",
                content=None if directory else "",
            )
            if path in paths:
                raise ValueError("Manifest path has conflicting kinds.")
            paths.add(path)
            for parent in PurePosixPath(path).parents:
                if str(parent) != "." and manifest.get(str(parent) + "/") != "directory":
                    raise ValueError("Missing manifest parent directory.")
        return self


def _allowed(previous: str, command: StartAttempt | AttemptTransition) -> bool:
    if isinstance(command, StartAttempt) or previous in TERMINAL:
        return False
    return previous == "started" or (
        previous == "close_requested" and command.kind in {"cancel", "mark_incomplete"}
    )


class AttemptJournal:
    """Trusted local journal; an active reservation is not a process or filesystem lock."""

    def __init__(self, data: ProductStore, policy: JournalPolicy | None = None) -> None:
        self.data = data
        self.policy = policy or AttemptPolicy()
        self.captures = CaptureArchive(data, self.policy.snapshot)

    def _workspace(
        self, principal: Principal, workspace: Path, *, strict: bool
    ) -> tuple[Path, str]:
        if workspace.is_symlink():
            raise AttemptError("symlink_workspace")
        root = workspace.resolve(strict=strict)
        if root != Path(principal.assertion.inventory.root).resolve(strict=strict):
            raise AttemptError("attempt_workspace_binding_mismatch")
        identity = crypto.keyed_hash(self.data.keys.hmac_key(), "attempt-workspace:" + str(root))
        return root, identity

    @staticmethod
    def _aad(
        session: str,
        attempt: str,
        event: str,
        workspace: str,
        phase: str,
        sequence: int,
        capacity_version: int = 0,
    ) -> bytes:
        base = f"attempt:{session}:{attempt}:{event}:{workspace}:{phase}:{sequence}"
        if capacity_version:
            base += f":capacity:{capacity_version}"
        return base.encode()

    def _decode(self, principal: Principal, key: bytes, row: dict[str, Any]) -> AttemptEvent:
        aad = self._aad(
            principal.session_hmac,
            row["attempt_key"],
            row["event_key"],
            row["workspace_key"],
            row["event_type"],
            row["attempt_seq"],
            row["capacity_version"],
        )
        try:
            event = AttemptEvent.model_validate_json(
                crypto.decrypt(key, row["nonce"], row["ciphertext"], aad)
            )
        except (InvalidTag, ValidationError, ValueError, TypeError) as exc:
            raise AttemptError("attempt_integrity_failure") from exc
        if (
            row["session_hmac"] != principal.session_hmac
            or row["attempt_key"]
            != crypto.keyed_hash(key, "attempt:" + str(event.command.attempt_id))
            or row["event_key"]
            != crypto.keyed_hash(key, "attempt-event:" + str(event.command.event_id))
            or event.sequence != row["attempt_seq"]
            or event.phase != row["event_type"]
            or event.workspace_ref != "hmac:" + row["workspace_key"]
            or event.recorded_at.isoformat() != row["ts"]
        ):
            raise AttemptError("attempt_integrity_failure")
        if event.initial_manifest is not None and event.initial_source_ref != _tree_ref(
            self.data.keys.hmac_key(), dict(event.initial_manifest)
        ):
            raise AttemptError("attempt_integrity_failure")
        return event

    def _history(
        self, principal: Principal, key: bytes, rows: list[dict[str, Any]]
    ) -> tuple[AttemptEvent, ...]:
        if not rows:
            raise AttemptError("attempt_unavailable")
        events = tuple(self._decode(principal, key, row) for row in rows)
        if not isinstance(events[0].command, StartAttempt) or events[0].policy is None:
            raise AttemptError("attempt_history_incomplete")
        if len(events) > events[0].policy.max_events_per_attempt:
            raise AttemptError("attempt_history_incomplete")
        for index, event in enumerate(events):
            if (
                event.sequence != index
                or event.workspace_ref != events[0].workspace_ref
                or (index > 0 and not _allowed(events[index - 1].phase, event.command))
                or rows[index]["capacity_version"]
                != int(isinstance(events[0].policy, AttemptPolicy))
            ):
                raise AttemptError("attempt_history_incomplete")
        return events

    @staticmethod
    def _check_grant(
        history: tuple[AttemptEvent, ...], start: dict[str, Any], grant: dict[str, Any] | None
    ) -> None:
        policy = history[0].policy
        if isinstance(policy, AttemptPolicy):
            expected = {
                "session_hmac": start["session_hmac"],
                "attempt_key": start["attempt_key"],
                "start_event_key": start["event_key"],
                "reserved_bytes": policy.terminal_reserve_bytes,
                "history_limit": policy.max_history_bytes,
            }
            if grant != expected:
                raise AttemptError("attempt_capacity_integrity_failure")
        elif grant is not None:
            raise AttemptError("attempt_capacity_integrity_failure")

    @staticmethod
    def _capacity_state(conn: sqlite3.Connection) -> tuple[int, int | None]:
        # Cross-session accounting uses only this explicit metadata. Session erasure must
        # not make a still-pending quota commitment disappear. No mutable release counter.
        inconsistent = conn.execute(
            "SELECT 1 FROM product_attempt_events s LEFT JOIN product_attempt_capacity c "
            "ON c.session_hmac=s.session_hmac AND c.attempt_key=s.attempt_key "
            "WHERE s.event_type='started' AND ((s.capacity_version=1 AND "
            "(c.attempt_key IS NULL OR c.start_event_key!=s.event_key OR s.attempt_seq!=0)) "
            "OR (s.capacity_version=0 AND c.attempt_key IS NOT NULL)) "
            "UNION ALL SELECT 1 FROM product_attempt_capacity c "
            "LEFT JOIN product_attempt_events s ON c.session_hmac=s.session_hmac "
            "AND c.start_event_key=s.event_key WHERE s.event_key IS NULL "
            "OR s.event_type!='started' OR s.attempt_key!=c.attempt_key "
            "OR s.capacity_version!=1 OR s.attempt_seq!=0 LIMIT 1"
        ).fetchone()
        if inconsistent:
            raise AttemptError("attempt_capacity_integrity_failure")
        row = conn.execute(
            "SELECT COALESCE(SUM(c.reserved_bytes),0), MIN(c.history_limit) "
            "FROM product_attempt_capacity c WHERE NOT EXISTS "
            "(SELECT 1 FROM product_attempt_events t WHERE t.session_hmac=c.session_hmac "
            "AND t.attempt_key=c.attempt_key AND t.event_type IN ('cancelled','incomplete'))"
        ).fetchone()
        return int(row[0]), int(row[1]) if row[1] is not None else None

    @staticmethod
    def _terminal_floor(event: AttemptEvent) -> int:
        """Maximum permitted terminal plaintext size under this exact serialized schema."""
        assert isinstance(event.policy, AttemptPolicy)
        sizes = []
        for reason in (
            "operator_cancelled",
            "operator_interrupted",
            "supervisor_lost",
            "capture_unavailable",
            "quiescence_unavailable",
        ):
            terminal = AttemptEvent(
                command=AttemptTransition.model_validate(
                    {
                        "kind": "cancel" if reason == "operator_cancelled" else "mark_incomplete",
                        "reason": reason,
                        "event_id": event.command.event_id,
                        "attempt_id": event.command.attempt_id,
                    }
                ),
                sequence=event.policy.max_events_per_attempt - 1,
                recorded_at=datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
                workspace_ref=event.workspace_ref,
            )
            sizes.append(len(terminal.model_dump_json().encode()))
        return max(sizes)

    def read(self, principal: Principal, attempt_id: UUID) -> tuple[AttemptEvent, ...]:
        key = self.captures._key(principal)
        rows = self.data.ledger.read(
            "SELECT * FROM product_attempt_events WHERE session_hmac=? AND attempt_key=? "
            "ORDER BY attempt_seq",
            (principal.session_hmac, crypto.keyed_hash(key, "attempt:" + str(attempt_id))),
        )
        events = self._history(principal, key, [dict(row) for row in rows])
        grants = self.data.ledger.read(
            "SELECT * FROM product_attempt_capacity WHERE session_hmac=? AND attempt_key=?",
            (principal.session_hmac, rows[0]["attempt_key"]),
        )
        self._check_grant(events, dict(rows[0]), dict(grants[0]) if grants else None)
        _, workspace = self._workspace(
            principal, Path(principal.assertion.inventory.root), strict=False
        )
        if events[0].workspace_ref != "hmac:" + workspace:
            raise AttemptError("attempt_workspace_binding_mismatch")
        if self.captures._key(principal) != key:
            raise AttemptError("attempt_key_unavailable")
        return events

    def _same_request(
        self, event: AttemptEvent, command: StartAttempt | AttemptTransition, workspace: str
    ) -> bool:
        return (
            event.command == command
            and event.workspace_ref == "hmac:" + workspace
            and (not isinstance(command, StartAttempt) or event.policy == self.policy)
        )

    async def start(
        self, principal: Principal, workspace: Path, command: StartAttempt
    ) -> AttemptEvent:
        key = self.captures._key(principal)
        root, identity = await asyncio.to_thread(self._workspace, principal, workspace, strict=True)
        # A retry preserves the original starting point, even after the task has edited files.
        prior = self.data.ledger.read(
            "SELECT * FROM product_attempt_events WHERE session_hmac=? AND event_key=?",
            (
                principal.session_hmac,
                crypto.keyed_hash(key, "attempt-event:" + str(command.event_id)),
            ),
        )
        if prior:
            event = self._decode(principal, key, dict(prior[0]))
            if not self._same_request(event, command, identity):
                raise AttemptError("attempt_event_conflict")
            self.read(principal, command.attempt_id)
            return event
        if isinstance(self.policy, LegacyAttemptPolicy):
            raise AttemptError("legacy_attempt_admission_refused")
        _, entries = await asyncio.to_thread(self.captures._inputs, principal, root)
        initial = tuple(sorted(_manifest(entries).items()))
        del entries
        return await self._append(principal, key, identity, command, initial)

    async def transition(self, principal: Principal, command: AttemptTransition) -> AttemptEvent:
        key = self.captures._key(principal)
        _, workspace = await asyncio.to_thread(
            self._workspace, principal, Path(principal.assertion.inventory.root), strict=False
        )
        return await self._append(principal, key, workspace, command, None)

    async def _append(
        self,
        principal: Principal,
        key: bytes,
        workspace: str,
        command: StartAttempt | AttemptTransition,
        initial: tuple[tuple[str, str], ...] | None,
    ) -> AttemptEvent:
        attempt_key = crypto.keyed_hash(key, "attempt:" + str(command.attempt_id))
        event_key = crypto.keyed_hash(key, "attempt-event:" + str(command.event_id))

        def write(conn: sqlite3.Connection) -> tuple[str, dict[str, Any] | None]:
            if principal.assertion.expires_at <= time.time():
                return "attempt_credential_expired", None
            if (
                self.data.keys.get_session_key(principal.session_hmac) != key
                or conn.execute(
                    "SELECT 1 FROM lineage_events WHERE lineage_hmac=? AND event_type='erased' "
                    "UNION ALL SELECT 1 FROM session_keys "
                    "WHERE session_hmac=? AND action='shredded'",
                    (principal.session_hmac, principal.session_hmac),
                ).fetchone()
            ):
                return "attempt_key_unavailable", None

            def rows_for(identity: str) -> list[dict[str, Any]]:
                return [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM product_attempt_events WHERE session_hmac=? "
                        "AND attempt_key=? ORDER BY attempt_seq",
                        (principal.session_hmac, identity),
                    )
                ]

            rows = rows_for(attempt_key)
            try:
                history = self._history(principal, key, rows) if rows else ()
                if history:
                    grant = conn.execute(
                        "SELECT * FROM product_attempt_capacity "
                        "WHERE session_hmac=? AND attempt_key=?",
                        (principal.session_hmac, attempt_key),
                    ).fetchone()
                    self._check_grant(history, rows[0], dict(grant) if grant else None)
                prior = conn.execute(
                    "SELECT * FROM product_attempt_events WHERE session_hmac=? AND event_key=?",
                    (principal.session_hmac, event_key),
                ).fetchone()
                if prior:
                    event = self._decode(principal, key, dict(prior))
                    if not self._same_request(event, command, workspace):
                        return "attempt_event_conflict", None
                    return "prior", dict(prior)
                committed_bytes, committed_ceiling = self._capacity_state(conn)
                if isinstance(command, StartAttempt):
                    if rows:
                        return "attempt_already_started", None
                    check_execution_fence(conn, workspace, self.data.keys.hmac_key_id())
                    if conn.execute(
                        "SELECT 1 FROM product_captures WHERE session_hmac=? "
                        "AND (attempt_key=? OR capture_key=?)",
                        (
                            principal.session_hmac,
                            attempt_key,
                            crypto.keyed_hash(key, "capture:" + str(command.capture_id)),
                        ),
                    ).fetchone():
                        return "capture_predates_attempt", None
                    if conn.execute(
                        "SELECT 1 FROM product_attempt_events a WHERE workspace_key=? "
                        "AND event_type IN ('started','close_requested') AND NOT EXISTS "
                        "(SELECT 1 FROM product_attempt_events b "
                        "WHERE b.session_hmac=a.session_hmac "
                        "AND b.attempt_key=a.attempt_key AND b.attempt_seq>a.attempt_seq)",
                        (workspace,),
                    ).fetchone():
                        return "workspace_reserved", None
                    starts = list(
                        conn.execute(
                            "SELECT * FROM product_attempt_events "
                            "WHERE session_hmac=? AND event_type='started'",
                            (principal.session_hmac,),
                        )
                    )
                    for row in starts:
                        previous = self._decode(principal, key, dict(row)).command
                        if (
                            isinstance(previous, StartAttempt)
                            and previous.capture_id == command.capture_id
                        ):
                            return "capture_id_reserved", None
                    if len(starts) >= self.policy.max_session_attempts:
                        return "session_attempt_limit", None
                    if command.parent_attempt_id is not None:
                        parent_key = crypto.keyed_hash(
                            key, "attempt:" + str(command.parent_attempt_id)
                        )
                        parent_rows = rows_for(parent_key)
                        parent = self._history(principal, key, parent_rows)
                        parent_grant = conn.execute(
                            "SELECT * FROM product_attempt_capacity "
                            "WHERE session_hmac=? AND attempt_key=?",
                            (principal.session_hmac, parent_key),
                        ).fetchone()
                        self._check_grant(
                            parent, parent_rows[0], dict(parent_grant) if parent_grant else None
                        )
                        parent_spec = parent[0].command
                        if (
                            parent[-1].phase not in TERMINAL
                            or not isinstance(parent_spec, StartAttempt)
                            or parent_spec.task_ref != command.task_ref
                            or parent[0].workspace_ref != "hmac:" + workspace
                        ):
                            return "parent_attempt_mismatch", None
                    policy = self.policy
                else:
                    if not history:
                        return "attempt_unavailable", None
                    if history[0].workspace_ref != "hmac:" + workspace:
                        return "attempt_workspace_binding_mismatch", None
                    if not _allowed(history[-1].phase, command):
                        return "attempt_transition_conflict", None
                    assert history[0].policy is not None
                    policy = history[0].policy
                if len(rows) >= policy.max_events_per_attempt:
                    return "attempt_event_limit", None
                is_terminal = not isinstance(command, StartAttempt) and command.kind in {
                    "cancel",
                    "mark_incomplete",
                }
                if (
                    isinstance(policy, AttemptPolicy)
                    and not is_terminal
                    and len(rows) >= policy.max_events_per_attempt - 1
                ):
                    return "attempt_terminal_slot_reserved", None
                event = AttemptEvent(
                    command=command,
                    sequence=len(rows),
                    recorded_at=datetime.now(UTC),
                    workspace_ref="hmac:" + workspace,
                    policy=policy if isinstance(command, StartAttempt) else None,
                    initial_manifest=initial,
                    initial_source_ref=_tree_ref(self.data.keys.hmac_key(), dict(initial))
                    if initial is not None
                    else None,
                )
                if isinstance(command, StartAttempt) and isinstance(policy, AttemptPolicy):
                    terminal_bytes = self._terminal_floor(event)
                    if terminal_bytes > policy.max_event_bytes:
                        return "attempt_terminal_payload_limit", None
                    # AES-GCM adds a 16-byte tag and the archive uses a 12-byte nonce.
                    if terminal_bytes + 28 > policy.terminal_reserve_bytes:
                        return "attempt_terminal_reserve_limit", None
            except AttemptError as exc:
                return str(exc), None
            plaintext = event.model_dump_json().encode()
            if len(plaintext) > policy.max_event_bytes:
                return "attempt_payload_limit", None
            nonce, ciphertext = crypto.encrypt(
                key,
                plaintext,
                self._aad(
                    principal.session_hmac,
                    attempt_key,
                    event_key,
                    workspace,
                    event.phase,
                    event.sequence,
                    int(isinstance(policy, AttemptPolicy)),
                ),
            )
            size = conn.execute(
                "SELECT COALESCE(SUM(LENGTH(ciphertext)+LENGTH(nonce)),0) "
                "FROM product_attempt_events"
            ).fetchone()[0]
            event_bytes = len(ciphertext) + len(nonce)
            reservation_delta = 0
            if isinstance(policy, AttemptPolicy):
                if isinstance(command, StartAttempt):
                    reservation_delta = policy.terminal_reserve_bytes
                elif is_terminal:
                    if event_bytes > policy.terminal_reserve_bytes:
                        return "attempt_terminal_reserve_limit", None
                    reservation_delta = -policy.terminal_reserve_bytes
            ceiling = policy.max_history_bytes
            if committed_ceiling is not None:
                ceiling = min(ceiling, committed_ceiling)
            if not (isinstance(policy, AttemptPolicy) and is_terminal):
                ceiling = min(ceiling, self.policy.max_history_bytes)
            if size + event_bytes + committed_bytes + reservation_delta > ceiling:
                return "attempt_history_limit", None
            cursor = conn.execute(
                "INSERT INTO product_attempt_events "
                "(session_hmac,attempt_key,event_key,workspace_key,"
                "event_type,attempt_seq,nonce,ciphertext,ts,capacity_version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    principal.session_hmac,
                    attempt_key,
                    event_key,
                    workspace,
                    event.phase,
                    event.sequence,
                    nonce,
                    ciphertext,
                    event.recorded_at.isoformat(),
                    int(isinstance(policy, AttemptPolicy)),
                ),
            )
            if isinstance(command, StartAttempt) and isinstance(policy, AttemptPolicy):
                conn.execute(
                    "INSERT INTO product_attempt_capacity "
                    "(session_hmac,attempt_key,start_event_key,reserved_bytes,history_limit) "
                    "VALUES (?,?,?,?,?)",
                    (
                        principal.session_hmac,
                        attempt_key,
                        event_key,
                        policy.terminal_reserve_bytes,
                        policy.max_history_bytes,
                    ),
                )
            return "recorded", dict(
                conn.execute(
                    "SELECT * FROM product_attempt_events WHERE seq=?", (cursor.lastrowid,)
                ).fetchone()
            )

        status, row = cast(
            tuple[str, dict[str, Any] | None], await self.data.ledger.write_through(write)
        )
        if row is None:
            raise AttemptError(status)
        event = self._decode(principal, key, row)
        if self.captures._key(principal) != key:
            raise AttemptError("attempt_key_unavailable")
        return event
