"""Stop coordination with permanent workspace fences. Primary: ADRL-OPS-001.

Secondary: ADRL-MEM-001/002/003/005/010, ADRL-SAF-007, ADRL-TRU-001.
Internal synthetic-fixture execution only. No release, successful close, capture binding,
PID recovery or learning authority. Group cleanup does not prove all writers stopped.
"""

from __future__ import annotations

import asyncio
import contextvars
import sqlite3
import threading
import time
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from adrl.api.auth import Principal
from adrl.core.process_owner import ProcessOwner, ProcessPolicy, ProcessReport, ProcessSpec
from adrl.ledger import crypto
from adrl.ledger.attempts import (
    TERMINAL,
    AttemptError,
    AttemptJournal,
    AttemptPolicy,
    AttemptTransition,
    check_execution_fence,
)

StopCause = Literal[
    "none", "requested", "revoked", "expired", "journal_closed", "authority_unavailable"
]


class CoordinationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    schema_version: Literal["group-attempt-coordination-v1"] = "group-attempt-coordination-v1"
    poll_seconds: float = Field(default=0.05, ge=0.01, le=1)
    max_workspace_fences: int = Field(default=128, ge=1, le=128)
    process: ProcessPolicy = Field(default_factory=ProcessPolicy)


class CoordinationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["group-attempt-coordination-report-v1"] = (
        "group-attempt-coordination-report-v1"
    )
    attempt_id: UUID
    stop_cause: StopCause
    process: ProcessReport | None
    process_error: bool
    terminal_record: Literal["recorded", "already_terminal", "unavailable"]
    workspace_state: Literal["blocked"] = "blocked"
    exact_close_eligible: Literal[False] = False
    eligible_for_learning: Literal[False] = False
    policy: CoordinationPolicy


class AttemptCoordinator:
    """One active in-memory run; committed fences survive any result and restart.

    The entire worker, including admission and terminal writing, drains on cancellation.
    A separate monitor thread observes revocation even while the caller event loop is busy.
    There is no atomic launch/erasure transaction and no hard scheduling or I/O deadline.
    """

    def __init__(self, journal: AttemptJournal, policy: CoordinationPolicy | None = None) -> None:
        self.journal = journal
        self.policy = policy or CoordinationPolicy()
        self._active = threading.Lock()
        self._owner = ProcessOwner(journal.data.keys.hmac_key(), self.policy.process)
        self.last_report: CoordinationReport | None = None

    async def run(
        self,
        principal: Principal,
        attempt_id: UUID,
        spec: ProcessSpec,
        *,
        stop: threading.Event | None = None,
    ) -> CoordinationReport:
        copied = ProcessSpec.model_validate(spec.model_dump())
        if not self._active.acquire(blocking=False):
            raise AttemptError("coordinator_already_active")
        stopping = stop if stop is not None else threading.Event()
        context = contextvars.copy_context()
        self.last_report = None
        worker = asyncio.get_running_loop().run_in_executor(
            None, context.run, self._run, principal, attempt_id, copied, stopping
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

    def _admit(
        self, principal: Principal, attempt_id: UUID, spec: ProcessSpec, stop: threading.Event
    ) -> None:
        key = self.journal.captures._key(principal)
        _, workspace = self.journal._workspace(principal, spec.cwd, strict=True)
        data = self.journal.data
        attempt_key = crypto.keyed_hash(key, "attempt:" + str(attempt_id))
        host_key_id = data.keys.hmac_key_id()

        def write(conn: sqlite3.Connection) -> None:
            if stop.is_set():
                raise AttemptError("execution_admission_stopped")
            if self.journal.captures._key(principal) != key:
                raise AttemptError("execution_key_unavailable")
            check_execution_fence(conn, workspace, host_key_id)
            rows = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM product_attempt_events WHERE session_hmac=? AND attempt_key=? "
                    "ORDER BY attempt_seq",
                    (principal.session_hmac, attempt_key),
                )
            ]
            history = self.journal._history(principal, key, rows)
            grant = conn.execute(
                "SELECT * FROM product_attempt_capacity WHERE session_hmac=? AND attempt_key=?",
                (principal.session_hmac, attempt_key),
            ).fetchone()
            self.journal._check_grant(history, rows[0], dict(grant) if grant else None)
            if not isinstance(history[0].policy, AttemptPolicy):
                raise AttemptError("execution_requires_v2_attempt")
            if history[-1].phase != "started":
                raise AttemptError("execution_attempt_not_started")
            if history[0].workspace_ref != "hmac:" + workspace:
                raise AttemptError("execution_workspace_mismatch")
            if conn.execute("SELECT COUNT(*) FROM product_execution_fences").fetchone()[0] >= (
                self.policy.max_workspace_fences
            ):
                raise AttemptError("execution_fence_limit")
            conn.execute(
                "INSERT INTO product_execution_fences "
                "(workspace_key,session_hmac,attempt_key,start_event_key,"
                "host_key_id,policy_json,ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    workspace,
                    principal.session_hmac,
                    attempt_key,
                    rows[0]["event_key"],
                    host_key_id,
                    self.policy.model_dump_json(),
                    datetime.now(UTC).isoformat(),
                ),
            )

        # A timeout/lost acknowledgement never permits launch or replay. The writer may still
        # commit the fence; treat that workspace as uncertain, not safe to retry automatically.
        data.ledger.submit(write).result(timeout=10)

    def _authority(self, principal: Principal, attempt_id: UUID) -> StopCause:
        try:
            if self.journal.data.keys.is_revoked(principal.session_hmac):
                return "revoked"
            if principal.assertion.expires_at <= time.time():
                return "expired"
            if self.journal.read(principal, attempt_id)[-1].phase != "started":
                return "journal_closed"
        except Exception:
            # No raw exception, path or program output is copied into the report.
            return "authority_unavailable"
        return "none"

    def _terminal(
        self, principal: Principal, attempt_id: UUID
    ) -> Literal["recorded", "already_terminal", "unavailable"]:
        try:
            if self.journal.read(principal, attempt_id)[-1].phase in TERMINAL:
                return "already_terminal"
            asyncio.run(
                self.journal.transition(
                    principal,
                    AttemptTransition(
                        kind="mark_incomplete",
                        event_id=uuid4(),
                        attempt_id=attempt_id,
                        reason="quiescence_unavailable",
                    ),
                )
            )
            return "recorded"
        except Exception:
            # Commit may have succeeded before acknowledgement/readback failed. Do not invent
            # a completion receipt or retry with a new event identity.
            return "unavailable"

    def _run(
        self, principal: Principal, attempt_id: UUID, spec: ProcessSpec, stop: threading.Event
    ) -> CoordinationReport:
        self._admit(principal, attempt_id, spec, stop)
        finished = threading.Event()
        cause: list[StopCause] = ["requested" if stop.is_set() else "none"]

        def monitor() -> None:
            while not finished.is_set():
                observed = self._authority(principal, attempt_id)
                if observed != "none":
                    cause[0] = observed
                    stop.set()
                    return
                if stop.is_set():
                    cause[0] = "requested"
                    return
                finished.wait(self.policy.poll_seconds)

        owner = self._owner
        # A failed new launch must not borrow a previous run's cleanup observation.
        owner.last_report = None
        watcher = threading.Thread(target=monitor, name="adrl-attempt-authority", daemon=True)
        process: ProcessReport | None = None
        failed = False
        try:
            observed = self._authority(principal, attempt_id)
            if observed != "none":
                cause[0] = observed
                stop.set()
            watcher.start()
            process = asyncio.run(owner.run(spec, stop=stop))
        except Exception:
            failed = True
            stop.set()
            process = owner.last_report
        finally:
            finished.set()
            if watcher.ident is not None:
                watcher.join()
        if cause[0] == "none" and stop.is_set():
            cause[0] = "requested"
        report = CoordinationReport(
            attempt_id=attempt_id,
            stop_cause=cause[0],
            process=process,
            process_error=failed,
            terminal_record=self._terminal(principal, attempt_id),
            policy=self.policy,
        )
        self.last_report = report
        return report
