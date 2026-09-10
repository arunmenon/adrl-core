"""Verification events with provenance, and the begin/finish job flow. Primary: ADRL-MEM-003.

Secondary: ADRL-SAF-007 (sandboxed execution through the SandboxRunner port), ADRL-MEM-002
(late evidence), ADRL-MEM-009 (explicit route_id only).

A verification run is its own appended event. It records the verifier version, every argv as
a keyed hash, the protected-path policy version, the working-tree identity it ran against and a
pass, fail or indeterminate result. Policy-blocked, environment-failed and sandbox-unavailable
runs are indeterminate, never fail. A run against a tree that drifted beyond the turn's own
edits is flagged tree_drift and excluded from capability labels. Commands come only from the
operator's plan; nothing in a transcript is ever executed.

Prompt-class material a job needs between begin and finish (the workspace path, touched paths,
the argv plan, command output) is sealed under the session key of the decision's session
(ADRL-MEM-005, ADRL-MEM-010); shredding that key makes it unreadable. Nothing in the
verification_jobs or events tables holds a path, a command line or program output in clear.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field, model_validator

from adrl.core.enums import FailureType, OutcomeState, VerificationResult
from adrl.core.ids import RouteId, SessionId
from adrl.core.ports import SandboxRunner
from adrl.ledger import crypto
from adrl.ledger.events import (
    OUTCOME_EVENT,
    VERIFIER_FAILED_EVENT,
    CauseCandidate,
    producer_seq_for,
    read_stored_events,
    verification_event,
)
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.labels import outcome_state
from adrl.ledger.outcomes import append_late_evidence
from adrl.ledger.store import LedgerStore, utc_now_iso

log = structlog.get_logger(__name__)

VERIFIER_VERSION = "verifier-v1"
PROTECTED_PATH_POLICY_VERSION = "protected-paths-v1"
JOB_SCHEMA_VERSION = "verification-job-v2"
_PROCESS_LOCAL_MATERIAL: dict[str, dict[str, Any]] = {}
OUTPUT_TAIL_CHARS = 400
PROTECTED_GIT_GLOB = ".git/**"

IGNORED_PATH_GLOBS: tuple[str, ...] = (
    ".git/**",
    ".pytest_cache/**",
    "**/.pytest_cache/**",
    "__pycache__/**",
    "**/__pycache__/**",
    "*.pyc",
    "**/*.pyc",
    "node_modules/**",
    "**/node_modules/**",
    ".venv/**",
    "**/.venv/**",
    "dist/**",
    "**/dist/**",
    "build/**",
    "**/build/**",
    "coverage/**",
    "**/coverage/**",
)


class CommandCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    argv: tuple[str, ...] = Field(min_length=1)
    timeout_s: float = 120.0
    required: bool = True
    pass_codes: tuple[int, ...] = (0,)


class VerificationPlan(BaseModel):
    """Operator-authored, argv-only plan. Deserialisation is strict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_version: str
    command_checks: tuple[CommandCheck, ...] = Field(min_length=1)
    require_changes: bool = True
    forbidden_path_globs: tuple[str, ...] = (PROTECTED_GIT_GLOB,)
    max_changed_files: int | None = None
    allowed_commands: tuple[str, ...] = Field(
        default=(), description="argv[0] allow-list; empty means every check's argv[0]"
    )

    @model_validator(mode="after")
    def _protect_git(self) -> VerificationPlan:
        if PROTECTED_GIT_GLOB not in self.forbidden_path_globs:
            raise ValueError("serialized plans cannot remove the .git/** protected path")
        names = [c.name for c in self.command_checks]
        if len(set(names)) != len(names):
            raise ValueError("check names must be unique")
        return self

    @property
    def effective_allow_list(self) -> tuple[str, ...]:
        if self.allowed_commands:
            return self.allowed_commands
        return tuple(dict.fromkeys(c.argv[0] for c in self.command_checks))

    def sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def _matches(path: str, globs: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, g) for g in globs)


def _git_head(workspace: Path) -> str | None:
    head = workspace / ".git" / "HEAD"
    if not head.is_file():
        return None
    text = head.read_text(encoding="utf-8").strip()
    if not text.startswith("ref:"):
        return text or None
    ref = text.split(":", 1)[1].strip()
    ref_path = workspace / ".git" / ref
    if ref_path.is_file():
        return ref_path.read_text(encoding="utf-8").strip() or None
    packed = workspace / ".git" / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


@dataclass(frozen=True, slots=True)
class TreeIdentity:
    """Content identity of a working tree (ADRL-MEM-003 clause 1)."""

    head_commit: str | None
    content_hash: str
    excluding_touched_hash: str
    file_hashes: Mapping[str, str] = field(default_factory=dict)

    def as_record(self) -> dict[str, Any]:
        return {
            "head_commit": self.head_commit,
            "content_hash": self.content_hash,
            "excluding_touched_hash": self.excluding_touched_hash,
            "file_count": len(self.file_hashes),
        }


def snapshot_tree(
    workspace: Path,
    touched_paths: Sequence[str] = (),
    *,
    path_secret: bytes | None = None,
    ignored: Sequence[str] = IGNORED_PATH_GLOBS,
    only: Sequence[str] | None = None,
) -> TreeIdentity:
    """Hash every non-ignored file. Paths are keyed pseudonyms when a secret is supplied.

    With `only`, just the files matching those globs are hashed (used for protected paths).
    """
    hashes: dict[str, str] = {}
    root = workspace.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if not _matches(os.path.normpath(os.path.join(rel_dir, d)) + "/x", ignored)
        ]
        for name in sorted(filenames):
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if rel.startswith("./"):
                rel = rel[2:]
            if _matches(rel, ignored):
                continue
            if only is not None and not _matches(rel, only):
                continue
            try:
                data = (root / rel).read_bytes()
            except OSError:
                continue
            hashes[rel] = hashlib.sha256(data).hexdigest()
    touched = set(touched_paths)
    whole = hashlib.sha256()
    partial = hashlib.sha256()
    for rel in sorted(hashes):
        line = f"{rel}\0{hashes[rel]}\n".encode()
        whole.update(line)
        if rel not in touched:
            partial.update(line)
    if path_secret is not None:
        keyed = {
            hmac.new(path_secret, rel.encode(), hashlib.sha256).hexdigest(): h
            for rel, h in hashes.items()
        }
    else:
        keyed = dict(hashes)
    return TreeIdentity(_git_head(root), whole.hexdigest(), partial.hexdigest(), keyed)


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    job_id: str
    route_id: RouteId
    result: VerificationResult
    checks: tuple[dict[str, Any], ...]
    changed_files: int
    violations: tuple[str, ...]
    tree_drift: bool
    unverifiable_reason: str | None
    late_evidence: bool


class VerificationJobs:
    """Two-phase organic verification bound to an explicit route_id (ADRL-MEM-009)."""

    def __init__(
        self,
        store: LedgerStore,
        runner: SandboxRunner | None,
        *,
        path_secret: bytes | None = None,
        keystore: FileKeyStore | None = None,
    ) -> None:
        self._store = store
        self._runner = runner
        self._path_secret = path_secret
        self._keystore = keystore
        # without a keystore the job material cannot be sealed to disk; it lives only in this
        # process and a finish from another process is refused rather than stored in clear
        self._unsealed = _PROCESS_LOCAL_MATERIAL

    # sealing ---------------------------------------------------------------------------------

    def _keyed(self, text: str) -> str:
        if self._path_secret is None:
            return hashlib.sha256(text.encode()).hexdigest()
        return hmac.new(self._path_secret, text.encode(), hashlib.sha256).hexdigest()

    def _seal(self, job_id: str, session: SessionId, material: Mapping[str, Any]) -> dict[str, Any]:
        if self._keystore is None:
            self._unsealed[job_id] = dict(material)
            return {"sealed": None, "sealed_reason": "no_keystore_process_local"}
        key = self._keystore.create_session_key(session)
        nonce, ciphertext = crypto.encrypt(
            key, json.dumps(dict(material), sort_keys=True).encode(), aad=job_id.encode()
        )
        return {
            "sealed": {
                "session_hmac": str(session),
                "key_id": crypto.key_id(key),
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            },
            "sealed_reason": None,
        }

    def _unseal(self, job_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        sealed = payload.get("sealed")
        if sealed is None:
            material = self._unsealed.get(job_id)
            if material is None:
                raise ValueError(
                    f"verification job {job_id} material is not recoverable in this process; "
                    "begin and finish with a keystore to seal it durably"
                )
            return material
        if self._keystore is None:
            raise ValueError("sealed verification job needs a keystore to finish")
        key = self._keystore.get_session_key(SessionId(str(sealed["session_hmac"])))
        if key is None:
            raise ValueError(
                f"verification job {job_id} material was erased (session key shredded)"
            )
        raw = crypto.decrypt(
            key,
            bytes.fromhex(sealed["nonce"]),
            bytes.fromhex(sealed["ciphertext"]),
            aad=job_id.encode(),
        )
        loaded = json.loads(raw)
        return dict(loaded) if isinstance(loaded, dict) else {}

    def _session_of(self, route_id: RouteId) -> SessionId:
        row = self._store.read_decision(str(route_id))
        if row is None:
            raise ValueError(f"route_id {route_id} is not in the ledger; refusing to bind")
        return SessionId(str(row["session_hmac"]))

    def _append_job(
        self, job_id: str, route_id: RouteId, status: str, payload: Mapping[str, Any]
    ) -> None:
        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO verification_jobs (job_id, route_id, status, payload_json, ts) "
                "VALUES (?,?,?,?,?)",
                (
                    job_id,
                    str(route_id),
                    status,
                    json.dumps(dict(payload), sort_keys=True),
                    utc_now_iso(),
                ),
            )

        self._store.submit(write).result(timeout=30)

    def workspace_of(self, job_id: str) -> Path:
        """Workspace recorded at begin, recovered from the sealed material (never stored in clear).

        Used by the CLI only to take an immutable snapshot of the workspace (ADRL-SAF-007).
        """
        loaded = self._latest_job(job_id)
        if loaded is None:
            raise ValueError(f"unknown verification job {job_id}")
        _status, _route, payload = loaded
        material = self._unseal(job_id, payload)
        return Path(str(material["workspace"]))

    def _latest_job(self, job_id: str) -> tuple[str, RouteId, dict[str, Any]] | None:
        rows = self._store.read(
            "SELECT * FROM verification_jobs WHERE job_id=? ORDER BY seq DESC LIMIT 1", (job_id,)
        )
        if not rows:
            return None
        row = rows[0]
        return (
            str(row["status"]),
            RouteId(str(row["route_id"])),
            json.loads(str(row["payload_json"])),
        )

    def begin(
        self,
        route_id: RouteId,
        workspace: Path,
        plan: VerificationPlan,
        *,
        served_rung: str,
        model: str,
        harness: str,
        touched_paths: Sequence[str] = (),
    ) -> str:
        session = self._session_of(route_id)
        baseline = snapshot_tree(workspace, touched_paths, path_secret=self._path_secret)
        protected = snapshot_tree(
            workspace, path_secret=self._path_secret, ignored=(), only=plan.forbidden_path_globs
        )
        closed_turn_identity: dict[str, Any] | None = None
        for event in read_stored_events(self._store, route_id, OUTCOME_EVENT):
            identity = event.payload.get("tree_identity")
            if str(event.payload.get("state")) == OutcomeState.CLOSED_TURN.value and identity:
                closed_turn_identity = dict(identity)
        job_id = f"{int(datetime.now(UTC).timestamp() * 1000)}-{os.urandom(6).hex()}"
        material = {
            "workspace": str(workspace.resolve()),
            "plan": plan.model_dump(mode="json"),
            "touched_paths": list(touched_paths),
        }
        payload: dict[str, Any] = {
            "schema_version": JOB_SCHEMA_VERSION,
            "workspace_hash": self._keyed(str(workspace.resolve())),
            "plan_sha256": plan.sha256(),
            "plan_version": plan.plan_version,
            "check_names": [c.name for c in plan.command_checks],
            "argv_hashes": [self._keyed(" ".join(c.argv)) for c in plan.command_checks],
            "served_rung": served_rung,
            "model": model,
            "harness": harness,
            "touched_path_hashes": [self._keyed(p) for p in touched_paths],
            "baseline": baseline.as_record(),
            "baseline_files": dict(baseline.file_hashes),
            "protected_files": dict(protected.file_hashes),
            "closed_turn_identity": closed_turn_identity,
        }
        payload.update(self._seal(job_id, session, material))
        self._append_job(job_id, route_id, "begun", payload)
        return job_id

    def _run_checks(
        self, plan: VerificationPlan, snapshot_dir: Path, outputs: dict[str, dict[str, str]]
    ) -> tuple[list[dict[str, Any]], str | None]:
        if self._runner is None:
            return [], "sandbox_runner_absent"
        allow = plan.effective_allow_list
        results: list[dict[str, Any]] = []
        for check in plan.command_checks:
            if check.argv[0] not in allow:
                results.append(
                    {
                        "name": check.name,
                        "status": "not_allowed",
                        "argv_hash": self._keyed(" ".join(check.argv)),
                    }
                )
                continue
            run = self._runner.run(check.argv, str(snapshot_dir), allow, timeout_s=check.timeout_s)
            if not run.available:
                return results, run.unavailable_reason or "sandbox_unavailable"
            status = (
                "pass"
                if run.exit_code is not None and run.exit_code in check.pass_codes
                else ("timeout" if run.exit_code is None else "fail")
            )
            results.append(
                {
                    "name": check.name,
                    "status": status,
                    "argv_hash": self._keyed(" ".join(check.argv)),
                    "exit_code": run.exit_code,
                    "required": check.required,
                    "duration_s": run.duration_s,
                    "stdout_bytes": len(run.stdout_tail.encode()),
                    "stderr_bytes": len(run.stderr_tail.encode()),
                    "stdout_hash": self._keyed(run.stdout_tail),
                    "stderr_hash": self._keyed(run.stderr_tail),
                }
            )
            outputs[check.name] = {
                "stdout_tail": run.stdout_tail[-OUTPUT_TAIL_CHARS:],
                "stderr_tail": run.stderr_tail[-OUTPUT_TAIL_CHARS:],
            }
        return results, None

    async def finish(self, job_id: str, *, snapshot_dir: Path) -> VerificationOutcome:
        """Finish a job by running its checks inside ``snapshot_dir``, never the live tree."""
        if snapshot_dir is None:  # pragma: no cover - guarded for untyped callers
            raise ValueError("snapshot_dir is required: checks never run in the live workspace")
        loaded = self._latest_job(job_id)
        if loaded is None:
            raise ValueError(f"unknown verification job {job_id}")
        status, route_id, payload = loaded
        if status != "begun":
            raise ValueError(f"verification job {job_id} is {status}, not begun")
        material = self._unseal(job_id, payload)
        plan = VerificationPlan.model_validate(material["plan"])
        workspace = Path(str(material["workspace"]))
        touched = [str(p) for p in material.get("touched_paths", [])]
        started = utc_now_iso()
        current = snapshot_tree(workspace, touched, path_secret=self._path_secret)
        baseline_files: dict[str, str] = dict(payload.get("baseline_files", {}))
        changed = sorted(
            set(k for k in current.file_hashes if current.file_hashes[k] != baseline_files.get(k))
            | set(baseline_files) - set(current.file_hashes)
        )
        violations: list[str] = []
        protected_before: dict[str, str] = dict(payload.get("protected_files", {}))
        protected_now = snapshot_tree(
            workspace, path_secret=self._path_secret, ignored=(), only=plan.forbidden_path_globs
        ).file_hashes
        if protected_before != dict(protected_now):
            touched_protected = len(set(protected_before.items()) ^ set(protected_now.items()))
            violations.append(f"protected_path_changed:{touched_protected}")
        if plan.max_changed_files is not None and len(changed) > plan.max_changed_files:
            violations.append(f"max_changed_files:{len(changed)}")
        if plan.require_changes and not changed:
            violations.append("no_changes")

        closed_turn_identity = payload.get("closed_turn_identity") or payload.get("baseline")
        drift = bool(
            closed_turn_identity
            and closed_turn_identity.get("excluding_touched_hash") != current.excluding_touched_hash
        )

        checks: list[dict[str, Any]] = []
        unavailable: str | None = None
        outputs: dict[str, dict[str, str]] = {}
        if not violations:
            checks, unavailable = self._run_checks(plan, snapshot_dir, outputs)

        if violations:
            result = VerificationResult.INDETERMINATE
            reason: str | None = "policy_blocked:" + ",".join(violations)
        elif unavailable is not None:
            result = VerificationResult.INDETERMINATE
            reason = unavailable
        elif any(c["status"] in ("timeout", "not_allowed") for c in checks):
            result = VerificationResult.INDETERMINATE
            reason = "check_timeout_or_not_allowed"
        elif any(c["status"] == "fail" and c.get("required", True) for c in checks):
            result = VerificationResult.FAIL
            reason = None
        else:
            result = VerificationResult.PASS
            reason = None

        finished = utc_now_iso()
        causes = (
            (CauseCandidate(FailureType.TASK_CAPABILITY, None, "verifier"),)
            if result is VerificationResult.FAIL
            else ()
        )
        event = verification_event(
            route_id,
            producer_seq_for(job_id),
            verifier_version=VERIFIER_VERSION,
            argv=[(c.name, "hmac:" + self._keyed(" ".join(c.argv))) for c in plan.command_checks],
            protected_path_policy_version=PROTECTED_PATH_POLICY_VERSION,
            tree_identity=current.as_record(),
            result=result,
            started_at=started,
            finished_at=finished,
            tree_drift=drift,
            checks=checks,
            unverifiable_reason=reason,
            job_id=job_id,
            causes=causes,
        )
        await self._store.write_through(
            LedgerStore.insert_event(
                event.route_id,
                event.event_type,
                event.producer,
                event.producer_seq,
                event.payload,
                event.schema_version,
            )
        )
        if result is VerificationResult.FAIL:
            # wire class (e): the failure reaches the cascade as a lineage signal (ADRL-CAS-001)
            decision_row = self._store.read_decision(route_id)
            if decision_row is not None:
                await self._store.write_through(
                    LedgerStore.insert_lineage_event(
                        str(decision_row["lineage_hmac"]),
                        VERIFIER_FAILED_EVENT,
                        {
                            "route_id": route_id,
                            "job_id": job_id,
                            "verifier_version": VERIFIER_VERSION,
                            "tree_drift": drift,
                        },
                    )
                )
        late = False
        events = read_stored_events(self._store, route_id)
        if outcome_state(events) is OutcomeState.CLOSED_FINAL:
            await append_late_evidence(
                self._store,
                route_id,
                source="verification",
                detail={"job_id": job_id, "result": result.value, "tree_drift": drift},
                producer="verifier",
                evidence_id=job_id,
            )
            late = True
        finished_payload: dict[str, Any] = {
            "schema_version": JOB_SCHEMA_VERSION,
            "result": result.value,
            "tree_drift": drift,
            "violations": violations,
            "reason": reason,
        }
        if outputs:
            sealed_session = payload.get("sealed", {}) or {}
            session = (
                SessionId(str(sealed_session["session_hmac"]))
                if sealed_session
                else self._session_of(route_id)
            )
            finished_payload.update(self._seal(job_id + ":output", session, outputs))
        self._append_job(job_id, route_id, "finished", finished_payload)
        self._unsealed.pop(job_id, None)
        log.info(
            "verification_finished",
            route_id=str(route_id),
            job_id=job_id,
            result=result.value,
            tree_drift=drift,
        )
        return VerificationOutcome(
            job_id,
            route_id,
            result,
            tuple(checks),
            len(changed),
            tuple(violations),
            drift,
            reason,
            late,
        )
