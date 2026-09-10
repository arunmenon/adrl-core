"""Snapshot execution and bound-session operator checks. Primary: ADRL-MEM-003.

Secondary: ADRL-SEM-007, ADRL-SAF-007, ADRL-MEM-001/010, ADRL-LRN-001.
No routing decision is fabricated. Plans and check artifacts come from the operator outside
harness workspaces. Only declared failure exit codes mean failure; other nonzero exits,
unavailable sandboxes, timeouts and drift are indeterminate. No result enters learning.
SnapshotVerifier also supports offline experiments; its execution envelope alone asserts no
session binding. SessionVerifier supplies that binding and persists session receipts.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import tempfile
from datetime import UTC, datetime
from inspect import getsourcefile
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from adrl.api.contracts import OpaqueId, SessionVerification, VerifierCheck, VersionRef
from adrl.api.store import ProductStore
from adrl.core.ids import SessionId
from adrl.core.ports import SandboxRunner
from adrl.ledger import crypto

RESERVED = ".adrl-verifier"
IGNORED = frozenset({".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: Path
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class SessionCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: OpaqueId
    argv: tuple[str, ...] = Field(min_length=1)
    timeout_s: float = Field(default=60, gt=0, le=600, allow_inf_nan=False)
    failure_exit_codes: tuple[int, ...] = ()

    @model_validator(mode="after")
    def command_contract(self) -> SessionCheck:
        if not Path(self.argv[0]).is_absolute() or any("\0" in item for item in self.argv):
            raise ValueError("Commands need an absolute executable and valid argv.")
        if any(code <= 0 or code > 255 for code in self.failure_exit_codes):
            raise ValueError("Failure codes must be positive exit statuses.")
        return self


class SnapshotLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_files: int = Field(default=10000, ge=1, le=100000)
    max_bytes: int = Field(default=100_000_000, ge=1, le=1_000_000_000)


class SessionPlan(SnapshotLimits):
    schema_version: Literal["session-verifier-plan-v1"] = "session-verifier-plan-v1"
    verifier: VersionRef
    task_ref: OpaqueId
    checks: tuple[SessionCheck, ...] = Field(min_length=1, max_length=20)
    artifacts: dict[str, Artifact] = Field(min_length=1)

    @model_validator(mode="after")
    def names_are_unambiguous(self) -> SessionPlan:
        if len({c.name for c in self.checks}) != len(self.checks):
            raise ValueError("Check names must be unique.")
        for name in self.artifacts:
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or str(path) != name or name == ".":
                raise ValueError("Artifact names must be relative paths without traversal.")
        return self


class SnapshotInvalidError(ValueError):
    """The planned snapshot or verifier cannot be captured consistently."""


def _file_bytes(path: Path, limit: int = 1_000_000_000) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SnapshotInvalidError("non_regular_file")
        if os.fstat(fd).st_size > limit:
            raise SnapshotInvalidError("snapshot_limit_exceeded")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            content = handle.read(limit + 1)
        if len(content) > limit:
            raise SnapshotInvalidError("snapshot_limit_exceeded")
        return content
    finally:
        os.close(fd)


def _tree(root: Path, plan: SnapshotLimits, target: Path | None = None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    total = 0
    if not root.is_dir():
        raise SnapshotInvalidError("workspace_unavailable")

    def unreadable(error: OSError) -> None:
        raise error

    for directory, dirs, names in os.walk(root, onerror=unreadable):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED)
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink():
                raise SnapshotInvalidError("symlink_not_supported")
            relative = str(path.relative_to(root))
            if len(hashes) >= plan.max_files:
                raise SnapshotInvalidError("snapshot_limit_exceeded")
            hashes[relative + "/"] = "directory"
            if target is not None:
                (target / relative).mkdir(parents=True, exist_ok=True)
        for name in sorted(names):
            if name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            content = _file_bytes(path, plan.max_bytes - total)
            total += len(content)
            if len(hashes) >= plan.max_files or total > plan.max_bytes:
                raise SnapshotInvalidError("snapshot_limit_exceeded")
            executable = os.access(path, os.X_OK)
            hashes[relative] = f"{int(executable)}:" + hashlib.sha256(content).hexdigest()
            if target is not None:
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                destination.chmod(0o555 if executable else 0o444)
    return hashes


def snapshot_digest(workspace: Path, limits: SnapshotLimits) -> str:
    """Pin a curated experiment input using the same exclusions as execution."""
    manifest = _tree(workspace.resolve(strict=True), limits)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def snapshot_fingerprint(workspace: Path, limits: SnapshotLimits, secret: bytes) -> tuple[str, str]:
    """Return a digest and keyed execution identity from the same input scan."""
    manifest = _tree(workspace.resolve(strict=True), limits)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest(), _tree_ref(secret, manifest)


def _tree_ref(secret: bytes, hashes: dict[str, str]) -> str:
    canonical = json.dumps(hashes, sort_keys=True, separators=(",", ":"))
    return "hmac:" + crypto.keyed_hash(secret, canonical)


def _artifacts(plan: SessionPlan, workspace: Path) -> dict[str, bytes]:
    if any(Path(check.argv[0]).resolve().is_relative_to(workspace) for check in plan.checks):
        raise SnapshotInvalidError("executable_inside_workspace")
    content: dict[str, bytes] = {}
    total = 0
    for name, artifact in plan.artifacts.items():
        if artifact.path.resolve().is_relative_to(workspace):
            raise SnapshotInvalidError("verifier_artifact_inside_workspace")
        data = _file_bytes(artifact.path, plan.max_bytes - total)
        total += len(data)
        if hashlib.sha256(data).hexdigest() != artifact.sha256:
            raise SnapshotInvalidError("verifier_artifact_changed")
        content[name] = data
    return content


class SnapshotVerifier:
    """Execute an operator plan without claiming a bound session or learning authority."""

    def __init__(self, secret: bytes, runner: SandboxRunner) -> None:
        self.runner = runner
        self.secret = secret
        module_path = getsourcefile(type(runner))
        if module_path is None:
            raise ValueError("The sandbox implementation needs an auditable source version.")
        self.sandbox = VersionRef(
            id=runner.platform_id,
            version="sha256:" + hashlib.sha256(_file_bytes(Path(module_path))).hexdigest(),
        )

    def _ref(self, value: str) -> str:
        return "hmac:" + crypto.keyed_hash(self.secret, value)

    def _check(self, check: SessionCheck, snapshot: Path) -> VerifierCheck:
        command_ref = self._ref(json.dumps(check.argv, separators=(",", ":")))
        details: dict[str, object] = {
            "name": check.name,
            "command_ref": command_ref,
            "duration_s": 0,
        }
        try:
            executable = Path(check.argv[0]).resolve(strict=True)
            if not os.access(executable, os.X_OK):
                raise OSError("executable unavailable")
            details["executable_ref"] = self._ref(
                hashlib.sha256(_file_bytes(executable)).hexdigest()
            )
            result = self.runner.run(
                check.argv, str(snapshot), (check.argv[0],), timeout_s=check.timeout_s
            )
        except (OSError, ValueError):
            return VerifierCheck.model_validate(
                details | {"result": "indeterminate", "reason": "execution_unavailable"}
            )
        details.update(
            duration_s=result.duration_s,
            exit_code=result.exit_code,
            stdout_ref=self._ref(result.stdout_tail),
            stderr_ref=self._ref(result.stderr_tail),
        )
        if not result.available:
            outcome, reason = "indeterminate", "sandbox_unavailable"
        elif result.exit_code is None:
            outcome, reason = "indeterminate", "check_timeout"
        elif result.exit_code == 0:
            outcome, reason = "passed", None
        elif result.exit_code in check.failure_exit_codes:
            outcome, reason = "failed", "declared_check_failure"
        else:
            outcome, reason = "indeterminate", "unclassified_exit"
        return VerifierCheck.model_validate(details | {"result": outcome, "reason": reason})

    def start(self, plan: SessionPlan) -> SessionVerification:
        return SessionVerification(
            sandbox_implementation=self.sandbox,
            job_id=str(uuid4()),
            task_ref=plan.task_ref,
            phase="started",
            verifier=plan.verifier,
            plan_ref=self._ref(plan.model_dump_json()),
            started_at=datetime.now(UTC),
        )

    async def evaluate(
        self, workspace: Path, plan: SessionPlan, receipt: SessionVerification
    ) -> SessionVerification:
        if (
            receipt.phase != "started"
            or receipt.plan_ref != self._ref(plan.model_dump_json())
            or receipt.verifier != plan.verifier
            or receipt.task_ref != plan.task_ref
            or receipt.sandbox_implementation != self.sandbox
        ):
            raise ValueError("The started receipt does not match this execution plan.")
        checks: tuple[VerifierCheck, ...] = ()
        source_ref = None
        executed_ref = None
        unchanged = None
        reason: str | None = None
        result = "indeterminate"
        try:
            workspace = await asyncio.to_thread(workspace.resolve, strict=True)
            if (workspace / RESERVED).exists() or (workspace / RESERVED).is_symlink():
                raise SnapshotInvalidError("reserved_verifier_path")
            artifact_bytes = await asyncio.to_thread(_artifacts, plan, workspace)
            before = await asyncio.to_thread(_tree, workspace, plan)
            source_ref = _tree_ref(self.secret, before)
            with tempfile.TemporaryDirectory(prefix="adrl-verify-") as directory:
                snapshot = (await asyncio.to_thread(Path(directory).resolve)) / "snapshot"
                snapshot.mkdir()
                captured = await asyncio.to_thread(_tree, workspace, plan, snapshot)
                if captured != before:
                    raise SnapshotInvalidError("workspace_changed_during_capture")
                for name, data in artifact_bytes.items():
                    destination = snapshot / RESERVED / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    destination.chmod(0o444)
                executed = await asyncio.to_thread(_tree, snapshot, plan)
                executed_ref = _tree_ref(self.secret, executed)
                checks = tuple(
                    [await asyncio.to_thread(self._check, check, snapshot) for check in plan.checks]
                )
                after = await asyncio.to_thread(_tree, snapshot, plan)
                live_after = await asyncio.to_thread(_tree, workspace, plan)
                unchanged = after == executed and live_after == before
                if not unchanged:
                    reason = "snapshot_or_workspace_changed"
                elif any(check.result == "indeterminate" for check in checks):
                    reason = "check_indeterminate"
                elif any(check.result == "failed" for check in checks):
                    result = "failed"
                else:
                    result = "passed"
        except SnapshotInvalidError as exc:
            reason = str(exc)
        except OSError:
            reason = "snapshot_unavailable"
        # Validate the finished envelope rather than bypassing validation with model_copy.
        finished = SessionVerification.model_validate(
            receipt.model_dump()
            | {
                "phase": "finished",
                "result": result,
                "reason": reason,
                "checks": checks,
                "source_snapshot_ref": source_ref,
                "executed_snapshot_ref": executed_ref,
                "snapshot_unchanged": unchanged,
                "finished_at": datetime.now(UTC),
            }
        )
        return finished


class SessionVerifier:
    """Bound-session wrapper; public event intake cannot submit verifier receipts."""

    def __init__(self, data: ProductStore, runner: SandboxRunner) -> None:
        self.data = data
        self.executor = SnapshotVerifier(data.keys.hmac_key(), runner)

    async def verify(
        self, session: SessionId, workspace: Path, plan: SessionPlan
    ) -> SessionVerification:
        if self.data.binding(session) is None:
            raise ValueError("A bound product session is required.")
        receipt = self.executor.start(plan)
        await self.data.append_verification(session, receipt)
        finished = await self.executor.evaluate(workspace, plan, receipt)
        await self.data.append_verification(session, finished)
        return finished
