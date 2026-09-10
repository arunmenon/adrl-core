"""Retained operator-time snapshots. Primary: ADRL-MEM-003.

Secondary: ADRL-MEM-001/002/005/010, ADRL-SEM-002/007, ADRL-TRU-001, ADRL-SAF-007.
Internal trusted-operator API, not harness intake. Captures assert neither exact task close
nor successful verification. Payloads reuse the bound session key; no keys are created here.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import os
import sqlite3
import stat
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast
from uuid import UUID

from cryptography.exceptions import InvalidTag
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from adrl.api.auth import Principal
from adrl.api.contracts import OpaqueId
from adrl.api.store import ProductStore
from adrl.core.ids import session_identity
from adrl.ledger import crypto
from adrl.ledger.session_verification import IGNORED, RESERVED, SnapshotLimits, _tree_ref
from adrl.ledger.store import utc_now_iso


class CaptureError(ValueError):
    """The capture is unavailable, inconsistent or outside its declared limits."""


class CapturePolicy(SnapshotLimits):
    schema_version: Literal["operator-capture-policy-v1"] = "operator-capture-policy-v1"
    max_files: int = Field(default=10000, ge=1, le=10000)
    max_bytes: int = Field(default=100_000_000, ge=1, le=100_000_000)
    max_session_captures: int = Field(default=3, ge=1, le=3)
    max_archive_bytes: int = Field(default=500_000_000, ge=1, le=500_000_000)


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["operator-capture-request-v1"] = "operator-capture-request-v1"
    attribution: Literal["operator_capture"] = "operator_capture"
    capture_id: UUID
    attempt_id: UUID
    parent_attempt_id: UUID | None = None
    task_ref: OpaqueId

    @model_validator(mode="after")
    def distinct_parent(self) -> CaptureRequest:
        if self.parent_attempt_id == self.attempt_id:
            raise ValueError("An attempt cannot be its own parent.")
        return self


class CaptureEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str = Field(min_length=1, max_length=4096)
    kind: Literal["file", "directory"]
    executable: bool = False
    content: str | None = None

    @model_validator(mode="after")
    def safe_entry(self) -> CaptureEntry:
        path = PurePosixPath(self.path)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or str(path) != self.path
            or "\0" in self.path
            or "\\" in self.path
            or path.parts[0] == RESERVED
            or any(part in IGNORED for part in path.parts)
            or self.path.endswith(".pyc")
        ):
            raise ValueError("Invalid capture path.")
        if self.kind == "directory":
            if self.content is not None or self.executable:
                raise ValueError("Directory entries cannot carry file content or mode.")
        elif self.content is None:
            raise ValueError("File content is required.")
        else:
            self.bytes()
        return self

    def bytes(self) -> bytes:
        try:
            return base64.b64decode(self.content or "", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CaptureError("invalid_capture_content") from exc


def _manifest(entries: tuple[CaptureEntry, ...]) -> dict[str, str]:
    return {
        entry.path + ("/" if entry.kind == "directory" else ""): (
            "directory"
            if entry.kind == "directory"
            else f"{int(entry.executable)}:" + hashlib.sha256(entry.bytes()).hexdigest()
        )
        for entry in entries
    }


class CapturedSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["retained-operator-capture-v1"] = "retained-operator-capture-v1"
    request: CaptureRequest
    policy: CapturePolicy
    captured_at: datetime
    workspace_ref: str = Field(pattern=r"^hmac:[a-f0-9]{64}$")
    source_ref: str = Field(pattern=r"^hmac:[a-f0-9]{64}$")
    entries: tuple[CaptureEntry, ...] = Field(max_length=10000)

    @model_validator(mode="after")
    def complete_tree(self) -> CapturedSnapshot:
        by_path = {entry.path: entry for entry in self.entries}
        if len(by_path) != len(self.entries) or len(by_path) > self.policy.max_files:
            raise ValueError("Duplicate entries or capture count limit exceeded.")
        if self.captured_at.tzinfo is None:
            raise ValueError("Capture time requires a timezone.")
        if sum(len(entry.bytes()) for entry in self.entries) > self.policy.max_bytes:
            raise ValueError("Capture byte limit exceeded.")
        for entry in self.entries:
            for parent in PurePosixPath(entry.path).parents:
                if str(parent) == ".":
                    continue
                if str(parent) not in by_path or by_path[str(parent)].kind != "directory":
                    raise ValueError("Missing directory or file used as directory.")
        return self


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _scan(root: Path, policy: CapturePolicy) -> tuple[CaptureEntry, ...]:
    """Scan via directory descriptors; reject symlinks, special files and observed drift."""
    entries: list[CaptureEntry] = []
    total = 0

    def walk(directory: int, prefix: str) -> None:
        nonlocal total
        before = os.fstat(directory)
        for name in sorted(os.listdir(directory)):
            if name in IGNORED or name.endswith(".pyc"):
                continue
            if not prefix and name == RESERVED:
                raise CaptureError("reserved_verifier_path")
            if len(entries) >= policy.max_files:
                raise CaptureError("capture_count_limit")
            relative = prefix + name
            initial = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(initial.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                try:
                    if _stamp(initial) != _stamp(os.fstat(child)):
                        raise CaptureError("workspace_changed_during_capture")
                    entries.append(CaptureEntry(path=relative, kind="directory"))
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                )
                try:
                    opened = os.fstat(descriptor)
                    if _stamp(initial) != _stamp(opened):
                        raise CaptureError("workspace_changed_during_capture")
                    if opened.st_size > policy.max_bytes - total:
                        raise CaptureError("capture_byte_limit")
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        content = stream.read(policy.max_bytes - total + 1)
                    if _stamp(opened) != _stamp(os.fstat(descriptor)):
                        raise CaptureError("workspace_changed_during_capture")
                finally:
                    os.close(descriptor)
                total += len(content)
                if total > policy.max_bytes:
                    raise CaptureError("capture_byte_limit")
                entries.append(
                    CaptureEntry(
                        path=relative,
                        kind="file",
                        executable=bool(opened.st_mode & 0o111),
                        content=base64.b64encode(content).decode(),
                    )
                )
            else:
                raise CaptureError("symlink_special_or_hardlinked_file")
        if _stamp(before) != _stamp(os.fstat(directory)):
            raise CaptureError("workspace_changed_during_capture")

    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(descriptor)
        walk(descriptor, "")
        if _stamp(initial) != _stamp(root.stat(follow_symlinks=False)):
            raise CaptureError("workspace_changed_during_capture")
    finally:
        os.close(descriptor)
    return tuple(entries)


def _capture(root: Path, policy: CapturePolicy) -> tuple[CaptureEntry, ...]:
    first = _scan(root, policy)
    second = _scan(root, policy)
    if first != second:
        raise CaptureError("workspace_changed_during_capture")
    return second


class CaptureArchive:
    """Local operator storage; callers supply a previously authenticated Principal.

    Public/harness intake never calls this API. Same-OS-user compromise is outside its trust
    boundary. Raw identity, path, policy, hashes and file bytes are all session-key encrypted.
    """

    def __init__(self, data: ProductStore, policy: CapturePolicy | None = None) -> None:
        self.data = data
        self.policy = policy or CapturePolicy()

    def _key(self, principal: Principal) -> bytes:
        binding = self.data.binding(principal.session_hmac)
        if (
            binding is None
            or binding["workload_ref"] != principal.workload_ref
            or principal.assertion.session_id != principal.session_id
            or principal.assertion.expires_at <= time.time()
            or session_identity(principal.session_id, self.data.keys.hmac_key())
            != principal.session_hmac
        ):
            raise CaptureError("capture_session_binding_unavailable")
        key = self.data.keys.get_session_key(principal.session_hmac)
        if key is None or self.data.was_erased(principal.session_hmac):
            raise CaptureError("capture_key_unavailable")
        return key

    def _decode(self, principal: Principal, key: bytes, row: dict[str, Any]) -> CapturedSnapshot:
        aad = f"capture:{principal.session_hmac}:{row['capture_key']}:{row['attempt_key']}".encode()
        try:
            capture = CapturedSnapshot.model_validate_json(
                crypto.decrypt(key, row["nonce"], row["ciphertext"], aad=aad)
            )
        except (InvalidTag, ValidationError, ValueError) as exc:
            raise CaptureError("capture_integrity_failure") from exc
        if (
            row["session_hmac"] != principal.session_hmac
            or row["capture_key"]
            != crypto.keyed_hash(key, "capture:" + str(capture.request.capture_id))
            or row["attempt_key"]
            != crypto.keyed_hash(key, "attempt:" + str(capture.request.attempt_id))
            or capture.source_ref
            != _tree_ref(self.data.keys.hmac_key(), _manifest(capture.entries))
        ):
            raise CaptureError("capture_integrity_failure")
        if self._key(principal) != key:
            raise CaptureError("capture_key_unavailable")
        return capture

    def read(self, principal: Principal, capture_id: UUID) -> CapturedSnapshot:
        key = self._key(principal)
        rows = self.data.ledger.read(
            "SELECT * FROM product_captures WHERE session_hmac=? AND capture_key=?",
            (principal.session_hmac, crypto.keyed_hash(key, "capture:" + str(capture_id))),
        )
        if not rows:
            raise CaptureError("capture_unavailable")
        return self._decode(principal, key, dict(rows[0]))

    def _inputs(
        self, principal: Principal, workspace: Path
    ) -> tuple[Path, tuple[CaptureEntry, ...]]:
        if workspace.is_symlink():
            raise CaptureError("symlink_workspace")
        root = workspace.resolve(strict=True)
        if Path(principal.assertion.inventory.root).resolve(strict=True) != root:
            raise CaptureError("capture_workspace_binding_mismatch")
        return root, _capture(root, self.policy)

    async def capture(
        self, principal: Principal, workspace: Path, request: CaptureRequest
    ) -> CapturedSnapshot:
        key = self._key(principal)
        try:
            root, entries = await asyncio.to_thread(self._inputs, principal, workspace)
        except OSError as exc:
            raise CaptureError("capture_input_unavailable") from exc
        snapshot = CapturedSnapshot(
            request=request,
            policy=self.policy,
            captured_at=datetime.now(UTC),
            workspace_ref="hmac:" + crypto.keyed_hash(key, str(root)),
            source_ref=_tree_ref(self.data.keys.hmac_key(), _manifest(entries)),
            entries=entries,
        )
        if self._key(principal) != key:
            raise CaptureError("capture_key_unavailable")
        capture_key = crypto.keyed_hash(key, "capture:" + str(request.capture_id))
        attempt_key = crypto.keyed_hash(key, "attempt:" + str(request.attempt_id))
        aad = f"capture:{principal.session_hmac}:{capture_key}:{attempt_key}".encode()
        nonce, ciphertext = crypto.encrypt(key, snapshot.model_dump_json().encode(), aad=aad)

        def write(conn: sqlite3.Connection) -> tuple[str, dict[str, Any] | None]:
            if principal.assertion.expires_at <= time.time():
                return "capture_session_binding_unavailable", None
            erased = conn.execute(
                "SELECT 1 FROM lineage_events WHERE lineage_hmac=? AND event_type='erased' "
                "UNION ALL SELECT 1 FROM session_keys WHERE session_hmac=? AND action='shredded'",
                (principal.session_hmac, principal.session_hmac),
            ).fetchone()
            if erased or self.data.keys.get_session_key(principal.session_hmac) != key:
                return "capture_key_unavailable", None
            prior = conn.execute(
                "SELECT * FROM product_captures WHERE session_hmac=? AND capture_key=?",
                (principal.session_hmac, capture_key),
            ).fetchone()
            if prior:
                return "prior", dict(prior)
            if conn.execute(
                "SELECT 1 FROM product_captures WHERE session_hmac=? AND attempt_key=?",
                (principal.session_hmac, attempt_key),
            ).fetchone():
                return "attempt_already_captured", None
            if request.parent_attempt_id is not None:
                parent = conn.execute(
                    "SELECT 1 FROM product_captures WHERE session_hmac=? AND attempt_key=?",
                    (
                        principal.session_hmac,
                        crypto.keyed_hash(key, "attempt:" + str(request.parent_attempt_id)),
                    ),
                ).fetchone()
                if parent is None:
                    return "parent_capture_unavailable", None
            count = conn.execute(
                "SELECT COUNT(*) FROM product_captures WHERE session_hmac=?",
                (principal.session_hmac,),
            ).fetchone()[0]
            size = conn.execute(
                "SELECT COALESCE(SUM(LENGTH(ciphertext)+LENGTH(nonce)),0) FROM product_captures"
            ).fetchone()[0]
            if count >= self.policy.max_session_captures:
                return "session_capture_limit", None
            if size + len(ciphertext) + len(nonce) > self.policy.max_archive_bytes:
                return "archive_byte_limit", None
            cursor = conn.execute(
                "INSERT INTO product_captures "
                "(session_hmac,capture_key,attempt_key,nonce,ciphertext,ts) VALUES (?,?,?,?,?,?)",
                (
                    principal.session_hmac,
                    capture_key,
                    attempt_key,
                    nonce,
                    ciphertext,
                    utc_now_iso(),
                ),
            )
            return "recorded", dict(
                conn.execute(
                    "SELECT * FROM product_captures WHERE seq=?", (cursor.lastrowid,)
                ).fetchone()
            )

        status, row = cast(
            tuple[str, dict[str, Any] | None], await self.data.ledger.write_through(write)
        )
        if row is None:
            raise CaptureError(status)
        stored = self._decode(principal, key, row)
        if stored.model_dump(exclude={"captured_at"}) != snapshot.model_dump(
            exclude={"captured_at"}
        ):
            raise CaptureError("capture_identity_conflict")
        return stored

    @contextmanager
    def materialize(self, principal: Principal, capture_id: UUID, scratch: Path) -> Iterator[Path]:
        """Lease a disposable plaintext copy; cleanup runs on exit, exceptions and cancellation.

        Killing the process can leave this copy on disk. This internal slice has no startup
        reconciler and must not yet be enabled for real task payloads. Erasure denies new reads;
        an already leased copy is removed when this context exits, not retroactively withdrawn.
        """
        snapshot = self.read(principal, capture_id)
        if scratch.is_symlink() or not scratch.is_dir():
            raise CaptureError("invalid_capture_scratch")
        scratch = scratch.resolve(strict=True)
        root = Path(principal.assertion.inventory.root).resolve()
        if (
            scratch == root
            or scratch.is_relative_to(root)
            or self.data.keys.root.resolve().is_relative_to(scratch)
            or scratch.is_relative_to(self.data.keys.root.resolve())
        ):
            raise CaptureError("invalid_capture_scratch")
        with tempfile.TemporaryDirectory(prefix="adrl-capture-", dir=scratch) as directory:
            target = Path(directory)
            for entry in sorted(
                snapshot.entries, key=lambda item: (len(PurePosixPath(item.path).parts), item.path)
            ):
                path = target / entry.path
                if entry.kind == "directory":
                    path.mkdir(mode=0o700)
                else:
                    with path.open("xb") as output:
                        output.write(entry.bytes())
                    path.chmod(0o500 if entry.executable else 0o400)
            self._key(principal)
            yield target
