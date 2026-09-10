"""Fault cases for retained operator captures. Primary: ADRL-MEM-003, ADRL-MEM-010."""

from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import threading
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from adrl.api.auth import Principal
from adrl.api.contracts import SessionRequest, VersionRef
from adrl.api.store import ProductStore
from adrl.core.errors import LedgerAppendFailure
from adrl.core.ids import session_identity
from adrl.gates.workload import RepoInventory, WorkloadAssertion
from adrl.ledger import capture as module
from adrl.ledger.capture import (
    CaptureArchive,
    CaptureEntry,
    CaptureError,
    CapturePolicy,
    CaptureRequest,
)
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.session_verification import snapshot_fingerprint
from adrl.ledger.store import LedgerStore


@dataclass
class Fixture:
    store: LedgerStore
    keys: FileKeyStore
    data: ProductStore
    archive: CaptureArchive
    principal: Principal
    workspace: Path
    scratch: Path

    def request(self, **changes: Any) -> CaptureRequest:
        return CaptureRequest.model_validate(
            {"capture_id": uuid4(), "attempt_id": uuid4(), "task_ref": "task-one"} | changes
        )


async def bind(data: ProductStore, workspace: Path, sid: str) -> Principal:
    assertion = WorkloadAssertion(
        RepoInventory(str(workspace), None, None, "a" * 64, 1),
        time.time() - 1,
        time.time() + 3600,
        str(uuid4()),
        data.keys.hmac_key_id(),
        sid,
    )
    principal = Principal(sid, session_identity(sid, data.keys.hmac_key()), "fixture", assertion)
    data.keys.create_session_key(principal.session_hmac)
    await data.bind(
        principal,
        SessionRequest(
            adapter=VersionRef(id="claude-code", version="1"),
            profile=VersionRef(id="anthropic-messages-v1", version="1"),
            workload_ref="fixture",
        ),
        "fixture-policy",
        "fixture-config",
    )
    return principal


@pytest.fixture
async def capture(tmp_path: Path) -> AsyncIterator[Fixture]:
    workspace = tmp_path / "work"
    workspace.mkdir()
    (workspace / "code.txt").write_text("output-A-private-canary")
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    store = LedgerStore(tmp_path / "ledger.db")
    store.open()
    keys = FileKeyStore(tmp_path / "keys", store=store)
    data = ProductStore(store, keys)
    principal = await bind(data, workspace, str(uuid4()))
    try:
        yield Fixture(store, keys, data, CaptureArchive(data), principal, workspace, scratch)
    finally:
        store.close()
        shutil.rmtree(tmp_path)


async def test_retained_a_survives_b_restart_and_materialization(capture: Fixture) -> None:
    (capture.workspace / "empty").mkdir()
    executable = capture.workspace / "run"
    executable.write_bytes(b"binary\0content")
    executable.chmod(0o700)
    request = capture.request()
    first = await capture.archive.capture(capture.principal, capture.workspace, request)
    (_, reference) = snapshot_fingerprint(capture.workspace, first.policy, capture.keys.hmac_key())
    assert first.source_ref == reference
    assert first.request.attribution == "operator_capture"
    (capture.workspace / "code.txt").write_text("output-B")
    capture.store.close()
    capture.store.open()
    archive = CaptureArchive(
        ProductStore(capture.store, FileKeyStore(capture.keys.root, store=capture.store))
    )
    assert archive.read(capture.principal, request.capture_id) == first
    with archive.materialize(capture.principal, request.capture_id, capture.scratch) as restored:
        assert (restored / "code.txt").read_text() == "output-A-private-canary"
        assert (restored / "empty").is_dir()
        assert (restored / "run").read_bytes() == b"binary\0content"
        assert os.access(restored / "run", os.X_OK)
        assert snapshot_fingerprint(restored, first.policy, capture.keys.hmac_key())[1] == reference
    assert not restored.exists()
    assert not list(capture.scratch.iterdir())
    row = dict(capture.store.read("SELECT * FROM product_captures")[0])
    serialized = repr(row).encode()
    for private in [
        b"output-A-private-canary",
        b"code.txt",
        str(request.attempt_id).encode(),
        str(capture.workspace).encode(),
    ]:
        assert private not in serialized
    assert not capture.store.read("SELECT * FROM decisions")
    assert not capture.store.read("SELECT * FROM product_verifications")


async def test_idempotent_retry_conflicts_and_distinct_attempts(capture: Fixture) -> None:
    request = capture.request()
    first = await capture.archive.capture(capture.principal, capture.workspace, request)
    assert await capture.archive.capture(capture.principal, capture.workspace, request) == first
    with pytest.raises(CaptureError, match="attempt_already_captured"):
        await capture.archive.capture(
            capture.principal, capture.workspace, capture.request(attempt_id=request.attempt_id)
        )
    second = await capture.archive.capture(
        capture.principal, capture.workspace, capture.request(task_ref="task-two")
    )
    assert first.request.attempt_id != second.request.attempt_id
    (capture.workspace / "code.txt").write_text("B")
    with pytest.raises(CaptureError, match="identity_conflict"):
        await capture.archive.capture(capture.principal, capture.workspace, request)
    assert capture.archive.read(capture.principal, request.capture_id) == first
    assert len(capture.store.read("SELECT * FROM product_captures")) == 2


async def test_parent_must_be_captured_in_same_session(capture: Fixture) -> None:
    parent = capture.request()
    with pytest.raises(CaptureError, match="parent_capture_unavailable"):
        await capture.archive.capture(
            capture.principal,
            capture.workspace,
            capture.request(parent_attempt_id=parent.attempt_id),
        )
    await capture.archive.capture(capture.principal, capture.workspace, parent)
    child = capture.request(parent_attempt_id=parent.attempt_id)
    assert (
        await capture.archive.capture(capture.principal, capture.workspace, child)
    ).request == child


async def test_wrong_session_workload_root_and_expiry_are_denied(capture: Fixture) -> None:
    request = capture.request()
    await capture.archive.capture(capture.principal, capture.workspace, request)
    other = await bind(capture.data, capture.workspace, str(uuid4()))
    with pytest.raises(CaptureError, match="capture_unavailable"):
        capture.archive.read(other, request.capture_id)
    for principal in [
        replace(capture.principal, workload_ref="wrong"),
        replace(capture.principal, assertion=replace(capture.principal.assertion, expires_at=0)),
    ]:
        with pytest.raises(CaptureError, match="binding_unavailable"):
            capture.archive.read(principal, request.capture_id)
    with pytest.raises(CaptureError, match="workspace_binding_mismatch"):
        await capture.archive.capture(capture.principal, capture.scratch, capture.request())


@pytest.mark.parametrize(
    "kind", ["file_symlink", "directory_symlink", "fifo", "hardlink", "reserved"]
)
async def test_unsafe_inputs_never_commit(capture: Fixture, kind: str) -> None:
    target = capture.workspace / "unsafe"
    if kind == "file_symlink":
        target.symlink_to(capture.workspace / "code.txt")
    elif kind == "directory_symlink":
        target.symlink_to(capture.scratch, target_is_directory=True)
    elif kind == "fifo":
        os.mkfifo(target)
    elif kind == "hardlink":
        os.link(capture.workspace / "code.txt", target)
    else:
        (capture.workspace / ".adrl-verifier").mkdir()
    with pytest.raises(CaptureError):
        await capture.archive.capture(capture.principal, capture.workspace, capture.request())
    assert not capture.store.read("SELECT * FROM product_captures")


@pytest.mark.parametrize(
    "path", ["../escape", "/escape", "a/../b", "a//b", ".", "a\\b", ".adrl-verifier/x"]
)
def test_untrusted_manifest_paths_rejected(path: str) -> None:
    with pytest.raises(ValidationError):
        CaptureEntry(path=path, kind="file", content="")


@pytest.mark.parametrize("change", ["edit", "remove"])
async def test_capture_drift_or_missing_file_never_commits(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    original = module._scan
    count = 0

    def scan(root: Path, policy: CapturePolicy) -> tuple[CaptureEntry, ...]:
        nonlocal count
        count += 1
        if count == 2:
            if change == "edit":
                (root / "code.txt").write_text("changed during capture")
            else:
                (root / "code.txt").unlink()
        return original(root, policy)

    monkeypatch.setattr(module, "_scan", scan)
    with pytest.raises(CaptureError, match="changed_during_capture"):
        await capture.archive.capture(capture.principal, capture.workspace, capture.request())
    assert not capture.store.read("SELECT * FROM product_captures")


async def test_directory_swap_cannot_follow_symlink(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = capture.workspace / "nested"
    nested.mkdir()
    (capture.scratch / "private").write_text("outside capture")
    original = os.open

    def open_checked(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if path == "nested" and dir_fd is not None:
            nested.rename(capture.scratch / "moved")
            nested.symlink_to(capture.scratch, target_is_directory=True)
        return original(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(module.os, "open", open_checked)
    with pytest.raises(CaptureError, match="capture_input_unavailable"):
        await capture.archive.capture(capture.principal, capture.workspace, capture.request())
    assert not capture.store.read("SELECT * FROM product_captures")


@pytest.mark.parametrize(
    "policy",
    [CapturePolicy(max_bytes=1), CapturePolicy(max_files=1), CapturePolicy(max_archive_bytes=1)],
)
async def test_limits_cannot_leave_partial_capture(capture: Fixture, policy: CapturePolicy) -> None:
    (capture.workspace / "second").write_text("two")
    archive = CaptureArchive(capture.data, policy)
    with pytest.raises(CaptureError, match="limit"):
        await archive.capture(capture.principal, capture.workspace, capture.request())
    assert not capture.store.read("SELECT * FROM product_captures")


async def test_session_quota_preserves_idempotency(capture: Fixture) -> None:
    archive = CaptureArchive(capture.data, CapturePolicy(max_session_captures=1))
    request = capture.request()
    first = await archive.capture(capture.principal, capture.workspace, request)
    assert await archive.capture(capture.principal, capture.workspace, request) == first
    with pytest.raises(CaptureError, match="session_capture_limit"):
        await archive.capture(capture.principal, capture.workspace, capture.request())


async def test_archive_quota_counts_other_and_erased_sessions(capture: Fixture) -> None:
    await capture.archive.capture(capture.principal, capture.workspace, capture.request())
    row = capture.store.read("SELECT * FROM product_captures")[0]
    used = len(row["ciphertext"]) + len(row["nonce"])
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture_erasure")
    other = await bind(capture.data, capture.workspace, str(uuid4()))
    archive = CaptureArchive(capture.data, CapturePolicy(max_archive_bytes=used + 1))
    with pytest.raises(CaptureError, match="archive_byte_limit"):
        await archive.capture(other, capture.workspace, capture.request())
    assert len(capture.store.read("SELECT * FROM product_captures")) == 1


async def test_missing_capture_never_materializes_workspace(capture: Fixture) -> None:
    with (
        pytest.raises(CaptureError, match="capture_unavailable"),
        capture.archive.materialize(capture.principal, uuid4(), capture.scratch),
    ):
        pass
    assert not list(capture.scratch.iterdir())


def test_request_cannot_claim_exact_close_or_verification() -> None:
    request = {"capture_id": uuid4(), "attempt_id": uuid4(), "task_ref": "fixture"}
    for extra in [{"attribution": "trusted_close"}, {"verified": True}]:
        with pytest.raises(ValidationError):
            CaptureRequest.model_validate(request | extra)


async def test_erasure_and_restored_key_do_not_resurrect(capture: Fixture) -> None:
    request = capture.request()
    await capture.archive.capture(capture.principal, capture.workspace, request)
    path = capture.keys.root / "sessions" / f"{capture.principal.session_hmac}.key"
    prior = path.read_bytes()
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture_erasure")
    for restore in [False, True]:
        if restore:
            path.write_bytes(prior)
        with pytest.raises(CaptureError, match="key_unavailable"):
            capture.archive.read(capture.principal, request.capture_id)
        with pytest.raises(CaptureError, match="key_unavailable"):
            await capture.archive.capture(capture.principal, capture.workspace, request)
        with (
            pytest.raises(CaptureError, match="key_unavailable"),
            capture.archive.materialize(capture.principal, request.capture_id, capture.scratch),
        ):
            pass
    assert len(capture.store.read("SELECT * FROM product_captures")) == 1
    assert not list(capture.scratch.iterdir())


async def test_erasure_before_queued_append_is_rechecked(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = capture.store.write_through

    async def erase_then_write(fn: Any) -> Any:
        capture.keys.shred_session_key(capture.principal.session_hmac, "fixture_erasure")
        return await original(fn)

    monkeypatch.setattr(capture.store, "write_through", erase_then_write)
    with pytest.raises(CaptureError, match="key_unavailable"):
        await capture.archive.capture(capture.principal, capture.workspace, capture.request())
    assert not capture.store.read("SELECT * FROM product_captures")


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "attempt_key"])
async def test_corruption_never_falls_back_to_working_tree(capture: Fixture, field: str) -> None:
    request = capture.request()
    await capture.archive.capture(capture.principal, capture.workspace, request)
    with sqlite3.connect(capture.store.path) as connection:
        connection.execute(f"UPDATE product_captures SET {field}=?", (b"tampered",))
    with pytest.raises(CaptureError, match="integrity_failure"):
        capture.archive.read(capture.principal, request.capture_id)
    assert not list(capture.scratch.iterdir())


async def test_failed_transaction_is_absent_after_reopen(capture: Fixture) -> None:
    request = capture.request()
    with sqlite3.connect(capture.store.path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_capture BEFORE INSERT ON product_captures "
            "BEGIN SELECT RAISE(ABORT,'injected failure'); END"
        )
    with pytest.raises(LedgerAppendFailure):
        await capture.archive.capture(capture.principal, capture.workspace, request)
    capture.store.close()
    capture.store.open()
    with pytest.raises(CaptureError, match="capture_unavailable"):
        capture.archive.read(capture.principal, request.capture_id)
    with sqlite3.connect(capture.store.path) as connection:
        connection.execute("DROP TRIGGER fail_capture")
    await capture.archive.capture(capture.principal, capture.workspace, request)
    assert len(capture.store.read("SELECT * FROM product_captures")) == 1


async def test_cancel_before_commit_leaves_no_record(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = module._capture

    def wait_then_capture(root: Path, policy: CapturePolicy) -> tuple[CaptureEntry, ...]:
        started.set()
        try:
            if not release.wait(timeout=5):
                raise RuntimeError("fixture wait timed out")
            return original(root, policy)
        finally:
            finished.set()

    monkeypatch.setattr(module, "_capture", wait_then_capture)
    task = asyncio.create_task(
        capture.archive.capture(capture.principal, capture.workspace, capture.request())
    )
    try:
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 5)
    assert not capture.store.read("SELECT * FROM product_captures")


async def test_lost_acknowledgement_retries_original_record(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = capture.store.write_through

    async def commit_then_cancel(fn: Any) -> Any:
        await original(fn)
        raise asyncio.CancelledError

    request = capture.request()
    monkeypatch.setattr(capture.store, "write_through", commit_then_cancel)
    with pytest.raises(asyncio.CancelledError):
        await capture.archive.capture(capture.principal, capture.workspace, request)
    stored = capture.archive.read(capture.principal, request.capture_id)
    monkeypatch.setattr(capture.store, "write_through", original)
    assert await capture.archive.capture(capture.principal, capture.workspace, request) == stored
    assert len(capture.store.read("SELECT * FROM product_captures")) == 1


@pytest.mark.parametrize("failure", [RuntimeError, asyncio.CancelledError])
async def test_materialization_cleans_on_exception_or_cancellation(
    capture: Fixture, failure: type[BaseException]
) -> None:
    request = capture.request()
    await capture.archive.capture(capture.principal, capture.workspace, request)
    with (
        pytest.raises(failure),
        capture.archive.materialize(
            capture.principal, request.capture_id, capture.scratch
        ) as target,
    ):
        assert target.exists()
        raise failure()
    assert not list(capture.scratch.iterdir())
