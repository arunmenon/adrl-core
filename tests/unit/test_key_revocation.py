"""Crash/failure ordering for key revocation. Primary: ADRL-MEM-010, ADRL-OPS-001."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from adrl.core.errors import LedgerAppendFailure
from adrl.core.ids import SessionId
from adrl.ledger import keystore as module
from adrl.ledger.attempts import AttemptJournal
from adrl.ledger.capture import CaptureError
from adrl.ledger.erasure import ErasureService
from adrl.ledger.keystore import FileKeyStore, KeyRevokedError, KeyStoreBusyError

from .test_attempt_capacity import charged
from .test_attempts import start, transition
from .test_capture import Fixture
from .test_capture import capture as capture


def deny_shred_audit(capture: Fixture) -> None:
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute(
            "CREATE TRIGGER deny_shred BEFORE INSERT ON session_keys "
            "WHEN NEW.action='shredded' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END"
        )


async def test_failed_audit_cannot_restore_capture_or_recreate_key(capture: Fixture) -> None:
    request = capture.request()
    await capture.archive.capture(capture.principal, capture.workspace, request)
    sid = capture.principal.session_hmac
    path = capture.keys.root / "sessions" / f"{sid}.key"
    wrapped = path.read_bytes()
    deny_shred_audit(capture)
    with pytest.raises(LedgerAppendFailure):
        await ErasureService(capture.store, capture.keys).erase_session(sid, "synthetic")
    assert not path.exists()
    path.write_bytes(wrapped)
    keys = FileKeyStore(capture.keys.root, store=capture.store)
    assert keys.is_revoked(sid) and keys.get_session_key(sid) is None
    assert not keys.has_session_key(sid) and capture.data.was_erased(sid)
    with pytest.raises(KeyRevokedError):
        keys.create_session_key(sid)
    with pytest.raises(CaptureError, match="key_unavailable"):
        capture.archive.read(capture.principal, request.capture_id)
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute("DROP TRIGGER deny_shred")
    assert keys.shred_session_key(sid, "retry")
    assert not keys.shred_session_key(sid, "retry again")
    assert not path.exists() and keys.is_revoked(sid)


async def test_failed_audit_keeps_attempt_and_capacity_blocked(capture: Fixture) -> None:
    journal, request = AttemptJournal(capture.data), start()
    await journal.start(capture.principal, capture.workspace, request)
    before = charged(capture)
    deny_shred_audit(capture)
    with pytest.raises(LedgerAppendFailure):
        capture.keys.shred_session_key(capture.principal.session_hmac, "synthetic")
    with pytest.raises(CaptureError):
        await journal.transition(capture.principal, transition(request, "cancel"))
    assert charged(capture) == before and before[1] == 1024
    assert capture.store.read("SELECT event_type FROM product_attempt_events")[0][0] == "started"


def test_removal_failure_stays_revoked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("fixture")
    keys.create_session_key(sid)
    remove = keys._remove_session_key

    def fail(session: SessionId) -> bool:
        raise OSError("synthetic removal failure")

    monkeypatch.setattr(keys, "_remove_session_key", fail)
    with pytest.raises(OSError, match="removal"):
        keys.shred_session_key(sid, "fixture")
    assert (keys.root / "sessions" / "fixture.key").exists()
    assert keys.get_session_key(sid) is None
    with pytest.raises(KeyRevokedError):
        keys.create_session_key(sid)
    monkeypatch.setattr(keys, "_remove_session_key", remove)
    assert keys.shred_session_key(sid, "retry")


@pytest.mark.parametrize("stage", ["create", "flush"])
def test_marker_failure_precedes_key_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("fixture")
    original = keys.create_session_key(sid)
    path = keys.root / "sessions" / "fixture.key"
    before = path.read_bytes()
    if stage == "create":
        publish = keys._publish_revocation

        def cannot_publish(session: SessionId) -> None:
            raise OSError("synthetic marker failure")

        monkeypatch.setattr(keys, "_publish_revocation", cannot_publish)
    else:
        sync = module._sync_directory

        def cannot_flush(directory: Path) -> None:
            if directory.name == "revoked":
                raise OSError("synthetic marker failure")
            sync(directory)

        monkeypatch.setattr(module, "_sync_directory", cannot_flush)
    with pytest.raises(OSError, match="marker"):
        keys.shred_session_key(sid, "fixture")
    assert path.read_bytes() == before
    if stage == "create":
        assert keys.get_session_key(sid) == original
        monkeypatch.setattr(keys, "_publish_revocation", publish)
    else:
        assert keys.get_session_key(sid) is None
        monkeypatch.setattr(module, "_sync_directory", sync)
    assert keys.shred_session_key(sid, "retry") and keys.get_session_key(sid) is None


def test_absent_key_and_partial_marker_permanently_deny_creation(tmp_path: Path) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("never-created")
    marker = keys.root / "revoked" / "never-created.revoked"
    marker.touch(mode=0o600)
    assert keys.get_session_key(sid) is None
    with pytest.raises(KeyRevokedError):
        keys.create_session_key(sid)
    assert not keys.shred_session_key(sid, "fixture")
    assert marker.read_bytes() == module.REVOCATION_VERSION
    assert FileKeyStore(keys.root).is_revoked(sid)


def test_missing_key_without_marker_becomes_revoked(tmp_path: Path) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("absent")
    assert not keys.shred_session_key(sid, "fixture")
    assert keys.is_revoked(sid)
    with pytest.raises(KeyRevokedError):
        keys.create_session_key(sid)


async def test_legacy_audit_denies_restored_key_without_marker(capture: Fixture) -> None:
    sid = capture.principal.session_hmac
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute(
            "INSERT INTO session_keys (session_hmac,key_id,wrapped_key,action,reason,ts) "
            "VALUES (?,'fixture',NULL,'shredded','old audit','2026-09-08')",
            (sid,),
        )
    assert not (capture.keys.root / "revoked" / f"{sid}.revoked").exists()
    assert capture.keys.get_session_key(sid) is None
    with pytest.raises(KeyRevokedError):
        capture.keys.create_session_key(sid)


def test_cooperating_lock_contention_is_explicit(tmp_path: Path) -> None:
    first = FileKeyStore(tmp_path / "keys")
    second = FileKeyStore(first.root)
    sid = SessionId("fixture")
    initial = first.create_session_key(sid)
    with first._lock():
        for operation in [
            lambda: second.get_session_key(sid),
            lambda: second.create_session_key(sid),
            lambda: second.shred_session_key(sid, "fixture"),
        ]:
            with pytest.raises(KeyStoreBusyError):
                operation()
    with first._lock(shared=True):
        assert second.get_session_key(sid) == initial
        with pytest.raises(KeyStoreBusyError):
            second.shred_session_key(sid, "fixture")
    assert second.shred_session_key(sid, "fixture")
    assert first.get_session_key(sid) is None


async def test_audit_wait_does_not_hold_ledger_writer_lock(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Inject a real ledger key read immediately before queuing the shred audit. It must
    # succeed (returning None for revocation), rather than seeing a held exclusive file lock.
    audit = capture.keys._audit
    observations: list[bytes | None] = []

    def with_reader(session: SessionId, action: str, identifier: str, reason: str | None) -> None:
        if action == "shredded":
            future = capture.store.submit(lambda conn: capture.keys.get_session_key(session))
            observations.append(future.result(timeout=2))
        audit(session, action, identifier, reason)

    monkeypatch.setattr(capture.keys, "_audit", with_reader)
    assert capture.keys.shred_session_key(capture.principal.session_hmac, "fixture")
    assert observations == [None]


@pytest.mark.parametrize("identity", ["../outside", ".", "..", "a/b", "bad\0", ""])
def test_unsafe_identity_is_rejected(tmp_path: Path, identity: str) -> None:
    keys = FileKeyStore(tmp_path / "keys")
    for operation in [
        lambda: keys.create_session_key(SessionId(identity)),
        lambda: keys.get_session_key(SessionId(identity)),
        lambda: keys.shred_session_key(SessionId(identity), "fixture"),
    ]:
        with pytest.raises(ValueError, match="invalid_session_key_identity"):
            operation()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_lock_file_rejected(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "keys"
    root.mkdir()
    lock = root / ".keystore.lock"
    outside = tmp_path / "outside"
    outside.write_text("preserve")
    if kind == "symlink":
        lock.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, lock)
    else:
        os.mkfifo(lock)
    with pytest.raises((OSError, ValueError)):
        FileKeyStore(root)
    assert outside.read_text() == "preserve"


def test_corrupt_key_can_be_revoked_and_removed(tmp_path: Path) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("fixture")
    path = keys.root / "sessions" / "fixture.key"
    path.write_bytes(b"corrupt")
    assert keys.shred_session_key(sid, "fixture")
    assert keys.get_session_key(sid) is None and not path.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_key_file_never_blocks_or_touches_target(tmp_path: Path, kind: str) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("fixture")
    path = keys.root / "sessions" / "fixture.key"
    outside = tmp_path / "outside"
    outside.write_text("preserve")
    if kind == "symlink":
        path.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, path)
    else:
        os.mkfifo(path)
    with pytest.raises((ValueError, OSError)):
        keys.get_session_key(sid)
    with pytest.raises((ValueError, OSError)):
        keys.shred_session_key(sid, "fixture")
    assert keys.is_revoked(sid) and keys.get_session_key(sid) is None
    assert outside.read_text() == "preserve"


def test_marker_and_lock_are_private_and_payload_free(tmp_path: Path) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("fixture")
    secret = keys.create_session_key(sid)
    keys.shred_session_key(sid, "private-reason-canary")
    marker = keys.root / "revoked" / "fixture.revoked"
    assert marker.read_bytes() == module.REVOCATION_VERSION
    assert secret not in marker.read_bytes() and b"private-reason-canary" not in marker.read_bytes()
    assert marker.stat().st_mode & 0o777 == 0o600
    assert marker.parent.stat().st_mode & 0o777 == 0o700
    assert (keys.root / ".keystore.lock").stat().st_mode & 0o777 == 0o600


def test_owned_pending_key_copies_removed_on_shred(tmp_path: Path) -> None:
    keys, sid = FileKeyStore(tmp_path / "keys"), SessionId("fixture")
    keys.create_session_key(sid)
    path = keys.root / "sessions" / "fixture.key"
    pending = path.parent / ".key-write-fixture.key-interrupted"
    pending.write_bytes(path.read_bytes())
    unrelated = path.parent / ".key-write-other.key-interrupted"
    unrelated.write_bytes(b"other-owned-session")
    assert keys.shred_session_key(sid, "fixture")
    assert not pending.exists() and unrelated.exists()
    assert not list(path.parent.glob(".key-write-fixture.key-*"))


async def test_process_death_after_marker_keeps_key_denied(tmp_path: Path) -> None:
    root, ready = tmp_path / "keys", tmp_path / "ready"
    keys, sid = FileKeyStore(root), SessionId("fixture")
    keys.create_session_key(sid)
    script = (
        "from pathlib import Path\nimport time\n"
        "from adrl.ledger.keystore import FileKeyStore\nfrom adrl.core.ids import SessionId\n"
        f"k=FileKeyStore(Path({str(root)!r}))\noriginal=k._publish_revocation\n"
        "def publish(s):\n original(s)\n"
        f" Path({str(ready)!r}).touch()\n time.sleep(10)\n"
        "k._publish_revocation=publish\nk.shred_session_key(SessionId('fixture'),'fixture')\n"
    )
    child = await asyncio.to_thread(
        subprocess.Popen,
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(150):
            if await asyncio.to_thread(ready.exists):
                break
            await asyncio.sleep(0.02)
        assert await asyncio.to_thread(ready.exists)
        child.kill()
        await asyncio.to_thread(child.wait, timeout=3)
        reopened = FileKeyStore(root)
        assert (root / "sessions" / "fixture.key").exists()
        assert reopened.get_session_key(sid) is None
        assert reopened.shred_session_key(sid, "retry")
        with pytest.raises(KeyRevokedError):
            reopened.create_session_key(sid)
    finally:
        if child.poll() is None:
            child.kill()
            await asyncio.to_thread(child.wait, timeout=3)
