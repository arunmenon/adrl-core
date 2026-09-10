"""Attempt history and admission fault cases. Primary: ADRL-MEM-002, ADRL-OPS-001."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from adrl.api.store import ProductStore
from adrl.core.errors import LedgerAppendFailure
from adrl.ledger import attempts as module
from adrl.ledger.attempts import (
    AttemptError,
    AttemptJournal,
    AttemptPolicy,
    AttemptTransition,
    StartAttempt,
)
from adrl.ledger.capture import CaptureArchive
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.migrations import load_migrations
from adrl.ledger.session_verification import snapshot_fingerprint
from adrl.ledger.store import LedgerStore

from .test_capture import Fixture, bind
from .test_capture import capture as capture


def start(**changes: Any) -> StartAttempt:
    return StartAttempt.model_validate(
        {"event_id": uuid4(), "attempt_id": uuid4(), "task_ref": "task-one", "capture_id": uuid4()}
        | changes
    )


def transition(spec: StartAttempt, kind: str, **changes: Any) -> AttemptTransition:
    reasons = {"cancel": "operator_cancelled", "mark_incomplete": "operator_interrupted"}
    return AttemptTransition.model_validate(
        {
            "event_id": uuid4(),
            "attempt_id": spec.attempt_id,
            "kind": kind,
            "reason": reasons.get(kind),
        }
        | changes
    )


async def test_start_retry_preserves_initial_tree_after_edits_and_later_events(
    capture: Fixture,
) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    first = await journal.start(capture.principal, capture.workspace, spec)
    reference = snapshot_fingerprint(
        capture.workspace, journal.policy.snapshot, capture.keys.hmac_key()
    )[1]
    assert first.initial_source_ref == reference
    assert dict(first.initial_manifest or ())["code.txt"].startswith("0:")
    (capture.workspace / "code.txt").write_text("B")
    close = await journal.transition(capture.principal, transition(spec, "request_close"))
    assert close.phase == "close_requested" and close.attribution == "unestablished"
    assert await journal.start(capture.principal, capture.workspace, spec) == first
    history = journal.read(capture.principal, spec.attempt_id)
    assert [event.sequence for event in history] == [0, 1]
    assert not any(event.eligible_for_learning for event in history)
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 2
    assert not capture.store.read("SELECT * FROM product_captures")
    row = dict(capture.store.read("SELECT * FROM product_attempt_events LIMIT 1")[0])
    for private in [
        b"code.txt",
        str(capture.workspace).encode(),
        str(spec.attempt_id).encode(),
        b"task-one",
    ]:
        assert private not in repr(row).encode()
    assert "output-A-private-canary" not in first.model_dump_json()


@pytest.mark.parametrize("change", ["task", "capture", "attempt", "policy", "workspace"])
async def test_changed_start_identity_conflicts(capture: Fixture, change: str) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    await journal.start(capture.principal, capture.workspace, spec)
    principal, workspace = capture.principal, capture.workspace
    if change == "task":
        spec = spec.model_copy(update={"task_ref": "different"})
    elif change == "capture":
        spec = spec.model_copy(update={"capture_id": uuid4()})
    elif change == "attempt":
        spec = spec.model_copy(update={"attempt_id": uuid4()})
    elif change == "policy":
        journal = AttemptJournal(capture.data, AttemptPolicy(max_session_attempts=1))
    else:
        workspace = capture.scratch
        principal = replace(
            principal,
            assertion=replace(
                principal.assertion,
                inventory=replace(principal.assertion.inventory, root=str(workspace)),
            ),
        )
    with pytest.raises(AttemptError, match="event_conflict"):
        await journal.start(principal, workspace, spec)
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 1


async def test_order_duplicate_close_and_terminal_history(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    close = transition(spec, "request_close")
    with pytest.raises(AttemptError, match="attempt_unavailable"):
        await journal.transition(capture.principal, close)
    await journal.start(capture.principal, capture.workspace, spec)
    original = await journal.transition(capture.principal, close)
    with pytest.raises(AttemptError, match="transition_conflict"):
        await journal.transition(capture.principal, transition(spec, "request_close"))
    await journal.transition(capture.principal, transition(spec, "cancel"))
    assert await journal.transition(capture.principal, close) == original
    with pytest.raises(AttemptError, match="transition_conflict"):
        await journal.transition(capture.principal, transition(spec, "mark_incomplete"))
    changed = transition(spec, "cancel", event_id=close.event_id)
    with pytest.raises(AttemptError, match="event_conflict"):
        await journal.transition(capture.principal, changed)
    assert [event.phase for event in journal.read(capture.principal, spec.attempt_id)] == [
        "started",
        "close_requested",
        "cancelled",
    ]


async def test_restart_preserves_reservation_until_explicit_incomplete(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    await journal.start(capture.principal, capture.workspace, spec)
    close = transition(spec, "request_close")
    original = await journal.transition(capture.principal, close)
    capture.store.close()
    capture.store.open()
    journal = AttemptJournal(capture.data)
    assert await journal.transition(capture.principal, close) == original
    other = await bind(capture.data, capture.workspace, str(uuid4()))
    with pytest.raises(AttemptError, match="workspace_reserved"):
        await journal.start(other, capture.workspace, start())
    await journal.transition(
        capture.principal, transition(spec, "mark_incomplete", reason="supervisor_lost")
    )
    assert journal.read(capture.principal, spec.attempt_id)[-1].attribution == "unestablished"
    await journal.start(other, capture.workspace, start(task_ref="separate-task"))
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 4


async def test_simultaneous_sessions_get_only_one_workspace_reservation(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data)
    other = await bind(capture.data, capture.workspace, str(uuid4()))
    results = await asyncio.gather(
        journal.start(capture.principal, capture.workspace, start()),
        journal.start(other, capture.workspace, start()),
        return_exceptions=True,
    )
    assert sum(isinstance(result, AttemptError) for result in results) == 1
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 1
    assert any(
        isinstance(result, AttemptError) and str(result) == "workspace_reserved"
        for result in results
    )


async def test_different_workspaces_remain_independent(capture: Fixture) -> None:
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    journal = AttemptJournal(capture.data)
    first, second = start(), start(task_ref="task-two")
    await journal.start(capture.principal, capture.workspace, first)
    await journal.start(other, capture.scratch, second)
    assert journal.read(capture.principal, first.attempt_id)[0].command.task_ref == "task-one"
    assert journal.read(other, second.attempt_id)[0].command.task_ref == "task-two"
    with pytest.raises(AttemptError, match="attempt_unavailable"):
        journal.read(other, first.attempt_id)


@pytest.mark.parametrize("case", ["valid", "task", "session", "workspace", "active"])
async def test_parent_scope_and_terminal_state(capture: Fixture, case: str) -> None:
    journal = AttemptJournal(capture.data)
    parent = start()
    await journal.start(capture.principal, capture.workspace, parent)
    if case != "active":
        await journal.transition(capture.principal, transition(parent, "cancel"))
    principal, workspace = capture.principal, capture.workspace
    if case == "session":
        principal = await bind(capture.data, workspace, str(uuid4()))
    if case == "workspace":
        workspace = capture.scratch
        principal = replace(
            principal,
            assertion=replace(
                principal.assertion,
                inventory=replace(principal.assertion.inventory, root=str(workspace)),
            ),
        )
    child = start(
        parent_attempt_id=parent.attempt_id, task_ref="other" if case == "task" else parent.task_ref
    )
    if case == "valid":
        event = await journal.start(principal, workspace, child)
        assert event.command.parent_attempt_id == parent.attempt_id
    else:
        with pytest.raises(AttemptError):
            await journal.start(principal, workspace, child)


async def test_reserved_capture_id_and_retrospective_start_are_rejected(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    await journal.start(capture.principal, capture.workspace, spec)
    await journal.transition(capture.principal, transition(spec, "cancel"))
    with pytest.raises(AttemptError, match="capture_id_reserved"):
        await journal.start(capture.principal, capture.workspace, start(capture_id=spec.capture_id))
    existing = capture.request()
    await capture.archive.capture(capture.principal, capture.workspace, existing)
    for proposed in [start(attempt_id=existing.attempt_id), start(capture_id=existing.capture_id)]:
        with pytest.raises(AttemptError, match="capture_predates_attempt"):
            await journal.start(capture.principal, capture.workspace, proposed)


@pytest.mark.parametrize("case", ["expired", "workload", "root"])
async def test_invalid_context_denied(capture: Fixture, case: str) -> None:
    principal = capture.principal
    if case == "expired":
        principal = replace(principal, assertion=replace(principal.assertion, expires_at=0))
    elif case == "workload":
        principal = replace(principal, workload_ref="wrong")
    else:
        principal = replace(
            principal,
            assertion=replace(
                principal.assertion,
                inventory=replace(principal.assertion.inventory, root=str(capture.scratch)),
            ),
        )
    with pytest.raises(ValueError):
        await AttemptJournal(capture.data).start(principal, capture.workspace, start())
    assert not capture.store.read("SELECT * FROM product_attempt_events")


@pytest.mark.parametrize("case", ["expiry", "erasure"])
async def test_queued_append_rechecks_expiry_and_erasure(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    original = capture.store.write_through

    async def intervene(fn: Any) -> Any:
        if case == "expiry":
            monkeypatch.setattr(
                module.time, "time", lambda: capture.principal.assertion.expires_at + 1
            )
        else:
            capture.keys.shred_session_key(capture.principal.session_hmac, "fixture-erasure")
        return await original(fn)

    monkeypatch.setattr(capture.store, "write_through", intervene)
    with pytest.raises(AttemptError, match=r"expired|key_unavailable"):
        await AttemptJournal(capture.data).start(capture.principal, capture.workspace, start())
    assert not capture.store.read("SELECT * FROM product_attempt_events")


async def test_erased_history_cannot_be_restored_with_old_key(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    await journal.start(capture.principal, capture.workspace, spec)
    path = capture.keys.root / "sessions" / f"{capture.principal.session_hmac}.key"
    old = path.read_bytes()
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture-erasure")
    path.write_bytes(old)
    with pytest.raises(ValueError, match="key_unavailable"):
        journal.read(capture.principal, spec.attempt_id)
    with pytest.raises(ValueError, match="key_unavailable"):
        await journal.transition(capture.principal, transition(spec, "cancel"))
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 1


async def test_erased_pending_attempt_stays_reserved_and_counts_against_quota(
    capture: Fixture,
) -> None:
    journal = AttemptJournal(capture.data)
    await journal.start(capture.principal, capture.workspace, start())
    row = capture.store.read("SELECT * FROM product_attempt_events")[0]
    used = len(row["ciphertext"]) + len(row["nonce"])
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture-erasure")
    same = await bind(capture.data, capture.workspace, str(uuid4()))
    with pytest.raises(AttemptError, match="workspace_reserved"):
        await journal.start(same, capture.workspace, start())
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    limited = AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=used + 1))
    with pytest.raises(AttemptError, match="attempt_history_limit"):
        await limited.start(other, capture.scratch, start())
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 1


@pytest.mark.parametrize(
    "case", ["ciphertext", "event_type", "workspace_key", "ts", "missing_start", "gap"]
)
async def test_corrupt_or_incomplete_history_is_rejected(capture: Fixture, case: str) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    await journal.start(capture.principal, capture.workspace, spec)
    await journal.transition(capture.principal, transition(spec, "request_close"))
    await journal.transition(capture.principal, transition(spec, "cancel"))
    with sqlite3.connect(capture.store.path) as conn:
        if case in {"missing_start", "gap"}:
            conn.execute(
                "DELETE FROM product_attempt_events WHERE attempt_seq=?",
                (0 if case == "missing_start" else 1,),
            )
        else:
            conn.execute(
                f"UPDATE product_attempt_events SET {case}=? WHERE attempt_seq=1", (b"tampered",)
            )
    with pytest.raises(AttemptError, match=r"integrity|history_incomplete"):
        journal.read(capture.principal, spec.attempt_id)


async def test_failed_commit_and_lost_ack_are_recoverable(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = AttemptJournal(capture.data)
    spec = start()
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute(
            "CREATE TRIGGER fail_attempt BEFORE INSERT ON product_attempt_events "
            "BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    with pytest.raises(LedgerAppendFailure):
        await journal.start(capture.principal, capture.workspace, spec)
    assert not capture.store.read("SELECT * FROM product_attempt_events")
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute("DROP TRIGGER fail_attempt")
    original = capture.store.write_through

    async def commit_without_ack(fn: Any) -> Any:
        await original(fn)
        raise asyncio.CancelledError

    monkeypatch.setattr(capture.store, "write_through", commit_without_ack)
    with pytest.raises(asyncio.CancelledError):
        await journal.start(capture.principal, capture.workspace, spec)
    stored = journal.read(capture.principal, spec.attempt_id)[0]
    monkeypatch.setattr(capture.store, "write_through", original)
    assert await journal.start(capture.principal, capture.workspace, spec) == stored
    assert len(capture.store.read("SELECT * FROM product_attempt_events")) == 1


@pytest.mark.parametrize(
    "policy", [AttemptPolicy(max_event_bytes=1), AttemptPolicy(max_history_bytes=1)]
)
async def test_initial_storage_limits_are_atomic(capture: Fixture, policy: AttemptPolicy) -> None:
    with pytest.raises(AttemptError, match="limit"):
        await AttemptJournal(capture.data, policy).start(
            capture.principal, capture.workspace, start()
        )
    assert not capture.store.read("SELECT * FROM product_attempt_events")


async def test_event_and_session_limits_do_not_reclaim_history(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data, AttemptPolicy(max_events_per_attempt=2))
    spec = start()
    await journal.start(capture.principal, capture.workspace, spec)
    with pytest.raises(AttemptError, match="terminal_slot_reserved"):
        await journal.transition(capture.principal, transition(spec, "request_close"))
    await journal.transition(capture.principal, transition(spec, "cancel"))
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    journal = AttemptJournal(capture.data, AttemptPolicy(max_session_attempts=1))
    spec = start()
    await journal.start(other, capture.scratch, spec)
    await journal.transition(other, transition(spec, "cancel"))
    with pytest.raises(AttemptError, match="session_attempt_limit"):
        await journal.start(other, capture.scratch, start())


@pytest.mark.parametrize("kind", ["success", "verified", "writers_quiesced", "closed"])
def test_unimplemented_authority_cannot_be_submitted(kind: str) -> None:
    with pytest.raises(ValidationError):
        AttemptTransition.model_validate({"kind": kind, "attempt_id": uuid4(), "event_id": uuid4()})


async def test_version_seven_capture_survives_attempt_migration(capture: Fixture) -> None:
    request = capture.request()
    snapshot = await capture.archive.capture(capture.principal, capture.workspace, request)
    legacy = capture.scratch / "version-seven.db"
    with sqlite3.connect(legacy) as conn:
        for migration in load_migrations():
            if migration.version <= 7:
                conn.executescript(migration.sql)
        for table in ["product_sessions", "product_captures"]:
            row = dict(capture.store.read(f"SELECT * FROM {table}")[0])
            conn.execute(
                f"INSERT INTO {table} ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",
                tuple(row.values()),
            )
        conn.execute("PRAGMA user_version=7")
    store = LedgerStore(legacy)
    store.open()
    try:
        archive = CaptureArchive(ProductStore(store, FileKeyStore(capture.keys.root, store=store)))
        assert store.schema_user_version() == 12
        assert archive.read(capture.principal, request.capture_id) == snapshot
        assert not store.read("SELECT * FROM product_attempt_events")
    finally:
        store.close()
