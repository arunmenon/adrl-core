"""Reserved terminal capacity and compatibility. Primary: ADRL-MEM-002, ADRL-OPS-001."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from adrl.api.store import ProductStore
from adrl.core.errors import LedgerAppendFailure
from adrl.ledger import crypto
from adrl.ledger.attempts import (
    AttemptError,
    AttemptEvent,
    AttemptJournal,
    AttemptPolicy,
    LegacyAttemptPolicy,
    StartAttempt,
)
from adrl.ledger.capture import CaptureError
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.migrations import load_migrations
from adrl.ledger.session_verification import _tree, _tree_ref
from adrl.ledger.store import LedgerStore

from .test_attempts import start, transition
from .test_capture import Fixture, bind
from .test_capture import capture as capture


def charged(capture: Fixture) -> tuple[int, int]:
    stored = capture.store.read(
        "SELECT COALESCE(SUM(LENGTH(nonce)+LENGTH(ciphertext)),0) AS n FROM product_attempt_events"
    )[0]["n"]
    with sqlite3.connect(capture.store.path) as conn:
        reserved, _ = AttemptJournal._capacity_state(conn)
    return stored, reserved


async def test_default_start_grant_is_atomic_durable_and_private(capture: Fixture) -> None:
    journal, request = AttemptJournal(capture.data), start()
    event = await journal.start(capture.principal, capture.workspace, request)
    grants = [dict(row) for row in capture.store.read("SELECT * FROM product_attempt_capacity")]
    assert len(grants) == 1 and grants[0]["reserved_bytes"] == 1024
    assert event.policy is not None and event.policy.schema_version == "operator-attempt-policy-v2"
    stored, reserved = charged(capture)
    assert stored > 0 and reserved == 1024
    assert str(request.attempt_id) not in repr(grants)
    assert str(capture.workspace) not in repr(grants) and "code.txt" not in repr(grants)
    capture.store.close()
    capture.store.open()
    assert await journal.start(capture.principal, capture.workspace, request) == event
    assert charged(capture) == (stored, reserved)
    assert [
        dict(row) for row in capture.store.read("SELECT * FROM product_attempt_capacity")
    ] == grants


async def test_start_must_fit_its_terminal_reserve(capture: Fixture) -> None:
    # The event alone is below this limit, but adding the fixed 1 KiB grant exceeds it.
    policy = AttemptPolicy(max_history_bytes=2000)
    journal, request = AttemptJournal(capture.data, policy), start()
    with pytest.raises(AttemptError, match="history_limit"):
        await journal.start(capture.principal, capture.workspace, request)
    assert not capture.store.read("SELECT * FROM product_attempt_capacity")
    assert not capture.store.read("SELECT * FROM product_attempt_events")
    # The same source/policy shape can be admitted with enough room; measure its actual size.
    event = await AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=3000)).start(
        capture.principal, capture.workspace, request
    )
    assert len(event.model_dump_json().encode()) + 28 < 2000
    assert charged(capture)[0] + policy.terminal_reserve_bytes > 2000


async def test_close_cannot_consume_reserved_bytes_but_terminal_can(capture: Fixture) -> None:
    journal, request = AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=2500)), start()
    await journal.start(capture.principal, capture.workspace, request)
    before = charged(capture)
    with pytest.raises(AttemptError, match="history_limit"):
        await journal.transition(capture.principal, transition(request, "request_close"))
    assert charged(capture) == before
    terminal = await journal.transition(capture.principal, transition(request, "cancel"))
    assert terminal.phase == "cancelled" and not terminal.eligible_for_learning
    stored, reserved = charged(capture)
    assert reserved == 0 and stored <= 2500
    assert len(capture.store.read("SELECT * FROM product_attempt_capacity")) == 1


@pytest.mark.parametrize(
    "reason",
    [
        "operator_cancelled",
        "operator_interrupted",
        "supervisor_lost",
        "capture_unavailable",
        "quiescence_unavailable",
    ],
)
async def test_each_terminal_reason_fits_last_slot_and_bytes(capture: Fixture, reason: str) -> None:
    journal = AttemptJournal(capture.data, AttemptPolicy(max_events_per_attempt=2))
    request = start()
    await journal.start(capture.principal, capture.workspace, request)
    kind = "cancel" if reason == "operator_cancelled" else "mark_incomplete"
    with pytest.raises(AttemptError, match="terminal_slot_reserved"):
        await journal.transition(capture.principal, transition(request, "request_close"))
    initial = charged(capture)[0]
    event = await journal.transition(capture.principal, transition(request, kind, reason=reason))
    stored, reserved = charged(capture)
    assert stored - initial <= 1024 and reserved == 0
    assert event.attribution == "unestablished" and not event.eligible_for_learning


async def test_lowered_caller_budget_preserves_existing_terminal_grant(capture: Fixture) -> None:
    original, request = AttemptJournal(capture.data), start()
    await original.start(capture.principal, capture.workspace, request)
    lower = AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=1, max_event_bytes=1))
    with pytest.raises(AttemptError, match="history_limit"):
        await lower.transition(capture.principal, transition(request, "request_close"))
    event = await lower.transition(capture.principal, transition(request, "mark_incomplete"))
    assert event.phase == "incomplete" and charged(capture)[1] == 0
    with pytest.raises(AttemptError, match="limit"):
        await lower.start(capture.principal, capture.workspace, start())


async def test_larger_caller_cannot_spend_smaller_active_commitment(capture: Fixture) -> None:
    journal, request = AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=3000)), start()
    await journal.start(capture.principal, capture.workspace, request)
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    with pytest.raises(AttemptError, match="history_limit"):
        await AttemptJournal(capture.data).start(other, capture.scratch, start())
    await journal.transition(capture.principal, transition(request, "cancel"))
    # Consuming the smaller grant lifts that active ceiling, while its history stays charged.
    await AttemptJournal(capture.data).start(other, capture.scratch, start())
    assert (
        charged(capture)[1] == 1024
        and len(capture.store.read("SELECT * FROM product_attempt_capacity")) == 2
    )


async def test_scarce_budget_serializes_distinct_workspace_admission(capture: Fixture) -> None:
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    journal = AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=4000))
    requests = [start(), start()]
    result = await asyncio.gather(
        journal.start(capture.principal, capture.workspace, requests[0]),
        journal.start(other, capture.scratch, requests[1]),
        return_exceptions=True,
    )
    assert sum(isinstance(item, AttemptEvent) for item in result) == 1
    assert sum(isinstance(item, AttemptError) for item in result) == 1
    assert sum(charged(capture)) <= 4000 and charged(capture)[1] == 1024
    assert len(capture.store.read("SELECT * FROM product_attempt_capacity")) == 1


async def test_lost_terminal_ack_and_duplicate_do_not_consume_twice(
    capture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal, request = AttemptJournal(capture.data), start()
    await journal.start(capture.principal, capture.workspace, request)
    command = transition(request, "cancel")
    write = capture.store.write_through

    async def lost_ack(fn: Any) -> Any:
        await write(fn)
        raise asyncio.CancelledError

    monkeypatch.setattr(capture.store, "write_through", lost_ack)
    with pytest.raises(asyncio.CancelledError):
        await journal.transition(capture.principal, command)
    saved = journal.read(capture.principal, request.attempt_id)[-1]
    size = charged(capture)
    monkeypatch.setattr(capture.store, "write_through", write)
    assert await journal.transition(capture.principal, command) == saved
    assert charged(capture) == size and size[1] == 0


async def test_failure_between_start_and_grant_rolls_back_both(capture: Fixture) -> None:
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute(
            "CREATE TRIGGER fail_capacity BEFORE INSERT ON product_attempt_capacity "
            "BEGIN SELECT RAISE(ABORT,'fixture'); END"
        )
    with pytest.raises(LedgerAppendFailure):
        await AttemptJournal(capture.data).start(capture.principal, capture.workspace, start())
    assert charged(capture) == (0, 0)
    assert not capture.store.read("SELECT * FROM product_attempt_events")


async def test_terminal_failure_preserves_full_grant(capture: Fixture) -> None:
    journal, request = AttemptJournal(capture.data), start()
    await journal.start(capture.principal, capture.workspace, request)
    before = charged(capture)
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute(
            "CREATE TRIGGER fail_terminal AFTER INSERT ON product_attempt_events "
            "WHEN NEW.event_type='cancelled' BEGIN SELECT RAISE(ABORT,'fixture'); END"
        )
    with pytest.raises(LedgerAppendFailure):
        await journal.transition(capture.principal, transition(request, "cancel"))
    assert charged(capture) == before
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute("DROP TRIGGER fail_terminal")
    await journal.transition(capture.principal, transition(request, "cancel"))
    assert charged(capture)[1] == 0


@pytest.mark.parametrize("fault", ["missing", "bytes", "ceiling", "header"])
async def test_owning_grant_and_authenticated_header_checked(capture: Fixture, fault: str) -> None:
    journal, request = AttemptJournal(capture.data), start()
    await journal.start(capture.principal, capture.workspace, request)
    with sqlite3.connect(capture.store.path) as conn:
        if fault == "missing":
            conn.execute("DELETE FROM product_attempt_capacity")
        elif fault == "header":
            conn.execute("UPDATE product_attempt_events SET capacity_version=0")
        elif fault == "bytes":
            conn.execute("UPDATE product_attempt_capacity SET reserved_bytes=2048")
        else:
            conn.execute("UPDATE product_attempt_capacity SET history_limit=30000000")
    with pytest.raises(AttemptError, match="integrity"):
        journal.read(capture.principal, request.attempt_id)
    with pytest.raises(AttemptError, match="integrity"):
        await journal.transition(capture.principal, transition(request, "cancel"))


async def test_missing_required_grant_blocks_other_admission(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data)
    await journal.start(capture.principal, capture.workspace, start())
    with sqlite3.connect(capture.store.path) as conn:
        conn.execute("DELETE FROM product_attempt_capacity")
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    with pytest.raises(AttemptError, match="capacity_integrity"):
        await journal.start(other, capture.scratch, start())


@pytest.mark.parametrize("fault", ["erased", "expired"])
async def test_terminal_grant_does_not_bypass_erasure_or_expiry(
    capture: Fixture, fault: str
) -> None:
    journal, request = AttemptJournal(capture.data), start()
    await journal.start(capture.principal, capture.workspace, request)
    before = charged(capture)
    principal = capture.principal
    if fault == "erased":
        capture.keys.shred_session_key(principal.session_hmac, "fixture")
    else:
        principal = replace(principal, assertion=replace(principal.assertion, expires_at=0))
    with pytest.raises((AttemptError, CaptureError)):
        await journal.transition(principal, transition(request, "cancel"))
    assert charged(capture) == before and before[1] == 1024


def legacy_database(
    capture: Fixture, policy: LegacyAttemptPolicy
) -> tuple[Path, StartAttempt, AttemptEvent]:
    """Actual schema-8 encrypted row, using the unchanged v1 AAD and schema."""
    path, request = capture.scratch / "v8.db", start()
    key = capture.keys.get_session_key(capture.principal.session_hmac)
    assert key is not None
    workspace = crypto.keyed_hash(
        capture.keys.hmac_key(), "attempt-workspace:" + str(capture.workspace)
    )
    initial = _tree(capture.workspace, policy.snapshot)
    event = AttemptEvent(
        command=request,
        sequence=0,
        recorded_at=datetime.now(UTC),
        workspace_ref="hmac:" + workspace,
        policy=policy,
        initial_manifest=tuple(sorted(initial.items())),
        initial_source_ref=_tree_ref(capture.keys.hmac_key(), initial),
    )
    attempt_key = crypto.keyed_hash(key, "attempt:" + str(request.attempt_id))
    event_key = crypto.keyed_hash(key, "attempt-event:" + str(request.event_id))
    nonce, encrypted = crypto.encrypt(
        key,
        event.model_dump_json().encode(),
        AttemptJournal._aad(
            capture.principal.session_hmac, attempt_key, event_key, workspace, "started", 0
        ),
    )
    with sqlite3.connect(path) as conn:
        for migration in load_migrations():
            if migration.version <= 8:
                conn.executescript(migration.sql)
        row = dict(capture.store.read("SELECT * FROM product_sessions")[0])
        conn.execute(
            f"INSERT INTO product_sessions ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",
            tuple(row.values()),
        )
        conn.execute(
            "INSERT INTO product_attempt_events (session_hmac,attempt_key,event_key,workspace_key,"
            "event_type,attempt_seq,nonce,ciphertext,ts) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                capture.principal.session_hmac,
                attempt_key,
                event_key,
                workspace,
                "started",
                0,
                nonce,
                encrypted,
                event.recorded_at.isoformat(),
            ),
        )
        conn.execute("PRAGMA user_version=8")
    return path, request, event


@pytest.mark.parametrize("event_slots", [1, 8])
async def test_v1_migrates_without_invented_capacity(capture: Fixture, event_slots: int) -> None:
    policy = LegacyAttemptPolicy(max_events_per_attempt=event_slots)
    path, request, event = await asyncio.to_thread(legacy_database, capture, policy)
    with sqlite3.connect(path) as conn:
        before = conn.execute("SELECT nonce,ciphertext FROM product_attempt_events").fetchone()
    store = LedgerStore(path)
    store.open()
    try:
        data = ProductStore(store, FileKeyStore(capture.keys.root, store=store))
        journal = AttemptJournal(data, policy)
        assert store.schema_user_version() == 12
        row = store.read("SELECT nonce,ciphertext,capacity_version FROM product_attempt_events")[0]
        assert (row["nonce"], row["ciphertext"]) == before and row["capacity_version"] == 0
        assert journal.read(capture.principal, request.attempt_id) == (event,)
        assert await journal.start(capture.principal, capture.workspace, request) == event
        assert not store.read("SELECT * FROM product_attempt_capacity")
        if event_slots == 1:
            with pytest.raises(AttemptError, match="event_limit"):
                await journal.transition(capture.principal, transition(request, "cancel"))
        else:
            assert (
                await journal.transition(capture.principal, transition(request, "cancel"))
            ).phase == "cancelled"
        with pytest.raises(AttemptError, match="legacy_attempt_admission_refused"):
            await journal.start(capture.principal, capture.workspace, start())
    finally:
        store.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"max_events_per_attempt": 1},
        {"terminal_reserve_bytes": 1023},
        {"terminal_reserve_bytes": 4097},
    ],
)
def test_v2_policy_rejects_unusable_or_excessive_reservations(changes: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        AttemptPolicy.model_validate(changes)


async def test_v1_continuation_respects_new_session_grant(capture: Fixture) -> None:
    path, old_request, _ = await asyncio.to_thread(legacy_database, capture, LegacyAttemptPolicy())
    other_root = capture.workspace.parent / "other-workspace"
    other_root.mkdir()
    (other_root / "code.txt").write_text("synthetic")
    store = LedgerStore(path)
    store.open()
    try:
        data = ProductStore(store, FileKeyStore(capture.keys.root, store=store))
        other = await bind(data, other_root, str(uuid4()))
        bounded = AttemptJournal(data, AttemptPolicy(max_history_bytes=3300))
        new_request = start()
        await bounded.start(other, other_root, new_request)
        legacy = AttemptJournal(data, LegacyAttemptPolicy())
        with pytest.raises(AttemptError, match="history_limit"):
            await legacy.transition(capture.principal, transition(old_request, "request_close"))
        await bounded.transition(other, transition(new_request, "cancel"))
        assert (
            await legacy.transition(capture.principal, transition(old_request, "cancel"))
        ).phase == "cancelled"
        assert len(store.read("SELECT * FROM product_attempt_capacity")) == 1
    finally:
        store.close()


async def test_erased_pending_grant_still_blocks_larger_admission(capture: Fixture) -> None:
    journal = AttemptJournal(capture.data, AttemptPolicy(max_history_bytes=2500))
    await journal.start(capture.principal, capture.workspace, start())
    capture.keys.shred_session_key(capture.principal.session_hmac, "fixture")
    other = await bind(capture.data, capture.scratch, str(uuid4()))
    with pytest.raises(AttemptError, match="history_limit"):
        await AttemptJournal(capture.data).start(other, capture.scratch, start())
    assert charged(capture)[1] == 1024
