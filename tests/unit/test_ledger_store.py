"""Evidence ledger store: append-only, idempotent, migrated, WAL, concurrent producers."""

from __future__ import annotations

import sqlite3
import threading

import pytest

from adrl.core import Decision, PermittedSet, Rung, mint_route_id
from adrl.core.errors import LedgerAppendFailure
from adrl.core.ids import LineageId, RouteId
from adrl.core.types import LedgerEvent
from adrl.ledger.facade import MemoryFacade, NullProvider, SqliteLedgerProvider
from adrl.ledger.store import LedgerStore


def _decision(route_id: RouteId | None = None) -> Decision:
    return Decision(
        route_id=route_id or mint_route_id(),
        rung=Rung.LOCAL,
        permitted=PermittedSet.all(),
        estimator="band-heuristic",
        estimator_version="v1",
        policy_version="policy-v1",
        objective_version="objective-v1",
        cascade_feasible=True,
        cascade_reason=None,
        features={"tool_count": 3},
        features_version="features-v1",
    )


_CONTEXT = {
    "session_hmac": "s",
    "lineage_hmac": "l",
    "request_class": "user_turn",
    "content_bearing": True,
}


def test_migration_applies_and_wal_is_set(ledger_store: LedgerStore) -> None:
    assert ledger_store.schema_user_version() >= 2
    assert ledger_store.journal_mode() == "wal"
    tables = {
        r["name"] for r in ledger_store.read("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {
        "decisions",
        "events",
        "lineage_events",
        "embeddings",
        "session_keys",
        "projections",
    } <= tables


async def test_decision_write_through_and_duplicate_is_noop(ledger_store: LedgerStore) -> None:
    provider = SqliteLedgerProvider(ledger_store)
    decision = _decision()
    assert await provider.append_decision(decision, _CONTEXT) is True
    assert await provider.append_decision(decision, _CONTEXT) is False
    row = ledger_store.read_decision(decision.route_id)
    assert row is not None and row["decided_rung"] == "local"


async def test_event_idempotency_key(ledger_store: LedgerStore) -> None:
    provider = SqliteLedgerProvider(ledger_store)
    route_id = mint_route_id()
    event = LedgerEvent(route_id, "outcome", "proxy", 1, {"state": "pending"})
    assert await provider.append_event(event) is True
    assert await provider.append_event(event) is False
    assert await provider.append_event(
        LedgerEvent(route_id, "outcome", "proxy", 2, {"state": "closed_turn"})
    )
    events = await provider.read_events(route_id)
    assert [e.payload["state"] for e in events] == ["pending", "closed_turn"]


def test_append_only_is_enforced_by_query_only_reader(ledger_store: LedgerStore) -> None:
    with pytest.raises(sqlite3.OperationalError):
        ledger_store.read("UPDATE decisions SET decided_rung='frontier'")


def test_writer_thread_survives_concurrent_producers(ledger_store: LedgerStore) -> None:
    errors: list[BaseException] = []

    def produce(prefix: int) -> None:
        try:
            for i in range(50):
                fut = ledger_store.submit(
                    LedgerStore.insert_lineage_event(f"lineage-{prefix}", "tick", {"i": i})
                )
                fut.result(timeout=10)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=produce, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    count = ledger_store.read("SELECT COUNT(*) AS c FROM lineage_events")[0]["c"]
    assert count == 300


def test_writer_reports_failure_without_dying(ledger_store: LedgerStore) -> None:
    def bad(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO no_such_table VALUES (1)")

    with pytest.raises(LedgerAppendFailure):
        ledger_store.submit(bad).result(timeout=5)
    ok = ledger_store.submit(LedgerStore.insert_lineage_event("l", "after", {})).result(timeout=5)
    assert ok >= 1


def test_data_version_changes_after_write(ledger_store: LedgerStore) -> None:
    before = ledger_store.data_version()
    ledger_store.submit(LedgerStore.insert_lineage_event("l", "x", {})).result(timeout=5)
    ledger_store.read("SELECT 1")
    assert ledger_store.data_version() != before


async def test_facade_degrades_to_null_and_treats_pin_as_unknown(ledger_store: LedgerStore) -> None:
    class Broken(SqliteLedgerProvider):
        async def read_lineage_events(self, lineage: LineageId, event_type: str | None = None):  # type: ignore[override]
            raise RuntimeError("disk gone")

        async def append_decision(self, decision: Decision, context):  # type: ignore[override,no-untyped-def]
            raise RuntimeError("disk gone")

    facade = MemoryFacade(Broken(ledger_store), fallback=NullProvider())
    assert await facade.append_decision(_decision(), _CONTEXT) is False
    assert facade.degraded and facade.degraded_count == 1
    lookup = await facade.pin_state(LineageId("l"))
    assert lookup.effective_pinned


async def test_facade_pin_state_reads_lineage_events(ledger_store: LedgerStore) -> None:
    from adrl.core.ports import LineageEvent

    facade = MemoryFacade(SqliteLedgerProvider(ledger_store))
    lineage = LineageId("lin")
    assert not (await facade.pin_state(lineage)).effective_pinned
    await facade.append_lineage_event(LineageEvent(lineage, "pinned", {"finding_id": "f1"}))
    assert (await facade.pin_state(lineage)).effective_pinned
    await facade.append_lineage_event(LineageEvent(lineage, "released", {"finding_id": "f1"}))
    assert not (await facade.pin_state(lineage)).effective_pinned
    await facade.append_lineage_event(LineageEvent(lineage, "pinned", {"finding_id": "f2"}))
    assert (await facade.pin_state(lineage)).effective_pinned
