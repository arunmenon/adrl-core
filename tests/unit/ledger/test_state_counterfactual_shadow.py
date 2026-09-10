"""State provider durability, counterfactual binding, shadow retrieval (MEM-006/008/009)."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

from adrl.core.enums import OutcomeState, PinLookup, ProjectionState, Rung
from adrl.core.ids import LineageId, RouteId, SessionId, mint_route_id
from adrl.core.ports import StateProvider, StickyState
from adrl.ledger import counterfactual as counterfactual_module
from adrl.ledger.counterfactual import attach_counterfactual
from adrl.ledger.embeddings import EmbeddingWriter, HashingEmbedder
from adrl.ledger.events import COUNTERFACTUAL_EVENT, SHADOW_RETRIEVAL_EVENT, read_stored_events
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.projections import NumpyIndex
from adrl.ledger.shadow_retrieval import ShadowRetriever
from adrl.ledger.state import SqliteStateProvider
from adrl.ledger.store import LedgerStore
from tests.unit.ledger.conftest import write_decision, write_outcome


async def test_state_provider_survives_reopen_and_unknown_is_none(ledger_paths: dict) -> None:  # type: ignore[type-arg]
    store = LedgerStore(ledger_paths["ledger"])
    store.open()
    provider = SqliteStateProvider(store)
    assert isinstance(provider, StateProvider)
    lineage = LineageId("lin-a")
    assert await provider.get_sticky(lineage) is None
    assert await provider.get_pin(lineage) is PinLookup.UNPINNED
    await provider.set_sticky(
        StickyState(
            lineage,
            mint_route_id(),
            Rung.CHEAP_CLOUD,
            True,
            "m",
            "anthropic",
            "gateway_reported",
            3,
            datetime.now(UTC),
        )
    )
    await provider.set_pin(lineage, "f1", "aws_key")
    store.close()

    reopened = LedgerStore(ledger_paths["ledger"])
    reopened.open()
    try:
        fresh = SqliteStateProvider(reopened)
        assert await fresh.load_all() == 2
        sticky = await fresh.get_sticky(lineage)
        assert sticky is not None and sticky.rung is Rung.CHEAP_CLOUD and sticky.escalated
        assert not sticky.state_loss
        assert await fresh.get_pin(lineage) is PinLookup.PINNED
        assert await fresh.get_sticky(LineageId("never-seen")) is None
        assert await fresh.get_pin(LineageId("never-seen")) is PinLookup.UNPINNED
    finally:
        reopened.close()


async def test_counterfactual_binds_only_to_persisted_route(ledger_store: LedgerStore) -> None:
    unknown = mint_route_id()
    receipt = await attach_counterfactual(ledger_store, unknown, "pair-1", {"arm": "frontier"})
    assert not receipt.attached and receipt.reason == "route_id_not_persisted"
    rid = write_decision(ledger_store)
    ok = await attach_counterfactual(
        ledger_store, rid, "pair-1", {"arm": "frontier", "verified": "pass"}
    )
    assert ok.attached
    dup = await attach_counterfactual(ledger_store, rid, "pair-1", {"arm": "frontier"})
    assert not dup.attached and dup.reason == "duplicate"
    events = read_stored_events(ledger_store, rid, COUNTERFACTUAL_EVENT)
    assert len(events) == 1 and events[0].payload["tier"] == "T5"
    sub = await attach_counterfactual(ledger_store, rid, "pair-2", {"subagent": True})
    assert sub.reason == "subagent_excluded"
    source = inspect.getsource(counterfactual_module)
    assert (
        "latest" not in source.lower().replace("latest non", "")
        and "most recent" not in source.lower()
    )


async def test_shadow_retrieval_writes_only_to_ledger(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    embedder = HashingEmbedder(16)
    writer = EmbeddingWriter(ledger_store, keystore, embedder)
    neighbour = write_decision(ledger_store, session="s1", rung=Rung.LOCAL)
    await writer.write(neighbour, SessionId("s1"), "rename a variable", pinned=False)
    write_outcome(
        ledger_store,
        neighbour,
        OutcomeState.CLOSED_FINAL,
        producer_seq=3,
        session="s1",
        harness_reported_success=True,
    )
    index = NumpyIndex(ledger_store, keystore, embedder.embedder_version)
    index.rebuild()
    retriever = ShadowRetriever(ledger_store, index, k=3)
    query = write_decision(ledger_store, session="s2")
    advice = await retriever.advise(query, embedder.embed(["rename a variable"])[0])
    assert not advice.abstained and advice.neighbours[0].route_id == neighbour
    assert advice.neighbour_local_success_rate is None
    events = read_stored_events(ledger_store, query, SHADOW_RETRIEVAL_EVENT)
    assert len(events) == 1 and events[0].payload["projection_state"] == "valid"
    assert 0.0 < retriever.suppressed_fraction() < 1.0
    await erase_session_s1(ledger_store, keystore)
    assert index.state() is ProjectionState.INVALID
    abstained = await retriever.advise(query, embedder.embed(["x"])[0])
    assert abstained.abstained and abstained.reason == "projection_invalid"


async def erase_session_s1(store: LedgerStore, keystore: FileKeyStore) -> None:
    from adrl.ledger.erasure import ErasureService

    await ErasureService(store, keystore).erase_session(SessionId("s1"), "test")


def test_route_ids_are_strings() -> None:
    assert isinstance(RouteId("x"), str)
