"""Prompt-class artefacts: keyed hashes, encryption, shredding, projections (MEM-005/007/010)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np

from adrl.config.models import PolicyConfig
from adrl.core.enums import ProjectionState
from adrl.core.ids import LineageId, RouteId, SessionId, mint_route_id
from adrl.ledger.embeddings import (
    EmbeddingWriter,
    HashingEmbedder,
    InstructionHasher,
    embedding_row_count,
    read_vectors,
)
from adrl.ledger.erasure import ErasureService
from adrl.ledger.events import ERASED_EVENT
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.projections import NumpyIndex
from adrl.ledger.replay import replay
from adrl.ledger.retention import RetentionSweeper
from adrl.ledger.store import LedgerStore
from tests.unit.ledger.conftest import write_decision

EMBEDDER = HashingEmbedder(32)


async def _embed_turns(
    store: LedgerStore, keystore: FileKeyStore, session: str, count: int, lineage: str = "lin"
) -> list[RouteId]:
    writer = EmbeddingWriter(store, keystore, EMBEDDER)
    routes: list[RouteId] = []
    for i in range(count):
        rid = write_decision(store, session=session, lineage=lineage)
        assert await writer.write(rid, SessionId(session), f"edit file number {i}", pinned=False)
        routes.append(rid)
    return routes


def test_keyed_hashes_differ_across_hosts(ledger_store: LedgerStore, tmp_path: Path) -> None:
    host_a = FileKeyStore(tmp_path / "a")
    host_b = FileKeyStore(tmp_path / "b")
    digest_a, key_a = InstructionHasher(ledger_store, host_a).hash("fix the failing test")
    digest_b, key_b = InstructionHasher(ledger_store, host_b).hash("fix the failing test")
    assert digest_a != digest_b and key_a != key_b
    assert InstructionHasher(ledger_store, host_a).hash("fix the failing test")[0] == digest_a
    old, new = host_a.rotate_hmac_key()
    assert old == key_a and new != old


async def test_pinned_and_private_turns_get_no_artefacts(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    writer = EmbeddingWriter(ledger_store, keystore, EMBEDDER)
    rid = write_decision(ledger_store, session="p")
    assert not await writer.write(rid, SessionId("p"), "secret stuff", pinned=True)
    assert not await writer.write(rid, SessionId("p"), "secret stuff", pinned=False, private=True)
    hasher = InstructionHasher(ledger_store, keystore)
    assert await hasher.write(rid, SessionId("p"), "secret", pinned=True) is None
    assert embedding_row_count(ledger_store, SessionId("p")) == 0
    assert not keystore.has_session_key(SessionId("p"))


async def test_pin_at_turn_four_shreds_turns_one_to_three_and_rebuilds_index(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    routes = await _embed_turns(ledger_store, keystore, "s1", 3, lineage="lin1")
    other = await _embed_turns(ledger_store, keystore, "s2", 2, lineage="lin2")
    index = NumpyIndex(ledger_store, keystore, EMBEDDER.embedder_version)
    index.rebuild()
    assert index.size == 5 and index.state() is ProjectionState.VALID

    erasure = ErasureService(ledger_store, keystore)
    shredded = await erasure.suppress(LineageId("lin1"), SessionId("s1"), "privacy_pin")
    assert shredded == 3
    assert index.state() is ProjectionState.INVALID
    assert not keystore.has_session_key(SessionId("s1"))
    assert embedding_row_count(ledger_store, SessionId("s1")) == 3
    readable = read_vectors(ledger_store, keystore)
    assert {v.route_id for v in readable} == set(other)
    assert not any(r in {v.route_id for v in readable} for r in routes)

    index.refresh()
    assert index.size == 2 and index.state() is ProjectionState.VALID
    assert set(index.route_ids) == set(other)
    writer = EmbeddingWriter(ledger_store, keystore, EMBEDDER)
    rid = write_decision(ledger_store, session="s1", lineage="lin1")
    assert not await writer.write(rid, SessionId("s1"), "after the pin", pinned=False)
    erased = ledger_store.read_lineage_events("s1", ERASED_EVENT)
    assert len(erased) == 1
    assert await erasure.suppress_lineage(LineageId("lin1"), SessionId("s1"), "privacy_pin") is None


async def test_incremental_refresh_equals_full_rebuild(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    await _embed_turns(ledger_store, keystore, "s1", 4)
    incremental = NumpyIndex(ledger_store, keystore, EMBEDDER.embedder_version)
    incremental.rebuild()
    await _embed_turns(ledger_store, keystore, "s2", 3)
    await ErasureService(ledger_store, keystore).erase_session(SessionId("s1"), "test")
    await _embed_turns(ledger_store, keystore, "s3", 2)
    assert incremental.state() is ProjectionState.INVALID
    incremental.refresh()
    full = NumpyIndex(ledger_store, keystore, EMBEDDER.embedder_version)
    full.rebuild()
    assert incremental.equivalent(full)
    assert incremental.stamp == full.stamp
    assert np.allclose(incremental.vectors(), full.vectors())
    assert incremental.size == 5


async def test_as_of_rebuild_excludes_later_routes(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    first = await _embed_turns(ledger_store, keystore, "s1", 2)
    index = NumpyIndex(ledger_store, keystore, EMBEDDER.embedder_version)
    stamp = index.rebuild()
    later = await _embed_turns(ledger_store, keystore, "s1", 2)
    as_of = NumpyIndex(ledger_store, keystore, EMBEDDER.embedder_version)
    as_of.rebuild(as_of_seq=stamp.high_water_seq)
    assert set(as_of.route_ids) == set(first)
    assert not set(as_of.route_ids) & set(later)
    assert index.state() is ProjectionState.STALE
    neighbours = index.query(EMBEDDER.embed(["edit file number 0"])[0], k=1)
    assert neighbours and neighbours[0].route_id == first[0]


async def test_second_process_write_is_detected_as_stale(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    await _embed_turns(ledger_store, keystore, "s1", 1)
    index = NumpyIndex(ledger_store, keystore, EMBEDDER.embedder_version)
    index.rebuild()
    assert not index.ledger_changed()
    other_process = LedgerStore(ledger_store.path)
    other_process.open()
    try:
        writer = EmbeddingWriter(other_process, keystore, EMBEDDER)
        rid = write_decision(other_process, session="s1")
        assert await writer.write(rid, SessionId("s1"), "from another process", pinned=False)
    finally:
        other_process.close()
    assert index.ledger_changed()
    assert index.state() is ProjectionState.STALE
    await index.persist_stamp()
    assert (
        NumpyIndex.stored_stamp_state(ledger_store, EMBEDDER.embedder_version)
        is ProjectionState.STALE
    )
    assert NumpyIndex.stored_stamp_state(ledger_store, "other-embedder") is ProjectionState.INVALID


async def test_retention_sweep_only_appends_and_removes_keys(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    await _embed_turns(ledger_store, keystore, "old", 2)
    policy = PolicyConfig.model_validate(
        {
            "version": "policy-test",
            "tau_by_rung": {"local": 0.8, "cheap_cloud": 0.85, "frontier": 0.5},
            "bands": [],
            "objective_version": "objective-v1",
            "objective_weights": {
                "verified_quality": 1,
                "retry_risk": 0,
                "latency": 0,
                "session_cost": 0,
            },
            "retention_prompt_class_days": 90,
            "retention_skeleton_days": 730,
        }
    )
    sweeper = RetentionSweeper(ledger_store, keystore, policy)
    before = ledger_store.read("SELECT COUNT(*) AS c FROM embeddings")[0]["c"]
    report_now = await sweeper.sweep()
    assert report_now.erased == ()
    report = await sweeper.sweep(now=datetime.now(UTC) + timedelta(days=91))
    assert [r.session_hmac for r in report.erased] == ["old"]
    assert report.skeleton_expired_routes == 0
    after = ledger_store.read("SELECT COUNT(*) AS c FROM embeddings")[0]["c"]
    assert after == before
    assert ledger_store.read_lineage_events("old", ERASED_EVENT)
    assert not keystore.has_session_key(SessionId("old"))
    audit = [
        str(r["action"])
        for r in ledger_store.read(
            "SELECT action FROM session_keys WHERE session_hmac='old' ORDER BY seq"
        )
    ]
    assert audit == ["created", "shredded"]


async def test_replay_is_idempotent_and_reports_timing(
    ledger_store: LedgerStore, keystore: FileKeyStore
) -> None:
    await _embed_turns(ledger_store, keystore, "s1", 3)
    first = await replay(ledger_store, keystore, EMBEDDER.embedder_version)
    second = await replay(ledger_store, keystore, EMBEDDER.embedder_version)
    assert first.index_rows == second.index_rows == 3
    assert first.stamp == second.stamp and first.seconds >= 0
    assert second.summary()["routes"] == 0
    assert (await replay(ledger_store, keystore, EMBEDDER.embedder_version)).index_rows == 3


def test_hashing_embedder_is_deterministic_and_normalised() -> None:
    a, b = EMBEDDER.embed(["read file x", "read file x"])
    assert a == b and abs(float(np.linalg.norm(a)) - 1.0) < 1e-9
    assert EMBEDDER.dimension == 32 and EMBEDDER.embedder_version.startswith("hashing-test-v1")


def test_mint_route_id_sorts_with_time() -> None:
    assert mint_route_id(1) < mint_route_id(2)
