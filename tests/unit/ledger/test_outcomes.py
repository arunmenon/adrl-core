"""Outcome lifecycle: close-v1, escalation split, late evidence, human correction (ADRL-MEM-002)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from adrl.config.models import CloseRule
from adrl.core.enums import FailureType, OutcomeState, Rung
from adrl.core.ids import mint_route_id
from adrl.ledger.events import (
    EPISODE_BOUNDARY_EVENT,
    LABEL_CORRECTION_EVENT,
    LATE_EVIDENCE_EVENT,
    OUTCOME_EVENT,
    CauseCandidate,
    read_stored_events,
)
from adrl.ledger.outcomes import (
    Closer,
    HumanCorrectionDetector,
    append_late_evidence,
    current_label,
    measure_closing,
    read_projection,
    routes_in_state,
)
from adrl.ledger.store import LedgerStore
from tests.unit.ledger.conftest import write_decision, write_outcome

RULE = CloseRule(subsequent_turns=3, idle_minutes=30)


async def test_close_v1_emits_closed_final_with_rule_id_after_n_turns(
    ledger_store: LedgerStore,
) -> None:
    rid = write_decision(ledger_store, session="s1")
    write_outcome(ledger_store, rid, OutcomeState.PENDING, producer_seq=1, session="s1")
    write_outcome(ledger_store, rid, OutcomeState.CLOSED_TURN, producer_seq=2, session="s1")
    closer = Closer(ledger_store, RULE)
    assert await closer.scan() == []
    for _ in range(3):
        write_decision(ledger_store, session="s1")
    closed = await closer.scan()
    assert closed == [(rid, "subsequent_turns")]
    projection = read_projection(ledger_store, rid)
    assert projection.state is OutcomeState.CLOSED_FINAL
    assert projection.closed_final_rule_id == "close-v1"
    assert await closer.scan() == []


async def test_close_v1_idle_and_episode_boundary_triggers(ledger_store: LedgerStore) -> None:
    idle = write_decision(ledger_store, session="s2", lineage="l2")
    write_outcome(
        ledger_store, idle, OutcomeState.CLOSED_TURN, producer_seq=2, session="s2", lineage="l2"
    )
    closer = Closer(ledger_store, RULE)
    later = datetime.now(UTC) + timedelta(minutes=31)
    assert await closer.scan(now=later) == [(idle, "idle")]

    boundary = write_decision(ledger_store, session="s3", lineage="l3")
    write_outcome(
        ledger_store, boundary, OutcomeState.CLOSED_TURN, producer_seq=2, session="s3", lineage="l3"
    )
    ledger_store.submit(
        LedgerStore.insert_lineage_event("l3", EPISODE_BOUNDARY_EVENT, {"signal": "clear"})
    ).result(timeout=5)
    assert await closer.scan() == [(boundary, "episode_boundary")]


async def test_local_attempt_closes_as_capability_failure_and_frontier_is_separate_route(
    ledger_store: LedgerStore,
) -> None:
    local = write_decision(ledger_store, session="s4", rung=Rung.LOCAL)
    frontier = mint_route_id()
    write_outcome(
        ledger_store,
        local,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        session="s4",
        causes=[CauseCandidate(FailureType.TASK_CAPABILITY, 3, "loop")],
        extra={"escalated_to_route_id": str(frontier)},
    )
    write_decision(ledger_store, session="s4", rung=Rung.FRONTIER, route_id=frontier)
    write_outcome(
        ledger_store,
        frontier,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        session="s4",
        harness_reported_success=True,
    )
    closer = Closer(ledger_store, CloseRule(subsequent_turns=1, idle_minutes=30))
    for _ in range(1):
        write_decision(ledger_store, session="s4")
    closed = dict(await closer.scan())
    assert set(closed) == {local, frontier}
    local_label = current_label(ledger_store, local)
    assert local_label.result == "failure"
    assert local_label.failure_type is FailureType.TASK_CAPABILITY
    assert current_label(ledger_store, frontier).result == "success"
    assert read_projection(ledger_store, frontier).route_id != local


async def test_late_evidence_after_closed_final_flips_label_and_supersedes(
    ledger_store: LedgerStore,
) -> None:
    rid = write_decision(ledger_store, session="s5")
    write_outcome(
        ledger_store,
        rid,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        session="s5",
        harness_reported_success=True,
    )
    closer = Closer(ledger_store, RULE)
    await closer.scan(now=datetime.now(UTC) + timedelta(hours=1))
    assert current_label(ledger_store, rid).result == "success"
    label = await append_late_evidence(
        ledger_store,
        rid,
        source="revert",
        detail={"kind": "git_revert"},
        causes=[CauseCandidate(FailureType.TASK_CAPABILITY, 9, "revert")],
    )
    assert label.result == "failure" and label.failure_type is FailureType.TASK_CAPABILITY
    events = read_stored_events(ledger_store, rid)
    assert any(e.event_type == LATE_EVIDENCE_EVENT for e in events)
    corrections = [e for e in events if e.event_type == LABEL_CORRECTION_EVENT]
    assert corrections and corrections[-1].payload["supersedes_seq"] is not None
    measurements = measure_closing(ledger_store)
    assert measurements.closed_final_count == 1
    assert measurements.label_flip_fraction == 1.0
    assert measurements.median_seconds is not None and measurements.median_seconds >= 0


async def test_human_correction_detector_emits_late_evidence(ledger_store: LedgerStore) -> None:
    rid = write_decision(ledger_store, session="s6")
    write_outcome(
        ledger_store,
        rid,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        session="s6",
        touched_paths=["p1", "p2"],
    )
    other = write_decision(ledger_store, session="s6")
    write_outcome(
        ledger_store,
        other,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        session="s6",
        touched_paths=["p2"],
    )
    detector = HumanCorrectionDetector(ledger_store, window_minutes=30)
    hits = detector.find(rid)
    assert hits and hits[0]["overlap"] == ["p2"] and hits[0]["kind"] == "re_edit"
    assert await detector.emit(rid) == 1
    assert await detector.emit(rid) == 1
    assert len(read_stored_events(ledger_store, rid, LATE_EVIDENCE_EVENT)) == 1
    assert routes_in_state(ledger_store, OutcomeState.CLOSED_TURN)
    assert not [
        e
        for e in read_stored_events(ledger_store, rid, OUTCOME_EVENT)
        if e.payload.get("state") == "closed_final"
    ]
