"""Events, upcasting, label derivation, censoring and readiness (ADRL-MEM-001/002/004)."""

from __future__ import annotations

import sqlite3

import pytest

from adrl.core.enums import FailureType, OutcomeState
from adrl.core.ids import mint_route_id
from adrl.core.types import LedgerEvent
from adrl.ledger.events import (
    OUTCOME_EVENT,
    PRODUCER_CASCADE,
    CauseCandidate,
    ProducerSequencer,
    producer_seq_for,
    read_stored_events,
)
from adrl.ledger.labels import derive_label, is_countable
from adrl.ledger.readiness import learning_readiness
from adrl.ledger.store import LedgerStore
from adrl.ledger.upcast import upcast_payload
from tests.unit.ledger.conftest import write_decision, write_outcome


def test_producer_seq_is_stable_and_sequencer_monotonic() -> None:
    assert producer_seq_for("close-v1") == producer_seq_for("close-v1")
    assert producer_seq_for("close-v1") != producer_seq_for("close-v2")
    seq = ProducerSequencer()
    rid = mint_route_id()
    assert [seq.next("p", rid), seq.next("p", rid)] == [1, 2]
    seq.observe("p", rid, 10)
    assert seq.next("p", rid) == 11


def test_duplicate_outcome_replay_yields_one_event(ledger_store: LedgerStore) -> None:
    rid = write_decision(ledger_store)
    write_outcome(ledger_store, rid, OutcomeState.PENDING, producer_seq=1)
    write_outcome(ledger_store, rid, OutcomeState.PENDING, producer_seq=1)
    assert len(read_stored_events(ledger_store, rid, OUTCOME_EVENT)) == 1


def test_no_update_or_delete_reaches_the_ledger(ledger_store: LedgerStore) -> None:
    with pytest.raises(sqlite3.OperationalError):
        ledger_store.read("DELETE FROM events")
    from adrl.ledger.state import SqliteStateProvider

    assert not [m for m in dir(SqliteStateProvider) if m.startswith(("update", "delete"))]


def test_failure_types_v1_upcasts_to_v2() -> None:
    v1 = {
        "failure_types_version": "failure-types-v1",
        "failure_type": "dialect",
        "causes": [{"failure_type": "difficulty"}, {"failure_type": "policy_constraint"}],
    }
    out = upcast_payload(v1)
    assert out["failure_type"] == FailureType.HARNESS_DIALECT.value
    assert [c["failure_type"] for c in out["causes"]] == ["task_capability", "policy_constraint"]
    assert out["failure_types_version"] == "failure-types-v2"
    unknown = upcast_payload({"failure_type": "gremlins"})
    assert unknown["failure_type"] == "unverifiable"
    label = upcast_payload({"label": {"failure_type": "quality"}, "failure_types_version": "x"})
    assert label["label"]["failure_type"] == "user_abort"


def test_label_without_tripwire_or_verifier_is_unverifiable(ledger_store: LedgerStore) -> None:
    rid = write_decision(ledger_store)
    write_outcome(ledger_store, rid, OutcomeState.CLOSED_TURN, producer_seq=2)
    label = derive_label(read_stored_events(ledger_store, rid))
    assert label.failure_type is FailureType.UNVERIFIABLE
    assert label.result == "excluded" and label.label_confidence == 0.0


def test_precedence_first_occurring_cause_is_primary(ledger_store: LedgerStore) -> None:
    rid = write_decision(ledger_store)
    write_outcome(
        ledger_store,
        rid,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        causes=[
            CauseCandidate(FailureType.TASK_CAPABILITY, 5, "verifier"),
            CauseCandidate(FailureType.HARNESS_DIALECT, 2, "edit_apply"),
        ],
    )
    label = derive_label(read_stored_events(ledger_store, rid))
    assert label.failure_type is FailureType.HARNESS_DIALECT
    assert label.secondary_type is FailureType.TASK_CAPABILITY
    assert label.basis == "tripwire" and label.source_event_id is not None


def test_precedence_without_action_index_uses_cas002_order() -> None:
    events = [
        LedgerEvent(
            mint_route_id(),
            OUTCOME_EVENT,
            PRODUCER_CASCADE,
            1,
            {
                "state": "closed_turn",
                "causes": [{"failure_type": "task_capability"}, {"failure_type": "infrastructure"}],
            },
        )
    ]
    from adrl.ledger.events import StoredEvent

    label = derive_label([StoredEvent(1, "2026-01-01T00:00:00+00:00", events[0])])
    assert label.failure_type is FailureType.INFRASTRUCTURE
    assert label.result == "excluded"


def test_closed_turn_is_censored_and_readiness_counts_only_capability(
    ledger_store: LedgerStore,
) -> None:
    open_route = write_decision(ledger_store)
    write_outcome(ledger_store, open_route, OutcomeState.CLOSED_TURN, producer_seq=2)
    assert not is_countable(read_stored_events(ledger_store, open_route))

    capability = write_decision(ledger_store, session="s2")
    write_outcome(
        ledger_store,
        capability,
        OutcomeState.CLOSED_FINAL,
        producer_seq=3,
        causes=[CauseCandidate(FailureType.TASK_CAPABILITY, 1, "loop")],
    )
    infra = write_decision(ledger_store, session="s3")
    write_outcome(
        ledger_store,
        infra,
        OutcomeState.CLOSED_FINAL,
        producer_seq=3,
        causes=[CauseCandidate(FailureType.INFRASTRUCTURE, 1, "gateway")],
    )
    report = learning_readiness(ledger_store)
    assert report.censored_count == 1
    assert report.closed_final_count == 2
    assert report.capability_evidence_count == 1
    assert report.excluded_by_type == {"infrastructure": 1}
    assert report.excluded_fraction == 0.5
    assert not report.window_blocked
