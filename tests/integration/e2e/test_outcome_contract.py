"""ADRL-MEM-002: persisted cascade outcomes reach the canonical lifecycle consumers.

Synthetic ASGI transport only. The shared E2E fixture loads SHADOW configuration into
LIVE components; these tests do not qualify live configuration admission or real traffic.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from adrl.cascade.controller import CascadeController
from adrl.cascade.sticky import MemoryStateProvider
from adrl.config.models import CloseRule
from adrl.core.enums import FailureType, OutcomeState
from adrl.core.ids import RouteId
from adrl.core.types import LedgerEvent
from adrl.ledger.events import OUTCOME_EVENT, read_stored_events
from adrl.ledger.outcomes import Closer, read_projection, routes_in_state
from adrl.ledger.readiness import learning_readiness
from adrl.ledger.store import LedgerStore
from adrl.proxy.pipeline import _Turn
from adrl.telemetry.metrics import EVENT_DROPPED_TOTAL
from adrl.wire.observe import ResponseObservation
from tests.unit.routing.helpers import make_ctx, make_gate, make_obs, user_body

from .conftest import E2E, user_turn_body


async def test_composed_outcomes_close_once_without_inventing_success(live: E2E) -> None:
    await live.send("user_turn", body=user_turn_body("Fix the typo in README.md"))
    first = RouteId(live.decisions()[0]["route_id"])
    await live.send("user_turn", body=user_turn_body("Fix another typo in README.md"))
    second = RouteId(live.decisions()[1]["route_id"])
    assert [e.route_id for e in routes_in_state(live.store, OutcomeState.CLOSED_TURN)] == [first]
    events = read_stored_events(live.store, first, OUTCOME_EVENT)
    assert [e.payload["state"] for e in events] == ["pending", "closed_turn"]
    assert all(
        e.event.producer == "cascade" and e.event.schema_version == "events-v1" for e in events
    )
    assert [e.event.producer_seq for e in events] == [1, 2]
    assert all(e.payload.get("harness_reported_success") is None for e in events)
    assert events[-1].payload["session_hmac"] == live.decisions()[0]["session_hmac"]
    assert read_projection(live.store, second).state is OutcomeState.PENDING
    closer = Closer(live.store, CloseRule(subsequent_turns=100, idle_minutes=30))
    future = datetime.now(UTC) + timedelta(days=1)
    assert await closer.scan(now=future) == [(first, "idle")]
    assert await closer.scan(now=future) == []
    projected = read_projection(live.store, first)
    assert projected.state is OutcomeState.CLOSED_FINAL
    assert projected.label.failure_type is FailureType.UNVERIFIABLE
    assert projected.label.result == "excluded"
    assert len(live.store.read_events(first, "label")) == 1
    readiness = learning_readiness(live.store)
    assert readiness.closed_final_count == 1
    assert readiness.censored_count == 1
    assert readiness.capability_evidence_count == readiness.verified_success_count == 0
    assert readiness.window_blocked and "no_capability_evidence" in readiness.blockers


@pytest.mark.parametrize(
    "status,cause", [(503, FailureType.INFRASTRUCTURE), (400, FailureType.INFRASTRUCTURE)]
)
async def test_terminal_cause_survives_next_turn_and_close(
    live: E2E, status: int, cause: FailureType
) -> None:
    live.gateway_state.status_code = status
    response = await live.send("user_turn")
    assert response.status_code == status
    first = RouteId(live.decisions()[0]["route_id"])
    assert read_projection(live.store, first).state is OutcomeState.CLOSED_TURN
    live.gateway_state.status_code = 200
    await live.send("user_turn", body=user_turn_body("Fix the typo in README.md"))
    closed = [
        e
        for e in read_stored_events(live.store, first, OUTCOME_EVENT)
        if e.payload["state"] == "closed_turn"
    ]
    assert len(closed) == 2
    assert closed[0].payload["failure_type"] == cause.value
    assert closed[-1].payload["reason"] == "next_user_turn"
    await Closer(live.store, CloseRule(subsequent_turns=100, idle_minutes=30)).scan(
        now=datetime.now(UTC) + timedelta(days=1)
    )
    label = read_projection(live.store, first).label
    assert label.result == "excluded" and label.failure_type is cause
    assert learning_readiness(live.store).capability_evidence_count == 0


async def test_completed_400_stays_unverifiable(live: E2E) -> None:
    controller = CascadeController(
        live.components.bundle, MemoryStateProvider(), ledger=live.components.facade
    )
    ctx = make_ctx(user_body())
    decision = await live.components.router.decide(ctx, make_gate(), None)
    plan = await controller.plan(ctx, decision, make_gate(), None)
    await controller.observe(ctx, plan, make_obs(status=400, completed=True))
    projected = read_projection(live.store, decision.route_id)
    assert projected.state is OutcomeState.CLOSED_TURN
    assert projected.label.failure_type is FailureType.UNVERIFIABLE
    assert not projected.label.is_capability_evidence


@pytest.mark.parametrize("forwarded", [False, True])
async def test_continuation_terminal_event_preserves_identity(
    live: E2E, monkeypatch: pytest.MonkeyPatch, forwarded: bool
) -> None:
    await live.send("user_turn")
    route = RouteId(live.decisions()[0]["route_id"])
    finalize = live.components.pipeline._finalize
    different_route = RouteId("different-current-decision")
    assert different_route != route

    async def divergent_finalization(turn: _Turn, obs: ResponseObservation) -> None:
        assert turn.plan.route_id == route
        # Force divergence at the stage boundary: ordinary continuations inherit identity.
        altered = replace(turn, decision=replace(turn.decision, route_id=different_route))
        assert altered.decision.route_id != altered.plan.route_id
        await finalize(altered, obs)

    monkeypatch.setattr(live.components.pipeline, "_finalize", divergent_finalization)
    if forwarded:
        # Only observe-phase fallback is supported; plan-phase persistence requires a ledger.
        monkeypatch.setattr(live.components.cascade, "_ledger", None)
    live.gateway_state.status_code = 503
    await live.send("continuation")
    closed = routes_in_state(live.store, OutcomeState.CLOSED_TURN)
    assert len(closed) == 1 and closed[0].route_id == route
    assert closed[0].event.producer == "cascade"
    assert closed[0].event.producer_seq == 2
    assert closed[0].event.schema_version == "events-v1"
    assert closed[0].payload["failure_type"] == "infrastructure"


async def test_restart_sequence_includes_legacy_events(live: E2E) -> None:
    ctx = make_ctx(user_body())
    decision = await live.components.router.decide(ctx, make_gate(), None)
    legacy = LedgerEvent(decision.route_id, "pending", "cascade", 77, {"legacy": True})
    await live.components.facade.append_event(legacy)
    controller = CascadeController(
        live.components.bundle, MemoryStateProvider(), ledger=live.components.facade
    )
    await controller.plan(ctx, decision, make_gate(), None)
    events = read_stored_events(live.store, decision.route_id)
    assert events[0].event == legacy
    assert events[-1].event_type == OUTCOME_EVENT
    assert events[-1].event.producer_seq == 78
    assert events[-1].payload["state"] == "pending"


async def test_legacy_only_route_is_absent_from_readiness(live: E2E) -> None:
    route = RouteId("legacy-only")
    await live.components.facade.append_event(
        LedgerEvent(route, "closed_turn", "cascade", 1, {"reason": "historical"})
    )
    assert routes_in_state(live.store, OutcomeState.CLOSED_TURN) == []
    report = learning_readiness(live.store)
    assert report.closed_final_count == report.censored_count == 0
    assert read_projection(live.store, route).state is None


@pytest.mark.parametrize("trigger", ["subsequent_turns", "episode_boundary"])
async def test_context_identity_enables_closing_triggers(live: E2E, trigger: str) -> None:
    await live.send("user_turn")
    first = RouteId(live.decisions()[0]["route_id"])
    await live.send("user_turn", body=user_turn_body("Fix another typo"))
    if trigger == "subsequent_turns":
        await live.send("user_turn", body=user_turn_body("Fix a third typo"))
    else:
        await live.store.write_through(
            LedgerStore.insert_lineage_event(
                live.decisions()[0]["lineage_hmac"], "episode_boundary", {"signal": "clear"}
            )
        )
    rule = CloseRule(
        subsequent_turns=1 if trigger == "subsequent_turns" else 100, idle_minutes=10000
    )
    closed = await Closer(live.store, rule).scan()
    assert (first, trigger) in closed


async def test_dropped_forwarded_event_is_observable(
    live: E2E, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    await live.send("user_turn")
    monkeypatch.setattr(live.components.cascade, "_ledger", None)
    append = live.components.facade.append_event

    async def reject_outcome(event: LedgerEvent) -> bool:
        if event.event_type == OUTCOME_EVENT and event.producer == "cascade":
            return False
        return await append(event)

    monkeypatch.setattr(live.components.facade, "append_event", reject_outcome)
    metric = EVENT_DROPPED_TOTAL.labels(producer="cascade")
    before = metric._value.get()
    live.gateway_state.status_code = 503
    await live.send("continuation")
    assert metric._value.get() == before + 1
    output = capsys.readouterr().out
    assert "event_dropped" in output and "finalize_failed" not in output
