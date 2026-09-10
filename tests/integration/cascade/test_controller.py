"""CAS-003/005/006/007/008 controller flows against the SQLite ledger."""

from __future__ import annotations

import json

import pytest

from adrl.cascade.controller import ESCALATION_EVENT, CascadeController
from adrl.cascade.sticky import MemoryStateProvider
from adrl.core.enums import (
    EpisodeSignal,
    FailureType,
    OutcomeState,
    RequestClass,
    Rung,
    ServedSource,
)
from adrl.core.errors import ErrorCode
from adrl.core.ids import LineageId
from adrl.core.types import PermittedSet
from adrl.ledger.events import OUTCOME_EVENT
from adrl.ledger.facade import SqliteLedgerProvider
from adrl.ledger.store import LedgerStore
from adrl.routing.router import Router
from tests.unit.routing.helpers import LINEAGE, make_ctx, make_gate, make_obs, tool_turn, user_body


@pytest.fixture
def ledger(ledger_store: LedgerStore) -> SqliteLedgerProvider:
    return SqliteLedgerProvider(ledger_store)


@pytest.fixture
def controller(bundle, ledger) -> CascadeController:  # type: ignore[no-untyped-def]
    return CascadeController(bundle, MemoryStateProvider(), ledger=ledger)


def _events(store: LedgerStore, event_type: str) -> list[dict]:  # type: ignore[type-arg]
    return [
        json.loads(r["payload_json"])
        for r in store.read(
            "SELECT payload_json FROM events WHERE event_type = ? ORDER BY seq", (event_type,)
        )
    ]


def _looping_continuation(n: int = 3, *, complete: bool = True) -> dict:  # type: ignore[type-arg]
    extra = []
    for i in range(n):
        extra += tool_turn("Read", {"file_path": "a.py"}, "same", idx=i)
    if not complete:
        extra[-1] = {"role": "user", "content": []}
        extra.append(
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_x1",
                        "name": "Read",
                        "input": {"file_path": "b.py"},
                    },
                    {
                        "type": "tool_use",
                        "id": "toolu_x2",
                        "name": "Read",
                        "input": {"file_path": "c.py"},
                    },
                ],
            }
        )
        extra.append(
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_x1", "content": "b"}],
            }
        )
    return user_body("Fix the typo in README.md", extra_messages=extra)


async def test_tripwire_then_escalation_only_at_boundary_and_sticky(
    bundle, controller, ledger_store
) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, make_gate(), None)
    assert decision.rung is Rung.LOCAL
    plan = await controller.plan(turn, decision, make_gate(), None)
    assert plan.rung is Rung.LOCAL and plan.is_boundary and not plan.escalated
    events = await controller.observe(turn, plan, make_obs(rung=Rung.LOCAL))
    assert not events.fired and events.sticky.served_model == "adrl-local/qwen"

    # the model loops: continuation with a partial tool_result set is not a boundary
    partial = make_ctx(_looping_continuation(complete=False), RequestClass.CONTINUATION)
    sticky = events.sticky
    plan2 = await controller.plan(partial, decision, make_gate(), sticky)
    assert not plan2.is_boundary and plan2.rung is Rung.LOCAL
    events2 = await controller.observe(partial, plan2, make_obs(rung=Rung.LOCAL))
    assert events2.fired and events2.escalation_pending
    assert controller.pending_for(LINEAGE) is not None

    # still not a boundary: passthrough on the served rung, no escalation
    plan3 = await controller.plan(partial, decision, make_gate(), events2.sticky)
    assert not plan3.escalated and plan3.rung is Rung.LOCAL

    # boundary: escalation to the next permitted rung with a handoff
    full = make_ctx(_looping_continuation(complete=True), RequestClass.CONTINUATION)
    plan4 = await controller.plan(full, decision, make_gate(), events2.sticky)
    assert plan4.escalated and plan4.from_rung is Rung.LOCAL and plan4.rung is Rung.CHEAP_CLOUD
    assert plan4.handoff is not None and plan4.body is not None
    assert plan4.pair_rule is not None and plan4.pair_rule.source_family == "local"
    assert plan4.sticky.escalated
    escalations = _events(ledger_store, ESCALATION_EVENT)
    assert escalations and escalations[0]["to_rung"] == "cheap_cloud"

    # CAS-005: a later continuation stays escalated; a new user turn with a local decision stays up
    events4 = await controller.observe(full, plan4, make_obs(rung=Rung.CHEAP_CLOUD, model="haiku"))
    plan5 = await controller.plan(full, decision, make_gate(), events4.sticky)
    assert plan5.rung is Rung.CHEAP_CLOUD and not plan5.escalated
    next_turn = make_ctx(user_body("Now fix the second typo"))
    decision2 = await router.decide(next_turn, make_gate(), events4.sticky)
    plan6 = await controller.plan(next_turn, decision2, make_gate(), events4.sticky)
    assert plan6.rung is Rung.CHEAP_CLOUD
    closed = [
        e
        for e in _events(ledger_store, OUTCOME_EVENT)
        if e["state"] == OutcomeState.CLOSED_TURN.value
    ]
    assert closed and closed[-1]["reason"] == "next_user_turn"

    # SEM-005 boundary releases the ratchet only; the next decision decides afresh
    released = await controller.episode_boundary(LINEAGE, EpisodeSignal.CLEAR)
    assert released is not None and not released.escalated
    plan7 = await controller.plan(next_turn, decision2, make_gate(), released)
    assert plan7.rung is decision2.rung


async def test_pinned_lineage_never_escalates(bundle, controller) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    gate = make_gate(pinned=True)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, gate, None)
    plan = await controller.plan(turn, decision, gate, None)
    events = await controller.observe(turn, plan, make_obs(rung=Rung.LOCAL))
    full = make_ctx(_looping_continuation(), RequestClass.CONTINUATION)
    plan2 = await controller.plan(full, decision, gate, events.sticky)
    events2 = await controller.observe(full, plan2, make_obs(rung=Rung.LOCAL))
    assert events2.fired and not events2.escalation_pending
    plan3 = await controller.plan(full, decision, gate, events2.sticky)
    assert not plan3.escalated and plan3.rung is Rung.LOCAL


async def test_mid_episode_pin_precedes_stickiness(bundle, controller, ledger_store) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    turn = make_ctx(user_body("Refactor the whole payments module"))
    decision = await router.decide(turn, make_gate(), None)
    assert decision.rung is Rung.FRONTIER
    plan = await controller.plan(turn, decision, make_gate(), None)
    events = await controller.observe(turn, plan, make_obs(rung=Rung.FRONTIER, model="claude-x"))
    pinned = make_gate(pinned=True)
    cont = make_ctx(_looping_continuation(1), RequestClass.CONTINUATION)
    plan2 = await controller.plan(cont, decision, pinned, events.sticky)
    assert plan2.rung is Rung.LOCAL and plan2.policy_constrained
    constraints = _events(ledger_store, "policy_constraint")
    assert constraints and constraints[0]["reason"] == "gate_precedes_stickiness"


async def test_within_rung_model_change_is_infrastructure_and_assumed_identity_is_unverifiable(
    bundle, controller, ledger_store
) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, make_gate(), None)
    plan = await controller.plan(turn, decision, make_gate(), None)
    events = await controller.observe(turn, plan, make_obs(rung=Rung.LOCAL, model="qwen-a"))
    cont = make_ctx(_looping_continuation(1), RequestClass.CONTINUATION)
    plan2 = await controller.plan(cont, decision, make_gate(), events.sticky)
    events2 = await controller.observe(cont, plan2, make_obs(rung=Rung.LOCAL, model="qwen-b"))
    assert events2.infrastructure_event
    infra = _events(ledger_store, "infrastructure")
    assert infra and infra[0]["reason"] == "within_rung_model_change" and infra[0]["cache_cold"]

    plan3 = await controller.plan(cont, decision, make_gate(), events2.sticky)
    assumed = make_obs(rung=Rung.LOCAL, model=None, source=ServedSource.ASSUMED_INTENDED)
    events3 = await controller.observe(cont, plan3, assumed)
    assert events3.sticky.served_source == "assumed_intended"
    plan4 = await controller.plan(cont, decision, make_gate(), events3.sticky)
    failed = await controller.observe(
        cont,
        plan4,
        make_obs(
            status=400,
            rung=Rung.LOCAL,
            model=None,
            source=ServedSource.ASSUMED_INTENDED,
            error={"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}},
        ),
    )
    assert failed.failure_type is FailureType.UNVERIFIABLE


async def test_state_loss_marks_fresh_decision(bundle, controller) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    cont = make_ctx(_looping_continuation(1), RequestClass.CONTINUATION)
    decision = await router.decide(cont, make_gate(), None)
    plan = await controller.plan(cont, decision, make_gate(), None)
    assert plan.state_loss and plan.sticky.state_loss


async def test_failure_after_streamed_tool_use_is_surfaced_not_reissued(
    bundle, controller, ledger_store
) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, make_gate(), None)
    plan = await controller.plan(turn, decision, make_gate(), None)
    obs = make_obs(status=200, rung=Rung.LOCAL, completed=False, streamed_tool_content=True)
    events = await controller.observe(turn, plan, obs)
    assert events.surfaced_error is not None
    assert events.surfaced_error["type"] == "error"
    assert events.surfaced_error["error"]["message"].startswith(
        ErrorCode.PARTIAL_STREAM_FAILURE.value
    )
    assert events.failure_type is FailureType.INFRASTRUCTURE
    closed = [
        e
        for e in _events(ledger_store, OUTCOME_EVENT)
        if e["state"] == OutcomeState.CLOSED_TURN.value
    ]
    assert closed[-1]["partial_stream"] is True and closed[-1]["surfaced"] is True
    assert closed[-1]["gateway_attempts_observed"] == 1
    assert controller.pending_for(LINEAGE) is None


async def test_prompt_too_long_is_context_feasibility(bundle, controller) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, make_gate(), None)
    plan = await controller.plan(turn, decision, make_gate(), None)
    obs = make_obs(
        status=400,
        rung=Rung.LOCAL,
        error={
            "type": "error",
            "error": {
                "type": "invalid_request_error",
                "message": "prompt is too long: 140000 tokens > 131072",
            },
        },
    )
    events = await controller.observe(turn, plan, obs)
    assert events.failure_type is FailureType.CONTEXT_FEASIBILITY


async def test_subagent_interim_is_constrained_passthrough_without_wires(
    bundle, controller, ledger_store
) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    child = LineageId("child-lineage")
    body = _looping_continuation(3)
    body["model"] = "claude-haiku-4-5-20251001"
    ctx = make_ctx(body, RequestClass.SUBAGENT, lineage=child, agent_id="agent-1")
    decision = await router.decide(ctx, make_gate(), None)
    plan = await controller.plan(ctx, decision, make_gate(), None)
    assert plan.subagent and plan.rung is Rung.FRONTIER
    events = await controller.observe(ctx, plan, make_obs(rung=Rung.FRONTIER, model="claude-haiku"))
    assert not events.fired and not events.escalation_pending
    recorded = _events(ledger_store, "subagent_passthrough")
    assert recorded and recorded[0]["subagent"] is True
    pinned_child = await controller.plan(ctx, decision, make_gate(pinned=True), None)
    assert pinned_child.rung is Rung.LOCAL and pinned_child.subagent


async def test_gate_block_short_circuits(bundle, controller) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, make_gate(), None)
    gate = make_gate(PermittedSet(frozenset()), pinned=True)
    from dataclasses import replace

    blocked = replace(gate, block=ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG)
    plan = await controller.plan(turn, decision, blocked, None)
    assert plan.block is ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG
