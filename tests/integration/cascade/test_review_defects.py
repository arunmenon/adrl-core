"""Conformance-review defects 3 and 4: thinking handoff contract and the verifier wire.

ADRL-CAS-004 (a source turn without thinking blocks cannot be continued with thinking on) and
ADRL-CAS-001 wire (e) (verifier failures reach the cascade as a lineage signal).
"""

from __future__ import annotations

from typing import Any

import pytest

from adrl.cascade.controller import CascadeController
from adrl.cascade.handoff import (
    HandoffError,
    needs_thinking_suppression,
    transform,
    validate_thinking_contract,
)
from adrl.cascade.sticky import MemoryStateProvider, escalate, new_sticky
from adrl.cascade.tripwires import TRIPWIRE_EVENT, WireClass
from adrl.core.enums import RequestClass, Rung
from adrl.core.ids import RouteId
from adrl.core.ports import LineageEvent
from adrl.core.types import HandoffNote
from adrl.ledger.events import VERIFIER_FAILED_EVENT
from adrl.ledger.facade import SqliteLedgerProvider
from adrl.ledger.store import LedgerStore
from adrl.routing.router import Router
from tests.unit.routing.helpers import LINEAGE, make_ctx, make_gate, make_obs, user_body

THINKING = {"type": "enabled", "budget_tokens": 2048}


def _continuation_without_thinking_blocks() -> dict[str, Any]:
    """A turn served by a rung without thinking, now continued with thinking on."""
    return user_body(
        "Fix the bug",
        thinking=THINKING,
        extra_messages=[
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "toolu_a", "name": "Read", "input": {"f": "a.py"}}
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_a", "content": "x"}],
            },
        ],
    )


def test_untransformed_request_violates_the_anthropic_thinking_rule() -> None:
    body = _continuation_without_thinking_blocks()
    assert needs_thinking_suppression(body)
    with pytest.raises(HandoffError):
        validate_thinking_contract(body)


def test_new_user_turn_re_enables_thinking() -> None:
    body = user_body("Now do the next thing", thinking=THINKING)
    assert not needs_thinking_suppression(body)
    validate_thinking_contract(body)


def test_same_family_rule_disables_thinking_when_source_turn_has_none(bundle: Any) -> None:
    body = _continuation_without_thinking_blocks()
    rule = bundle.provider_pairs.rule_for("anthropic", "anthropic", True, source_has_thinking=False)
    assert rule.action == "disable_thinking_for_handoff"
    note = HandoffNote(
        cause="loop", from_rung=Rung.CHEAP_CLOUD, to_rung=Rung.FRONTIER, executed_side_effects=[]
    )
    result = transform(body, rule, note)
    assert result.thinking_disabled and "thinking" not in result.body
    validate_thinking_contract(result.body)
    # the general keep-latest rule reaches the same safe result when there is nothing to keep
    general = bundle.provider_pairs.rule_for("anthropic", "anthropic", True)
    assert general.action == "keep_latest_thinking"
    fallback = transform(body, general, note)
    assert fallback.thinking_disabled and "thinking" not in fallback.body
    validate_thinking_contract(fallback.body)


async def test_post_escalation_continuation_is_forwarded_without_thinking(bundle: Any) -> None:
    controller = CascadeController(bundle, MemoryStateProvider())
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the bug", thinking=THINKING))
    decision = await router.decide(turn, make_gate(), None)
    sticky = escalate(
        new_sticky(LINEAGE, RouteId("route-esc"), Rung.CHEAP_CLOUD, previous=None), Rung.FRONTIER
    )
    continuation = make_ctx(_continuation_without_thinking_blocks(), RequestClass.CONTINUATION)
    plan = await controller.plan(continuation, decision, make_gate(), sticky)
    assert plan.rung is Rung.FRONTIER and plan.thinking_suppressed
    next_turn = make_ctx(user_body("Next task", thinking=THINKING))
    decision2 = await router.decide(next_turn, make_gate(), plan.sticky)
    plan2 = await controller.plan(next_turn, decision2, make_gate(), plan.sticky)
    assert not plan2.thinking_suppressed


async def test_verifier_failure_on_the_lineage_fires_the_wire_and_arms_escalation(
    bundle: Any, ledger_store: LedgerStore
) -> None:
    ledger = SqliteLedgerProvider(ledger_store)
    controller = CascadeController(bundle, MemoryStateProvider(), ledger=ledger)
    router = Router(bundle)
    turn = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(turn, make_gate(), None)
    plan = await controller.plan(turn, decision, make_gate(), None)
    assert plan.rung is Rung.LOCAL
    events = await controller.observe(turn, plan, make_obs(rung=Rung.LOCAL))
    assert not events.fired and controller.pending_for(LINEAGE) is None

    # the verification job finished with FAIL and recorded the lineage signal
    await ledger.append_lineage_event(
        LineageEvent(
            lineage_hmac=LINEAGE,
            event_type=VERIFIER_FAILED_EVENT,
            payload={"route_id": str(decision.route_id), "job_id": "job-1"},
        )
    )
    boundary = make_ctx(
        user_body(
            "Fix the typo in README.md",
            extra_messages=[
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "toolu_v", "name": "Edit", "input": {"f": "a"}}
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "toolu_v", "content": "ok"}],
                },
            ],
        ),
        RequestClass.CONTINUATION,
    )
    plan2 = await controller.plan(boundary, decision, make_gate(), events.sticky)
    assert plan2.escalated and plan2.from_rung is Rung.LOCAL and plan2.rung is Rung.CHEAP_CLOUD
    assert plan2.handoff is not None and "e_verifier_failure" in plan2.handoff.cause
    fired = [
        r
        for r in ledger_store.read(
            "SELECT payload_json FROM events WHERE event_type=? ORDER BY seq", (TRIPWIRE_EVENT,)
        )
    ]
    assert fired and WireClass.VERIFIER_FAILURE.value in str(fired[-1]["payload_json"])
    # the same signal is consumed once: a later boundary does not re-arm
    plan3 = await controller.plan(boundary, decision, make_gate(), plan2.sticky)
    assert not plan3.escalated
