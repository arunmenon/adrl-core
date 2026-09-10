"""ADRL-FND-001 thinking strip, ADRL-SEM-003 inheritance, ADRL-FND-003 per-lineage boundaries."""

from __future__ import annotations

import asyncio
import json

from adrl.core.enums import RoutingMode, Rung

from .conftest import EscalatingCascade, FixedRouter, Harness, load_fixture


async def test_first_turn_local_strips_thinking_and_escalation_keeps_it(harness_factory) -> None:
    harness: Harness = await harness_factory(routing_mode=RoutingMode.LIVE)
    harness.pipeline._router = FixedRouter(harness.bundle, Rung.LOCAL)
    harness.pipeline._cascade = EscalatingCascade()
    harness.gateway_state.served_model_header = None
    try:
        first = await harness.send("user_turn")
        assert first.status_code == 200
        local_body = harness.last_gateway_body()
        assert local_body["model"] == "local-qwen-7b"
        assert "thinking" not in local_body
        assert b"event: error" not in first.content
        second = await harness.send("continuation")
        assert second.status_code == 200
        frontier_body = harness.last_gateway_body()
        assert frontier_body["model"] == "claude-fable-5-1"
        assert frontier_body["thinking"] == {"type": "adaptive"}
    finally:
        await harness.client.aclose()
    requests = harness.events("request")
    assert requests[0]["payload"]["target_rung"] == "local"
    assert requests[1]["payload"]["escalated"] is True
    assert requests[1]["payload"]["target_rung"] == "frontier"


async def test_continuation_inherits_sticky_route_without_new_decision(harness_factory) -> None:
    harness: Harness = await harness_factory(routing_mode=RoutingMode.LIVE)
    harness.pipeline._router = FixedRouter(harness.bundle, Rung.LOCAL)
    harness.gateway_state.served_model_header = None
    try:
        await harness.send("user_turn")
        await harness.send("parallel_tools_partial")
        await harness.send("pre_warm")
    finally:
        await harness.client.aclose()
    assert len(harness.decisions()) == 1
    route_ids = {e["route_id"] for e in harness.events("request")}
    assert len(route_ids) == 1
    for event in harness.events("request"):
        assert event["payload"]["target_rung"] == "local"
    partial = harness.events("request")[1]["payload"]
    assert partial["is_boundary"] is False


async def test_pre_warm_never_creates_a_decision_before_the_real_turn(harness: Harness) -> None:
    await harness.send("pre_warm")
    first = harness.decisions()
    await harness.send("user_turn")
    second = harness.decisions()
    assert len(first) == 1
    assert len(second) == 2
    assert first[0]["request_class"] == "pre_warm"
    assert json.loads(first[0]["context_json"])["state_loss"] is True


async def test_parallel_siblings_have_independent_routes_and_no_lost_writes(
    harness: Harness,
) -> None:
    await harness.send("user_turn")
    headers = [{"x-claude-code-agent-id": f"agent-{i}"} for i in range(3)]
    responses = await asyncio.gather(*(harness.send("fork_subagent", headers=h) for h in headers))
    assert all(r.status_code == 200 for r in responses)
    decisions = harness.decisions()
    lineages = {d["lineage_hmac"] for d in decisions}
    assert len(lineages) == 4
    assert len(harness.state.sticky) == 4


async def test_shadow_mode_records_a_decision_but_forwards_original_bytes(
    harness: Harness,
) -> None:
    await harness.send("user_turn")
    raw = json.dumps(load_fixture("user_turn")["body"]).encode()
    assert harness.gateway_requests()[0]["raw"] == raw
    decision = harness.decisions()[0]
    assert decision["decided_rung"] == "frontier"
    assert decision["estimator"] == "harness-requested"
    assert harness.events("request")[0]["payload"]["forward_original"] is True


async def test_sticky_state_follows_the_served_rung_not_the_intended_one(
    harness_factory,
) -> None:
    """ADRL-CAS-006: the gateway header wins over the decided rung in sticky state."""
    harness: Harness = await harness_factory(routing_mode=RoutingMode.LIVE)
    harness.pipeline._router = FixedRouter(harness.bundle, Rung.LOCAL)
    try:
        await harness.send("user_turn")
    finally:
        await harness.client.aclose()
    served = harness.events("served")[0]["payload"]
    assert served["intended_rung"] == "local"
    assert served["served_rung"] == "frontier"
    assert served["served_source"] == "gateway_reported"
    sticky = harness.state.sticky[harness.lineage_of("user_turn")]
    assert sticky.rung is Rung.FRONTIER
