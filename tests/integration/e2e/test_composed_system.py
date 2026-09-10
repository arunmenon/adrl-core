"""ADRL-FND-002 composition: every real stage wired through build_components, end to end."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from adrl.core.enums import RoutingMode
from adrl.core.errors import VENDOR_PROMPT_TOO_LONG_PHRASE
from adrl.gates.egress import audit_lineage
from tests.conftest import build_fake_gateway

from .conftest import (
    AWS_KEY,
    E2E,
    EchoGatewayState,
    build_e2e,
    continuation_with_result,
    load_fixture,
    looping_continuation,
    user_turn_body,
)

LOCAL_ALIASES = {"adrl-local", "adrl-local-large", "local-qwen-7b", "local-qwen-32b"}
CLOUD_ALIASES = {"adrl-cheap-cloud", "adrl-frontier", "cheap-haiku-us", "frontier-fable-us"}


def _is_local(model: str) -> bool:
    return model in LOCAL_ALIASES


async def test_every_real_stage_is_installed(live: E2E) -> None:
    assert live.components.installed
    assert all(live.components.installed.values()), live.components.installed
    assert type(live.components.gate).__name__ == "GatePipeline"
    assert type(live.components.router).__name__ == "Router"
    assert type(live.components.cascade).__name__ == "CascadeController"
    assert type(live.components.state).__name__ == "SqliteStateProvider"


async def test_user_turn_decides_and_continuation_and_pre_warm_inherit(live: E2E) -> None:
    first = await live.send("user_turn")
    assert first.status_code == 200
    rows = live.decisions()
    assert len(rows) == 1
    row = rows[0]
    assert row["estimator"] and row["estimator_version"]
    assert row["policy_version"] == "policy-v1"
    assert row["objective_version"] == "objective-v1"
    features = json.loads(row["features_json"])
    assert "context_tokens_estimate" in features
    assert "verb_class" in features
    assert "served_rung" not in features

    second = await live.send("continuation")
    assert second.status_code == 200
    assert len(live.decisions()) == 1, "a continuation never mints a decision"

    third = await live.send("pre_warm")
    assert third.status_code == 200
    assert len(live.decisions()) == 1, "pre-warm inherits the sticky route"
    models = live.gateway_models()
    assert models[1] == models[0] and models[2] == models[0]


async def test_secret_in_tool_result_pins_lineage_and_forces_local(live: E2E) -> None:
    lineage = live.lineage_of("user_turn")
    assert audit_lineage(live.components.egress, str(lineage))["left_machine"] is False
    await live.send("user_turn")
    pinned_response = await live.send(
        "continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n")
    )
    assert pinned_response.status_code == 200
    pins = live.lineage_events(lineage, "pinned")
    assert pins, "the finding must pin the lineage"
    assert pins[0]["payload"].get("detector_id")
    egress_rows = live.components.egress.lineage_left_machine(str(lineage))
    assert egress_rows
    assert any(r.get("gate_verdicts_json") for r in egress_rows)
    # the pinning request itself and everything after it is served by the local rung only
    models = live.gateway_models()
    assert _is_local(models[-1]), models
    follow_up = await live.send("continuation", body=continuation_with_result("clean output"))
    assert follow_up.status_code == 200
    assert _is_local(live.gateway_models()[-1])
    assert not any(m in CLOUD_ALIASES for m in live.gateway_models()[1:])
    audit = audit_lineage(live.components.egress, str(lineage))
    assert audit["left_machine"] is True
    assert audit["deployment_tags"] == [live.settings.deployment_tag]


async def test_pinned_lineage_over_local_ceiling_is_blocked_without_a_gateway_call(
    live: E2E,
) -> None:
    await live.send("user_turn")
    await live.send("continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n"))
    sent_before = len(live.gateway_requests())
    huge = continuation_with_result("x" * 700_000)
    blocked = await live.send("continuation", body=huge)
    assert 400 <= blocked.status_code < 500
    payload = blocked.json()
    message = payload["error"]["message"]
    assert "capability_rejected: prompt_too_long" in message
    assert VENDOR_PROMPT_TOO_LONG_PHRASE.lower() in message.lower()
    assert "ANTHROPIC_BASE_URL" not in message
    assert len(live.gateway_requests()) == sent_before


async def test_pinned_count_tokens_and_cosmetic_utility_never_reach_the_cloud(live: E2E) -> None:
    await live.send("user_turn")
    await live.send("continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n"))
    sent_before = len(live.gateway_requests())
    counted = await live.send("count_tokens")
    assert counted.status_code == 200
    assert counted.json()["input_tokens"] >= 1
    assert len(live.gateway_requests()) == sent_before, "count_tokens body never left"

    title = await live.send("title")
    assert title.status_code == 200
    body = title.json()
    assert body["type"] == "message"
    if len(live.gateway_requests()) > sent_before:
        assert _is_local(live.gateway_models()[-1])
    else:
        assert body["stop_reason"] == "end_turn"
        assert body["content"] and body["content"][0]["type"] == "text"


async def test_pin_survives_a_restart_of_the_composition(tmp_path: Path) -> None:
    first = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    lineage = first.lineage_of("user_turn")
    try:
        await first.send("user_turn")
        await first.send("continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n"))
        assert first.lineage_events(lineage, "pinned")
    finally:
        await first.aclose()

    second = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    try:
        assert second.lineage_of("user_turn") == lineage
        response = await second.send("continuation", body=continuation_with_result("after restart"))
        assert response.status_code == 200
        assert _is_local(second.gateway_models()[-1]), second.gateway_models()
        assert second.components.egress is not None
        assert second.components.egress.verify_chain().ok
    finally:
        await second.aclose()


async def test_fork_subagent_under_pinned_parent_is_served_local(live: E2E) -> None:
    await live.send("user_turn")
    await live.send("continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n"))
    fork = await live.send("fork_subagent")
    assert fork.status_code == 200
    assert _is_local(live.gateway_models()[-1]), live.gateway_models()
    child = live.lineage_of("fork_subagent")
    inherited = live.lineage_events(child, "pinned")
    assert inherited and inherited[0]["payload"].get("inherited_from")


async def test_tripwire_escalates_at_the_next_boundary_with_a_handoff(live: E2E) -> None:
    text = "Fix the typo in README.md"
    first = await live.send("user_turn", body=user_turn_body(text))
    assert first.status_code == 200
    assert live.decisions()[0]["decided_rung"] == "local"
    assert _is_local(live.gateway_models()[-1]), live.gateway_models()

    looping = await live.send("continuation", body=looping_continuation(text, repeats=3))
    assert looping.status_code == 200
    assert _is_local(live.gateway_models()[-1])
    assert live.events("tripwire_fired"), "three identical Read calls trip the local wire"

    boundary = await live.send("continuation", body=looping_continuation(text, repeats=4))
    assert boundary.status_code == 200
    sent = live.gateway_requests()[-1]["body"]
    assert sent["model"] == "cheap-haiku-us", sent["model"]
    assert "thinking" not in sent
    last_user = sent["messages"][-1]
    blocks = last_user["content"]
    result_indexes = [i for i, b in enumerate(blocks) if b.get("type") == "tool_result"]
    note_indexes = [
        i
        for i, b in enumerate(blocks)
        if b.get("type") == "text" and "adrl-handoff" in str(b.get("text", "")).lower()
    ]
    assert note_indexes, "handoff note must be present"
    assert max(result_indexes) < min(note_indexes), "note goes after every tool_result"
    # the handoff never edits system text; the rung rewrite only drops cache_control markers
    assert [b["text"] for b in sent["system"]] == [
        b["text"] for b in user_turn_body(text)["system"]
    ]
    escalations = live.events("escalation")
    assert escalations and escalations[-1]["payload"]["to_rung"] == "cheap_cloud"


async def test_shadow_mode_with_real_stages_is_byte_transparent(tmp_path: Path) -> None:
    state = EchoGatewayState(served_model_header=None)
    app = build_fake_gateway(state)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://fake-gateway"
    ) as direct_client:
        shadow = await build_e2e(
            tmp_path,
            routing_mode=RoutingMode.SHADOW,
            gateway_state=state,
            gateway_app=app,
            gateway_client=direct_client,
        )
        try:
            for name in (
                "user_turn",
                "continuation",
                "pre_warm",
                "title",
                "compaction",
                "count_tokens",
                "parallel_tools_full",
                "parallel_tools_partial",
                "fork_subagent",
            ):
                data = load_fixture(name)
                raw = json.dumps(data["body"]).encode("utf-8")
                direct = await direct_client.request(
                    data["method"], data["path"], content=raw, headers=data["headers"]
                )
                state.requests.clear()
                via = await shadow.send(name)
                assert via.status_code == direct.status_code, name
                assert via.content == direct.content, name
                assert len(state.requests) == 1, name
                assert state.requests[0]["raw"] == raw, name
            assert shadow.decisions(), "shadow mode still records decisions"
        finally:
            await shadow.aclose()


async def test_egress_chain_verifies_after_traffic(live: E2E) -> None:
    await live.send("user_turn")
    await live.send("continuation")
    await live.send("continuation", body=continuation_with_result(f"AWS_KEY={AWS_KEY}\n"))
    assert live.components.egress is not None
    verification = live.components.egress.verify_chain()
    assert verification.ok, verification
    assert verification.entries >= 3
