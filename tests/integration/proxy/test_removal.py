"""ADRL-FND-001 removal test: with routing off, ADRL is byte-invisible in both directions."""

from __future__ import annotations

import json

import httpx
import pytest

from adrl.core.enums import RoutingMode
from tests.conftest import FakeGatewayState

from .conftest import Harness, load_fixture

TRANSPARENT_FIXTURES = [
    "user_turn",
    "continuation",
    "pre_warm",
    "title",
    "compaction",
    "count_tokens",
    "parallel_tools_full",
    "parallel_tools_partial",
    "fork_subagent",
    "nested_subagent",
]


@pytest.mark.parametrize("name", TRANSPARENT_FIXTURES)
@pytest.mark.parametrize("routing_mode", [RoutingMode.OFF, RoutingMode.SHADOW])
async def test_request_and_response_bytes_are_identical(
    harness_factory, gateway_client: httpx.AsyncClient, name: str, routing_mode: RoutingMode
) -> None:
    harness: Harness = await harness_factory(routing_mode=routing_mode)
    data = load_fixture(name)
    raw = json.dumps(data["body"]).encode("utf-8")
    try:
        direct = await gateway_client.request(
            data["method"], data["path"], content=raw, headers=data["headers"]
        )
        direct_body = direct.content
        harness.gateway_state.requests.clear()
        via = await harness.send(name)
    finally:
        await harness.client.aclose()
    assert via.status_code == direct.status_code
    assert via.content == direct_body
    assert len(harness.gateway_requests()) == 1
    seen = harness.gateway_requests()[0]
    assert seen["raw"] == raw
    assert seen["headers"]["anthropic-version"] == data["headers"]["anthropic-version"]
    assert seen["headers"]["anthropic-beta"] == data["headers"]["anthropic-beta"]
    assert seen["headers"]["accept-encoding"] == "identity"
    if data["body"].get("stream"):
        assert b"event: ping" in via.content
        assert via.headers["content-type"].startswith("text/event-stream")


async def test_upstream_error_wording_is_relayed_verbatim(
    harness: Harness, gateway_state: FakeGatewayState
) -> None:
    gateway_state.status_code = 500
    gateway_state.error_body = {
        "type": "error",
        "error": {"type": "overloaded_error", "message": "Overloaded, exact vendor wording"},
    }
    response = await harness.send("user_turn")
    assert response.status_code == 500
    assert json.loads(response.content) == gateway_state.error_body
    assert len(harness.gateway_requests()) == 1
    assert harness.events("upstream_error")


async def test_non_api_path_is_forwarded_unchanged(harness: Harness) -> None:
    response = await harness.client.get("/health")
    assert response.status_code == 200
    assert "healthy_endpoints" in response.json()


async def test_served_identity_and_usage_reach_the_ledger(harness: Harness) -> None:
    await harness.send("user_turn")
    served = harness.events("served")
    assert len(served) == 1
    payload = served[0]["payload"]
    assert payload["served_source"] == "gateway_reported"
    assert payload["served_model"] == "claude-fable-5-1"
    assert payload["usage"]["cache_read_input_tokens"] == 100
    decisions = harness.decisions()
    assert len(decisions) == 1
    assert decisions[0]["route_id"] == served[0]["route_id"]
    context = json.loads(decisions[0]["context_json"])
    assert context["unscanned"] is True
    assert context["routing_mode"] == "shadow"
