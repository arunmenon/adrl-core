"""The extracted boundary preserves recorded scope. Primary: ADRL-SEM-007."""

from __future__ import annotations

import json

import pytest

from .conftest import Harness


async def test_decisions_record_profile_and_adapter_versions(harness: Harness) -> None:
    response = await harness.send("user_turn")
    assert response.status_code == 200
    context = json.loads(harness.decisions()[0]["context_json"])
    assert context["protocol_profile_id"] == "anthropic-messages-v1"
    assert context["protocol_profile_version"] == "1"
    assert context["harness_adapter_id"] == "claude-code"
    assert context["harness_adapter_version"] == "1"
    assert context["protocol_operation_supported"] is True


async def test_capability_discovery_is_local_and_not_a_policy_attestation(harness: Harness) -> None:
    response = await harness.client.get("/adrl/v1/capabilities")
    assert response.status_code == 200
    assert response.json()["scope"] == "distribution"
    assert "GET /adrl/v1/capabilities" in response.json()["product_operations"]
    assert len(response.json()["product_operations"]) == 6
    assert not harness.gateway_requests()
    assert not harness.decisions()


@pytest.mark.parametrize(
    "path",
    [
        "/adrl/v1",
        "/adrl/v1/sessions",
        "/adrl/v1/events",
        "/adrl/v1/unknown",
        "/adrl/v1/sessions/s1/timeline",
        "/adrl/v1/decisions/r1",
    ],
)
async def test_unimplemented_product_payload_never_reaches_gateway(
    harness: Harness,
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forbidden_forward(*args, **kwargs):
        pytest.fail("A product payload reached provider forwarding")

    monkeypatch.setattr(harness.pipeline._gateway, "forward", forbidden_forward)
    response = await harness.client.post(path, json={"private_probe": "do not forward"})
    assert response.status_code == 501
    assert response.json()["code"] == "not_implemented"
    assert not harness.decisions()
