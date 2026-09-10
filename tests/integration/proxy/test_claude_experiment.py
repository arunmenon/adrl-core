"""Synthetic pipeline composition, not live admission or native Claude qualification."""

import json
from dataclasses import replace

import pytest

from adrl.core.enums import GateMode, RoutingMode, Rung
from adrl.gates.deployments import DeploymentPolicy
from adrl.proxy.claude_experiment import ClaudeExperimentClient, ClaudeExperimentConfig
from adrl.proxy.observe_only import ObserveOnlyGate
from adrl.proxy.pipeline import Pipeline

from .conftest import load_fixture


def build(harness, *, mode=RoutingMode.LIVE, qualify=False):
    old = harness.pipeline
    cfg = ClaudeExperimentConfig(
        source_model="claude-fable-5-1",
        target_model="claude-sonnet-5",
        target_deployment="offline-direct-sonnet",
    )
    client = ClaudeExperimentClient(cfg, client=old._gateway.client)
    bundle = harness.bundle
    if qualify:
        # Synthetic config fixture only. These refs do not qualify shipped rungs.
        specs = {
            r: s.model_copy(
                update={
                    "boundary": s.boundary.model_copy(
                        update={"evidence_ref": "offline-fixture-not-production-admission"}
                    )
                }
            )
            for r, s in bundle.rungs.rungs.items()
        }
        template = bundle.endpoint_inventory.deployments[-1]
        dep = template.model_copy(
            update={
                "id": cfg.target_deployment,
                "rung": Rung.FRONTIER,
                "provider": "anthropic",
                "api_base": "https://api.anthropic.com",
                "model": cfg.target_model,
                "trust_zone": "cloud",
            }
        )
        bundle = replace(
            bundle,
            rungs=bundle.rungs.model_copy(update={"rungs": specs}),
            endpoint_inventory=bundle.endpoint_inventory.model_copy(update={"deployments": (dep,)}),
        )
    policy = DeploymentPolicy(bundle.endpoint_inventory)

    class Gate(ObserveOnlyGate):
        async def evaluate(self, ctx):
            result = await super().evaluate(ctx)
            return replace(
                result,
                permitted_deployments=policy.permitted_for(
                    permitted_rungs=result.permitted.rungs,
                    pinned=result.pinned,
                    residency=result.residency,
                ),
            )

    return Pipeline(
        settings=harness.settings.model_copy(
            update={"routing_mode": mode, "gate_mode": GateMode.ENFORCE}
        ),
        bundle=bundle,
        ledger=old._ledger,
        egress=old._egress,
        gateway=client,
        gate=Gate(old._ledger),
        router=old._router,
        cascade=old._cascade,
        state=old._state,
        identity=old._identity,
    )


@pytest.mark.parametrize("mode", [RoutingMode.SHADOW, RoutingMode.OFF])
async def test_nonlive_cannot_activate_candidate(harness, mode):
    with pytest.raises(ValueError, match="explicit LIVE"):
        build(harness, mode=mode)


async def test_current_config_cannot_activate_candidate(harness):
    with pytest.raises(ValueError, match="cannot bypass LIVE"):
        build(harness)


async def test_pipeline_records_forced_choice_and_preserves_fields(harness):
    pipeline = build(harness, qualify=True)
    harness.gateway_state.served_model = "claude-sonnet-5"
    # Even a gateway-style header must not override direct-provider model observation.
    harness.gateway_state.served_model_header = "fake-litellm-id"
    fixture = load_fixture("user_turn")
    payload = {**fixture["body"], "max_tokens": 1024}
    original = json.loads(json.dumps(payload))
    response = await pipeline.handle(
        "POST",
        "/v1/messages",
        fixture.get("headers", {}),
        json.dumps(payload).encode(),
        ("127.0.0.1", 1),
    )
    if response.stream is not None:
        async for _ in response.stream:
            pass
    if response.after is not None:
        await response.after()
    await pipeline.drain()
    assert response.status == 200
    sent = harness.last_gateway_body()
    original["model"] = "claude-sonnet-5"
    assert sent == original
    decisions = harness.decisions()
    assert decisions[-1]["estimator"] == "experiment_forced_claude"
    served = harness.events("served")[-1]["payload"]
    assert served["served_model"] == "claude-sonnet-5"
    assert served["served_source"] == "proxy_observed"
    assert served["served_deployment_id"] is None
    assert served["intended_deployment_id"] == "offline-direct-sonnet"
    rows = harness.egress.events_for_lineage(
        pipeline._claude_experiment.selection.lineage, "served_receipt"
    )
    assert rows[-1]["deployment_id"] is None
    assert rows[-1]["geo"] is None and rows[-1]["trust_zone"] is None
    assert rows[-1]["api_base_host"] == "api.anthropic.com"
    assert rows[-1]["receipt_source"] == "proxy_observed"


async def test_query_is_refused_without_silent_removal(harness):
    pipeline = build(harness, qualify=True)
    response = await pipeline.handle(
        "POST", "/v1/messages", {}, b"{}", ("127.0.0.1", 1), query="beta=true"
    )
    assert response.status == 400
    assert not harness.gateway_state.requests


async def test_upstream_error_stops_further_dispatch(harness):
    pipeline = build(harness, qualify=True)
    harness.gateway_state.status_code = 429
    fixture = load_fixture("user_turn")
    payload = {**fixture["body"], "max_tokens": 1024, "stream": False}
    for _ in range(2):
        response = await pipeline.handle(
            "POST",
            "/v1/messages",
            fixture.get("headers", {}),
            json.dumps(payload).encode(),
            ("127.0.0.1", 1),
        )
        if response.after:
            await response.after()
    await pipeline.drain()
    assert pipeline._claude_experiment.stopped
    assert len(harness.gateway_state.requests) == 1
