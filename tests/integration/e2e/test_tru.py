"""Residency and destination receipts through the composed system (ADRL-SAF-008/009)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

from adrl.app import build_components
from adrl.config.loaders import canonical_json, load_bundle
from adrl.core.enums import RoutingMode
from adrl.gates.egress import audit_lineage
from adrl.gates.workload import HEADER_WORKLOAD_ASSERTION, RepoInventory, sign_assertion
from adrl.proxy.asgi import build_asgi
from tests.conftest import CONFIG_DIR, build_fake_gateway
from tests.integration.e2e.conftest import E2E, EchoGatewayState, make_settings

EU_ROOT = "/repos/eu-data"


def _eu_config(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for path in CONFIG_DIR.iterdir():
        if path.is_file():
            (config_dir / path.name).write_bytes(path.read_bytes())
    (config_dir / "keys" / "dev").mkdir(parents=True)
    for key in (CONFIG_DIR / "keys" / "dev").iterdir():
        (config_dir / "keys" / "dev" / key.name).write_bytes(key.read_bytes())
    data = json.loads((config_dir / "repo-classification-v1.json").read_text())
    data["repos"].append({"repo_id": "eu", "match": EU_ROOT, "class_id": "residency-eu"})
    (config_dir / "repo-classification-v1.json").write_text(json.dumps(data))
    key = serialization.load_pem_private_key(
        (config_dir / "keys" / "dev" / "manifest-signing.key").read_bytes(), password=None
    )
    payload = canonical_json(json.loads((config_dir / "repo-classification-v1.json").read_bytes()))
    (config_dir / "repo-classification-v1.sig").write_text(
        base64.b64encode(key.sign(payload)).decode() + "\n"  # type: ignore[union-attr]
    )
    return config_dir


async def _build(tmp_path: Path, routing_mode: RoutingMode) -> E2E:
    config_dir = _eu_config(tmp_path)
    state = EchoGatewayState(served_model_header=None)
    gw_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_fake_gateway(state)), base_url="http://fake-gateway"
    )
    settings = make_settings(tmp_path, routing_mode=routing_mode).model_copy(
        update={"config_dir": config_dir, "residency_unreachable_is_error": False}
    )
    bundle = load_bundle(settings.model_copy(update={"routing_mode": RoutingMode.SHADOW}))
    components = build_components(settings, bundle=bundle, gateway_client=gw_client)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_asgi(components.pipeline)), base_url="http://adrl"
    )
    return E2E(settings, components, client, state, gw_client)


def _eu_assertion(e2e: E2E) -> dict[str, str]:
    assert e2e.components.keystore is not None
    inventory = RepoInventory(
        root=EU_ROOT, remote=None, head="cafebabe", fingerprint="f" * 64, tracked_files=3
    )
    return {
        HEADER_WORKLOAD_ASSERTION: sign_assertion(inventory, e2e.components.keystore.hmac_key())
    }


@pytest.mark.parametrize("routing_mode", [RoutingMode.LIVE, RoutingMode.SHADOW])
async def test_residency_eu_lineage_never_reaches_a_us_deployment(
    tmp_path: Path, routing_mode: RoutingMode
) -> None:
    e2e = await _build(tmp_path, routing_mode)
    try:
        headers = _eu_assertion(e2e)
        response = await e2e.send("user_turn", headers=headers)
        models = e2e.gateway_models()
        cloud = {"cheap-haiku-us", "frontier-fable-us", "adrl-cheap-cloud", "adrl-frontier"}
        assert not (set(models) & cloud), models
        if response.status_code == 200:
            assert models and models[-1] in {"local-qwen-7b", "local-qwen-32b"}
        else:
            assert response.status_code == 400 and not models
        lineage = e2e.lineage_of("user_turn", **headers)
        report = audit_lineage(e2e.components.egress, str(lineage))
        assert report["left_machine"] is False
        decisions = e2e.decisions()
        if decisions:
            context = json.loads(decisions[-1]["context_json"])
            assert context["residency"] == "eu"
            assert all(d.startswith("local-") for d in context["permitted_deployment_ids"])
    finally:
        await e2e.aclose()


async def test_receipt_confirms_destination_and_absence_is_unconfirmed(live: E2E) -> None:
    live.gateway_state.served_model_header = "frontier-fable-us"
    await live.send("user_turn", body={**live_body("Design a new distributed cache layer")})
    lineage = live.lineage_of("user_turn")
    report = audit_lineage(live.components.egress, str(lineage))
    assert report["left_machine"] is True and report["confirmed_by_receipt"] is True
    assert report["deployments"] == ["frontier-fable-us"] and report["geos"] == ["us"]
    served = live.events("served")[-1]["payload"]
    assert served["served_deployment_id"] == "frontier-fable-us"
    assert served["receipt_confirmed"] is True

    live.gateway_state.served_model_header = None
    await live.send(
        "user_turn",
        headers={"x-claude-code-session-id": "no-receipt-session"},
        body={**live_body("Design another distributed cache layer")},
    )
    other = live.lineage_of("user_turn", **{"x-claude-code-session-id": "no-receipt-session"})
    report = audit_lineage(live.components.egress, str(other))
    assert report["left_machine"] is True
    assert report["confirmed_by_receipt"] is False and report["unconfirmed_count"] >= 1
    assert live.components.egress.verify_chain().ok


def live_body(text: str) -> dict[str, object]:
    from tests.integration.e2e.conftest import user_turn_body

    return user_turn_body(text)
