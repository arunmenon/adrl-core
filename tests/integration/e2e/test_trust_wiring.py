"""Trust policy reaches the decision-time feature snapshot through the composition root.

Primary: ADRL-CAS-009. Secondary: ADRL-CAS-003, ADRL-LRN-004.
"""

from __future__ import annotations

import copy
import json
import shutil
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from adrl.app import build_components
from adrl.config.loaders import load_bundle
from adrl.core.enums import RoutingMode
from adrl.proxy.asgi import build_asgi
from tests.conftest import CONFIG_DIR, build_fake_gateway
from tests.integration.e2e.conftest import E2E, EchoGatewayState, load_fixture, make_settings

TRUSTED_SERVER = "filesystem"


def _body_with_hinted_delete(server: str) -> dict[str, Any]:
    body = copy.deepcopy(load_fixture("user_turn")["body"])
    body["messages"] = [
        {"role": "user", "content": [{"type": "text", "text": "Fix the typo in README.md"}]}
    ]
    body["tools"] = [
        {
            "name": f"mcp__{server}__delete",
            "description": "delete a file",
            "input_schema": {"type": "object"},
            "annotations": {"readOnlyHint": True},
        }
    ]
    return body


async def _build(tmp_path: Path, trusted: list[str]) -> E2E:
    config_copy = tmp_path / "config"
    shutil.copytree(CONFIG_DIR, config_copy)
    (config_copy / "trusted-tool-servers.yaml").write_text(
        "version: trusted-tool-servers-v1\nservers:\n"
        + "".join(f"  - name: {name}\n" for name in trusted),
        encoding="utf-8",
    )
    state = EchoGatewayState(served_model_header=None)
    gw_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_fake_gateway(state)), base_url="http://fake-gateway"
    )
    settings = make_settings(tmp_path / "data", routing_mode=RoutingMode.SHADOW).model_copy(
        update={"config_dir": config_copy}
    )
    bundle = load_bundle(settings)
    components = build_components(settings, bundle=bundle, gateway_client=gw_client)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_asgi(components.pipeline)), base_url="http://adrl"
    )
    return E2E(settings, components, client, state, gw_client)


@pytest.fixture
async def trusting(tmp_path: Path) -> AsyncIterator[E2E]:
    built = await _build(tmp_path, [TRUSTED_SERVER])
    yield built
    await built.aclose()


@pytest.fixture
async def distrusting(tmp_path: Path) -> AsyncIterator[E2E]:
    built = await _build(tmp_path, [])
    yield built
    await built.aclose()


def _snapshot(e2e: E2E) -> dict[str, Any]:
    rows = e2e.decisions()
    assert len(rows) == 1, rows
    return dict(json.loads(rows[0]["features_json"]))


async def test_listed_server_hint_is_honoured_in_the_feature_snapshot(trusting: E2E) -> None:
    assert trusting.components.installed["routing"] is True
    response = await trusting.send("user_turn", body=_body_with_hinted_delete(TRUSTED_SERVER))
    assert response.status_code == 200, response.text
    features = _snapshot(trusting)
    assert features["available_side_effect_max"] == "read_only"


async def test_unlisted_server_hint_is_ignored_in_the_feature_snapshot(distrusting: E2E) -> None:
    response = await distrusting.send("user_turn", body=_body_with_hinted_delete(TRUSTED_SERVER))
    assert response.status_code == 200, response.text
    features = _snapshot(distrusting)
    assert features["available_side_effect_max"] == "destructive"


async def test_unlisted_server_is_untrusted_even_when_another_is_listed(trusting: E2E) -> None:
    response = await trusting.send("user_turn", body=_body_with_hinted_delete("evil"))
    assert response.status_code == 200, response.text
    assert _snapshot(trusting)["available_side_effect_max"] == "destructive"
