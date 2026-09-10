"""End-to-end harness: the composition root with every real stage against the fake gateway."""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette

from adrl.app import Components, build_components
from adrl.config.settings import Settings
from adrl.core.enums import GateMode, RoutingMode
from adrl.core.ids import LineageId
from adrl.gates.workload import HEADER_WORKLOAD_ASSERTION, RepoInventory, sign_assertion
from adrl.proxy.asgi import build_asgi
from adrl.wire.identity import IdentityResolver
from adrl.wire.parse import parse_request
from tests.conftest import CONFIG_DIR, FakeGatewayState, build_fake_gateway

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "wire"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))


class EchoGatewayState(FakeGatewayState):
    """Reports the model it was asked for, so served identity follows the rung alias."""

    @property
    def served_model(self) -> str:  # type: ignore[override]
        if self.requests:
            model = self.requests[-1]["body"].get("model")
            if isinstance(model, str):
                return model
        return "claude-fable-5-1"

    @served_model.setter
    def served_model(self, value: str) -> None:
        del value


@dataclass
class E2E:
    settings: Settings
    components: Components
    client: httpx.AsyncClient
    gateway_state: EchoGatewayState
    gateway_client: httpx.AsyncClient

    @property
    def store(self) -> Any:
        return self.components.store

    @property
    def assertion_headers(self) -> dict[str, str]:
        """The workload assertion ``adrl launch`` would give a harness in the dev repo."""
        assert self.components.keystore is not None
        inventory = RepoInventory(
            root="/Users/arunmenon/projects/adrl-core",
            remote=None,
            head="deadbeef",
            fingerprint="e" * 64,
            tracked_files=1,
        )
        token = sign_assertion(inventory, self.components.keystore.hmac_key())
        return {HEADER_WORKLOAD_ASSERTION: token}

    def resolver(self) -> IdentityResolver:
        assert self.components.keystore is not None
        return IdentityResolver(self.components.keystore.hmac_key())

    def lineage_of(self, name: str, **headers: str) -> LineageId:
        data = load_fixture(name)
        parsed = parse_request(
            data["method"],
            data["path"],
            {**data["headers"], **self.assertion_headers, **headers},
            json.dumps(data["body"]).encode(),
        )
        return self.resolver().resolve(parsed, None).lineage_hmac

    async def send(
        self,
        name: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        raw: bytes | None = None,
    ) -> httpx.Response:
        data = load_fixture(name)
        merged = {**data["headers"], **self.assertion_headers, **(headers or {})}
        payload = raw if raw is not None else json.dumps(body or data["body"]).encode("utf-8")
        response = await self.client.request(
            data["method"], data["path"], content=payload, headers=merged
        )
        await self.components.pipeline.drain()
        return response

    def gateway_requests(self) -> Sequence[dict[str, Any]]:
        return self.gateway_state.requests

    def gateway_models(self) -> list[str]:
        return [str(r["body"].get("model")) for r in self.gateway_state.requests]

    def decisions(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.store.read("SELECT * FROM decisions ORDER BY ts")]

    def lineage_events(self, lineage: LineageId, event_type: str | None = None) -> list[Any]:
        rows = self.store.read_lineage_events(lineage, event_type)
        return [dict(r) | {"payload": json.loads(r["payload_json"])} for r in rows]

    def events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        if event_type is None:
            rows = self.store.read("SELECT * FROM events ORDER BY seq")
        else:
            rows = self.store.read(
                "SELECT * FROM events WHERE event_type=? ORDER BY seq", (event_type,)
            )
        return [dict(r) | {"payload": json.loads(r["payload_json"])} for r in rows]

    async def aclose(self) -> None:
        await self.client.aclose()
        await self.components.aclose()


def make_settings(
    tmp_path: Path, *, routing_mode: RoutingMode, gate_mode: GateMode = GateMode.ENFORCE
) -> Settings:
    return Settings(
        config_dir=CONFIG_DIR,
        data_dir=tmp_path,
        ledger_path=tmp_path / "adrl.db",
        egress_ledger_path=tmp_path / "egress.db",
        keystore_path=tmp_path / "keystore",
        gate_mode=gate_mode,
        routing_mode=routing_mode,
        fallback_mode=RoutingMode.LIVE,
        gateway_base_url="http://fake-gateway",
    )


async def build_e2e(
    tmp_path: Path,
    *,
    routing_mode: RoutingMode,
    gateway_state: EchoGatewayState | None = None,
    gateway_app: Starlette | None = None,
    gateway_client: httpx.AsyncClient | None = None,
) -> E2E:
    state = gateway_state or EchoGatewayState(served_model_header=None)
    app = gateway_app or build_fake_gateway(state)
    gw_client = gateway_client or httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://fake-gateway"
    )
    settings = make_settings(tmp_path, routing_mode=routing_mode)
    # The dev config carries no evidence_ref, so the bundle is loaded in shadow (config check)
    # and the runtime mode is applied to the settings the pipeline reads (as the proxy tests do).
    from adrl.config.loaders import load_bundle

    bundle = load_bundle(settings.model_copy(update={"routing_mode": RoutingMode.SHADOW}))
    components = build_components(settings, bundle=bundle, gateway_client=gw_client)
    asgi = build_asgi(components.pipeline)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url="http://adrl")
    return E2E(settings, components, client, state, gw_client)


@pytest.fixture
async def live(tmp_path: Path) -> AsyncIterator[E2E]:
    built = await build_e2e(tmp_path, routing_mode=RoutingMode.LIVE)
    yield built
    await built.aclose()


@pytest.fixture
async def shadow(tmp_path: Path) -> AsyncIterator[E2E]:
    built = await build_e2e(tmp_path, routing_mode=RoutingMode.SHADOW)
    yield built
    await built.aclose()


def continuation_with_result(text: str) -> dict[str, Any]:
    body = copy.deepcopy(load_fixture("continuation")["body"])
    body["messages"][-1]["content"][0]["content"] = text
    return body


def tool_turn(name: str, tool_input: dict[str, Any], result: str, idx: int) -> list[dict[str, Any]]:
    return [
        {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": f"toolu_loop_{idx}", "name": name, "input": tool_input}
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": f"toolu_loop_{idx}", "content": result}
            ],
        },
    ]


def user_turn_body(text: str) -> dict[str, Any]:
    body = copy.deepcopy(load_fixture("user_turn")["body"])
    body["messages"] = [{"role": "user", "content": [{"type": "text", "text": text}]}]
    return body


def looping_continuation(text: str, repeats: int) -> dict[str, Any]:
    body = user_turn_body(text)
    extra: list[dict[str, Any]] = []
    for i in range(repeats):
        extra += tool_turn("Read", {"file_path": "README.md"}, "same content", i)
    body["messages"] = body["messages"] + extra
    return body
