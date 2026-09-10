"""Shared fixtures: temp ledgers, settings, and a fake LiteLLM gateway speaking the Messages API."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from adrl.config.settings import Settings
from adrl.core.enums import GateMode, RoutingMode
from adrl.ledger.egress import EgressLedger
from adrl.ledger.store import LedgerStore

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"


@dataclass
class FakeGatewayState:
    """Mutable knobs a test sets before sending traffic."""

    status_code: int = 200
    error_body: dict[str, Any] | None = None
    served_model: str = "claude-fable-5-1"
    served_model_header: str | None = "adrl-frontier/claude-fable-5-1"
    stream_tool_use: bool = False
    text: str = "hello from the fake gateway"
    usage: dict[str, int] = field(
        default_factory=lambda: {
            "input_tokens": 120,
            "output_tokens": 8,
            "cache_read_input_tokens": 100,
            "cache_creation_input_tokens": 0,
        }
    )
    ping_events: int = 1
    disconnect_after_tool_use: bool = False
    requests: list[dict[str, Any]] = field(default_factory=list)


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def build_fake_gateway(state: FakeGatewayState) -> Starlette:
    async def messages(request: Request) -> Response:
        body = await request.body()
        parsed = json.loads(body) if body else {}
        state.requests.append({"headers": dict(request.headers), "body": parsed, "raw": body})
        headers: dict[str, str] = {}
        if state.served_model_header:
            headers["x-litellm-model-id"] = state.served_model_header
        if state.status_code != 200:
            error = state.error_body or {
                "type": "error",
                "error": {"type": "api_error", "message": "fake gateway error"},
            }
            return JSONResponse(error, status_code=state.status_code, headers=headers)
        if parsed.get("stream"):
            return StreamingResponse(_stream(), media_type="text/event-stream", headers=headers)
        content: list[dict[str, Any]] = [{"type": "text", "text": state.text}]
        stop_reason = "end_turn"
        if state.stream_tool_use:
            content = [
                {"type": "tool_use", "id": "toolu_fake_01", "name": "Read", "input": {"path": "x"}}
            ]
            stop_reason = "tool_use"
        return JSONResponse(
            {
                "id": "msg_fake_01",
                "type": "message",
                "role": "assistant",
                "model": state.served_model,
                "content": content,
                "stop_reason": stop_reason,
                "stop_sequence": None,
                "usage": state.usage,
            },
            headers=headers,
        )

    async def _stream() -> AsyncIterator[bytes]:
        yield _sse(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_fake_01",
                    "type": "message",
                    "role": "assistant",
                    "model": state.served_model,
                    "content": [],
                    "stop_reason": None,
                    "usage": {
                        "input_tokens": state.usage["input_tokens"],
                        "output_tokens": 0,
                        "cache_read_input_tokens": state.usage["cache_read_input_tokens"],
                        "cache_creation_input_tokens": state.usage["cache_creation_input_tokens"],
                    },
                },
            },
        )
        for _ in range(state.ping_events):
            yield _sse("ping", {"type": "ping"})
        if state.stream_tool_use:
            yield _sse(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu_fake_01",
                        "name": "Read",
                        "input": {},
                    },
                },
            )
            yield _sse(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": '{"path": "x"}'},
                },
            )
            if state.disconnect_after_tool_use:
                return
            yield _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
            stop_reason = "tool_use"
        else:
            yield _sse(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            )
            yield _sse(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": state.text},
                },
            )
            yield _sse("content_block_stop", {"type": "content_block_stop", "index": 0})
            stop_reason = "end_turn"
        yield _sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                "usage": {"output_tokens": state.usage["output_tokens"]},
            },
        )
        yield _sse("message_stop", {"type": "message_stop"})

    async def count_tokens(request: Request) -> Response:
        body = await request.body()
        parsed = json.loads(body) if body else {}
        state.requests.append(
            {"headers": dict(request.headers), "body": parsed, "raw": body, "count_tokens": True}
        )
        text = json.dumps(parsed.get("messages", []))
        return JSONResponse({"input_tokens": max(1, len(text) // 4)})

    async def health(_: Request) -> Response:
        return JSONResponse(
            {"healthy_endpoints": [{"model": "adrl-frontier"}], "unhealthy_endpoints": []}
        )

    return Starlette(
        routes=[
            Route("/v1/messages", messages, methods=["POST"]),
            Route("/v1/messages/count_tokens", count_tokens, methods=["POST"]),
            Route("/health", health, methods=["GET"]),
        ]
    )


@pytest.fixture
def gateway_state() -> FakeGatewayState:
    return FakeGatewayState()


@pytest.fixture
def fake_gateway(gateway_state: FakeGatewayState) -> Starlette:
    return build_fake_gateway(gateway_state)


@pytest.fixture
async def gateway_client(fake_gateway: Starlette) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=fake_gateway)
    async with httpx.AsyncClient(transport=transport, base_url="http://fake-gateway") as client:
        yield client


@pytest.fixture
def ledger_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "ledger": tmp_path / "adrl.db",
        "egress": tmp_path / "egress.db",
        "keystore": tmp_path / "keystore",
    }


@pytest.fixture
def settings(tmp_path: Path, ledger_paths: dict[str, Path]) -> Settings:
    return Settings(
        config_dir=CONFIG_DIR,
        data_dir=tmp_path,
        ledger_path=ledger_paths["ledger"],
        egress_ledger_path=ledger_paths["egress"],
        keystore_path=ledger_paths["keystore"],
        gate_mode=GateMode.ENFORCE,
        routing_mode=RoutingMode.SHADOW,
        gateway_base_url="http://fake-gateway",
    )


@pytest.fixture
def ledger_store(ledger_paths: dict[str, Path]) -> AsyncIterator[LedgerStore]:
    store = LedgerStore(ledger_paths["ledger"])
    store.open()
    yield store  # type: ignore[misc]
    store.close()


@pytest.fixture
def egress_ledger(ledger_paths: dict[str, Path]) -> AsyncIterator[EgressLedger]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ledger = EgressLedger(
        ledger_paths["egress"], signing_key=Ed25519PrivateKey.generate(), key_id="test"
    )
    ledger.open()
    yield ledger  # type: ignore[misc]
    ledger.close()
