"""ADRL-CAS-006 and ADRL-CAS-003 observation tests against the fake gateway stream."""

from __future__ import annotations

import json

import httpx
import pytest

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung, ServedSource
from adrl.wire.observe import SseObserver, observe_json, served_identity
from tests.conftest import FakeGatewayState


def _observer(bundle: ConfigBundle, headers: dict[str, str], status: int = 200) -> SseObserver:
    return SseObserver(
        status=status,
        headers=headers,
        intended_rung=Rung.FRONTIER,
        requested_model="claude-fable-5-1",
        rungs=bundle.rungs,
    )


async def test_stream_observation_records_usage_model_and_tool_use(
    gateway_client: httpx.AsyncClient, gateway_state: FakeGatewayState, bundle: ConfigBundle
) -> None:
    gateway_state.stream_tool_use = True
    body = {"model": "claude-fable-5-1", "max_tokens": 10, "stream": True, "messages": []}
    relayed = b""
    async with gateway_client.stream("POST", "/v1/messages", json=body) as response:
        observer = _observer(bundle, dict(response.headers), response.status_code)
        async for chunk in response.aiter_raw():
            observer.feed(chunk)
            relayed += chunk
    obs = observer.finish()
    assert obs.streamed_tool_content
    assert obs.tool_uses[0].id == "toolu_fake_01"
    assert obs.tool_uses[0].input_parse_ok
    assert obs.usage is not None
    assert obs.usage.cache_read_input_tokens == 100
    assert obs.usage.output_tokens == 8
    assert obs.stop_reason == "tool_use"
    assert obs.completed
    assert obs.served.source is ServedSource.GATEWAY_REPORTED
    assert obs.served.model == "claude-fable-5-1"
    assert obs.served.rung is Rung.FRONTIER
    assert b"event: ping" in relayed
    assert obs.bytes_relayed == len(relayed)


def test_partial_lines_across_chunks_and_malformed_tool_json(bundle: ConfigBundle) -> None:
    observer = _observer(bundle, {})
    events = [
        b'event: message_start\ndata: {"type":"message_start","message":{"model":"local-x",'
        b'"usage":{"input_tokens":3}}}\n\n',
        b'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
        b'"content_block":{"type":"tool_use","id":"t1","name":"Edit","input":{}}}\n\n',
        b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
        b'"delta":{"type":"input_json_delta","partial_json":"{\\"path\\": "}}\n\n',
        b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
        b'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"tool_use"},'
        b'"usage":{"output_tokens":4}}\n\nevent: message_stop\ndata: {"type":"message_stop"}\n\n',
    ]
    raw = b"".join(events)
    for i in range(0, len(raw), 7):
        observer.feed(raw[i : i + 7])
    obs = observer.finish()
    assert obs.malformed_tool_json
    assert obs.tool_uses[0].input_parse_ok is False
    assert obs.served.source is ServedSource.PROXY_OBSERVED
    assert obs.served.model == "local-x"
    assert obs.usage is not None and obs.usage.output_tokens == 4


def test_served_identity_falls_back_to_assumed_intended(bundle: ConfigBundle) -> None:
    served = served_identity(
        {}, None, intended_rung=Rung.LOCAL, requested_model="claude-fable-5-1", rungs=bundle.rungs
    )
    assert served.source is ServedSource.ASSUMED_INTENDED
    assert served.rung is Rung.LOCAL


def test_served_identity_header_maps_group_to_rung(bundle: ConfigBundle) -> None:
    served = served_identity(
        {"X-LiteLLM-Model-Id": "adrl-local/qwen-coder"},
        None,
        intended_rung=Rung.FRONTIER,
        requested_model="claude-fable-5-1",
        rungs=bundle.rungs,
    )
    assert served.rung is Rung.LOCAL
    assert served.model == "qwen-coder"


def test_non_stream_observation_and_error_body(bundle: ConfigBundle) -> None:
    body = json.dumps(
        {
            "type": "error",
            "error": {"type": "invalid_request_error", "message": "prompt is too long"},
        }
    ).encode()
    obs = observe_json(
        body,
        status=400,
        headers={},
        intended_rung=Rung.LOCAL,
        requested_model="m",
        rungs=bundle.rungs,
    )
    assert obs.error is not None
    assert obs.completed is False
    ok = observe_json(
        json.dumps(
            {
                "model": "claude-fable-5-1",
                "content": [{"type": "tool_use", "id": "t", "name": "Read", "input": {"a": 1}}],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 1, "output_tokens": 2},
            }
        ).encode(),
        status=200,
        headers={},
        intended_rung=Rung.FRONTIER,
        requested_model="m",
        rungs=bundle.rungs,
    )
    assert ok.streamed_tool_content and ok.tool_uses[0].name == "Read"


@pytest.fixture
def bundle() -> ConfigBundle:
    from pathlib import Path

    from adrl.config.loaders import load_bundle
    from adrl.config.settings import Settings

    return load_bundle(Settings(config_dir=Path(__file__).resolve().parents[3] / "config"))
