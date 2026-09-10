"""Offline candidate checks. Primary: ADRL-SEM-007; ADRL-FND-001/005, ADRL-TRU-002."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import httpx
import pytest

from adrl.core.enums import Rung
from adrl.core.types import DeploymentInfo, DeploymentSet
from adrl.proxy.claude_experiment import (
    ClaudeExperimentClient,
    ClaudeExperimentConfig,
    ClaudeSelection,
)
from adrl.proxy.upstream import UpstreamUnreachableError, read_all


def config(**changes):
    return ClaudeExperimentConfig(
        source_model="claude-opus-5",
        target_model="claude-sonnet-5",
        target_deployment="direct-sonnet",
        **changes,
    )


def permitted(**changes):
    dep = DeploymentInfo(
        "direct-sonnet",
        Rung.FRONTIER,
        "direct",
        "anthropic",
        "cloud",
        "unknown",
        "api.anthropic.com",
        model="claude-sonnet-5",
    )
    return DeploymentSet.all_of({dep.deployment_id: replace(dep, **changes)})


def body(**changes):
    return json.dumps(
        {
            "model": "claude-opus-5",
            "messages": [{"role": "user", "content": "Read numbers"}],
            "max_tokens": 100,
            **changes,
        }
    ).encode()


def test_model_only_preserves_features_and_continuation():
    selection = ClaudeSelection(config())
    original = body(
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        tools=[{"name": "Read", "input_schema": {"type": "object"}}],
        system=[{"type": "text", "text": "system", "cache_control": {"type": "ephemeral"}}],
    )
    raw, dep = selection.prepare(original, lineage="one", permitted=permitted(), pinned=False)
    expected = json.loads(original)
    expected["model"] = "claude-sonnet-5"
    assert json.loads(raw) == expected
    assert dep.model == "claude-sonnet-5"
    history = [
        {
            "role": "assistant",
            "content": [{"type": "thinking", "thinking": "synthetic", "signature": "SYNTHETIC"}],
        },
        {"role": "user", "content": "continue"},
    ]
    raw, _ = selection.prepare(
        body(messages=history), lineage="one", permitted=permitted(), pinned=False
    )
    assert json.loads(raw)["messages"] == history
    assert json.loads(original)["model"] == "claude-opus-5"


@pytest.mark.parametrize(
    "changes",
    [
        {"rung": Rung.LOCAL},
        {"api_base_host": "other.example"},
        {"provider": "other"},
        {"model": "other"},
        {"trust_zone": "local_host"},
    ],
)
def test_wrong_target_denied(changes):
    with pytest.raises(ValueError):
        ClaudeSelection(config()).prepare(
            body(), lineage="one", permitted=permitted(**changes), pinned=False
        )


def test_pin_removal_and_cross_lineage_denied():
    selection = ClaudeSelection(config())
    for pin, allowed in [(True, permitted()), (False, permitted().tighten([]))]:
        with pytest.raises(ValueError):
            selection.prepare(body(), lineage="one", permitted=allowed, pinned=pin)
    selection.prepare(body(), lineage="one", permitted=permitted(), pinned=False)
    with pytest.raises(ValueError):
        selection.prepare(body(), lineage="two", permitted=permitted(), pinned=False)
    with pytest.raises(ValueError):
        selection.prepare(body(), lineage="one", permitted=permitted().tighten([]), pinned=False)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"model":"claude-opus-5","model":"claude-sonnet-5"}',
        body(messages=[{"role": "assistant", "content": "old"}]),
        body(messages=[{"role": "user", "content": [{"type": "tool_result"}]}]),
    ],
)
def test_ambiguous_or_existing_session_denied(raw):
    with pytest.raises(ValueError):
        ClaudeSelection(config()).prepare(raw, lineage="one", permitted=permitted(), pinned=False)


async def test_limits_cover_forward_and_send_failures_and_response_lifetime():
    calls = []

    async def handler(request):
        calls.append(request)
        return httpx.Response(400, stream=httpx.ByteStream(b"upstream error"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = ClaudeExperimentClient(config(messages_limit=2, count_tokens_limit=1), client=http)
        response = await client.send(
            body(),
            {
                "authorization": "Bearer SYNTHETIC",
                "anthropic-beta": "oauth-SYNTHETIC",
                "host": "other.example",
                "content-length": "1",
                "x-adrl-workload-assertion": "LOCAL",
                "x-adrl-session-id": "LOCAL-SESSION",
                "x-claude-code-session-id": "NATIVE-SESSION",
            },
            path="/v1/messages",
            rung=Rung.FRONTIER,
        )
        with pytest.raises(UpstreamUnreachableError):
            await client.forward("POST", "/v1/messages", {}, body())
        assert await read_all(response) == b"upstream error"
        assert calls[0].url.host == "api.anthropic.com"
        assert calls[0].headers["host"] == "api.anthropic.com"
        assert calls[0].headers["authorization"] == "Bearer SYNTHETIC"
        assert calls[0].headers["anthropic-beta"] == "oauth-SYNTHETIC"
        assert "x-adrl-workload-assertion" not in calls[0].headers
        assert "x-adrl-session-id" not in calls[0].headers
        assert calls[0].headers["x-claude-code-session-id"] == "NATIVE-SESSION"
        await read_all(await client.forward("POST", "/v1/messages", {}, body()))
        with pytest.raises(UpstreamUnreachableError):
            await client.send(body(), {}, path="/v1/messages", rung=Rung.FRONTIER)
        await read_all(await client.forward("POST", "/v1/messages/count_tokens", {}, body()))
        with pytest.raises(UpstreamUnreachableError):
            await client.forward("POST", "/v1/messages/count_tokens", {}, body())
        await client.health()
        assert len(calls) == 3


@pytest.mark.parametrize(
    "method,path,raw",
    [
        ("GET", "/v1/messages", body()),
        ("POST", "https://other.example/v1/messages", body()),
        ("POST", "/v1/messages?beta=true", body()),
        ("POST", "/v1/messages", body(max_tokens=4097)),
        ("POST", "/v1/messages", body(max_tokens=True)),
        ("POST", "/v1/messages", body(model="adrl-local")),
        ("POST", "/v1/messages", b"x" * 262145),
    ],
)
async def test_denial_before_http(method, path, raw):
    async def handler(request):
        raise AssertionError("must not dispatch")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = ClaudeExperimentClient(config(), client=http)
        with pytest.raises(UpstreamUnreachableError):
            await client.forward(method, path, {}, raw)
        assert sum(client.attempts.values()) == 0


async def test_timeout_consumes_attempt_and_no_retry():
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(1)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = ClaudeExperimentClient(config(messages_limit=1, request_seconds=0.01), client=http)
        with pytest.raises(UpstreamUnreachableError):
            await client.forward("POST", "/v1/messages", {}, body())
        with pytest.raises(UpstreamUnreachableError):
            await client.forward("POST", "/v1/messages", {}, body())
        assert len(calls) == 1 and not client.active


async def test_redirect_not_followed_and_closed_client_denied():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            307, headers={"location": "https://other.example/"}, stream=httpx.ByteStream(b"")
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as http:
        client = ClaudeExperimentClient(config(), client=http)
        response = await client.forward("POST", "/v1/messages", {}, body())
        assert response.status_code == 307
        await read_all(response)
        await client.aclose()
        with pytest.raises(UpstreamUnreachableError):
            await client.forward("POST", "/v1/messages", {}, body())
        assert len(calls) == 1


async def test_stream_deadline_releases_slot():
    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"first"
            await asyncio.sleep(1)
            yield b"late"

    def handler(request):
        return httpx.Response(200, stream=Slow())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = ClaudeExperimentClient(config(request_seconds=0.01), client=http)
        response = await client.forward("POST", "/v1/messages", {}, body())
        with pytest.raises(TimeoutError):
            await read_all(response)
        assert not client.active and client.attempts["/v1/messages"] == 1
