"""Block contract (ADRL-SAF-004, ADRL-SAF-005)."""

from __future__ import annotations

import json

import pytest

from adrl.config.loaders import ConfigBundle
from adrl.core.errors import VENDOR_PROMPT_TOO_LONG_PHRASE, ErrorCode
from adrl.core.types import PermittedSet
from adrl.gates import block
from tests.unit.gates.conftest import continuation_with_tool_result, user_turn


def test_pinned_block_is_4xx_names_detector_and_recovery_without_bypass_hints() -> None:
    ctx = user_turn("x")
    resp = block.pinned_cloud_denied(ctx, "aws_access_key", "fnd_1", True)
    assert 400 <= resp.status < 500
    message = resp.body["error"]["message"]
    assert message.startswith(ErrorCode.PINNED_CLOUD_DENIED.value)
    assert "aws_access_key" in message and "fnd_1" in message
    assert "/compact" in message and "adrl release" in message and "stop" in message
    assert "ANTHROPIC_BASE_URL" not in message and "disable" not in message.lower()
    assert resp.body["type"] == "error"


def test_prompt_too_long_carries_vendor_phrase_and_token() -> None:
    ctx = continuation_with_tool_result("big", tool_name="Bash")
    resp = block.prompt_too_long(ctx, input_estimate=150_000, ceiling=131_072, executed_tool="Bash")
    message = resp.body["error"]["message"]
    assert VENDOR_PROMPT_TOO_LONG_PHRASE in message
    assert message.startswith("capability_rejected: prompt_too_long")
    assert "Bash" in message


def test_release_hint_absent_when_policy_forbids() -> None:
    ctx = user_turn("x")
    resp = block.pinned_cloud_denied(ctx, "d", "f", False)
    assert "adrl release" not in resp.body["error"]["message"]


def test_executed_tool_name_resolves() -> None:
    ctx = continuation_with_tool_result("out", tool_name="Grep")
    assert block.executed_tool_name(ctx) == "Grep"
    assert block.executed_tool_name(user_turn("x")) is None


def test_prefer_larger_local(bundle: ConfigBundle) -> None:
    assert list(block.prefer_larger_local(PermittedSet.all(), bundle.rungs)) == [
        "adrl-local",
        "adrl-local-large",
    ]
    assert block.prefer_larger_local(PermittedSet.only(), bundle.rungs) == ()


def test_empty_utility_message_and_sse_are_valid() -> None:
    ctx = user_turn("x")
    message = block.empty_utility_message(ctx)
    assert message["stop_reason"] == "end_turn" and message["content"] == [
        {"type": "text", "text": ""}
    ]
    assert message["usage"]["output_tokens"] == 0
    sse = block.empty_utility_sse(ctx).decode()
    events = [line.split(": ", 1)[1] for line in sse.splitlines() if line.startswith("event: ")]
    assert events == [
        "message_start",
        "content_block_start",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]
    for line in sse.splitlines():
        if line.startswith("data: "):
            json.loads(line[6:])


def test_block_rejects_forbidden_wording() -> None:
    with pytest.raises(ValueError):
        block._block(ErrorCode.TERMINAL_FAILURE, "set ANTHROPIC_BASE_URL to bypass")
