"""Builders for RequestContext, GateOutcome and ResponseObservation used by RTG and CAS tests."""

from __future__ import annotations

import json
from typing import Any

from adrl.core.enums import InteractionMode, RequestClass, Rung, ServedSource
from adrl.core.ids import LineageId, SessionId
from adrl.core.types import PermittedSet, RequestContext, ServedIdentity, Usage
from adrl.gates.pipeline import GateOutcome
from adrl.wire.observe import ResponseObservation, ToolUseSummary

LINEAGE = LineageId("lineage-test-0001")
SESSION = SessionId("session-test-0001")


def user_body(
    text: str = "Fix the typo in README.md",
    *,
    tools: int = 3,
    model: str = "claude-fable-5-1",
    system: str = "You are Claude Code.",
    thinking: dict[str, Any] | None = None,
    extra_messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": 64000,
        "stream": True,
        "system": system,
        "tools": [
            {"name": name, "description": name, "input_schema": {"type": "object"}}
            for name in ("Read", "Edit", "Bash")[:tools]
        ],
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }
    if extra_messages:
        body["messages"].extend(extra_messages)
    if thinking is not None:
        body["thinking"] = thinking
    return body


def make_ctx(
    body: dict[str, Any],
    request_class: RequestClass = RequestClass.USER_TURN,
    *,
    lineage: LineageId = LINEAGE,
    agent_id: str | None = None,
    mode: InteractionMode = InteractionMode.INTERACTIVE,
    headers: dict[str, str] | None = None,
) -> RequestContext:
    raw = json.dumps(body).encode()
    return RequestContext(
        body=raw,
        json=body,
        headers=headers or {"x-claude-code-session-id": "s1"},
        path="/v1/messages",
        request_class=request_class,
        content_bearing=True,
        interaction_mode=mode,
        session_hmac=SESSION,
        lineage_hmac=lineage,
        requested_model=str(body.get("model", "claude-fable-5-1")),
        is_stream=bool(body.get("stream")),
        max_tokens=body.get("max_tokens"),
        agent_id=agent_id,
    )


def make_gate(permitted: PermittedSet | None = None, *, pinned: bool = False) -> GateOutcome:
    return GateOutcome(
        permitted=permitted or (PermittedSet.local_only() if pinned else PermittedSet.all()),
        verdicts=(),
        pinned=pinned,
        unscanned=False,
        findings=(),
        block=None,
        repo_class="default",
        residency=None,
        latency_s=0.001,
    )


def make_obs(
    *,
    status: int = 200,
    rung: Rung = Rung.LOCAL,
    model: str | None = "adrl-local/qwen",
    source: ServedSource = ServedSource.GATEWAY_REPORTED,
    completed: bool = True,
    streamed_tool_content: bool = False,
    error: dict[str, Any] | None = None,
    tool_uses: tuple[ToolUseSummary, ...] = (),
    malformed: bool = False,
) -> ResponseObservation:
    return ResponseObservation(
        status=status,
        served=ServedIdentity(rung=rung, model=model, provider="fake", source=source),
        usage=Usage(input_tokens=100, output_tokens=10),
        stop_reason="tool_use" if tool_uses else "end_turn",
        streamed_tool_content=streamed_tool_content,
        tool_uses=tool_uses,
        error=error,
        first_byte_at=0.01,
        completed=completed,
        malformed_tool_json=malformed,
        model_reported=model,
    )


def tool_turn(
    name: str, tool_input: dict[str, Any], result: str, *, is_error: bool = False, idx: int = 0
) -> list[dict[str, Any]]:
    """One assistant tool_use plus its tool_result, ids derived from idx."""
    tid = f"toolu_{idx:03d}"
    return [
        {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": tid, "name": name, "input": tool_input}],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": tid, "content": result, "is_error": is_error}
            ],
        },
    ]
