"""Action boundary on the wire. Primary: ADRL-CAS-003.

A boundary is a request whose last user message answers every tool_use id of the last
assistant message with a tool_result (is_error counts). A partial set is not a boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

INTERRUPT_PREFIX = "[Request interrupted by user"


@dataclass(frozen=True, slots=True)
class BoundaryAssessment:
    is_boundary: bool
    has_pending_tool_use: bool
    tool_use_ids: tuple[str, ...]
    answered_ids: tuple[str, ...]
    unanswered_ids: tuple[str, ...]
    interrupted: bool

    def as_record(self) -> dict[str, Any]:
        return {
            "is_boundary": self.is_boundary,
            "tool_use_ids": list(self.tool_use_ids),
            "answered_ids": list(self.answered_ids),
            "unanswered_ids": list(self.unanswered_ids),
            "interrupted": self.interrupted,
        }


def _messages(body: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = body.get("messages")
    return [m for m in raw if isinstance(m, Mapping)] if isinstance(raw, list) else []


def last_assistant_message(messages: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    for message in reversed(messages):
        if message.get("role") == "assistant":
            return message
    return None


def tool_use_ids(message: Mapping[str, Any] | None) -> tuple[str, ...]:
    if message is None or not isinstance(message.get("content"), list):
        return ()
    return tuple(
        str(b["id"])
        for b in message["content"]
        if isinstance(b, Mapping) and b.get("type") == "tool_use" and b.get("id") is not None
    )


def tool_result_ids(message: Mapping[str, Any] | None) -> tuple[str, ...]:
    if message is None or not isinstance(message.get("content"), list):
        return ()
    return tuple(
        str(b["tool_use_id"])
        for b in message["content"]
        if isinstance(b, Mapping)
        and b.get("type") == "tool_result"
        and b.get("tool_use_id") is not None
    )


def user_interrupted(message: Mapping[str, Any] | None) -> bool:
    if message is None:
        return False
    content = message.get("content")
    if isinstance(content, str):
        return content.startswith(INTERRUPT_PREFIX)
    if isinstance(content, list):
        for block in content:
            if isinstance(block, Mapping) and block.get("type") == "text":
                return str(block.get("text", "")).startswith(INTERRUPT_PREFIX)
    return False


def assess_boundary(body: Mapping[str, Any]) -> BoundaryAssessment:
    messages = _messages(body)
    last = messages[-1] if messages else None
    assistant = last_assistant_message(messages)
    if last is None or last.get("role") != "user":
        return BoundaryAssessment(False, False, (), (), (), False)
    pending = tool_use_ids(assistant)
    if not pending:
        return BoundaryAssessment(True, False, (), (), (), user_interrupted(last))
    answered = tuple(i for i in tool_result_ids(last) if i in pending)
    unanswered = tuple(i for i in pending if i not in answered)
    return BoundaryAssessment(
        is_boundary=not unanswered,
        has_pending_tool_use=True,
        tool_use_ids=pending,
        answered_ids=answered,
        unanswered_ids=unanswered,
        interrupted=user_interrupted(last),
    )
