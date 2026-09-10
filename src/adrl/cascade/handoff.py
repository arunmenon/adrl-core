"""Cross-model handoff transform. Primary: ADRL-CAS-004. Secondary: ADRL-CAS-003.

The reasoning rule is keyed by (source family, target family, thinking on target). Tool ids
are preserved verbatim within a provider and mapped 1:1 with the mapping recorded when the
target's id format differs. The handoff note is appended after all tool_result blocks in the
last user message, never in system, and nothing here touches tools or system.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from adrl.config.models import ProviderPairRule
from adrl.core.types import HandoffNote

THINKING_TYPES: frozenset[str] = frozenset({"thinking", "redacted_thinking"})
THINKING_PARAMETERS: tuple[str, ...] = ("thinking",)
DOWNGRADE_MARKER = "[adrl: {kind} content omitted for the target provider]"
OPENAI_TOOL_ID = re.compile(r"^call_[A-Za-z0-9_-]{1,64}$")
ANTHROPIC_TOOL_ID = re.compile(r"^toolu_[A-Za-z0-9_-]{1,64}$")
UNSUPPORTED_RESULT_TYPES_BY_FAMILY: dict[str, frozenset[str]] = {
    "openai": frozenset({"image", "document"}),
    "local": frozenset({"image", "document"}),
}


class HandoffError(ValueError):
    """The transformed transcript violates a CAS-004 invariant."""


def _thinking_enabled(body: Mapping[str, Any]) -> bool:
    thinking = body.get("thinking")
    return isinstance(thinking, Mapping) and thinking.get("type") != "disabled"


def latest_assistant_has_thinking(body: Mapping[str, Any]) -> bool | None:
    """None when there is no assistant turn; else whether it carries a thinking block."""
    for message in reversed(_messages(body)):
        if message.get("role") != "assistant":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            return False
        return any(isinstance(b, dict) and b.get("type") in THINKING_TYPES for b in content)
    return None


def needs_thinking_suppression(body: Mapping[str, Any]) -> bool:
    """True when the Anthropic thinking contract would reject this request as sent.

    With thinking enabled, a final assistant message that carries tool_use must start with a
    thinking or redacted_thinking block. A turn served by a rung without thinking cannot satisfy
    that, so the request must go out with thinking disabled (ADRL-CAS-004).
    """
    if not _thinking_enabled(body):
        return False
    messages = _messages(body)
    if len(messages) < 2 or messages[-1].get("role") != "user":
        return False
    last_content = messages[-1].get("content")
    is_continuation = isinstance(last_content, list) and any(
        isinstance(b, dict) and b.get("type") == "tool_result" for b in last_content
    )
    if not is_continuation:
        return False
    previous = messages[-2]
    if previous.get("role") != "assistant":
        return False
    content = previous.get("content")
    if not isinstance(content, list) or not content:
        return False
    has_tool_use = any(isinstance(b, dict) and b.get("type") == "tool_use" for b in content)
    first = content[0] if isinstance(content[0], dict) else {}
    return has_tool_use and first.get("type") not in THINKING_TYPES


def validate_thinking_contract(body: Mapping[str, Any]) -> None:
    """Raise HandoffError when the request violates the Anthropic thinking echo rule."""
    if needs_thinking_suppression(body):
        raise HandoffError(
            "thinking is enabled but the final assistant turn starts with tool_use and carries "
            "no thinking block; Anthropic rejects this request"
        )


def without_thinking(body: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(body)
    for key in THINKING_PARAMETERS:
        out.pop(key, None)
    return out


@dataclass(frozen=True, slots=True)
class TransformResult:
    body: dict[str, Any]
    tool_id_mapping: Mapping[str, str] = field(default_factory=dict)
    stripped_blocks: int = 0
    downgraded_blocks: int = 0
    note_applied: bool = False
    thinking_disabled: bool = False

    def as_record(self) -> dict[str, Any]:
        return {
            "tool_id_mapping": dict(self.tool_id_mapping),
            "stripped_blocks": self.stripped_blocks,
            "downgraded_blocks": self.downgraded_blocks,
            "note_applied": self.note_applied,
            "thinking_disabled": self.thinking_disabled,
        }


def _messages(body: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = body.get("messages")
    return [m for m in raw if isinstance(m, dict)] if isinstance(raw, list) else []


def _strip_reasoning(
    messages: list[dict[str, Any]], *, keep_latest: bool
) -> tuple[list[dict[str, Any]], int]:
    latest_index = -1
    for index in range(len(messages) - 1, -1, -1):
        if messages[index].get("role") == "assistant":
            latest_index = index
            break
    out: list[dict[str, Any]] = []
    stripped = 0
    for index, message in enumerate(messages):
        if message.get("role") != "assistant" or not isinstance(message.get("content"), list):
            out.append(message)
            continue
        if keep_latest and index == latest_index:
            out.append(message)
            continue
        kept = [
            b
            for b in message["content"]
            if not (isinstance(b, dict) and b.get("type") in THINKING_TYPES)
        ]
        stripped += len(message["content"]) - len(kept)
        if kept:
            out.append({**message, "content": kept})
    return out, stripped


def _target_id_format(target_family: str) -> re.Pattern[str] | None:
    if target_family == "openai":
        return OPENAI_TOOL_ID
    if target_family == "anthropic":
        return ANTHROPIC_TOOL_ID
    return None


def _map_tool_ids(
    messages: list[dict[str, Any]], target_family: str
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    pattern = _target_id_format(target_family)
    if pattern is None:
        return messages, {}
    ids: list[str] = []
    for message in messages:
        if message.get("role") == "assistant" and isinstance(message.get("content"), list):
            for block in message["content"]:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and isinstance(block.get("id"), str)
                ):
                    ids.append(block["id"])
    if all(pattern.match(i) for i in ids):
        return messages, {}
    prefix = "call_" if target_family == "openai" else "toolu_"
    mapping: dict[str, str] = {}
    for index, original in enumerate(dict.fromkeys(ids)):
        mapping[original] = f"{prefix}adrl{index:04d}"
    out: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message.get("content"), list):
            out.append(message)
            continue
        blocks: list[Any] = []
        for block in message["content"]:
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_use"
                and block.get("id") in mapping
            ):
                blocks.append({**block, "id": mapping[block["id"]]})
            elif (
                isinstance(block, dict)
                and block.get("type") == "tool_result"
                and block.get("tool_use_id") in mapping
            ):
                blocks.append({**block, "tool_use_id": mapping[block["tool_use_id"]]})
            else:
                blocks.append(block)
        out.append({**message, "content": blocks})
    return out, mapping


def _downgrade_results(
    messages: list[dict[str, Any]], target_family: str
) -> tuple[list[dict[str, Any]], int]:
    unsupported = UNSUPPORTED_RESULT_TYPES_BY_FAMILY.get(target_family)
    if not unsupported:
        return messages, 0
    downgraded = 0
    out: list[dict[str, Any]] = []
    for message in messages:
        if message.get("role") != "user" or not isinstance(message.get("content"), list):
            out.append(message)
            continue
        blocks: list[Any] = []
        for block in message["content"]:
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_result"
                and isinstance(block.get("content"), list)
            ):
                inner: list[Any] = []
                for part in block["content"]:
                    if isinstance(part, dict) and part.get("type") in unsupported:
                        inner.append(
                            {"type": "text", "text": DOWNGRADE_MARKER.format(kind=part["type"])}
                        )
                        downgraded += 1
                    else:
                        inner.append(part)
                blocks.append({**block, "content": inner})
            else:
                blocks.append(block)
        out.append({**message, "content": blocks})
    return out, downgraded


def _append_note(messages: list[dict[str, Any]], note: HandoffNote) -> list[dict[str, Any]]:
    block = note.as_content_block()
    if messages and messages[-1].get("role") == "user":
        last = messages[-1]
        content = last.get("content")
        if isinstance(content, str):
            new_content: list[Any] = [{"type": "text", "text": content}, block]
        elif isinstance(content, list):
            new_content = [*content, block]
        else:
            new_content = [block]
        return [*messages[:-1], {**last, "content": new_content}]
    return [*messages, {"role": "user", "content": [block]}]


def validate_tool_pairs(messages: list[dict[str, Any]]) -> None:
    """Every tool_use retains exactly one tool_result (ADRL-CAS-004 clause 2)."""
    uses: list[str] = []
    results: dict[str, int] = {}
    for message in messages:
        if not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                uses.append(str(block.get("id")))
            elif block.get("type") == "tool_result":
                key = str(block.get("tool_use_id"))
                results[key] = results.get(key, 0) + 1
    pending = uses[-_trailing_tool_uses(messages) :] if _trailing_tool_uses(messages) else []
    for use in uses:
        count = results.get(use, 0)
        if use in pending and count == 0:
            continue
        if count != 1:
            raise HandoffError(f"tool_use {use} has {count} results after transform")


def _trailing_tool_uses(messages: list[dict[str, Any]]) -> int:
    """tool_use blocks in a trailing assistant message have no result yet by construction."""
    if not messages or messages[-1].get("role") != "assistant":
        return 0
    content = messages[-1].get("content")
    if not isinstance(content, list):
        return 0
    return sum(1 for b in content if isinstance(b, dict) and b.get("type") == "tool_use")


def transform(
    body: Mapping[str, Any], rule: ProviderPairRule, note: HandoffNote | None
) -> TransformResult:
    """Apply the provider-pair rule and append the handoff note; tools and system untouched."""
    out = copy.deepcopy(dict(body))
    messages = _messages(out)
    keep_latest = rule.action == "keep_latest_thinking"
    if keep_latest and latest_assistant_has_thinking(out) is False:
        # the source turn was served without thinking blocks: nothing to keep, and the
        # target would reject a thinking-enabled request; fall back to the handoff rule
        keep_latest = False
    messages, stripped = _strip_reasoning(messages, keep_latest=keep_latest)
    thinking_disabled = False
    if not keep_latest:
        for key in THINKING_PARAMETERS:
            if key in out:
                del out[key]
                thinking_disabled = True
    mapping: dict[str, str] = {}
    if rule.map_tool_ids:
        messages, mapping = _map_tool_ids(messages, rule.target_family)
    messages, downgraded = _downgrade_results(messages, rule.target_family)
    applied = False
    if note is not None:
        messages = _append_note(messages, note)
        applied = True
    validate_tool_pairs(messages)
    out["messages"] = messages
    if "system" in body:
        out["system"] = copy.deepcopy(body["system"])
    if "tools" in body:
        out["tools"] = copy.deepcopy(body["tools"])
    if rule.target_family == "anthropic":
        validate_thinking_contract(out)
    return TransformResult(out, mapping, stripped, downgraded, applied, thinking_disabled)


def transform_transcript(
    body: Mapping[str, Any], rule: ProviderPairRule, note: HandoffNote | None
) -> dict[str, Any]:
    return transform(body, rule, note).body
