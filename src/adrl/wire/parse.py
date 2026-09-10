"""Read-only view of an inbound request. Primary: ADRL-SEM-001. Secondary: ADRL-FND-001.

The body bytes are kept verbatim; the JSON view exists for inspection only and is never
re-serialised on the passthrough path. Hop-by-hop headers are stripped in both directions and
Accept-Encoding is forced to identity so the relay observes plaintext.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

MESSAGES_PATH = "/v1/messages"
COUNT_TOKENS_PATH = "/v1/messages/count_tokens"

HOP_BY_HOP: frozenset[str] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "accept-encoding",
    }
)
LOCAL_HEADERS: frozenset[str] = frozenset({"x-adrl-workload-assertion", "x-adrl-session-id"})
REDACT_HEADERS: frozenset[str] = (
    frozenset({"authorization", "x-api-key", "cookie", "set-cookie"}) | LOCAL_HEADERS
)

HEADER_SESSION_ID = "x-claude-code-session-id"
HEADER_AGENT_ID = "x-claude-code-agent-id"
HEADER_PARENT_AGENT_ID = "x-claude-code-parent-agent-id"

_EMPTY: Mapping[str, Any] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ParsedRequest:
    """Inbound request as received. `json` is a read-only view; `body` is authoritative."""

    method: str
    path: str
    query: str
    headers: Mapping[str, str]
    body: bytes
    json: Mapping[str, Any] = field(default=_EMPTY)
    parse_ok: bool = True

    @property
    def is_messages(self) -> bool:
        return self.path == MESSAGES_PATH

    @property
    def is_count_tokens(self) -> bool:
        return self.path == COUNT_TOKENS_PATH

    @property
    def is_api(self) -> bool:
        return self.path.startswith(MESSAGES_PATH)

    @property
    def messages(self) -> list[Any]:
        raw = self.json.get("messages")
        return list(raw) if isinstance(raw, list) else []

    @property
    def tools(self) -> list[Any]:
        raw = self.json.get("tools")
        return list(raw) if isinstance(raw, list) else []

    @property
    def max_tokens(self) -> int | None:
        raw = self.json.get("max_tokens")
        return int(raw) if isinstance(raw, int) and not isinstance(raw, bool) else None

    @property
    def requested_model(self) -> str:
        raw = self.json.get("model")
        return str(raw) if isinstance(raw, str) else ""

    @property
    def is_stream(self) -> bool:
        return bool(self.json.get("stream", False))

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def system_text(self) -> str:
        return system_text(self.json)

    @property
    def last_message(self) -> Mapping[str, Any] | None:
        return last_message(self.json)


def parse_request(
    method: str, path: str, headers: Mapping[str, str], body: bytes, query: str = ""
) -> ParsedRequest:
    """Build the read-only view. Invalid JSON yields an empty view with parse_ok False."""
    lowered = {k.lower(): v for k, v in headers.items()}
    if not body:
        return ParsedRequest(method, path, query, MappingProxyType(lowered), body, _EMPTY, True)
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return ParsedRequest(method, path, query, MappingProxyType(lowered), body, _EMPTY, False)
    if not isinstance(data, dict):
        return ParsedRequest(method, path, query, MappingProxyType(lowered), body, _EMPTY, False)
    return ParsedRequest(
        method, path, query, MappingProxyType(lowered), body, MappingProxyType(data), True
    )


def forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Headers for the upstream request: hop-by-hop removed, identity encoding forced."""
    out = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP | LOCAL_HEADERS}
    out["accept-encoding"] = "identity"
    return out


def response_headers(headers: Iterable[tuple[str, str]] | Mapping[str, str]) -> dict[str, str]:
    """Headers relayed to the harness: hop-by-hop removed, everything else untouched."""
    items = headers.items() if isinstance(headers, Mapping) else headers
    return {k: v for k, v in items if k.lower() not in HOP_BY_HOP}


def redact_for_record(headers: Mapping[str, str]) -> dict[str, str]:
    """Headers safe to persist: credentials replaced, never applied on the wire."""
    return {k: ("<redacted>" if k.lower() in REDACT_HEADERS else v) for k, v in headers.items()}


def system_text(body: Mapping[str, Any]) -> str:
    system = body.get("system")
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        parts: list[str] = []
        for block in system:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return ""


def last_message(body: Mapping[str, Any]) -> Mapping[str, Any] | None:
    messages = body.get("messages")
    if isinstance(messages, list) and messages and isinstance(messages[-1], dict):
        return messages[-1]
    return None


def content_blocks(message: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if message is None:
        return []
    content = message.get("content")
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def block_types(message: Mapping[str, Any] | None) -> tuple[str, ...]:
    return tuple(str(b.get("type", "")) for b in content_blocks(message))


def has_tool_result(message: Mapping[str, Any] | None) -> bool:
    return "tool_result" in block_types(message)


def tool_result_ids(message: Mapping[str, Any] | None) -> frozenset[str]:
    return frozenset(
        str(b.get("tool_use_id"))
        for b in content_blocks(message)
        if b.get("type") == "tool_result" and b.get("tool_use_id") is not None
    )


def tool_use_ids(message: Mapping[str, Any] | None) -> frozenset[str]:
    return frozenset(
        str(b.get("id"))
        for b in content_blocks(message)
        if b.get("type") == "tool_use" and b.get("id") is not None
    )


def last_assistant_message(body: Mapping[str, Any]) -> Mapping[str, Any] | None:
    messages = body.get("messages")
    if not isinstance(messages, list):
        return None
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "assistant":
            return message
    return None


def message_text(message: Mapping[str, Any] | None) -> str:
    return "\n".join(
        str(b.get("text", "")) for b in content_blocks(message) if b.get("type") == "text"
    )


def estimate_chars(body: Mapping[str, Any]) -> int:
    """Character count of every text-bearing field, the input to a chars-per-token estimate."""
    total = len(system_text(body))
    messages = body.get("messages")
    if not isinstance(messages, list):
        return total
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            total += len(content)
            continue
        for block in content_blocks(message):
            text = block.get("text")
            if isinstance(text, str):
                total += len(text)
            nested = block.get("content")
            if isinstance(nested, str):
                total += len(nested)
            elif isinstance(nested, list):
                for inner in nested:
                    if isinstance(inner, dict) and isinstance(inner.get("text"), str):
                        total += len(inner["text"])
            tool_input = block.get("input")
            if isinstance(tool_input, dict | list):
                total += len(json.dumps(tool_input))
    return total
