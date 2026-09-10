"""Content extraction for gates: every scannable block with its position. Primary: ADRL-SAF-003.

Secondary: ADRL-SAF-006 (input estimate), ADRL-SAF-008 (path evidence). The extractor is the
only place that walks a Messages API body for the gates; it never returns raw content to any
ledger. Block keys are position plus a keyed hash so coverage can be persisted content-free.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SCANNABLE_TYPES = frozenset({"system", "tools", "text", "tool_use", "tool_result", "user_string"})
UNSCANNABLE_TYPES = frozenset({"document", "image"})
PATH_KEYS = ("file_path", "path", "filename", "notebook_path", "file", "cwd", "directory")


@dataclass(frozen=True, slots=True)
class ScanBlock:
    """One unit of content with its transcript position."""

    key: str
    message_index: int
    block_index: int
    content_type: str
    text: str
    path_hint: str | None = None

    @property
    def scannable(self) -> bool:
        return self.content_type in SCANNABLE_TYPES


def block_key(message_index: int, block_index: int, text: str, key: bytes) -> str:
    """Position plus keyed content hash; the hash is prompt-class data (ADRL-MEM-005)."""
    digest = hmac.new(key, text.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
    return f"{message_index}:{block_index}:{digest[:16]}"


def _text_of(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _path_hint(block: Mapping[str, Any]) -> str | None:
    inner = block.get("input")
    if isinstance(inner, Mapping):
        for key in PATH_KEYS:
            candidate = inner.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    return None


def _iter_system(body: Mapping[str, Any], key: bytes) -> Iterator[ScanBlock]:
    system = body.get("system")
    if isinstance(system, str):
        yield ScanBlock(block_key(-2, 0, system, key), -2, 0, "system", system)
    elif isinstance(system, list):
        for index, block in enumerate(system):
            if isinstance(block, Mapping):
                text = _text_of(block.get("text", ""))
            else:
                text = _text_of(block)
            yield ScanBlock(block_key(-2, index, text, key), -2, index, "system", text)


def _iter_tools(body: Mapping[str, Any], key: bytes) -> Iterator[ScanBlock]:
    tools = body.get("tools")
    if tools:
        text = _text_of(tools)
        yield ScanBlock(block_key(-1, 0, text, key), -1, 0, "tools", text)


def _iter_tool_result_content(
    content: Any, message_index: int, block_index: int, key: bytes, path_hint: str | None
) -> Iterator[ScanBlock]:
    if isinstance(content, str):
        yield ScanBlock(
            block_key(message_index, block_index, content, key),
            message_index,
            block_index,
            "tool_result",
            content,
            path_hint,
        )
        return
    if isinstance(content, list):
        parts: list[str] = []
        unscannable: list[str] = []
        for part in content:
            if not isinstance(part, Mapping):
                parts.append(_text_of(part))
                continue
            ptype = str(part.get("type", "text"))
            if ptype in UNSCANNABLE_TYPES:
                unscannable.append(ptype)
            else:
                parts.append(_text_of(part.get("text", part)))
        text = "\n".join(parts)
        yield ScanBlock(
            block_key(message_index, block_index, text, key),
            message_index,
            block_index,
            "tool_result",
            text,
            path_hint,
        )
        for sub_index, ptype in enumerate(unscannable):
            marker = f"{ptype}:{sub_index}"
            yield ScanBlock(
                block_key(message_index, block_index, marker, key) + f":{ptype}",
                message_index,
                block_index,
                ptype,
                "",
                path_hint,
            )
        return
    text = _text_of(content)
    yield ScanBlock(
        block_key(message_index, block_index, text, key),
        message_index,
        block_index,
        "tool_result",
        text,
        path_hint,
    )


def _iter_messages(body: Mapping[str, Any], key: bytes) -> Iterator[ScanBlock]:
    messages = body.get("messages")
    if not isinstance(messages, list):
        return
    for message_index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            continue
        content = message.get("content")
        if isinstance(content, str):
            yield ScanBlock(
                block_key(message_index, 0, content, key),
                message_index,
                0,
                "user_string",
                content,
            )
            continue
        if not isinstance(content, list):
            continue
        for block_index, block in enumerate(content):
            if not isinstance(block, Mapping):
                text = _text_of(block)
                yield ScanBlock(
                    block_key(message_index, block_index, text, key),
                    message_index,
                    block_index,
                    "text",
                    text,
                )
                continue
            btype = str(block.get("type", "text"))
            if btype == "text":
                text = _text_of(block.get("text", ""))
                yield ScanBlock(
                    block_key(message_index, block_index, text, key),
                    message_index,
                    block_index,
                    "text",
                    text,
                )
            elif btype == "tool_use":
                text = _text_of(block.get("input", {}))
                yield ScanBlock(
                    block_key(message_index, block_index, text, key),
                    message_index,
                    block_index,
                    "tool_use",
                    text,
                    _path_hint(block),
                )
            elif btype == "tool_result":
                yield from _iter_tool_result_content(
                    block.get("content", ""), message_index, block_index, key, None
                )
            elif btype in UNSCANNABLE_TYPES:
                marker = f"{btype}:{message_index}:{block_index}"
                yield ScanBlock(
                    block_key(message_index, block_index, marker, key) + f":{btype}",
                    message_index,
                    block_index,
                    btype,
                    "",
                )
            elif btype in {"thinking", "redacted_thinking"}:
                continue
            else:
                text = _text_of(block)
                yield ScanBlock(
                    block_key(message_index, block_index, text, key),
                    message_index,
                    block_index,
                    "text",
                    text,
                )


def extract_blocks(body: Mapping[str, Any], key: bytes) -> list[ScanBlock]:
    """Every block in transcript order: system, tools, then messages."""
    blocks: list[ScanBlock] = []
    blocks.extend(_iter_system(body, key))
    blocks.extend(_iter_tools(body, key))
    blocks.extend(_iter_messages(body, key))
    return blocks


def total_text(body: Mapping[str, Any]) -> str:
    """Concatenated text of everything the model would read; used for token estimates."""
    parts: list[str] = []
    for block in extract_blocks(body, b"estimate"):
        if block.text:
            parts.append(block.text)
    return "\n".join(parts)


def touched_paths(blocks: Sequence[ScanBlock]) -> list[str]:
    """Paths named by tool inputs, in order, for repository classification (ADRL-SAF-008)."""
    seen: dict[str, None] = {}
    for block in blocks:
        if block.path_hint:
            seen.setdefault(block.path_hint, None)
    return list(seen)
