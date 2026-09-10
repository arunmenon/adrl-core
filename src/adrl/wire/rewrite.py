"""Body rewrite for non-Claude rungs. Primary: ADRL-FND-001. Secondary: ADRL-FND-002.

The frontier and passthrough paths forward the original bytes. Only a request bound for a
non-frontier rung is re-serialised, and only after stripping the fields a non-Claude endpoint
would reject: thinking, output_config, cache_control markers and server-side beta tools.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung

REWRITE_VERSION = "rewrite-v1"
STRIPPED_TOP_LEVEL: tuple[str, ...] = ("thinking", "output_config")
SERVER_TOOL_TYPE_PREFIXES: tuple[str, ...] = (
    "web_search",
    "web_fetch",
    "computer",
    "bash",
    "text_editor",
    "code_execution",
    "memory",
)


def thinking_requested(body: Mapping[str, Any]) -> bool:
    thinking = body.get("thinking")
    if not isinstance(thinking, dict):
        return False
    return thinking.get("type") in ("enabled", "adaptive")


def _strip_cache_control(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip_cache_control(v) for k, v in node.items() if k != "cache_control"}
    if isinstance(node, list):
        return [_strip_cache_control(item) for item in node]
    return node


def _is_server_tool(tool: Mapping[str, Any]) -> bool:
    if "input_schema" in tool:
        return False
    tool_type = str(tool.get("type", ""))
    return tool_type.startswith(SERVER_TOOL_TYPE_PREFIXES)


def strip_for_rung(
    body: Mapping[str, Any], rung: Rung, alias: str, bundle: ConfigBundle
) -> dict[str, Any]:
    """Return a new body for a non-frontier rung; the input mapping is never mutated."""
    if rung is Rung.FRONTIER:
        raise ValueError("frontier bodies are never rewritten (ADRL-FND-001)")
    out: dict[str, Any] = copy.deepcopy(dict(body))
    for key in STRIPPED_TOP_LEVEL:
        out.pop(key, None)
    out["model"] = alias
    if "system" in out:
        out["system"] = _strip_cache_control(out["system"])
    if "messages" in out:
        out["messages"] = _strip_cache_control(out["messages"])
    tools = out.get("tools")
    if isinstance(tools, list):
        kept = [
            _strip_cache_control(t) for t in tools if isinstance(t, dict) and not _is_server_tool(t)
        ]
        if kept:
            out["tools"] = kept
        else:
            out.pop("tools", None)
            out.pop("tool_choice", None)
    _ = bundle.rungs.rungs[rung]
    return out


def serialise(body: Mapping[str, Any]) -> bytes:
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def body_bytes_for(original: bytes, rewritten: Mapping[str, Any] | None) -> bytes:
    """Original bytes when no rewrite applies; otherwise the serialised rewrite."""
    if rewritten is None:
        return original
    return serialise(rewritten)
