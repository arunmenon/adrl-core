"""ADRL-FND-001 rewrite tests."""

from __future__ import annotations

import json

import pytest

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung
from adrl.wire.rewrite import body_bytes_for, strip_for_rung, thinking_requested

from .conftest import parsed_fixture


def test_frontier_is_never_rewritten(bundle: ConfigBundle) -> None:
    parsed = parsed_fixture("user_turn")
    with pytest.raises(ValueError):
        strip_for_rung(parsed.json, Rung.FRONTIER, "adrl-frontier", bundle)
    assert body_bytes_for(parsed.body, None) is parsed.body


def test_local_rewrite_strips_thinking_cache_control_and_server_tools(
    bundle: ConfigBundle,
) -> None:
    parsed = parsed_fixture("user_turn")
    assert thinking_requested(parsed.json)
    out = strip_for_rung(parsed.json, Rung.LOCAL, "adrl-local", bundle)
    assert "thinking" not in out
    assert out["model"] == "adrl-local"
    dumped = json.dumps(out)
    assert "cache_control" not in dumped
    assert all("input_schema" in t for t in out["tools"])
    assert not any(t.get("name") == "web_search" for t in out["tools"])
    assert parsed.json["model"] == "claude-fable-5-1"
    assert "thinking" in parsed.json
    assert not thinking_requested(out)


def test_rewrite_preserves_tool_ids_and_transcript(bundle: ConfigBundle) -> None:
    parsed = parsed_fixture("continuation")
    out = strip_for_rung(parsed.json, Rung.CHEAP_CLOUD, "adrl-cheap-cloud", bundle)
    ids = [
        b["id"]
        for m in out["messages"]
        for b in (m["content"] if isinstance(m["content"], list) else [])
        if b.get("type") == "tool_use"
    ]
    assert ids == ["toolu_01"]
    assert body_bytes_for(parsed.body, out) != parsed.body
