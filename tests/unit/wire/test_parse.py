"""ADRL-SEM-001 parse tests."""

from __future__ import annotations

from adrl.wire.parse import (
    HOP_BY_HOP,
    estimate_chars,
    forward_headers,
    parse_request,
    redact_for_record,
    response_headers,
    tool_result_ids,
    tool_use_ids,
)

from .conftest import parsed_fixture


def test_body_bytes_are_kept_verbatim_and_json_is_a_view() -> None:
    raw = (
        b'{"model": "claude-fable-5-1", "max_tokens": 5, '
        b'"messages": [{"role":"user","content":"hi"}]}'
    )
    parsed = parse_request("POST", "/v1/messages", {"Anthropic-Version": "2023-06-01"}, raw)
    assert parsed.body is raw
    assert parsed.json["model"] == "claude-fable-5-1"
    assert parsed.max_tokens == 5
    assert parsed.header("anthropic-version") == "2023-06-01"
    assert parsed.parse_ok


def test_invalid_json_yields_empty_view_not_exception() -> None:
    parsed = parse_request("POST", "/v1/messages", {}, b"{not json")
    assert not parsed.parse_ok
    assert parsed.json == {}
    assert parsed.body == b"{not json"


def test_forward_headers_strip_hop_by_hop_and_force_identity() -> None:
    out = forward_headers(
        {"host": "proxy", "content-length": "9", "anthropic-beta": "x", "accept-encoding": "gzip"}
    )
    assert "host" not in out and "content-length" not in out
    assert out["anthropic-beta"] == "x"
    assert out["accept-encoding"] == "identity"
    assert all(k not in HOP_BY_HOP for k in out if k != "accept-encoding")


def test_response_headers_strip_hop_by_hop_only() -> None:
    out = response_headers([("transfer-encoding", "chunked"), ("x-litellm-model-id", "g/m")])
    assert out == {"x-litellm-model-id": "g/m"}


def test_redaction_is_for_records_not_the_wire() -> None:
    out = redact_for_record({"x-api-key": "sk-ant-secret", "anthropic-version": "1"})
    assert out["x-api-key"] == "<redacted>"
    assert out["anthropic-version"] == "1"


def test_tool_ids_from_fixture() -> None:
    parsed = parsed_fixture("parallel_tools_partial")
    messages = parsed.messages
    assert tool_use_ids(messages[-2]) == {"toolu_a", "toolu_b", "toolu_c"}
    assert tool_result_ids(messages[-1]) == {"toolu_a", "toolu_b"}


def test_estimate_chars_counts_nested_tool_results() -> None:
    parsed = parsed_fixture("continuation")
    assert estimate_chars(parsed.json) > len(parsed.system_text)
