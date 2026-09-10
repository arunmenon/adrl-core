"""CAS-004 handoff goldens and CAS-005/006 sticky helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from adrl.cascade.handoff import HandoffError, transform, transform_transcript
from adrl.cascade.sticky import (
    escalate,
    family_of_model,
    new_sticky,
    release_ratchet,
    with_served,
)
from adrl.core.enums import EpisodeSignal, Rung, ServedSource
from adrl.core.ids import LineageId, RouteId
from adrl.core.types import HANDOFF_NOTE_DELIMITER, HandoffNote, ServedIdentity
from tests.unit.routing.helpers import user_body


def _transcript_with_thinking() -> dict:  # type: ignore[type-arg]
    body = user_body("Fix the bug", thinking={"type": "enabled", "budget_tokens": 2048})
    body["messages"] += [
        {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "old", "signature": "sig0"},
                {
                    "type": "tool_use",
                    "id": "toolu_a",
                    "name": "Read",
                    "input": {"file_path": "a.py"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_a",
                    "content": [
                        {"type": "text", "text": "content"},
                        {
                            "type": "image",
                            "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"},
                        },
                    ],
                },
            ],
        },
        {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "latest", "signature": "sig1"},
                {"type": "redacted_thinking", "data": "opaque"},
                {
                    "type": "tool_use",
                    "id": "toolu_b",
                    "name": "Edit",
                    "input": {"file_path": "a.py"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "toolu_b", "content": "ok"},
            ],
        },
    ]
    return body


def _note() -> HandoffNote:
    return HandoffNote(cause="a_repeated_tool_calls", from_rung=Rung.LOCAL, to_rung=Rung.FRONTIER)


def test_anthropic_same_family_keeps_latest_thinking_unmodified(bundle) -> None:  # type: ignore[no-untyped-def]
    body = _transcript_with_thinking()
    rule = bundle.provider_pairs.rule_for("anthropic", "anthropic", True)
    result = transform(body, rule, _note())
    latest = [m for m in result.body["messages"] if m["role"] == "assistant"][-1]
    assert latest["content"][0] == {"type": "thinking", "thinking": "latest", "signature": "sig1"}
    assert latest["content"][1] == {"type": "redacted_thinking", "data": "opaque"}
    assert "thinking" in result.body and not result.thinking_disabled
    assert result.body["tools"] == body["tools"] and result.body["system"] == body["system"]


def test_cross_provider_strips_reasoning_and_disables_thinking(bundle) -> None:  # type: ignore[no-untyped-def]
    body = _transcript_with_thinking()
    rule = bundle.provider_pairs.rule_for("anthropic", "openai", True)
    result = transform(body, rule, _note())
    for message in result.body["messages"]:
        if message["role"] == "assistant":
            assert all(
                b["type"] not in {"thinking", "redacted_thinking"} for b in message["content"]
            )
    assert "thinking" not in result.body and result.thinking_disabled
    assert result.stripped_blocks == 3
    assert result.tool_id_mapping and all(
        v.startswith("call_") for v in result.tool_id_mapping.values()
    )
    assert result.downgraded_blocks == 1
    # the source body is untouched
    assert body["messages"][-2]["content"][0]["type"] == "thinking"


def test_local_to_anthropic_strips_and_unknown_pair_defaults(bundle) -> None:  # type: ignore[no-untyped-def]
    body = _transcript_with_thinking()
    rule = bundle.provider_pairs.rule_for("local", "anthropic", False)
    assert rule.action == "strip_and_disable"
    unknown = bundle.provider_pairs.rule_for("google", "local", True)
    assert unknown.action == "strip_and_disable" and "unknown" in unknown.note
    out = transform_transcript(body, unknown, None)
    assert all(
        b["type"] not in {"thinking", "redacted_thinking"}
        for m in out["messages"]
        if m["role"] == "assistant"
        for b in m["content"]
    )


def test_every_tool_use_has_exactly_one_result_after_transform(bundle) -> None:  # type: ignore[no-untyped-def]
    body = _transcript_with_thinking()
    rule = bundle.provider_pairs.rule_for("anthropic", "openai", False)
    out = transform_transcript(body, rule, _note())
    uses = [
        b["id"]
        for m in out["messages"]
        if m["role"] == "assistant"
        for b in m["content"]
        if b["type"] == "tool_use"
    ]
    results = [
        b["tool_use_id"]
        for m in out["messages"]
        if m["role"] == "user"
        for b in m["content"]
        if b["type"] == "tool_result"
    ]
    assert sorted(uses) == sorted(results) and len(set(results)) == len(results)
    broken = _transcript_with_thinking()
    broken["messages"][-1]["content"] = []
    with pytest.raises(HandoffError):
        transform(broken, rule, None)


def test_note_is_after_tool_results_in_last_user_message_never_in_system(bundle) -> None:  # type: ignore[no-untyped-def]
    body = _transcript_with_thinking()
    rule = bundle.provider_pairs.rule_for("anthropic", "anthropic", True)
    out = transform_transcript(body, rule, _note())
    last = out["messages"][-1]
    assert last["role"] == "user"
    assert last["content"][0]["type"] == "tool_result"
    assert last["content"][-1]["type"] == "text"
    assert last["content"][-1]["text"].startswith(HANDOFF_NOTE_DELIMITER)
    assert HANDOFF_NOTE_DELIMITER not in str(out["system"])
    assert "cause: a_repeated_tool_calls" in last["content"][-1]["text"]


def test_sticky_escalation_release_and_served_change() -> None:
    lineage = LineageId("l")
    sticky = new_sticky(lineage, RouteId("r1"), Rung.LOCAL, previous=None)
    assert sticky.turn_index == 1 and not sticky.escalated
    up = escalate(sticky, Rung.CHEAP_CLOUD)
    assert up.escalated and up.rung is Rung.CHEAP_CLOUD and up.served_source == "assumed_intended"
    now = datetime.now(UTC)
    served, changed = with_served(
        up,
        ServedIdentity(Rung.CHEAP_CLOUD, "haiku-a", "anthropic", ServedSource.GATEWAY_REPORTED),
        now,
    )
    assert not changed and served.served_model == "haiku-a" and served.last_served_at == now
    served2, changed2 = with_served(
        served,
        ServedIdentity(Rung.CHEAP_CLOUD, "haiku-b", "anthropic", ServedSource.GATEWAY_REPORTED),
        now,
    )
    assert changed2 and served2.served_model == "haiku-b"
    released = release_ratchet(served2, EpisodeSignal.CLEAR)
    assert not released.escalated and released.rung is Rung.CHEAP_CLOUD
    assert family_of_model("claude-haiku-4-5", Rung.CHEAP_CLOUD, "anthropic") == "anthropic"
    assert family_of_model("gpt-5-mini", Rung.CHEAP_CLOUD, "anthropic") == "openai"
    assert family_of_model("anything", Rung.LOCAL, "anthropic") == "local"
