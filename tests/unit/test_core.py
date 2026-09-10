"""Core vocabulary tests: enums, precedence, permitted sets, ids, errors, handoff note."""

from __future__ import annotations

import json

import pytest

from adrl.core import (
    HANDOFF_NOTE_DELIMITER,
    ErrorCode,
    FailureType,
    HandoffNote,
    PermittedSet,
    PermittedSetWidened,
    Rung,
    ServedIdentity,
    ServedSource,
    SideEffectRecord,
    Usage,
    mint_route_id,
    render_error,
    resolve_primary,
)
from adrl.core.enums import PinLookup, SideEffectClass
from adrl.core.ids import hmac_identity, lineage_identity, route_id_timestamp_ms, session_identity


def test_rung_ordering() -> None:
    assert Rung.LOCAL < Rung.CHEAP_CLOUD < Rung.FRONTIER
    assert max(Rung) is Rung.FRONTIER
    assert Rung.ordered() == (Rung.LOCAL, Rung.CHEAP_CLOUD, Rung.FRONTIER)
    assert not Rung.LOCAL.is_cloud and Rung.CHEAP_CLOUD.is_cloud


def test_failure_precedence_pairs() -> None:
    assert resolve_primary([FailureType.TASK_CAPABILITY, FailureType.INFRASTRUCTURE]) == (
        FailureType.INFRASTRUCTURE,
        FailureType.TASK_CAPABILITY,
    )
    assert resolve_primary([FailureType.HARNESS_DIALECT, FailureType.POLICY_CONSTRAINT]) == (
        FailureType.POLICY_CONSTRAINT,
        FailureType.HARNESS_DIALECT,
    )
    assert resolve_primary([FailureType.CONTEXT_FEASIBILITY, FailureType.INFRASTRUCTURE])[0] is (
        FailureType.CONTEXT_FEASIBILITY
    )


def test_failure_precedence_defaults_to_unverifiable() -> None:
    assert resolve_primary([]) == (FailureType.UNVERIFIABLE, None)
    assert resolve_primary([FailureType.UNVERIFIABLE]) == (FailureType.UNVERIFIABLE, None)
    assert resolve_primary([FailureType.USER_ABORT, FailureType.TASK_CAPABILITY]) == (
        FailureType.USER_ABORT,
        FailureType.TASK_CAPABILITY,
    )


def test_permitted_set_only_tightens() -> None:
    full = PermittedSet.all()
    tightened = full.tighten([Rung.LOCAL, Rung.CHEAP_CLOUD])
    assert tightened.rungs == {Rung.LOCAL, Rung.CHEAP_CLOUD}
    assert tightened.highest is Rung.CHEAP_CLOUD
    local_only = tightened.remove(Rung.CHEAP_CLOUD)
    assert local_only.rungs == {Rung.LOCAL}
    with pytest.raises(PermittedSetWidened):
        local_only.tighten([Rung.LOCAL, Rung.FRONTIER])
    assert local_only.remove(Rung.LOCAL).is_empty


def test_route_ids_are_time_ordered_and_unique() -> None:
    first = mint_route_id(now_ms=1_700_000_000_000)
    second = mint_route_id(now_ms=1_700_000_000_001)
    assert first < second
    assert route_id_timestamp_ms(first) == 1_700_000_000_000
    assert len({mint_route_id() for _ in range(500)}) == 500
    assert first[14] == "7"


def test_hmac_identities_differ_by_key() -> None:
    session_a = session_identity("sess-1", b"key-a")
    session_b = session_identity("sess-1", b"key-b")
    assert session_a != session_b
    assert hmac_identity("x", b"k") == hmac_identity("x", b"k")
    parent = lineage_identity(session_a, (), b"key-a")
    child = lineage_identity(session_a, ("agent-1",), b"key-a")
    assert parent == session_a and child != parent


def test_render_error_is_protocol_error_not_assistant_content() -> None:
    body = render_error(
        ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG, "pinned lineage exceeds local window"
    )
    assert body["type"] == "error"
    assert body["error"]["type"] == "invalid_request_error"
    assert body["error"]["message"].startswith("capability_rejected: prompt_too_long")
    assert "role" not in json.dumps(body)
    assert ErrorCode.CAPABILITY_REJECTED.http_status == 400


def test_handoff_note_renders_from_ledger_fields_only() -> None:
    note = HandoffNote(
        cause="tripwire:tool_error_repeats",
        from_rung=Rung.LOCAL,
        to_rung=Rung.FRONTIER,
        executed_side_effects=(
            SideEffectRecord("Edit", "src/x.py", "ok", SideEffectClass.IDEMPOTENT),
        ),
    )
    text = note.render()
    assert text.startswith(HANDOFF_NOTE_DELIMITER) and text.endswith(HANDOFF_NOTE_DELIMITER)
    assert "schema: handoff-note-v1" in text
    assert "tool=Edit target=src/x.py status=ok class=idempotent" in text
    assert note.as_content_block()["type"] == "text"


def test_usage_merge_and_served_identity() -> None:
    start = Usage.from_anthropic({"input_tokens": 10, "cache_read_input_tokens": 5})
    delta = Usage.from_anthropic({"output_tokens": 3})
    merged = start.merged(delta)
    assert (merged.input_tokens, merged.output_tokens, merged.cache_read_input_tokens) == (10, 3, 5)
    assumed = ServedIdentity.assumed(Rung.FRONTIER, "claude-fable-5-1")
    assert assumed.source is ServedSource.ASSUMED_INTENDED


def test_pin_lookup_unknown_is_pinned() -> None:
    assert PinLookup.UNKNOWN.effective_pinned
    assert PinLookup.PINNED.effective_pinned
    assert not PinLookup.UNPINNED.effective_pinned
