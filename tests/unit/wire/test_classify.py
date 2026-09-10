"""ADRL-SEM-001 and ADRL-SEM-004 classification goldens."""

from __future__ import annotations

import json

import pytest

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import InteractionMode, RequestClass, UtilityKind
from adrl.proxy.observe_only import is_action_boundary
from adrl.wire.classify import UnclassifiableError, classify, previous_turn_interrupted
from adrl.wire.parse import parse_request

from .conftest import fixture_names, load_fixture, parsed_fixture


def test_fixture_corpus_is_not_vacuous() -> None:
    assert len(fixture_names()) >= 10


@pytest.mark.parametrize("name", fixture_names())
def test_label_frozen(name: str, bundle: ConfigBundle) -> None:
    data = load_fixture(name)
    parsed = parsed_fixture(name)
    result = classify(parsed, bundle.utility_fingerprints)
    expected = data["expected"]
    assert result.request_class is RequestClass(expected["request_class"])
    if "utility_kind" in expected:
        assert result.utility_kind is UtilityKind(expected["utility_kind"])
    if "fingerprint_id" in expected:
        assert result.fingerprint_id == expected["fingerprint_id"]
    if "content_bearing" in expected:
        assert result.content_bearing is expected["content_bearing"]
    if "interaction_mode" in expected:
        assert result.interaction_mode is InteractionMode(expected["interaction_mode"])
    if "is_boundary" in expected:
        assert is_action_boundary(parsed.json) is expected["is_boundary"]


def test_pre_warm_is_never_a_user_turn(bundle: ConfigBundle) -> None:
    result = classify(parsed_fixture("pre_warm"), bundle.utility_fingerprints)
    assert result.request_class is RequestClass.PRE_WARM
    assert result.inherits_route and not result.is_routed


def test_only_cosmetic_utilities_are_cosmetic(bundle: ConfigBundle) -> None:
    kinds = {
        name: classify(parsed_fixture(name), bundle.utility_fingerprints).utility_kind
        for name in ("title", "topic_detect", "compaction")
    }
    assert kinds["title"] is UtilityKind.COSMETIC
    assert kinds["topic_detect"] is UtilityKind.COSMETIC
    assert kinds["compaction"] is UtilityKind.CONTEXT_BEARING


def test_utility_fingerprint_ignores_model_name(bundle: ConfigBundle) -> None:
    data = load_fixture("title")
    data["body"]["model"] = "claude-opus-5"
    parsed = parse_request(
        "POST", "/v1/messages", data["headers"], json.dumps(data["body"]).encode()
    )
    assert classify(parsed, bundle.utility_fingerprints).fingerprint_id == "title"


def test_unparseable_on_unpinned_is_passthrough(bundle: ConfigBundle) -> None:
    parsed = parse_request("POST", "/v1/messages", {}, b"\xff\xfe")
    result = classify(parsed, bundle.utility_fingerprints)
    assert result.request_class is RequestClass.PASSTHROUGH
    assert result.fingerprint_id == "unparseable"


def test_unparseable_on_pinned_never_defaults_to_cloud(bundle: ConfigBundle) -> None:
    parsed = parse_request("POST", "/v1/messages", {}, b"\xff\xfe")
    with pytest.raises(UnclassifiableError):
        classify(parsed, bundle.utility_fingerprints, pinned=True)


def test_subagent_continuation_keeps_continuation_class(bundle: ConfigBundle) -> None:
    data = load_fixture("continuation")
    data["headers"]["x-claude-code-agent-id"] = "agent-1"
    parsed = parse_request(
        "POST", "/v1/messages", data["headers"], json.dumps(data["body"]).encode()
    )
    result = classify(parsed, bundle.utility_fingerprints)
    assert result.request_class is RequestClass.CONTINUATION
    assert result.subagent_by_header
    assert result.interaction_mode is InteractionMode.BACKGROUND_SUBAGENT


def test_interrupt_marker_detected(bundle: ConfigBundle) -> None:
    data = load_fixture("user_turn")
    data["body"]["messages"].append(
        {"role": "user", "content": "[Request interrupted by user for tool use]"}
    )
    parsed = parse_request(
        "POST", "/v1/messages", data["headers"], json.dumps(data["body"]).encode()
    )
    assert previous_turn_interrupted(parsed)
