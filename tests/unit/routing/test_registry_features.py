"""RTG-001 registry and LRN-004 features."""

from __future__ import annotations

import pytest

from adrl.core.enums import Rung, SideEffectClass
from adrl.routing.features import (
    FEATURES_VERSION,
    assert_no_denied_fields,
    compute_features,
)
from adrl.routing.registry import RungRegistry, effort_parameters, strip_effort_parameters
from adrl.routing.side_effects import (
    classify_command,
    classify_tool,
    executed_side_effects_since_turn_start,
)
from tests.unit.routing.helpers import make_ctx, tool_turn, user_body


def test_registry_maps_groups_and_frontier_names(registry: RungRegistry) -> None:
    assert registry.rung_for_group("adrl-local") is Rung.LOCAL
    assert registry.rung_for_model_name("claude-fable-5-1") is Rung.FRONTIER
    assert registry.rung_for_model_name("adrl-cheap-cloud") is Rung.CHEAP_CLOUD
    assert registry.rung_for_model_name("unknown-model") is None
    assert registry.alias_for(Rung.LOCAL) == "adrl-local"
    assert registry.family_for(Rung.LOCAL) == "local"
    assert registry.family_for(Rung.FRONTIER) == "anthropic"


def test_rung_without_evidence_gets_conservative_scope(registry: RungRegistry) -> None:
    local = registry.entry(Rung.LOCAL)
    assert not local.has_organic_evidence
    assert set(local.permitted_task_classes) <= {"mechanical_edit", "small_diff", "small_context"}
    assert registry.entry(Rung.FRONTIER).permits_task_class("anything_at_all")
    cheap = registry.entry(Rung.CHEAP_CLOUD)
    assert not cheap.permits_task_class("medium_diff")


def test_effort_parameters_are_dispatch_only() -> None:
    body = user_body(thinking={"type": "enabled", "budget_tokens": 4096})
    assert effort_parameters(body) == {"thinking": {"type": "enabled", "budget_tokens": 4096}}
    assert "thinking" not in strip_effort_parameters(body)


def test_features_identical_when_only_effort_differs(bundle) -> None:  # type: ignore[no-untyped-def]
    a = compute_features(make_ctx(user_body()), bundle.policy.rule_thresholds)
    b = compute_features(
        make_ctx(user_body(thinking={"type": "enabled", "budget_tokens": 8000})),
        bundle.policy.rule_thresholds,
    )
    assert a == b
    assert a["features_version"] == FEATURES_VERSION


def test_features_never_carry_denied_fields(bundle) -> None:  # type: ignore[no-untyped-def]
    features = compute_features(make_ctx(user_body()), bundle.policy.rule_thresholds)
    for key in features:
        assert not key.startswith(("served_", "outcome_", "verified_", "closed_"))
    with pytest.raises(ValueError):
        assert_no_denied_fields({"served_rung": "local"})
    with pytest.raises(ValueError):
        assert_no_denied_fields({"escalated": True})


def test_features_reflect_trajectory_and_intent(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = tool_turn(
        "Edit", {"file_path": "a.py"}, "String to replace not found in file", is_error=True, idx=1
    )
    ctx = make_ctx(user_body("Fix the failing test", extra_messages=extra))
    features = compute_features(ctx, bundle.policy.rule_thresholds)
    assert features["verb_class"] == "fix"
    assert features["recent_edit_failures"] == 1
    assert features["recent_error_results"] == 1
    deploy = compute_features(
        make_ctx(user_body("deploy this to prod now")), bundle.policy.rule_thresholds
    )
    assert deploy["destructive_intent"] is True
    assert deploy["expected_first_action_side_effect"] == SideEffectClass.DESTRUCTIVE.value


def test_side_effect_table_and_commands() -> None:
    assert classify_tool("Read", {"file_path": "x"}) is SideEffectClass.READ_ONLY
    assert classify_tool("Edit", {"file_path": "x"}) is SideEffectClass.IDEMPOTENT
    assert classify_tool("Bash", {"command": "git push origin main"}) is SideEffectClass.DESTRUCTIVE
    assert classify_tool("Bash", {"command": "git status"}) is SideEffectClass.READ_ONLY
    assert classify_tool("Bash", {"command": "pytest -q"}) is SideEffectClass.IDEMPOTENT
    assert classify_command(None) is SideEffectClass.DESTRUCTIVE
    # MCP hints are untrusted unless the server is allow-listed (ADRL-CAS-003).
    assert (
        classify_tool("mcp__x__y", {}, {"annotations": {"readOnlyHint": True}})
        is SideEffectClass.DESTRUCTIVE
    )
    assert (
        classify_tool("mcp__x__y", {}, {"annotations": {"destructiveHint": True}})
        is SideEffectClass.DESTRUCTIVE
    )


def test_executed_side_effects_enumerated_since_turn_start() -> None:
    extra = [
        *tool_turn("Read", {"file_path": "a.py"}, "content", idx=1),
        *tool_turn("Edit", {"file_path": "a.py"}, "ok", idx=2),
        *tool_turn("Bash", {"command": "rm -rf build"}, "done", idx=3),
    ]
    body = user_body("Clean and edit", extra_messages=extra)
    records = executed_side_effects_since_turn_start(body)
    assert [r.tool for r in records] == ["Bash", "Edit", "Read"]
    assert records[0].side_effect_class is SideEffectClass.DESTRUCTIVE
    assert records[2].side_effect_class is SideEffectClass.READ_ONLY
    assert records[1].target == "a.py"
    assert all(r.status == "ok" for r in records)
