"""Mixed-intent feature precedence and compatibility. Primary: ADRL-LRN-004.

Secondary: ADRL-RTG-002, ADRL-RTG-003, ADRL-LRN-008.
"""

from pathlib import Path

import pytest

from adrl.app import _explorer
from adrl.config.loaders import ConfigBundle
from adrl.config.settings import Settings
from adrl.core.enums import Rung, SideEffectClass
from adrl.core.errors import ConfigError
from adrl.routing.features import FEATURES_VERSION, compute_features, verb_class
from adrl.routing.router import Router
from tests.unit.routing.helpers import make_ctx, make_gate, tool_turn, user_body


@pytest.mark.parametrize(
    "prompt",
    [
        "Rename a variable and redesign the concurrency algorithm in worker.py",
        "Explain the race condition and implement a fix in worker.py",
        "Redesign the concurrency algorithm and rename a variable in worker.py",
        "Rename this variable. Implement a scheduler in worker.py",
        "Fix the typo in README.md and debug the parser crash",
        "Explain this function; create a new parser in parser.py",
        "Rename the variable called `redesign` in worker.py",
        "Do not redesign anything; only rename this variable in worker.py",
        "Explain how to implement a scheduler",
    ],
)
async def test_easy_match_does_not_hide_stronger_signal(prompt: str, bundle: ConfigBundle) -> None:
    router = Router(bundle)
    for extra in (
        [],
        tool_turn(
            "Edit", {"file_path": "a.py"}, "String to replace not found in file", is_error=True
        ),
    ):
        ctx = make_ctx(user_body(prompt, extra_messages=extra))
        decision = await router.decide(ctx, make_gate(), None)
        assert decision.rung is Rung.FRONTIER
        assert decision.features_version == "features-v2"
        assert (
            decision.features["expected_first_action_side_effect"]
            != SideEffectClass.READ_ONLY.value
        )
        pinned = await router.decide(ctx, make_gate(pinned=True), None)
        assert pinned.rung is Rung.LOCAL


@pytest.mark.parametrize(
    "prompt",
    [
        "Fix the typo in README.md",
        "Correct the misspelling in README.md",
        "Rename a variable in worker.py",
        "Explain this function in worker.py",
        "Format this file in worker.py",
    ],
)
async def test_clear_simple_cases_remain_local(prompt: str, bundle: ConfigBundle) -> None:
    decision = await Router(bundle).decide(make_ctx(user_body(prompt)), make_gate(), None)
    assert decision.rung is Rung.LOCAL


def test_whole_phrase_only_normalization_retains_later_fix() -> None:
    assert verb_class("Fix the typo and fix the parser") == ("fix", 0.55)
    assert verb_class("Fix the typo and redesign the parser") == ("hard", 0.85)
    assert verb_class("Fix the typo") == ("trivial", 0.1)
    assert verb_class("Now fix the second typo") == ("trivial", 0.1)
    assert verb_class("Add a flag in cli.py") == ("small_edit", 0.35)
    assert verb_class("Add a flag and implement a scheduler") == ("write", 0.45)


def test_feature_version_does_not_silently_admit_old_exploration(bundle: ConfigBundle) -> None:
    assert bundle.learning_contract.feature_schema_version == "features-v1"
    assert FEATURES_VERSION == "features-v2"
    assert _explorer(Settings(), bundle) is None
    with pytest.raises(ConfigError, match="does not match live feature semantics"):
        _explorer(Settings(exploration_artifact_path=Path("not-loaded.json")), bundle)


def test_latest_request_only_controls_intent(bundle: ConfigBundle) -> None:
    body = user_body("Redesign the whole module")
    body["messages"].extend(
        [
            {"role": "assistant", "content": "Previous task finished."},
            {"role": "user", "content": "Fix the typo in README.md"},
        ]
    )
    features = compute_features(make_ctx(body), bundle.policy.rule_thresholds)
    assert features["verb_class"] == "trivial"
