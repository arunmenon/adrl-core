"""CAS-003 boundary and CAS-001 trip-wires."""

from __future__ import annotations

import json
from pathlib import Path

from adrl.cascade.boundary import assess_boundary
from adrl.cascade.tripwires import TripwireEvaluator, WireClass
from adrl.core.enums import FailureType, Rung
from tests.conftest import REPO_ROOT
from tests.unit.routing.helpers import make_obs, tool_turn, user_body

FIXTURE = REPO_ROOT / "tests" / "fixtures" / "wire" / "escalation_parallel_tools.json"


def _fixture_with(results_key: str) -> dict:  # type: ignore[type-arg]
    data = json.loads(Path(FIXTURE).read_text())
    body = {k: v for k, v in data.items() if k not in {"partial_results", "full_results", "_doc"}}
    body["messages"] = [*body["messages"], {"role": "user", "content": data[results_key]}]
    return body


def test_partial_results_are_not_a_boundary() -> None:
    assessment = assess_boundary(_fixture_with("partial_results"))
    assert not assessment.is_boundary
    assert assessment.unanswered_ids == ("toolu_03",)


def test_full_results_are_a_boundary() -> None:
    assessment = assess_boundary(_fixture_with("full_results"))
    assert assessment.is_boundary
    assert assessment.answered_ids == ("toolu_01", "toolu_02", "toolu_03")


def test_fresh_user_turn_is_a_boundary_and_interrupt_detected() -> None:
    assert assess_boundary(user_body()).is_boundary
    body = user_body("[Request interrupted by user]")
    assert assess_boundary(body).interrupted


def _evaluator(bundle):  # type: ignore[no-untyped-def]
    return TripwireEvaluator(bundle.tripwires, bundle.policy)


def test_repeated_identical_calls_fire(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = []
    for i in range(3):
        extra += tool_turn("Read", {"file_path": "a.py"}, "same content", idx=i)
    hits = _evaluator(bundle).evaluate(user_body("fix", extra_messages=extra), Rung.LOCAL)
    assert [h.wire for h in hits] == [WireClass.REPEATED_TOOL_CALLS]
    assert hits[0].failure_type is FailureType.TASK_CAPABILITY


def test_long_running_command_with_changing_observation_is_allowed(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = []
    for i in range(3):
        extra += tool_turn("Bash", {"command": "tail -n 1 build.log"}, f"progress {i}%", idx=i)
    hits = _evaluator(bundle).evaluate(user_body("build", extra_messages=extra), Rung.LOCAL)
    assert not any(h.wire is WireClass.REPEATED_TOOL_CALLS for h in hits)


def test_alternating_calls_fire(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = []
    for i in range(6):
        name = "Read" if i % 2 == 0 else "Grep"
        extra += tool_turn(name, {"file_path": "a.py"}, "x", idx=i)
    hits = _evaluator(bundle).evaluate(user_body("fix", extra_messages=extra), Rung.CHEAP_CLOUD)
    assert any(h.wire is WireClass.REPEATED_TOOL_CALLS and "alternating" in h.detail for h in hits)


def test_dialect_invalid_calls_typed_harness_dialect(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = []
    for i in range(2):
        extra += tool_turn(
            "Edit",
            {"file_path": "a.py"},
            "String to replace not found in file",
            is_error=True,
            idx=i,
        )
    hits = _evaluator(bundle).evaluate(user_body("fix", extra_messages=extra), Rung.LOCAL)
    wires = {h.wire: h for h in hits}
    assert WireClass.INVALID_TOOL_CALLS in wires
    assert wires[WireClass.INVALID_TOOL_CALLS].failure_type is FailureType.HARNESS_DIALECT


def test_malformed_streamed_tool_json_counts_as_invalid(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = tool_turn("Edit", {"file_path": "a.py"}, "input validation error", is_error=True, idx=0)
    obs = make_obs(malformed=True)
    hits = _evaluator(bundle).evaluate(
        user_body("fix", extra_messages=extra), Rung.LOCAL, observation=obs
    )
    assert any(h.wire is WireClass.INVALID_TOOL_CALLS for h in hits)


def test_tool_error_repeats(bundle) -> None:  # type: ignore[no-untyped-def]
    extra = []
    for i in range(3):
        extra += tool_turn("Bash", {"command": f"pytest -k t{i}"}, "boom", is_error=True, idx=i)
    hits = _evaluator(bundle).evaluate(user_body("fix", extra_messages=extra), Rung.LOCAL)
    assert any(h.wire is WireClass.TOOL_ERROR_REPEATS for h in hits)


def test_attempt_budget_exhausted_without_progress_fires_even_with_no_errors(bundle) -> None:  # type: ignore[no-untyped-def]
    limit = bundle.policy.local_attempt_budget.limit
    extra = []
    for i in range(limit):
        extra += tool_turn("Bash", {"command": f"echo {i % 2}"}, "same", idx=i)
    hits = _evaluator(bundle).evaluate(user_body("fix", extra_messages=extra), Rung.LOCAL)
    assert any(h.wire is WireClass.ATTEMPT_BUDGET_EXHAUSTED for h in hits)


def test_attempt_budget_with_recent_progress_does_not_fire(bundle) -> None:  # type: ignore[no-untyped-def]
    limit = bundle.policy.local_attempt_budget.limit
    extra = []
    for i in range(limit):
        extra += tool_turn("Read", {"file_path": f"file{i}.py"}, f"content {i}", idx=i)
    hits = _evaluator(bundle).evaluate(user_body("fix", extra_messages=extra), Rung.LOCAL)
    assert not any(h.wire is WireClass.ATTEMPT_BUDGET_EXHAUSTED for h in hits)


def test_frontier_has_no_attempt_budget_wire_but_verifier_is_first_class(bundle) -> None:  # type: ignore[no-untyped-def]
    hits = _evaluator(bundle).evaluate(user_body("fix"), Rung.FRONTIER, verifier_failed=True)
    assert [h.wire for h in hits] == [WireClass.VERIFIER_FAILURE]
