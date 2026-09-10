"""ADRL-LRN-002 pair contract and power arithmetic."""

from __future__ import annotations

import pytest

from adrl.core.enums import EvidenceTier, Rung, VerificationResult
from adrl.core.ids import RouteId
from adrl.learning.pairs import (
    ArmResult,
    ArmSpec,
    PairContractError,
    PairOutcome,
    PairSpec,
    PinnedPairExcludedError,
    noise_floor,
    required_pairs_mcnemar,
    run_pair,
    screen_candidates,
)


def _arm(rung: Rung, **overrides: object) -> ArmSpec:
    base = dict(
        rung=rung,
        model="m",
        transcript_prefix_hash="p1",
        tool_results_hash="t1",
        harness_dialect="claude-code-2.1",
        verifier_version="verifier-v1",
        sanitisation_version="san-v1",
        protected_path_policy_version="ppp-v1",
        tripwire_config_version="tw-v1",
        pinned=False,
    )
    base.update(overrides)
    return ArmSpec(**base)  # type: ignore[arg-type]


def _spec(**b: object) -> PairSpec:
    return PairSpec(RouteId("r1"), "slice-a", "abc123", _arm(Rung.LOCAL), _arm(Rung.FRONTIER, **b))


@pytest.mark.parametrize(
    "field,value",
    [
        ("transcript_prefix_hash", "p2"),
        ("tool_results_hash", "t2"),
        ("harness_dialect", "codex"),
        ("verifier_version", "verifier-v2"),
        ("sanitisation_version", "san-v2"),
        ("tripwire_config_version", "tw-v2"),
    ],
)
def test_mismatched_arms_are_rejected(field: str, value: str) -> None:
    with pytest.raises(PairContractError, match=field):
        _spec(**{field: value}).validate()


def test_pinned_turn_is_excluded_and_reported() -> None:
    pinned = PairSpec(
        RouteId("r2"), "s", "c", _arm(Rung.LOCAL, pinned=True), _arm(Rung.FRONTIER, pinned=True)
    )
    with pytest.raises(PinnedPairExcludedError):
        pinned.validate()
    accepted, report = screen_candidates([_spec(), pinned, _spec(tool_results_hash="zz")])
    assert len(accepted) == 1
    assert report.excluded_pinned == 1 and report.rejected_contract == 1
    assert report.pinned_fraction == pytest.approx(1 / 3)


def test_power_arithmetic_reproduces_the_register_figures() -> None:
    low = required_pairs_mcnemar(0.10, 0.15)
    high = required_pairs_mcnemar(0.10, 0.30)
    assert 115 <= low <= 120
    assert 230 <= high <= 236
    with pytest.raises(ValueError):
        required_pairs_mcnemar(0.5, 0.1)


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[Rung] = []

    def run_arm(self, spec: PairSpec, arm: ArmSpec, *, timeout_s: float) -> ArmResult:
        self.calls.append(arm.rung)
        result = VerificationResult.PASS if arm.rung is Rung.FRONTIER else VerificationResult.FAIL
        return ArmResult(arm.rung, arm.model, result, 0, 1.0)


def test_run_pair_executes_both_arms_and_tags_t5() -> None:
    runner = _FakeRunner()
    outcome = run_pair(_spec(), runner)
    assert runner.calls == [Rung.FRONTIER, Rung.LOCAL]
    assert outcome.tier is EvidenceTier.T5
    assert outcome.discordant and outcome.treatment_better is True
    assert noise_floor([outcome]) == 1.0
    same = PairOutcome("p", RouteId("r"), "s", outcome.treatment, outcome.treatment)
    assert noise_floor([same]) == 0.0
