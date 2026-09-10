"""ADRL-LRN-001 tier rules and pooling."""

from __future__ import annotations

import pytest

from adrl.core.enums import EvidenceTier, FailureType, OutcomeState, VerificationResult
from adrl.learning.tiers import (
    PoolingError,
    TieredDataset,
    assert_holdout_is_t1,
    assign_tier,
    verifier_precision_from_runs,
)
from tests.unit.learning.conftest import make_example


def test_t1_requires_every_condition(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    ok = make_example(0)
    assert assign_tier(ok, contract, good_precision).tier is EvidenceTier.T1

    closed_turn = make_example(1, state=OutcomeState.CLOSED_TURN)
    assert assign_tier(closed_turn, contract, good_precision).tier is EvidenceTier.T2

    indeterminate = make_example(2, verification=VerificationResult.INDETERMINATE, proxy=True)
    assert assign_tier(indeterminate, contract, good_precision).tier is EvidenceTier.T3

    drifted = make_example(3, tree_drift=True)
    assert assign_tier(drifted, contract, good_precision).tier is None

    for excluded in (
        FailureType.INFRASTRUCTURE,
        FailureType.POLICY_CONSTRAINT,
        FailureType.CONTEXT_FEASIBILITY,
        FailureType.USER_ABORT,
        FailureType.UNVERIFIABLE,
        FailureType.HARNESS_DIALECT,
    ):
        example = make_example(4, failure=excluded, verification=VerificationResult.FAIL)
        assert assign_tier(example, contract, good_precision).tier is None

    capability = make_example(
        5, failure=FailureType.TASK_CAPABILITY, verification=VerificationResult.FAIL
    )
    assert assign_tier(capability, contract, good_precision).tier is EvidenceTier.T1


def test_verifier_precision_below_threshold_demotes_to_t2(contract) -> None:  # type: ignore[no-untyped-def]
    flaky = {
        "verifier-v1": verifier_precision_from_runs(
            "verifier-v1",
            [[VerificationResult.PASS] * 10] * 5
            + [[VerificationResult.PASS] * 5 + [VerificationResult.FAIL] * 5] * 5,
        )
    }
    assert flaky["verifier-v1"].flake_rate == pytest.approx(0.5)
    assert assign_tier(make_example(0), contract, flaky).tier is EvidenceTier.T2
    assert assign_tier(make_example(0), contract, None).tier is EvidenceTier.T2


def test_sources_map_to_their_own_tiers(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    assert (
        assign_tier(make_example(0, source="simulator"), contract, good_precision).tier
        is EvidenceTier.T4
    )
    assert (
        assign_tier(make_example(0, source="counterfactual"), contract, good_precision).tier
        is EvidenceTier.T5
    )
    assert (
        assign_tier(
            make_example(0, explore_version="explore-v1", propensity=0.1), contract, good_precision
        ).tier
        is EvidenceTier.EXPLORE
    )


def test_pooling_is_refused(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    organic = TieredDataset.build([make_example(i) for i in range(3)], contract, good_precision)
    counterfactual = TieredDataset.build(
        [make_example(i, source="counterfactual") for i in range(3)], contract, good_precision
    )
    with pytest.raises(PoolingError):
        organic.merge(counterfactual)
    with pytest.raises(PoolingError):
        TieredDataset.build(
            [make_example(0), make_example(1, source="simulator")], contract, good_precision
        )
    assert organic.tier_mix()["T1"] == 3
    assert organic.objective_examples() and not organic.weak_signal_examples()


def test_holdout_with_t3_is_rejected(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    dataset = TieredDataset.build(
        [make_example(0), make_example(1, verification=None, proxy=True)], contract, good_precision
    )
    with pytest.raises(PoolingError, match="T3"):
        assert_holdout_is_t1(dataset.examples)
    assert_holdout_is_t1(dataset.objective_examples())


def test_excluded_and_pinned_fractions(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    dataset = TieredDataset.build(
        [make_example(0), make_example(1, tree_drift=True, pinned=True)], contract, good_precision
    )
    assert dataset.excluded_fraction() == pytest.approx(0.5)
    assert dataset.pinned_fraction() == pytest.approx(0.5)
    assert "tree drift excludes the verification (ADRL-MEM-003)" in dataset.exclusion_reasons()
