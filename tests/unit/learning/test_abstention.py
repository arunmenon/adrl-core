"""ADRL-LRN-006 selective prediction, OOD and bounds."""

from __future__ import annotations

import numpy as np
import pytest

from adrl.core.enums import AbstainReason
from adrl.learning.abstention import (
    AbstentionBounds,
    AbstentionGate,
    ConstantEstimator,
    KnnOodDetector,
    LogisticEstimator,
    SelectiveRule,
)
from adrl.learning.dataset import build_frame
from adrl.learning.tiers import TieredDataset
from tests.unit.learning.conftest import make_example


def _gate(contract, good_precision, scorer=None):  # type: ignore[no-untyped-def]
    rng = np.random.default_rng(1)
    train_matrix = rng.normal(size=(200, 3))
    holdout = TieredDataset.build([make_example(i) for i in range(60)], contract, good_precision)
    holdout_frame = build_frame(holdout.objective_examples(), contract)
    holdout_matrix = rng.normal(size=(60, 3))
    errors = (rng.uniform(size=60) < 0.2).astype(float)
    if scorer is None:
        scorer = LogisticEstimator().fit(holdout_matrix, errors)
    gate = AbstentionGate(scorer, SelectiveRule(target_risk=0.05), KnnOodDetector(k=5))
    gate.calibrate_on_holdout(train_matrix, holdout_frame, holdout_matrix, errors)
    return gate


def test_ood_abstains_even_when_estimator_is_confident(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    gate = _gate(contract, good_precision, scorer=ConstantEstimator(score=0.01))
    far = np.array([50.0, -50.0, 50.0])
    decision = gate.decide(far)
    assert decision.act is False and decision.reason is AbstainReason.OOD


def test_reason_codes_for_degraded_and_suppressed(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    gate = _gate(contract, good_precision)
    x = np.zeros(3)
    assert gate.decide(x, degraded_memory=True).reason is AbstainReason.DEGRADED_MEMORY
    assert gate.decide(x, privacy_suppressed=True).reason is AbstainReason.PRIVACY_SUPPRESSED


def test_threshold_is_chosen_for_risk_and_coverage_falls_out(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    gate = _gate(contract, good_precision)
    point = gate.rule.point
    assert point is not None
    assert point.realised_risk <= point.target_risk
    assert 0.0 <= point.coverage <= 1.0


def test_abstention_rate_outside_bounds_is_a_blocker(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    gate = _gate(contract, good_precision, scorer=ConstantEstimator(score=0.99))
    gate.bounds = AbstentionBounds(minimum=0.05, maximum=0.5)
    for _ in range(10):
        gate.decide(np.zeros(3))
    report = gate.report()
    assert report.abstention_rate == 1.0 and report.blocker is True
    assert report.as_dict()["evl_009_blocker"] is True


def test_holdout_must_be_t1_and_time_ordered(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    t3 = TieredDataset.build(
        [make_example(i, verification=None, proxy=True) for i in range(10)],
        contract,
        good_precision,
    )
    frame = build_frame(t3.examples, contract)
    gate = AbstentionGate(ConstantEstimator(), SelectiveRule(0.05), KnnOodDetector(k=2))
    with pytest.raises(ValueError, match="T1-only"):
        gate.calibrate_on_holdout(np.zeros((10, 2)), frame, np.zeros((10, 2)), np.zeros(10))
