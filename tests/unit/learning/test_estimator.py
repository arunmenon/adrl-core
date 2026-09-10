"""ADRL-LRN-003 estimand, learners and forbidden targets."""

from __future__ import annotations

import numpy as np
import pytest

from adrl.learning.estimator import (
    EffectPair,
    ForbiddenTargetError,
    PairwisePreferenceBaseline,
    SLearner,
    XLearner,
    bootstrap_effect,
    check_target_columns,
    effect_error,
)
from tests.unit.learning.conftest import synthetic_effect_data


def test_served_rung_target_is_rejected(contract) -> None:  # type: ignore[no-untyped-def]
    for column in ("served_rung", "decision", "decided_rung"):
        with pytest.raises(ForbiddenTargetError):
            check_target_columns([column], contract)
    check_target_columns(["verified_outcome"], contract)


def test_x_learner_beats_s_learner_on_heterogeneous_effect() -> None:
    matrix, t, y, tau = synthetic_effect_data(n=1500)
    s_error = effect_error(SLearner().fit(matrix, t, y).effect(matrix), tau)
    x_error = effect_error(XLearner().fit(matrix, t, y).effect(matrix), tau)
    assert x_error < s_error * 0.6
    assert abs(SLearner().fit(matrix, t, y).effect(matrix).std()) < tau.std() * 0.2


def test_bootstrap_outputs_effect_with_uncertainty_never_a_rung() -> None:
    matrix, t, y, _ = synthetic_effect_data(n=200)
    estimate = bootstrap_effect(
        XLearner, matrix, t, y, matrix[:5], pair=EffectPair.FRONTIER_VS_CHEAP_CLOUD, n_bootstrap=5
    )
    assert estimate.tau.shape == (5,) and estimate.std.shape == (5,)
    assert (estimate.lower <= estimate.upper).all()
    assert estimate.error_probability().min() >= 0.0
    assert estimate.pair.treatment.value == "frontier"


def test_pairwise_preference_baseline_evaluates_t1_only(contract, good_precision) -> None:  # type: ignore[no-untyped-def]
    from adrl.learning.dataset import build_frame
    from adrl.learning.tiers import TieredDataset
    from tests.unit.learning.conftest import make_example

    rng = np.random.default_rng(0)
    matrix = rng.normal(size=(40, 2))
    better = (matrix[:, 0] > 0).astype(float)
    baseline = PairwisePreferenceBaseline().fit(matrix, better)
    t1 = TieredDataset.build([make_example(i) for i in range(40)], contract, good_precision)
    frame = build_frame(t1.objective_examples(), contract)
    metrics = baseline.evaluate_t1_only(frame, matrix, better)
    assert metrics["accuracy"] > 0.8
    t3 = TieredDataset.build(
        [make_example(i, verification=None, proxy=True) for i in range(40)],
        contract,
        good_precision,
    )
    with pytest.raises(ValueError, match="T1-only"):
        baseline.evaluate_t1_only(build_frame(t3.examples, contract), matrix, better)
