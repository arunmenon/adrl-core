"""CATE estimator for the marginal effect of a higher rung. Primary: ADRL-LRN-003.

Secondary: ADRL-LRN-001 (T1-only evaluation), ADRL-LRN-004 (forbidden targets).

tau(x) = E[Y(treatment rung) - Y(control rung) | x]. Three rungs give two pairwise effects.
The estimator outputs a calibrated effect with an uncertainty, never a rung; RTG combines
the effect with post-cache marginal cost. The forbidden label is the heuristic's own
decision; the permitted label is a comparative verified outcome.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression, Ridge  # type: ignore[import-untyped]

from adrl.config.models import LearningContract
from adrl.core.enums import EvidenceTier, Rung
from adrl.learning.dataset import FeatureFrame, labels, treatments

ESTIMATOR_VERSION = "cate-xlearner-v1"


class ForbiddenTargetError(ValueError):
    """A training target that is the heuristic's own decision (ADRL-LRN-003 clause 4)."""


def check_target_columns(columns: Sequence[str], contract: LearningContract) -> None:
    forbidden = [c for c in columns if c in contract.forbidden_targets]
    if forbidden:
        raise ForbiddenTargetError(
            "forbidden target column(s): " + ",".join(forbidden) + " (ADRL-LRN-003)"
        )


class EffectPair(StrEnum):
    FRONTIER_VS_CHEAP_CLOUD = "frontier_vs_cheap_cloud"
    CHEAP_CLOUD_VS_LOCAL = "cheap_cloud_vs_local"

    @property
    def treatment(self) -> Rung:
        return Rung.FRONTIER if self is EffectPair.FRONTIER_VS_CHEAP_CLOUD else Rung.CHEAP_CLOUD

    @property
    def control(self) -> Rung:
        return Rung.CHEAP_CLOUD if self is EffectPair.FRONTIER_VS_CHEAP_CLOUD else Rung.LOCAL


class Regressor(Protocol):
    def fit(self, matrix: np.ndarray, y: np.ndarray) -> Any: ...

    def predict(self, matrix: np.ndarray) -> np.ndarray: ...


RegressorFactory = Callable[[], Regressor]


def default_regressor() -> Regressor:
    model: Regressor = GradientBoostingRegressor(
        n_estimators=200, max_depth=3, learning_rate=0.05, random_state=0
    )
    return model


def linear_regressor() -> Regressor:
    model: Regressor = Ridge(alpha=1.0)
    return model


class MetaLearner(Protocol):
    name: str

    def fit(self, matrix: np.ndarray, t: np.ndarray, y: np.ndarray) -> MetaLearner: ...

    def effect(self, matrix: np.ndarray) -> np.ndarray: ...


@dataclass(slots=True)
class SLearner:
    """Single model with treatment as a feature. Baseline only: shrinks tau toward zero."""

    make: RegressorFactory = linear_regressor
    name: str = "s-learner"
    _model: Regressor | None = None

    def fit(self, matrix: np.ndarray, t: np.ndarray, y: np.ndarray) -> SLearner:
        self._model = self.make()
        self._model.fit(np.column_stack([matrix, t]), y)
        return self

    def effect(self, matrix: np.ndarray) -> np.ndarray:
        if self._model is None:
            raise ValueError("not fitted")
        ones = np.ones(len(matrix))
        treated = np.asarray(self._model.predict(np.column_stack([matrix, ones])), dtype=float)
        control = np.asarray(self._model.predict(np.column_stack([matrix, 0 * ones])), dtype=float)
        effect: np.ndarray = treated - control
        return effect


@dataclass(slots=True)
class TLearner:
    """Two outcome models, one per arm."""

    make: RegressorFactory = default_regressor
    name: str = "t-learner"
    _mu0: Regressor | None = None
    _mu1: Regressor | None = None

    def fit(self, matrix: np.ndarray, t: np.ndarray, y: np.ndarray) -> TLearner:
        self._mu0 = self.make()
        self._mu1 = self.make()
        self._mu0.fit(matrix[t == 0], y[t == 0])
        self._mu1.fit(matrix[t == 1], y[t == 1])
        return self

    def effect(self, matrix: np.ndarray) -> np.ndarray:
        if self._mu0 is None or self._mu1 is None:
            raise ValueError("not fitted")
        mu1 = np.asarray(self._mu1.predict(matrix), dtype=float)
        mu0 = np.asarray(self._mu0.predict(matrix), dtype=float)
        effect: np.ndarray = mu1 - mu0
        return effect


@dataclass(slots=True)
class XLearner:
    """Kunzel et al. X-learner; preferred while pairs are few and arms are unbalanced."""

    make: RegressorFactory = default_regressor
    name: str = "x-learner"
    _mu0: Regressor | None = None
    _mu1: Regressor | None = None
    _tau0: Regressor | None = None
    _tau1: Regressor | None = None
    _propensity: Any = None

    def fit(self, matrix: np.ndarray, t: np.ndarray, y: np.ndarray) -> XLearner:
        if (t == 1).sum() < 2 or (t == 0).sum() < 2:
            raise ValueError("each arm needs at least two examples")
        self._mu0 = self.make()
        self._mu1 = self.make()
        self._mu0.fit(matrix[t == 0], y[t == 0])
        self._mu1.fit(matrix[t == 1], y[t == 1])
        imputed_1 = y[t == 1] - np.asarray(self._mu0.predict(matrix[t == 1]))
        imputed_0 = np.asarray(self._mu1.predict(matrix[t == 0])) - y[t == 0]
        self._tau1 = self.make()
        self._tau0 = self.make()
        self._tau1.fit(matrix[t == 1], imputed_1)
        self._tau0.fit(matrix[t == 0], imputed_0)
        self._propensity = LogisticRegression(max_iter=1000).fit(matrix, t)
        return self

    def effect(self, matrix: np.ndarray) -> np.ndarray:
        if self._tau0 is None or self._tau1 is None or self._propensity is None:
            raise ValueError("not fitted")
        g = np.asarray(self._propensity.predict_proba(matrix)[:, 1], dtype=float)
        tau0 = np.asarray(self._tau0.predict(matrix), dtype=float)
        tau1 = np.asarray(self._tau1.predict(matrix), dtype=float)
        effect: np.ndarray = g * tau0 + (1.0 - g) * tau1
        return effect


# uncertainty ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EffectEstimate:
    """A calibrated effect with an uncertainty; never a rung (ADRL-LRN-003 clause 3)."""

    pair: EffectPair
    tau: np.ndarray
    std: np.ndarray
    lower: np.ndarray
    upper: np.ndarray
    n_bootstrap: int
    estimator: str
    estimator_version: str = ESTIMATOR_VERSION

    def error_probability(self) -> np.ndarray:
        """Probability the sign of the effect is wrong, from the bootstrap normal approx."""
        from statistics import NormalDist

        normal = NormalDist()
        z = np.abs(self.tau) / np.maximum(self.std, 1e-9)
        return np.asarray([1.0 - normal.cdf(float(v)) for v in z])


def bootstrap_effect(
    make_learner: Callable[[], MetaLearner],
    matrix: np.ndarray,
    t: np.ndarray,
    y: np.ndarray,
    query: np.ndarray,
    *,
    pair: EffectPair,
    n_bootstrap: int = 50,
    seed: int = 0,
    alpha: float = 0.1,
) -> EffectEstimate:
    rng = np.random.default_rng(seed)
    point = make_learner().fit(matrix, t, y).effect(query)
    draws: list[np.ndarray] = []
    n = len(matrix)
    for _ in range(n_bootstrap):
        idx = rng.integers(0, n, size=n)
        tb = t[idx]
        if tb.sum() < 2 or (1 - tb).sum() < 2:
            continue
        draws.append(make_learner().fit(matrix[idx], tb, y[idx]).effect(query))
    if draws:
        stack = np.vstack(draws)
        std = stack.std(axis=0)
        lower = np.quantile(stack, alpha / 2, axis=0)
        upper = np.quantile(stack, 1 - alpha / 2, axis=0)
    else:
        std = np.full(len(query), np.inf)
        lower = np.full(len(query), -np.inf)
        upper = np.full(len(query), np.inf)
    learner_name = make_learner().name
    return EffectEstimate(pair, point, std, lower, upper, len(draws), learner_name)


# two effects for three rungs ---------------------------------------------------------------


@dataclass(slots=True)
class CateEstimator:
    """Two pairwise effects (frontier vs cheap_cloud, cheap_cloud vs local)."""

    contract: LearningContract
    make_learner: Callable[[], MetaLearner] = XLearner
    n_bootstrap: int = 50
    fitted: dict[EffectPair, tuple[np.ndarray, np.ndarray, np.ndarray]] = field(
        default_factory=dict
    )

    def fit(self, frame: FeatureFrame, matrix: np.ndarray) -> CateEstimator:
        check_target_columns(["verified_outcome"], self.contract)
        if any(r.tier is not EvidenceTier.T1 for r in frame.rows):
            raise ValueError("estimator objective accepts T1 only (ADRL-LRN-001)")
        y = labels(frame)
        for pair in EffectPair:
            mask = np.asarray(
                [r.rung in (pair.treatment, pair.control) for r in frame.rows], dtype=bool
            )
            if mask.sum() < 4:
                continue
            subset = FeatureFrame([r for r, keep in zip(frame.rows, mask, strict=True) if keep])
            t = treatments(subset, pair.treatment)
            self.fitted[pair] = (matrix[mask], t, y[mask])
        return self

    def predict(self, query: np.ndarray, *, seed: int = 0) -> dict[EffectPair, EffectEstimate]:
        out: dict[EffectPair, EffectEstimate] = {}
        for pair, (matrix, t, y) in self.fitted.items():
            out[pair] = bootstrap_effect(
                self.make_learner,
                matrix,
                t,
                y,
                query,
                pair=pair,
                n_bootstrap=self.n_bootstrap,
                seed=seed,
            )
        return out


# pairwise preference baseline ---------------------------------------------------------------


@dataclass(slots=True)
class PairwisePreferenceBaseline:
    """RouteLLM-style baseline: P(treatment arm's verified outcome is better | x)."""

    name: str = "pairwise-preference-logistic"
    _model: Any = None

    def fit(self, matrix: np.ndarray, treatment_better: np.ndarray) -> PairwisePreferenceBaseline:
        if len(set(treatment_better.tolist())) < 2:
            raise ValueError("need both preference outcomes to fit")
        self._model = LogisticRegression(max_iter=1000).fit(matrix, treatment_better)
        return self

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
        if self._model is None:
            raise ValueError("not fitted")
        return np.asarray(self._model.predict_proba(matrix)[:, 1])

    def evaluate_t1_only(
        self, frame: FeatureFrame, matrix: np.ndarray, treatment_better: np.ndarray
    ) -> Mapping[str, float]:
        if any(r.tier is not EvidenceTier.T1 for r in frame.rows):
            raise ValueError("baseline is evaluated T1-only (ADRL-LRN-003 follow-up)")
        p = self.predict_proba(matrix)
        accuracy = float(((p >= 0.5) == (treatment_better >= 0.5)).mean())
        brier = float(((p - treatment_better) ** 2).mean())
        return {"accuracy": accuracy, "brier": brier, "n": float(len(p))}


def effect_error(estimate: np.ndarray, truth: np.ndarray) -> float:
    return float(np.sqrt(np.mean((estimate - truth) ** 2)))
