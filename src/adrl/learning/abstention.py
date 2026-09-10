"""Selective prediction and out-of-distribution abstention. Primary: ADRL-LRN-006.

Secondary: ADRL-LRN-004 (feature-space OOD on the decision snapshot), ADRL-MEM-006 and
ADRL-MEM-005 (degraded-memory and privacy-suppressed reason codes), EVL-009 (bounds).

The threshold is chosen for a declared target risk on a time-ordered T1 holdout; coverage is
what falls out. OOD abstains regardless of confidence. The gate is built and tested with a
stub estimator before any real estimator exists (clause 4).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import numpy as np
from sklearn.isotonic import IsotonicRegression  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.neighbors import NearestNeighbors  # type: ignore[import-untyped]

from adrl.core.enums import AbstainReason, EvidenceTier
from adrl.learning.dataset import FeatureFrame

ABSTENTION_VERSION = "abstention-v1"


class EffectScorer(Protocol):
    """Anything that yields a raw error score in [0, 1] per row; the estimator or a stub."""

    name: str

    def error_score(self, matrix: np.ndarray) -> np.ndarray: ...


@dataclass(slots=True)
class ConstantEstimator:
    """Stub estimator: a fixed error score. Used to bring the gate to D2 first."""

    score: float = 0.5
    name: str = "stub-constant"

    def error_score(self, matrix: np.ndarray) -> np.ndarray:
        return np.full(len(matrix), self.score)


@dataclass(slots=True)
class LogisticEstimator:
    """Stub estimator: a logistic model whose predicted error is 1 - max class probability."""

    name: str = "stub-logistic"
    _model: Any = None

    def fit(self, matrix: np.ndarray, y: np.ndarray) -> LogisticEstimator:
        self._model = LogisticRegression(max_iter=1000).fit(matrix, y)
        return self

    def error_score(self, matrix: np.ndarray) -> np.ndarray:
        if self._model is None:
            raise ValueError("not fitted")
        proba = np.asarray(self._model.predict_proba(matrix))
        return 1.0 - proba.max(axis=1)


# selective prediction ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RiskCoveragePoint:
    target_risk: float
    realised_risk: float
    coverage: float
    threshold: float
    holdout_size: int
    method: str


@dataclass(slots=True)
class SelectiveRule:
    """Accept when the calibrated error probability is below the threshold (clause 1)."""

    target_risk: float
    method: str = "isotonic"
    threshold: float = 0.0
    point: RiskCoveragePoint | None = None
    _calibrator: Any = None

    def calibrate(self, raw_scores: np.ndarray, errors: np.ndarray) -> SelectiveRule:
        """Choose the threshold for the target risk; coverage falls out, never the reverse."""
        if len(raw_scores) != len(errors) or len(raw_scores) == 0:
            raise ValueError("scores and errors must be non-empty and aligned")
        if self.method == "isotonic":
            self._calibrator = IsotonicRegression(out_of_bounds="clip").fit(raw_scores, errors)
            calibrated = np.asarray(self._calibrator.predict(raw_scores))
        elif self.method == "conformal":
            self._calibrator = None
            calibrated = raw_scores
        else:
            raise ValueError(f"unknown method {self.method}")
        best_threshold = -1.0
        best_coverage = 0.0
        realised = 0.0
        total = len(calibrated)
        for value in np.unique(calibrated):
            accepted = calibrated <= value
            k = int(accepted.sum())
            risk = float(errors[accepted].sum() / k)
            if risk <= self.target_risk:
                best_threshold = float(value)
                best_coverage = k / total
                realised = risk
        if self.method == "conformal":
            quantile = 1.0 - self.target_risk
            if best_threshold < 0:
                best_threshold = float(np.quantile(calibrated, quantile))
        self.threshold = best_threshold
        self.point = RiskCoveragePoint(
            self.target_risk, realised, best_coverage, best_threshold, total, self.method
        )
        return self

    def calibrated_error(self, raw_scores: np.ndarray) -> np.ndarray:
        if self._calibrator is None:
            return raw_scores
        return np.asarray(self._calibrator.predict(raw_scores))

    def accept(self, raw_scores: np.ndarray) -> np.ndarray:
        if self.point is None:
            raise ValueError("rule is not calibrated")
        return self.calibrated_error(raw_scores) <= self.threshold


# out of distribution ----------------------------------------------------------------------


@dataclass(slots=True)
class KnnOodDetector:
    """kNN distance on the standardised decision-time feature snapshot (clause 2)."""

    k: int = 5
    quantile: float = 0.99
    threshold: float = 0.0
    _mean: np.ndarray | None = None
    _scale: np.ndarray | None = None
    _index: Any = None

    def fit(self, matrix: np.ndarray) -> KnnOodDetector:
        if len(matrix) <= self.k:
            raise ValueError("need more training rows than k")
        self._mean = matrix.mean(axis=0)
        self._scale = np.where(matrix.std(axis=0) > 0, matrix.std(axis=0), 1.0)
        standardised = self._standardise(matrix)
        self._index = NearestNeighbors(n_neighbors=self.k + 1).fit(standardised)
        distances, _ = self._index.kneighbors(standardised)
        self_distances = distances[:, 1:].mean(axis=1)
        self.threshold = float(np.quantile(self_distances, self.quantile))
        return self

    def _standardise(self, matrix: np.ndarray) -> np.ndarray:
        if self._mean is None or self._scale is None:
            raise ValueError("not fitted")
        standardised: np.ndarray = (matrix - self._mean) / self._scale
        return standardised

    def distance(self, matrix: np.ndarray) -> np.ndarray:
        if self._index is None:
            raise ValueError("not fitted")
        distances, _ = self._index.kneighbors(self._standardise(matrix), n_neighbors=self.k)
        mean_distance: np.ndarray = np.asarray(distances, dtype=float).mean(axis=1)
        return mean_distance

    def is_ood(self, matrix: np.ndarray) -> np.ndarray:
        return self.distance(matrix) > self.threshold


# the gate ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AbstentionDecision:
    act: bool
    reason: AbstainReason | None
    calibrated_error: float | None
    ood_distance: float | None


@dataclass(frozen=True, slots=True)
class AbstentionBounds:
    """Declared bounds; collapse toward 0 or rise toward 1 is an EVL-009 blocker."""

    minimum: float = 0.05
    maximum: float = 0.95


@dataclass(slots=True)
class AbstentionGate:
    scorer: EffectScorer
    rule: SelectiveRule
    ood: KnnOodDetector
    bounds: AbstentionBounds = AbstentionBounds()
    version: str = ABSTENTION_VERSION
    decisions: list[AbstentionDecision] = field(default_factory=list)

    def calibrate_on_holdout(
        self,
        train_matrix: np.ndarray,
        holdout: FeatureFrame,
        holdout_matrix: np.ndarray,
        errors: np.ndarray,
    ) -> AbstentionGate:
        """Calibrate on a time-ordered T1 holdout (clause 1); errors are 1 where the estimator
        got the routing effect wrong on that holdout row."""
        if any(r.tier is not EvidenceTier.T1 for r in holdout.rows):
            raise ValueError("calibration holdout must be T1-only (ADRL-LRN-006)")
        timestamps = [r.ts for r in holdout.rows]
        if timestamps != sorted(timestamps):
            raise ValueError("calibration holdout must be time-ordered")
        self.ood.fit(train_matrix)
        self.rule.calibrate(self.scorer.error_score(holdout_matrix), errors)
        return self

    def decide(
        self,
        x: np.ndarray,
        *,
        degraded_memory: bool = False,
        privacy_suppressed: bool = False,
    ) -> AbstentionDecision:
        row = x.reshape(1, -1)
        if privacy_suppressed:
            decision = AbstentionDecision(False, AbstainReason.PRIVACY_SUPPRESSED, None, None)
        elif degraded_memory:
            decision = AbstentionDecision(False, AbstainReason.DEGRADED_MEMORY, None, None)
        else:
            distance = float(self.ood.distance(row)[0])
            if distance > self.ood.threshold:
                decision = AbstentionDecision(False, AbstainReason.OOD, None, distance)
            else:
                raw = self.scorer.error_score(row)
                calibrated = float(self.rule.calibrated_error(raw)[0])
                if calibrated <= self.rule.threshold:
                    decision = AbstentionDecision(True, None, calibrated, distance)
                else:
                    decision = AbstentionDecision(
                        False, AbstainReason.UNCERTAIN, calibrated, distance
                    )
        self.decisions.append(decision)
        return decision

    def report(self) -> AbstentionReport:
        return AbstentionReport.from_decisions(self.decisions, self.bounds, self.rule.point)


@dataclass(frozen=True, slots=True)
class AbstentionReport:
    total: int
    abstained: int
    by_reason: dict[str, int]
    abstention_rate: float
    bounds: AbstentionBounds
    blocker: bool
    risk_coverage: RiskCoveragePoint | None

    @classmethod
    def from_decisions(
        cls,
        decisions: Sequence[AbstentionDecision],
        bounds: AbstentionBounds,
        point: RiskCoveragePoint | None,
    ) -> AbstentionReport:
        by_reason = {reason.value: 0 for reason in AbstainReason}
        abstained = 0
        for decision in decisions:
            if not decision.act and decision.reason is not None:
                abstained += 1
                by_reason[decision.reason.value] += 1
        rate = abstained / len(decisions) if decisions else 0.0
        blocker = bool(decisions) and (rate < bounds.minimum or rate > bounds.maximum)
        return cls(len(decisions), abstained, by_reason, rate, bounds, blocker, point)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "abstained": self.abstained,
            "by_reason": dict(self.by_reason),
            "abstention_rate": self.abstention_rate,
            "bounds": {"minimum": self.bounds.minimum, "maximum": self.bounds.maximum},
            "evl_009_blocker": self.blocker,
            "risk_coverage": None
            if self.risk_coverage is None
            else {
                "target_risk": self.risk_coverage.target_risk,
                "realised_risk": self.risk_coverage.realised_risk,
                "coverage": self.risk_coverage.coverage,
                "threshold": self.risk_coverage.threshold,
                "holdout_size": self.risk_coverage.holdout_size,
                "method": self.risk_coverage.method,
            },
        }
