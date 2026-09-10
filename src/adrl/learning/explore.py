"""Logged exploration in the ambiguous band and off-policy estimation. Primary: ADRL-LRN-008.

Secondary: ADRL-LRN-002 (validation against branched pairs), ADRL-LRN-005 (versioned
epsilon), ADRL-SAF-001/002 (never where a gate removed a rung, never pinned), ADRL-CAS-005
(never mid-episode).

The policy returns the rung it explored to and the propensity actually used. A non-explored
turn logs propensity 1.0. Structurally conforms to the routing package's Explorer Protocol
without importing it at runtime.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor  # type: ignore[import-untyped]

from adrl.core.enums import Rung
from adrl.core.types import PermittedSet, RequestContext
from adrl.learning.pairs import PairOutcome, mcnemar_counts

EPSILON_UPPER_BOUND = 0.10
EXPLORE_ARTIFACT_KIND = "exploration"


class ExplorationBoundsError(ValueError):
    """Epsilon outside the EVL-set bound (ADRL-LRN-008 clause 2)."""


@dataclass(frozen=True, slots=True)
class ExplorationArtifact:
    """Versioned exploration rule; changing epsilon is a new version (clause 5)."""

    version: str
    epsilon_by_rung: Mapping[Rung, float]
    graduated: bool = False

    def __post_init__(self) -> None:
        for rung, eps in self.epsilon_by_rung.items():
            if not 0.0 <= eps <= EPSILON_UPPER_BOUND:
                raise ExplorationBoundsError(
                    f"epsilon for {rung.value} is {eps}; bound is {EPSILON_UPPER_BOUND}"
                )
        if sum(self.epsilon_by_rung.values()) > 1.0:
            raise ExplorationBoundsError("epsilons sum above 1")


@dataclass(frozen=True, slots=True)
class ExplorationContext:
    """What the deterministic policy hands the explorer at a decision boundary."""

    band_id: str
    is_ambiguous: bool
    permitted: PermittedSet
    gate_removed_any: bool
    pinned: bool
    first_decision_of_episode: bool
    default_rung: Rung


@dataclass(frozen=True, slots=True)
class ExplorationChoice:
    rung: Rung | None
    propensity: float
    explore_version: str | None
    reason: str

    @property
    def explored(self) -> bool:
        return self.rung is not None


@dataclass(slots=True)
class ExplorationPolicy:
    artifact: ExplorationArtifact | None
    rng: random.Random = field(default_factory=lambda: random.Random(0))  # noqa: S311

    def sample(self, ctx: ExplorationContext) -> ExplorationChoice:
        """Explore only where every clause of ADRL-LRN-008 permits it."""
        if self.artifact is None or not self.artifact.graduated:
            return ExplorationChoice(None, 1.0, None, "no graduated exploration artifact")
        if not ctx.is_ambiguous:
            return ExplorationChoice(None, 1.0, None, "clear band")
        if ctx.pinned:
            return ExplorationChoice(None, 1.0, None, "pinned lineage")
        if ctx.gate_removed_any:
            return ExplorationChoice(None, 1.0, None, "a hard gate removed a rung")
        if not ctx.first_decision_of_episode:
            return ExplorationChoice(None, 1.0, None, "mid-episode")
        candidates = [
            (rung, eps)
            for rung, eps in self.artifact.epsilon_by_rung.items()
            if rung in ctx.permitted and rung is not ctx.default_rung and eps > 0.0
        ]
        if not candidates:
            return ExplorationChoice(None, 1.0, None, "no explorable rung")
        draw = self.rng.random()
        cumulative = 0.0
        for rung, eps in candidates:
            cumulative += eps
            if draw < cumulative:
                return ExplorationChoice(rung, eps, self.artifact.version, "explored")
        default_propensity = 1.0 - sum(eps for _, eps in candidates)
        return ExplorationChoice(None, default_propensity, self.artifact.version, "default rung")


@dataclass(frozen=True, slots=True)
class RoutingExplorationChoice:
    """Shape the routing `Explorer` port consumes: rung, propensity, version (ADRL-LRN-008)."""

    rung: Rung
    propensity: float
    explore_version: str


class RoutingExplorerAdapter:
    """Implements `adrl.routing.advisor.Explorer` structurally without importing routing.

    The router calls the explorer only at a fresh decision boundary, on the ambiguous band, when
    no gate removed a rung, on an unpinned lineage and outside an escalated episode; the adapter
    re-checks the clauses it can see and hands the rest to `ExplorationPolicy`. A non-explored
    turn under an active artifact still carries its default-arm propensity so the logged value
    is the one actually used (clause 3).
    """

    def __init__(self, policy: ExplorationPolicy) -> None:
        self._policy = policy

    @property
    def version(self) -> str:
        artifact = self._policy.artifact
        return artifact.version if artifact is not None else "none"

    def explore(
        self,
        ctx: RequestContext,
        features: Mapping[str, Any],
        band_id: str,
        permitted: PermittedSet,
        default: Rung,
    ) -> RoutingExplorationChoice | None:
        del ctx, features
        context = ExplorationContext(
            band_id=band_id,
            is_ambiguous=True,
            permitted=permitted,
            gate_removed_any=permitted.rungs != PermittedSet.all().rungs,
            pinned=False,
            first_decision_of_episode=True,
            default_rung=default,
        )
        choice = self._policy.sample(context)
        if choice.explore_version is None:
            return None
        return RoutingExplorationChoice(
            rung=choice.rung if choice.rung is not None else default,
            propensity=choice.propensity,
            explore_version=choice.explore_version,
        )


def exploration_policy_from_manifest(
    epsilon_by_rung: Mapping[str, float], version: str, *, graduated: bool, seed: int = 0
) -> ExplorationPolicy:
    """Build the policy from manifest fields (rung names to epsilon)."""
    artifact = ExplorationArtifact(
        version=version,
        epsilon_by_rung={Rung(name): float(eps) for name, eps in epsilon_by_rung.items()},
        graduated=graduated,
    )
    return ExplorationPolicy(artifact, rng=random.Random(seed))  # noqa: S311


# off-policy evaluation ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoggedTurn:
    """One logged decision with the propensity actually used (ADRL-LRN-008 clause 2)."""

    features: np.ndarray
    rung: Rung
    propensity: float
    reward: float


TargetPolicy = Callable[[np.ndarray], Mapping[Rung, float]]


@dataclass(slots=True)
class RewardModel:
    """Per-rung reward regressors q(x, a) fitted on logged data."""

    make: Callable[[], Any] = lambda: GradientBoostingRegressor(
        n_estimators=100, max_depth=2, random_state=0
    )
    _models: dict[Rung, Any] = field(default_factory=dict)
    _fallback: dict[Rung, float] = field(default_factory=dict)

    def fit(self, turns: Sequence[LoggedTurn]) -> RewardModel:
        for rung in Rung:
            rows = [t for t in turns if t.rung is rung]
            if len(rows) >= 5:
                matrix = np.vstack([t.features for t in rows])
                y = np.asarray([t.reward for t in rows])
                model = self.make()
                model.fit(matrix, y)
                self._models[rung] = model
            self._fallback[rung] = float(np.mean([t.reward for t in rows])) if rows else 0.0
        return self

    def predict(self, x: np.ndarray, rung: Rung) -> float:
        model = self._models.get(rung)
        if model is None:
            return self._fallback.get(rung, 0.0)
        return float(model.predict(x.reshape(1, -1))[0])


@dataclass(frozen=True, slots=True)
class OpeEstimate:
    value: float
    std_error: float
    n: int
    estimator: str = "doubly-robust-v1"


def doubly_robust_value(
    turns: Sequence[LoggedTurn], target: TargetPolicy, reward_model: RewardModel
) -> OpeEstimate:
    """Doubly-robust estimate of the target policy's value over logged propensities."""
    if not turns:
        raise ValueError("no logged turns")
    contributions: list[float] = []
    for turn in turns:
        if turn.propensity <= 0.0:
            raise ValueError("logged propensity must be positive; deterministic logs have none")
        pi = target(turn.features)
        direct = sum(pi.get(rung, 0.0) * reward_model.predict(turn.features, rung) for rung in Rung)
        weight = pi.get(turn.rung, 0.0) / turn.propensity
        correction = weight * (turn.reward - reward_model.predict(turn.features, turn.rung))
        contributions.append(direct + correction)
    values = np.asarray(contributions)
    return OpeEstimate(
        float(values.mean()),
        float(values.std(ddof=1) / np.sqrt(len(values))) if len(values) > 1 else float("inf"),
        len(values),
    )


@dataclass(frozen=True, slots=True)
class OpeValidation:
    ope_effect: float
    pair_effect: float
    tolerance: float

    @property
    def consistent(self) -> bool:
        return abs(self.ope_effect - self.pair_effect) <= self.tolerance


def validate_against_pairs(
    ope_treatment: OpeEstimate,
    ope_control: OpeEstimate,
    pairs: Sequence[PairOutcome],
    *,
    tolerance: float = 0.10,
) -> OpeValidation:
    """Compare the OPE effect with the branched-pair effect on the same slice (clause 4)."""
    better, worse = mcnemar_counts(pairs)
    pair_effect = (better - worse) / len(pairs) if pairs else 0.0
    return OpeValidation(ope_treatment.value - ope_control.value, pair_effect, tolerance)
