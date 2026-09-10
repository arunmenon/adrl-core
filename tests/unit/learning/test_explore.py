"""ADRL-LRN-008 exploration and off-policy estimation."""

from __future__ import annotations

import random

import numpy as np
import pytest

from adrl.core.enums import Rung, VerificationResult
from adrl.core.ids import RouteId
from adrl.core.types import PermittedSet
from adrl.learning.explore import (
    ExplorationArtifact,
    ExplorationBoundsError,
    ExplorationContext,
    ExplorationPolicy,
    LoggedTurn,
    RewardModel,
    doubly_robust_value,
    validate_against_pairs,
)
from adrl.learning.pairs import ArmResult, PairOutcome

ARTIFACT = ExplorationArtifact("explore-v1", {Rung.LOCAL: 0.10}, graduated=True)


def _ctx(**overrides: object) -> ExplorationContext:
    base = dict(
        band_id="ambiguous",
        is_ambiguous=True,
        permitted=PermittedSet.all(),
        gate_removed_any=False,
        pinned=False,
        first_decision_of_episode=True,
        default_rung=Rung.FRONTIER,
    )
    base.update(overrides)
    return ExplorationContext(**base)  # type: ignore[arg-type]


def test_epsilon_bound_is_enforced() -> None:
    with pytest.raises(ExplorationBoundsError):
        ExplorationArtifact("v", {Rung.LOCAL: 0.11})


def test_non_explored_turn_logs_propensity_one() -> None:
    policy = ExplorationPolicy(ARTIFACT, rng=random.Random(7))
    choice = policy.sample(_ctx(is_ambiguous=False))
    assert choice.rung is None and choice.propensity == 1.0 and choice.explore_version is None
    ungraduated = ExplorationPolicy(ExplorationArtifact("v", {Rung.LOCAL: 0.1}))
    assert ungraduated.sample(_ctx()).propensity == 1.0


@pytest.mark.parametrize(
    "overrides",
    [
        {"pinned": True},
        {"gate_removed_any": True, "permitted": PermittedSet.only(Rung.CHEAP_CLOUD, Rung.FRONTIER)},
        {"first_decision_of_episode": False},
    ],
)
def test_no_exploration_where_prohibited(overrides: dict[str, object]) -> None:
    policy = ExplorationPolicy(ARTIFACT, rng=random.Random(0))
    for _ in range(50):
        choice = policy.sample(_ctx(**overrides))
        assert choice.rung is None and choice.propensity == 1.0


def test_explored_turns_carry_their_propensity() -> None:
    policy = ExplorationPolicy(ARTIFACT, rng=random.Random(3))
    choices = [policy.sample(_ctx()) for _ in range(500)]
    explored = [c for c in choices if c.explored]
    assert 20 < len(explored) < 80
    assert all(c.rung is Rung.LOCAL and c.propensity == 0.10 for c in explored)
    assert all(c.propensity == pytest.approx(0.90) for c in choices if not c.explored)


def test_doubly_robust_requires_propensity_and_matches_pairs() -> None:
    rng = np.random.default_rng(0)
    turns: list[LoggedTurn] = []
    for _ in range(300):
        x = rng.normal(size=2)
        rung = Rung.LOCAL if rng.uniform() < 0.3 else Rung.FRONTIER
        reward = 0.8 if rung is Rung.FRONTIER else 0.5
        turns.append(LoggedTurn(x, rung, 0.3 if rung is Rung.LOCAL else 0.7, reward))
    model = RewardModel().fit(turns)
    frontier = doubly_robust_value(turns, lambda x: {Rung.FRONTIER: 1.0}, model)
    local = doubly_robust_value(turns, lambda x: {Rung.LOCAL: 1.0}, model)
    assert frontier.value == pytest.approx(0.8, abs=0.05)
    assert local.value == pytest.approx(0.5, abs=0.05)
    pairs = [
        PairOutcome(
            "p",
            RouteId("r"),
            "s",
            ArmResult(Rung.FRONTIER, "m", VerificationResult.PASS, 0, 1.0),
            ArmResult(
                Rung.LOCAL,
                "m",
                VerificationResult.PASS if i % 10 < 7 else VerificationResult.FAIL,
                0,
                1.0,
            ),
        )
        for i in range(100)
    ]
    validation = validate_against_pairs(frontier, local, pairs, tolerance=0.1)
    assert validation.consistent
    with pytest.raises(ValueError, match="propensity"):
        doubly_robust_value([LoggedTurn(np.zeros(2), Rung.LOCAL, 0.0, 1.0)], lambda x: {}, model)
