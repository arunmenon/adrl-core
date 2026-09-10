"""Synthetic data for the learning package tests. No ledger content, no prompts."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from adrl.config.loaders import load_bundle
from adrl.config.models import LearningContract
from adrl.config.settings import Settings
from adrl.core.enums import FailureType, OutcomeState, Rung, VerificationResult
from adrl.core.ids import RouteId, SessionId, mint_route_id
from adrl.learning.tiers import Example, VerifierPrecision
from tests.conftest import CONFIG_DIR

START = datetime(2026, 9, 1, tzinfo=UTC)


@pytest.fixture
def contract(settings: Settings) -> LearningContract:
    return load_bundle(settings).learning_contract


@pytest.fixture
def bundle(settings: Settings):  # type: ignore[no-untyped-def]
    return load_bundle(settings)


@pytest.fixture
def good_precision() -> dict[str, VerifierPrecision]:
    return {"verifier-v1": VerifierPrecision("verifier-v1", 0.98, 0.02, 0.01, 40)}


def make_example(
    index: int,
    *,
    session: int = 0,
    rung: Rung = Rung.LOCAL,
    source: str = "organic",
    state: OutcomeState = OutcomeState.CLOSED_FINAL,
    failure: FailureType | None = None,
    verification: VerificationResult | None = VerificationResult.PASS,
    tree_drift: bool = False,
    proxy: bool | None = None,
    pinned: bool = False,
    features_version: str = "features-v1",
    features: dict | None = None,  # type: ignore[type-arg]
    explore_version: str | None = None,
    propensity: float = 1.0,
    repo_class: str | None = "default",
    intent_class: str | None = "change.fix",
) -> Example:
    ts = START + timedelta(minutes=index)
    route_id = mint_route_id(int(ts.timestamp() * 1000))
    base = {
        "request_class": "user_turn",
        "context_tokens_est": 1000 + index * 10,
        "tool_count": 12,
        "turn_index": index % 5,
        "first_action_side_effect_class": "read_only",
        "band_id": "ambiguous",
        "repo_class": repo_class,
    }
    if features:
        base.update(features)
    return Example(
        route_id=RouteId(route_id),
        session_hmac=SessionId(f"session-{session}"),
        decision_ts=ts.isoformat(),
        rung=rung,
        features=base,
        features_version=features_version,
        source=source,  # type: ignore[arg-type]
        outcome_state=state,
        failure_type=failure,
        verification=verification,
        tree_drift=tree_drift,
        verifier_version="verifier-v1",
        harness_reported_success=proxy,
        propensity=propensity,
        explore_version=explore_version,
        pinned=pinned,
        repo_class=repo_class,
        intent_class=intent_class,
    )


@pytest.fixture
def organic_examples() -> list[Example]:
    rows: list[Example] = []
    for i in range(60):
        rows.append(
            make_example(
                i,
                session=i // 4,
                rung=Rung.LOCAL if i % 3 else Rung.CHEAP_CLOUD,
                verification=VerificationResult.PASS if i % 2 else VerificationResult.FAIL,
                repo_class=f"repo-{i % 4}",
                intent_class=f"intent-{i % 3}",
            )
        )
    return rows


def synthetic_effect_data(
    n: int = 600, seed: int = 0, treated_fraction: float = 0.25
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Heterogeneous effect: tau(x) = 2 * x0 * x1; unbalanced arms; nonlinear baseline."""
    rng = np.random.default_rng(seed)
    matrix = rng.uniform(-1, 1, size=(n, 3))
    t = (rng.uniform(size=n) < treated_fraction).astype(float)
    tau = 2.0 * matrix[:, 0] * matrix[:, 1]
    baseline = np.sin(2 * matrix[:, 2]) + 0.5 * matrix[:, 0] ** 2
    y = baseline + t * tau + rng.normal(scale=0.1, size=n)
    return matrix, t, y, tau


@pytest.fixture
def config_dir_iter() -> Iterator[str]:
    yield str(CONFIG_DIR)
