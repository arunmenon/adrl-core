"""Feasibility filter (ADRL-SAF-006)."""

from __future__ import annotations

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung
from adrl.core.types import PermittedSet
from adrl.gates.feasibility import FeasibilityFilter, StaticHealth


async def test_boundary_formula(bundle: ConfigBundle, feasibility: FeasibilityFilter) -> None:
    local = bundle.rungs.rungs[Rung.LOCAL]
    margin = bundle.policy.cascade_safety_margin_tokens
    # input_est * ratio + max_tokens + thinking <= ceiling - margin
    budget = local.boundary.context_ceiling - margin
    est_fits = budget - 100
    est_over = budget + 1
    assert feasibility.fits(Rung.LOCAL, est_fits, 100, 0)
    assert not feasibility.fits(Rung.LOCAL, est_over, 0, 0)
    assert not feasibility.fits(Rung.LOCAL, est_fits, 100, 1)


async def test_oversized_request_removes_local_only(feasibility: FeasibilityFilter) -> None:
    text = "x" * (140_000 * 4)
    body = {"max_tokens": 1000, "messages": [{"role": "user", "content": text}]}
    verdict = await feasibility.evaluate(body, PermittedSet.all())
    assert Rung.LOCAL not in verdict.permitted_after
    assert verdict.removed[Rung.LOCAL] == "context_infeasible"
    assert Rung.FRONTIER in verdict.permitted_after


async def test_unhealthy_rung_removed_and_unknown_kept(
    bundle: ConfigBundle, health: StaticHealth, feasibility: FeasibilityFilter
) -> None:
    health.set("adrl-cheap-cloud", False)
    body = {"max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}
    verdict = await feasibility.evaluate(body, PermittedSet.all())
    assert verdict.removed.get(Rung.CHEAP_CLOUD) == "unhealthy"
    fresh = FeasibilityFilter(bundle.rungs, {}, StaticHealth({}))
    verdict2 = await fresh.evaluate(body, PermittedSet.all())
    assert verdict2.permitted_after.rungs == frozenset(Rung)


async def test_thinking_budget_counts(feasibility: FeasibilityFilter) -> None:
    body = {
        "max_tokens": 1000,
        "thinking": {"type": "enabled", "budget_tokens": 200_000},
        "messages": [{"role": "user", "content": "hi"}],
    }
    verdict = await feasibility.evaluate(body, PermittedSet.all())
    assert Rung.LOCAL not in verdict.permitted_after
    assert verdict.thinking_budget == 200_000


def test_count_tokens_estimate_shape(feasibility: FeasibilityFilter) -> None:
    out = feasibility.estimate_count_tokens({"messages": [{"role": "user", "content": "a" * 400}]})
    assert set(out) == {"input_tokens"} and out["input_tokens"] >= 100
