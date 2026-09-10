"""Local-first only with a bounded, clean cascade. Primary: ADRL-RTG-004.

Feasibility is evaluated at decision time. On a pinned lineage local is the only rung, the
cascade is unavailable by design, and the ledger carries reason=pinned so the turn is never
evidence for or against local-first.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from adrl.config.models import PolicyConfig
from adrl.core.enums import Rung, SideEffectClass
from adrl.core.types import PermittedSet
from adrl.routing.registry import RungRegistry

HANDOFF_NOTE_TOKEN_ALLOWANCE = 400


@dataclass(frozen=True, slots=True)
class CascadeFeasibility:
    feasible: bool
    reason: str | None
    next_rung: Rung | None
    attempt_budget_limit: int
    attempt_budget_unit: str

    def as_record(self) -> dict[str, Any]:
        return {
            "cascade_feasible": self.feasible,
            "reason": self.reason,
            "next_rung": self.next_rung.value if self.next_rung else None,
            "attempt_budget": {
                "unit": self.attempt_budget_unit,
                "limit": self.attempt_budget_limit,
            },
        }


def evaluate_cascade(
    features: Mapping[str, Any],
    permitted: PermittedSet,
    *,
    pinned: bool,
    registry: RungRegistry,
    policy: PolicyConfig,
) -> CascadeFeasibility:
    budget = policy.local_attempt_budget
    if pinned:
        return CascadeFeasibility(False, "pinned", None, budget.limit, budget.unit)
    next_rung = registry.next_higher(Rung.LOCAL, permitted)
    if next_rung is None:
        return CascadeFeasibility(False, "no_higher_rung", None, budget.limit, budget.unit)
    if features.get("expected_first_action_side_effect") == SideEffectClass.DESTRUCTIVE.value:
        return CascadeFeasibility(
            False, "destructive_first_action", next_rung, budget.limit, budget.unit
        )
    context = int(features.get("context_tokens_estimate", 0))
    attempt_tokens = _attempt_budget_tokens(policy)
    needed = context + attempt_tokens + HANDOFF_NOTE_TOKEN_ALLOWANCE
    ceiling = registry.context_ceiling(next_rung) - policy.cascade_safety_margin_tokens
    if needed > ceiling:
        return CascadeFeasibility(False, "context_headroom", next_rung, budget.limit, budget.unit)
    return CascadeFeasibility(True, None, next_rung, budget.limit, budget.unit)


def _attempt_budget_tokens(policy: PolicyConfig) -> int:
    """Translate the attempt budget into a token allowance for the headroom check."""
    budget = policy.local_attempt_budget
    if budget.unit == "tokens":
        return budget.limit
    if budget.unit == "tool_calls":
        return budget.limit * 1_500
    return 12 * 1_500
