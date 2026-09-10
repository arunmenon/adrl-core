"""Bands, the band-heuristic-v1 estimator and threshold selection. Primary: ADRL-RTG-002.

Secondary: ADRL-RTG-003 (rules own clear cases). Band boundaries live in policy.yaml; the
rule ids there are bound to the predicates below so the population of clear cases can be
re-derived after any rule change.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from adrl.config.models import Band, PolicyConfig
from adrl.core.enums import Rung, SideEffectClass
from adrl.core.types import PermittedSet
from adrl.routing.cost import CostEstimate
from adrl.routing.registry import RungRegistry

ESTIMATOR_NAME = "band-heuristic"
ESTIMATOR_VERSION = "band-heuristic-v1"
AMBIGUOUS_BAND_ID = "ambiguous"

RulePredicate = Callable[[Mapping[str, Any], Mapping[str, float]], bool]


def _rule_mechanical_edit_small_file(f: Mapping[str, Any], t: Mapping[str, float]) -> bool:
    return (
        f.get("verb_class") in {"trivial", "small_edit"}
        and f.get("scope_hint") != "broad"
        and int(f.get("context_tokens_estimate", 0)) <= t.get("small_context_tokens", 8_000.0)
        and int(f.get("recent_edit_failures", 0)) == 0
        and not bool(f.get("prev_turn_interrupted", False))
        and not bool(f.get("destructive_intent", False))
        and f.get("expected_first_action_side_effect") != SideEffectClass.DESTRUCTIVE.value
    )


def _rule_read_only_lookup(f: Mapping[str, Any], t: Mapping[str, float]) -> bool:
    return (
        f.get("verb_class") == "explain"
        and int(f.get("context_tokens_estimate", 0)) <= t.get("small_context_tokens", 8_000.0)
        and f.get("expected_first_action_side_effect") == SideEffectClass.READ_ONLY.value
    )


def _rule_destructive_first_action(f: Mapping[str, Any], t: Mapping[str, float]) -> bool:
    return f.get("expected_first_action_side_effect") == SideEffectClass.DESTRUCTIVE.value


def _rule_large_context(f: Mapping[str, Any], t: Mapping[str, float]) -> bool:
    return int(f.get("context_tokens_estimate", 0)) > t.get("large_context_tokens", 20_000.0)


def _rule_multi_file_design(f: Mapping[str, Any], t: Mapping[str, float]) -> bool:
    return f.get("verb_class") == "hard" or (
        f.get("scope_hint") == "broad"
        and int(f.get("files_mentioned", 0)) >= t.get("multi_file_min_files", 4.0)
    )


RULES: dict[str, RulePredicate] = {
    "rule.mechanical_edit_small_file": _rule_mechanical_edit_small_file,
    "rule.read_only_lookup": _rule_read_only_lookup,
    "rule.destructive_first_action": _rule_destructive_first_action,
    "rule.large_context": _rule_large_context,
    "rule.multi_file_design": _rule_multi_file_design,
}


@dataclass(frozen=True, slots=True)
class BandMatch:
    band: Band
    rules_fired: tuple[str, ...]
    demoted: bool = False

    @property
    def is_ambiguous(self) -> bool:
        return self.band.rung is None or self.demoted

    @property
    def band_id(self) -> str:
        return self.band.band_id


def classify_band(
    features: Mapping[str, Any], policy: PolicyConfig, demoted_bands: frozenset[str] = frozenset()
) -> BandMatch:
    """Clear bands claim a turn by rule; ties resolve to the higher rung."""
    ambiguous = next(b for b in policy.bands if b.rung is None)
    unknown = [r for b in policy.bands for r in b.rule_ids if r not in RULES]
    if unknown:
        raise ValueError(f"policy cites rule ids with no predicate: {unknown}")
    matches: list[BandMatch] = []
    for band in policy.bands:
        if band.rung is None:
            continue
        fired = tuple(r for r in band.rule_ids if RULES[r](features, policy.rule_thresholds))
        if fired:
            matches.append(
                BandMatch(band=band, rules_fired=fired, demoted=band.band_id in demoted_bands)
            )
    if not matches:
        return BandMatch(band=ambiguous, rules_fired=())
    # when several clear bands claim a turn the conservative (higher) rung wins
    matches.sort(key=lambda m: m.band.rung.rank if m.band.rung else -1, reverse=True)
    return matches[0]


class BandHeuristicEstimator:
    """P(complete | rung, features) from the versioned coefficients in policy.yaml."""

    name = ESTIMATOR_NAME
    version = ESTIMATOR_VERSION

    def __init__(self, policy: PolicyConfig, registry: RungRegistry) -> None:
        self._p = policy.estimator_params
        self._registry = registry

    def probabilities(self, features: Mapping[str, Any], band: BandMatch) -> dict[Rung, float]:
        score = float(features.get("heuristic_score", 0.5))
        p = self._p
        raw = {
            Rung.FRONTIER: p["frontier_base"] - p["frontier_slope"] * score,
            Rung.CHEAP_CLOUD: p["cheap_cloud_base"] - p["cheap_cloud_slope"] * score,
            Rung.LOCAL: p["local_base"] - p["local_slope"] * score,
        }
        if not band.is_ambiguous and band.band.rung is not None:
            target = band.band.rung
            raw[target] = max(raw[target], p["clear_band_floor"])
            if target is Rung.FRONTIER:
                raw[Rung.LOCAL] = min(raw[Rung.LOCAL], p["clear_frontier_local_cap"])
                raw[Rung.CHEAP_CLOUD] = min(raw[Rung.CHEAP_CLOUD], p["clear_frontier_cheap_cap"])
        task_classes = features.get("task_classes") or []
        out: dict[Rung, float] = {}
        for rung, value in raw.items():
            entry = self._registry.entry(rung) if rung in self._registry.enabled_rungs() else None
            if (
                entry is not None
                and task_classes
                and not any(entry.permits_task_class(c) for c in task_classes)
            ):
                value = 0.0
            out[rung] = max(0.0, min(0.98, value))
        return out


@dataclass(frozen=True, slots=True)
class Selection:
    rung: Rung
    no_rung_met_threshold: bool
    probabilities: Mapping[Rung, float]
    costs: Mapping[Rung, CostEstimate]
    tau_by_rung: Mapping[Rung, float]
    ordering: tuple[Rung, ...]


def select_rung(
    permitted: PermittedSet,
    probabilities: Mapping[Rung, float],
    costs: Mapping[Rung, CostEstimate],
    policy: PolicyConfig,
) -> Selection:
    """Cheapest permitted rung (session-marginal, after cache) with P >= tau (RTG-002 cl. 1-3)."""
    if permitted.is_empty:
        raise ValueError("cannot select from an empty permitted set")
    ordering = tuple(sorted(permitted, key=lambda r: (costs[r].after_cache_usd, r.rank)))
    for rung in ordering:
        if probabilities.get(rung, 0.0) >= policy.tau_by_rung[rung]:
            return Selection(rung, False, probabilities, costs, policy.tau_by_rung, ordering)
    highest = permitted.highest
    assert highest is not None
    return Selection(highest, True, probabilities, costs, policy.tau_by_rung, ordering)
