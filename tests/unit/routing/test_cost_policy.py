"""RTG-002 selection, RTG-003 bands, RTG-009 cost."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from adrl.core.enums import Rung
from adrl.core.ids import LineageId, RouteId
from adrl.core.ports import StickyState
from adrl.core.types import PermittedSet
from adrl.routing.cost import CostInputs, CostModel
from adrl.routing.policy import BandHeuristicEstimator, classify_band, select_rung
from adrl.routing.registry import RungRegistry


def _sticky(rung: Rung, at: datetime, model: str = "m") -> StickyState:
    return StickyState(
        lineage_hmac=LineageId("l"),
        route_id=RouteId("r"),
        rung=rung,
        escalated=False,
        served_model=model,
        served_provider="p",
        served_source="gateway_reported",
        turn_index=3,
        last_served_at=at,
    )


def test_cached_session_and_cold_session_differ_in_cost(bundle, registry) -> None:  # type: ignore[no-untyped-def]
    model = CostModel(bundle.prices, bundle.policy, registry)
    now = datetime.now(UTC)
    permitted = PermittedSet.all()
    probs = {Rung.LOCAL: 0.9, Rung.CHEAP_CLOUD: 0.95, Rung.FRONTIER: 0.98}
    cached = CostInputs(
        120_000,
        2_000,
        "user_turn",
        "ambiguous",
        now,
        _sticky(Rung.FRONTIER, now - timedelta(seconds=30)),
    )
    cold = CostInputs(2_000, 2_000, "user_turn", "ambiguous", now, None)
    warm_frontier = model.estimate(Rung.FRONTIER, cached, p_complete=0.98, permitted=permitted)
    cold_frontier = model.estimate(Rung.FRONTIER, cold, p_complete=0.98, permitted=permitted)
    assert warm_frontier.cache_warm and not cold_frontier.cache_warm
    assert warm_frontier.after_cache_usd != cold_frontier.after_cache_usd
    assert warm_frontier.label == "after_cache_effects"
    # at the margin: with a warm 120k frontier cache, switching to cheap_cloud pays a write
    cheap_switch = model.estimate(Rung.CHEAP_CLOUD, cached, p_complete=0.95, permitted=permitted)
    assert cheap_switch.switch_cost_usd > 0
    assert warm_frontier.switch_cost_usd == 0
    cold_120 = CostInputs(120_000, 2_000, "user_turn", "ambiguous", now, None)
    cold_frontier_120 = model.estimate(
        Rung.FRONTIER, cold_120, p_complete=0.98, permitted=permitted
    )
    cold_cheap_120 = model.estimate(
        Rung.CHEAP_CLOUD, cold_120, p_complete=0.95, permitted=permitted
    )
    warm_gap = warm_frontier.after_cache_usd - cheap_switch.after_cache_usd
    cold_gap = cold_frontier_120.after_cache_usd - cold_cheap_120.after_cache_usd
    assert warm_gap < cold_gap
    chosen = select_rung(
        permitted, probs, model.estimate_all(cached, probs, permitted), bundle.policy
    )
    assert chosen.rung is Rung.LOCAL


def test_cache_expires_after_ttl(bundle, registry) -> None:  # type: ignore[no-untyped-def]
    model = CostModel(bundle.prices, bundle.policy, registry)
    now = datetime.now(UTC)
    stale = CostInputs(
        50_000, 500, "continuation", None, now, _sticky(Rung.FRONTIER, now - timedelta(seconds=900))
    )
    assert not model.cache_is_warm(Rung.FRONTIER, stale)


def test_escalation_is_exempt_from_switch_charge(bundle, registry) -> None:  # type: ignore[no-untyped-def]
    model = CostModel(bundle.prices, bundle.policy, registry)
    now = datetime.now(UTC)
    inputs = CostInputs(30_000, 1_000, "continuation", None, now, _sticky(Rung.LOCAL, now))
    charged = model.estimate(Rung.FRONTIER, inputs, p_complete=0.9, permitted=PermittedSet.all())
    exempt = model.estimate(
        Rung.FRONTIER, inputs, p_complete=0.9, permitted=PermittedSet.all(), escalation_exempt=True
    )
    assert charged.switch_cost_usd > 0
    assert exempt.switch_cost_usd == 0
    assert exempt.after_cache_usd < charged.after_cache_usd


def test_band_classification(bundle) -> None:  # type: ignore[no-untyped-def]
    small_edit = {
        "verb_class": "small_edit",
        "scope_hint": "narrow",
        "context_tokens_estimate": 3000,
        "recent_edit_failures": 0,
        "prev_turn_interrupted": False,
        "destructive_intent": False,
        "expected_first_action_side_effect": "idempotent",
        "files_mentioned": 1,
        "heuristic_score": 0.3,
    }
    assert classify_band(small_edit, bundle.policy).band_id == "clear-local"
    destructive = {**small_edit, "expected_first_action_side_effect": "destructive"}
    assert classify_band(destructive, bundle.policy).band_id == "clear-frontier"
    unknown = {**small_edit, "verb_class": "unknown", "scope_hint": "none"}
    assert classify_band(unknown, bundle.policy).is_ambiguous
    demoted = classify_band(small_edit, bundle.policy, frozenset({"clear-local"}))
    assert demoted.demoted and demoted.is_ambiguous


def test_select_rung_threshold_and_fallback(bundle, registry) -> None:  # type: ignore[no-untyped-def]
    model = CostModel(bundle.prices, bundle.policy, registry)
    inputs = CostInputs(1_000, 500, "user_turn", "clear-local", datetime.now(UTC), None)
    permitted = PermittedSet.all()
    probs = {Rung.LOCAL: 0.9, Rung.CHEAP_CLOUD: 0.9, Rung.FRONTIER: 0.9}
    selection = select_rung(
        permitted, probs, model.estimate_all(inputs, probs, permitted), bundle.policy
    )
    assert selection.rung is Rung.LOCAL and not selection.no_rung_met_threshold
    low = {Rung.LOCAL: 0.1, Rung.CHEAP_CLOUD: 0.2, Rung.FRONTIER: 0.3}
    selection = select_rung(
        permitted, low, model.estimate_all(inputs, low, permitted), bundle.policy
    )
    assert selection.rung is Rung.FRONTIER and selection.no_rung_met_threshold


def test_estimator_respects_rung_boundaries(bundle, registry: RungRegistry) -> None:  # type: ignore[no-untyped-def]
    estimator = BandHeuristicEstimator(bundle.policy, registry)
    features = {"heuristic_score": 0.2, "task_classes": ["large_change"]}
    band = classify_band({**features, "verb_class": "unknown"}, bundle.policy)
    probs = estimator.probabilities(features, band)
    assert probs[Rung.LOCAL] == 0.0
    assert probs[Rung.CHEAP_CLOUD] == 0.0
    assert probs[Rung.FRONTIER] > 0.8
