"""Router: composes features, bands, estimator, cost, advisor and cascade feasibility.

Primary: ADRL-RTG-002. Secondary: ADRL-RTG-003/004/006/009, ADRL-LRN-008 (explorer port).
The router always computes a full decision; routing mode (off/shadow/live) is honoured by the
proxy when it decides whether to act on it.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from adrl.config.loaders import ConfigBundle
from adrl.config.settings import Settings
from adrl.core.enums import Rung
from adrl.core.ids import mint_route_id
from adrl.core.ports import StickyState
from adrl.core.types import Decision, PermittedSet, RequestContext
from adrl.ledger.store import LedgerStore
from adrl.routing.advisor import (
    AdvisoryClassifier,
    ClassifierResult,
    Explorer,
    LocalHttpClassifier,
)
from adrl.routing.cascade_feasibility import evaluate_cascade
from adrl.routing.cost import CostInputs, CostModel
from adrl.routing.features import FEATURES_VERSION, compute_features
from adrl.routing.policy import BandHeuristicEstimator, BandMatch, classify_band, select_rung
from adrl.routing.registry import RungRegistry
from adrl.routing.rule_health import RuleHealthSnapshot, compute_rule_health
from adrl.routing.side_effects import UNTRUSTED, TrustPolicy, load_trust_policy

if TYPE_CHECKING:
    from adrl.gates.pipeline import GateOutcome

log = structlog.get_logger(__name__)


class Router:
    def __init__(
        self,
        bundle: ConfigBundle,
        *,
        registry: RungRegistry | None = None,
        cost_model: CostModel | None = None,
        classifier: AdvisoryClassifier | None = None,
        explorer: Explorer | None = None,
        rule_health: RuleHealthSnapshot | None = None,
        trust: TrustPolicy | None = None,
        now: Any = None,
    ) -> None:
        self._bundle = bundle
        self._trust = trust or UNTRUSTED
        self._policy = bundle.policy
        self._registry = registry or RungRegistry(bundle.rungs)
        self._cost = cost_model or CostModel(bundle.prices, bundle.policy, self._registry)
        self._estimator = BandHeuristicEstimator(bundle.policy, self._registry)
        self._classifier = classifier
        self._explorer = explorer
        self._rule_health = rule_health or RuleHealthSnapshot.empty(
            bundle.policy.rule_precision_threshold
        )
        self._now = now or (lambda: datetime.now(UTC))

    @classmethod
    def from_components(
        cls,
        *,
        bundle: ConfigBundle,
        settings: Settings,
        ledger: LedgerStore | None = None,
        explorer: Explorer | None = None,
        classifier_client: httpx.AsyncClient | None = None,
    ) -> Router:
        """Build the router with real adapters from config and settings (composition root)."""
        registry = RungRegistry(bundle.rungs)
        classifier: AdvisoryClassifier | None = None
        if settings.classifier_base_url:
            classifier = LocalHttpClassifier(
                settings.classifier_base_url,
                settings.classifier_model,
                timeout_s=bundle.policy.classifier_timeout_s,
                token_cap=bundle.policy.classifier_token_cap,
                prompt_version=bundle.policy.classifier_prompt_version,
                is_local=settings.classifier_is_local,
                client=classifier_client,
            )
        rule_health: RuleHealthSnapshot | None = None
        if ledger is not None:
            rule_health = compute_rule_health(
                ledger, threshold=bundle.policy.rule_precision_threshold
            )
        return cls(
            bundle,
            registry=registry,
            classifier=classifier,
            explorer=explorer,
            rule_health=rule_health,
            trust=load_trust_policy(settings.config_dir),
        )

    @property
    def registry(self) -> RungRegistry:
        return self._registry

    @property
    def trust(self) -> TrustPolicy:
        """MCP servers whose annotations the feature snapshot honours (ADRL-CAS-009)."""
        return self._trust

    def set_rule_health(self, snapshot: RuleHealthSnapshot) -> None:
        self._rule_health = snapshot

    async def decide(
        self, ctx: RequestContext, gate: GateOutcome, sticky: StickyState | None
    ) -> Decision:
        permitted = gate.permitted
        deployments = getattr(gate, "permitted_deployments", None)
        if deployments is not None:
            # a rung with no attested, permitted deployment is not a choice (ADRL-SAF-008)
            permitted = permitted.tighten(permitted.rungs & deployments.rungs())
        if permitted.is_empty:
            raise ValueError("router called with an empty permitted set; the gate must block")
        features = compute_features(ctx, self._policy.rule_thresholds, trust=self._trust)
        band = classify_band(features, self._policy, self._rule_health.demoted)
        probabilities = self._estimator.probabilities(features, band)
        inputs = CostInputs(
            context_tokens=int(features["context_tokens_estimate"]),
            expected_output_tokens=self._policy.expected_output_tokens_by_mode.get(
                ctx.interaction_mode.value, 2_000
            ),
            request_kind=ctx.request_class.value,
            band_id=band.band_id,
            now=self._now(),
            sticky=sticky,
        )
        costs = self._cost.estimate_all(inputs, probabilities, permitted)
        selection = select_rung(permitted, probabilities, costs, self._policy)
        rung = selection.rung
        provenance: dict[str, Any] | None = None
        classifier_result: ClassifierResult | None = None
        if band.is_ambiguous:
            rung, classifier_result = await self._advise(ctx, features, permitted, gate, rung)
            if classifier_result is not None:
                provenance = classifier_result.as_provenance()
                inputs_after = CostInputs(
                    context_tokens=inputs.context_tokens + classifier_result.tokens_used,
                    expected_output_tokens=inputs.expected_output_tokens,
                    request_kind=inputs.request_kind,
                    band_id=inputs.band_id,
                    now=inputs.now,
                    sticky=inputs.sticky,
                )
                costs = self._cost.estimate_all(inputs_after, probabilities, permitted)
        cascade = evaluate_cascade(
            features, permitted, pinned=gate.pinned, registry=self._registry, policy=self._policy
        )
        if rung is Rung.LOCAL and not gate.pinned and not cascade.feasible:
            fallback = cascade.next_rung or permitted.highest
            assert fallback is not None
            log.info("local_first_infeasible", reason=cascade.reason, fallback=fallback.value)
            rung = fallback
        propensity = 1.0
        explore_version: str | None = None
        if (
            self._explorer is not None
            and band.is_ambiguous
            and not gate.pinned
            and permitted.rungs == PermittedSet.all().rungs
            and (sticky is None or not sticky.escalated)
        ):
            choice = self._explorer.explore(ctx, features, band.band_id, permitted, rung)
            if choice is not None and choice.rung in permitted:
                rung = choice.rung
                propensity = choice.propensity
                explore_version = choice.explore_version
        decision = Decision(
            route_id=mint_route_id(),
            rung=rung,
            permitted=permitted,
            estimator=self._estimator.name,
            estimator_version=self._estimator.version,
            policy_version=self._policy.version,
            objective_version=self._policy.objective_version,
            cascade_feasible=cascade.feasible,
            cascade_reason=cascade.reason,
            features=features,
            features_version=FEATURES_VERSION,
            propensity=propensity,
            explore_version=explore_version,
            no_rung_met_threshold=selection.no_rung_met_threshold,
            classifier_provenance=provenance,
        )
        return decision

    def decision_context(
        self, decision: Decision, band: BandMatch | None = None, **extra: Any
    ) -> dict[str, Any]:
        """Context stored next to the decision row: band, rules, versions, weights."""
        features = decision.features
        if band is None:
            band = classify_band(features, self._policy, self._rule_health.demoted)
        return {
            "band_id": band.band_id,
            "band_demoted": band.demoted,
            "rules_fired": list(band.rules_fired),
            "tau_by_rung": {r.value: t for r, t in self._policy.tau_by_rung.items()},
            "objective_weights": self._policy.objective_weights.model_dump(),
            "config_versions": self._bundle.versions,
            "episode_estimator_version": self._cost.episode_estimator_version,
            "rule_health_version": self._rule_health.version,
            **extra,
        }

    async def _advise(
        self,
        ctx: RequestContext,
        features: Mapping[str, Any],
        permitted: PermittedSet,
        gate: GateOutcome,
        selected: Rung,
    ) -> tuple[Rung, ClassifierResult | None]:
        fallback = self._policy.ambiguous_fallback_rung
        if fallback not in permitted:
            highest = permitted.highest
            assert highest is not None
            fallback = highest
        if self._classifier is None:
            return fallback, None
        if gate.pinned and not self._classifier.is_local:
            log.info("classifier_skipped", reason="pinned_lineage_cloud_classifier")
            return fallback, None
        result = await self._classifier.classify(ctx, features, permitted)
        floor = self._policy.estimator_params.get("classifier_confidence_floor", 0.6)
        if result.timed_out or result.malformed or result.label is None:
            return fallback, result
        if result.confidence < floor:
            return fallback, result
        return result.label, result
