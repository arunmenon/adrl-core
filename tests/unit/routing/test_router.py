"""RTG-002/004/006 router goldens and RTG-003 demotion."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from adrl.core.enums import Rung
from adrl.core.types import PermittedSet, RequestContext
from adrl.routing.advisor import ClassifierResult, ExplorationChoice
from adrl.routing.router import Router
from adrl.routing.rule_health import RuleHealthSnapshot
from tests.unit.routing.helpers import make_ctx, make_gate, user_body

AMBIGUOUS_TEXT = "hmm can you look at the thing we discussed and sort it"


class RecordingClassifier:
    def __init__(
        self, *, is_local: bool, label: Rung | None = Rung.LOCAL, timed_out: bool = False
    ) -> None:
        self.calls = 0
        self._is_local = is_local
        self._label = label
        self._timed_out = timed_out

    @property
    def model_id(self) -> str:
        return "fake-classifier"

    @property
    def is_local(self) -> bool:
        return self._is_local

    async def classify(
        self, ctx: RequestContext, features: Mapping[str, Any], permitted: PermittedSet
    ) -> ClassifierResult:
        self.calls += 1
        return ClassifierResult(
            self._label,
            0.9,
            "{}",
            self.model_id,
            "classifier-prompt-v1",
            "abcd",
            self._timed_out,
            False,
            120,
            0.01,
        )


async def test_effort_only_change_does_not_change_rung(bundle) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    a = await router.decide(make_ctx(user_body()), make_gate(), None)
    b = await router.decide(
        make_ctx(user_body(thinking={"type": "enabled", "budget_tokens": 9000})), make_gate(), None
    )
    assert a.rung is b.rung
    assert a.estimator_version == "band-heuristic-v1"
    assert a.policy_version == bundle.policy.version


async def test_pinned_ambiguous_never_calls_cloud_classifier(bundle) -> None:  # type: ignore[no-untyped-def]
    cloud = RecordingClassifier(is_local=False)
    router = Router(bundle, classifier=cloud)
    decision = await router.decide(
        make_ctx(user_body(AMBIGUOUS_TEXT)), make_gate(pinned=True), None
    )
    assert cloud.calls == 0
    assert decision.rung is Rung.LOCAL
    assert decision.cascade_feasible is False and decision.cascade_reason == "pinned"
    local = RecordingClassifier(is_local=True)
    router = Router(bundle, classifier=local)
    decision = await router.decide(
        make_ctx(user_body(AMBIGUOUS_TEXT)), make_gate(pinned=True), None
    )
    assert local.calls == 1
    assert decision.classifier_provenance is not None


async def test_classifier_timeout_records_outcome_and_uses_fallback(bundle) -> None:  # type: ignore[no-untyped-def]
    router = Router(
        bundle, classifier=RecordingClassifier(is_local=True, label=None, timed_out=True)
    )
    decision = await router.decide(make_ctx(user_body(AMBIGUOUS_TEXT)), make_gate(), None)
    assert decision.classifier_provenance is not None
    assert decision.classifier_provenance["outcome"] == "classifier_timeout"
    assert decision.rung is bundle.policy.ambiguous_fallback_rung


async def test_ambiguous_without_classifier_takes_higher_side(bundle) -> None:  # type: ignore[no-untyped-def]
    decision = await Router(bundle).decide(make_ctx(user_body(AMBIGUOUS_TEXT)), make_gate(), None)
    assert decision.rung is bundle.policy.ambiguous_fallback_rung


async def test_demoted_band_routes_through_advisor(bundle) -> None:  # type: ignore[no-untyped-def]
    classifier = RecordingClassifier(is_local=True, label=Rung.CHEAP_CLOUD)
    router = Router(bundle, classifier=classifier)
    clear = make_ctx(user_body("Fix the typo in README.md"))
    decision = await router.decide(clear, make_gate(), None)
    assert classifier.calls == 0
    assert decision.rung is Rung.LOCAL
    snapshot = RuleHealthSnapshot(
        "rule-health-v1", bundle.policy.rule_precision_threshold, {}, 20, frozenset({"clear-local"})
    )
    router.set_rule_health(snapshot)
    decision = await router.decide(clear, make_gate(), None)
    assert classifier.calls == 1
    assert decision.rung is Rung.CHEAP_CLOUD


async def test_destructive_first_action_is_never_local_first(bundle) -> None:  # type: ignore[no-untyped-def]
    decision = await Router(bundle).decide(
        make_ctx(user_body("rename x to y then git push --force")), make_gate(), None
    )
    assert decision.rung is not Rung.LOCAL


async def test_pinned_session_records_reason_pinned_not_headroom(bundle) -> None:  # type: ignore[no-untyped-def]
    big = user_body("Fix the typo in README.md", system="x" * 800_000)
    decision = await Router(bundle).decide(make_ctx(big), make_gate(pinned=True), None)
    assert decision.rung is Rung.LOCAL
    assert decision.cascade_reason == "pinned"


async def test_context_headroom_blocks_local_first_when_unpinned(bundle) -> None:  # type: ignore[no-untyped-def]
    big = user_body("Fix the typo in README.md", system="x" * 700_000)
    decision = await Router(bundle).decide(make_ctx(big), make_gate(), None)
    assert decision.rung is not Rung.LOCAL


class FixedExplorer:
    version = "explore-test-v1"

    def __init__(self) -> None:
        self.calls = 0

    def explore(self, ctx, features, band_id, permitted, default):  # type: ignore[no-untyped-def]
        self.calls += 1
        return ExplorationChoice(Rung.LOCAL, 0.1, self.version)


async def test_exploration_only_in_ambiguous_band_and_unconstrained(bundle) -> None:  # type: ignore[no-untyped-def]
    explorer = FixedExplorer()
    router = Router(bundle, explorer=explorer)
    clear = await router.decide(make_ctx(user_body("Fix the typo in README.md")), make_gate(), None)
    assert explorer.calls == 0 and clear.propensity == 1.0
    ambiguous = await router.decide(make_ctx(user_body(AMBIGUOUS_TEXT)), make_gate(), None)
    assert (
        explorer.calls == 1
        and ambiguous.propensity == 0.1
        and ambiguous.explore_version == "explore-test-v1"
    )
    tightened = make_gate(PermittedSet.only(Rung.CHEAP_CLOUD, Rung.FRONTIER))
    constrained = await router.decide(make_ctx(user_body(AMBIGUOUS_TEXT)), tightened, None)
    assert explorer.calls == 1 and constrained.propensity == 1.0
    pinned = await router.decide(make_ctx(user_body(AMBIGUOUS_TEXT)), make_gate(pinned=True), None)
    assert explorer.calls == 1 and pinned.propensity == 1.0


async def test_decision_context_carries_band_and_versions(bundle) -> None:  # type: ignore[no-untyped-def]
    router = Router(bundle)
    decision = await router.decide(make_ctx(user_body()), make_gate(), None)
    context = router.decision_context(decision)
    assert context["band_id"] == "clear-local"
    assert context["config_versions"]["policy"] == bundle.policy.version
    assert "tau_by_rung" in context and "objective_weights" in context


async def test_empty_permitted_set_is_rejected(bundle) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        await Router(bundle).decide(
            make_ctx(user_body()), make_gate(PermittedSet(frozenset())), None
        )
