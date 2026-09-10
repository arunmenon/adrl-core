"""Learning readiness report. Primary: ADRL-LRN-001. Secondary: ADRL-FND-005, ADRL-EVL-004,
ADRL-EVL-009, ADRL-LRN-002, ADRL-LRN-006.

Every count reports its denominator and excluded fraction. Blockers are listed, never averaged.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from adrl.learning.abstention import AbstentionReport
from adrl.learning.pairs import PairBudget
from adrl.learning.tiers import TieredDataset, VerifierPrecision

READINESS_VERSION = "learning-readiness-v1"
T1_REQUIRED_DEFAULT = 300
MIN_DISTINCT_REPOS_DEFAULT = 3
MIN_DISTINCT_INTENTS_DEFAULT = 3


@dataclass(frozen=True, slots=True)
class DiversityReport:
    distinct_repo_classes: int
    distinct_intent_classes: int
    minimum_repos: int
    minimum_intents: int

    @property
    def met(self) -> bool:
        return (
            self.distinct_repo_classes >= self.minimum_repos
            and self.distinct_intent_classes >= self.minimum_intents
        )


@dataclass(slots=True)
class ReadinessReport:
    version: str = READINESS_VERSION
    tier_counts: dict[str, int] = field(default_factory=dict)
    t1_required: int = T1_REQUIRED_DEFAULT
    excluded_fraction: float = 0.0
    pinned_fraction: float = 0.0
    exclusion_reasons: dict[str, int] = field(default_factory=dict)
    diversity: DiversityReport | None = None
    pair_budgets: list[PairBudget] = field(default_factory=list)
    abstention: AbstentionReport | None = None
    verifier_precision: dict[str, VerifierPrecision] = field(default_factory=dict)
    verifier_precision_threshold: float = 0.9
    blockers: list[str] = field(default_factory=list)

    @property
    def t1_count(self) -> int:
        return self.tier_counts.get("T1", 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "tier_counts": dict(self.tier_counts),
            "t1_count": self.t1_count,
            "t1_required": self.t1_required,
            "excluded_fraction": self.excluded_fraction,
            "pinned_fraction": self.pinned_fraction,
            "exclusion_reasons": dict(self.exclusion_reasons),
            "diversity": None
            if self.diversity is None
            else {
                "distinct_repo_classes": self.diversity.distinct_repo_classes,
                "distinct_intent_classes": self.diversity.distinct_intent_classes,
                "met": self.diversity.met,
            },
            "pair_budgets": [
                {
                    "slice_id": b.slice_id,
                    "delta": b.delta,
                    "discordance": b.discordance,
                    "required": b.required,
                    "current": b.current,
                    "shortfall": b.shortfall,
                }
                for b in self.pair_budgets
            ],
            "abstention": None if self.abstention is None else self.abstention.as_dict(),
            "verifier_precision": {
                k: {
                    "repeat_run_agreement": v.repeat_run_agreement,
                    "flake_rate": v.flake_rate,
                    "tree_drift_rate": v.tree_drift_rate,
                    "runs": v.runs,
                    "meets_threshold": v.meets(self.verifier_precision_threshold),
                }
                for k, v in self.verifier_precision.items()
            },
            "blockers": list(self.blockers),
            "ready": not self.blockers,
        }

    def render_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)


def build_report(
    dataset: TieredDataset | None,
    *,
    pair_budgets: Sequence[PairBudget] = (),
    abstention: AbstentionReport | None = None,
    verifier_precision: Mapping[str, VerifierPrecision] | None = None,
    verifier_precision_threshold: float = 0.9,
    t1_required: int = T1_REQUIRED_DEFAULT,
    minimum_repos: int = MIN_DISTINCT_REPOS_DEFAULT,
    minimum_intents: int = MIN_DISTINCT_INTENTS_DEFAULT,
    graduated_artifact: bool = False,
) -> ReadinessReport:
    report = ReadinessReport(
        t1_required=t1_required, verifier_precision_threshold=verifier_precision_threshold
    )
    if dataset is not None:
        report.tier_counts = dataset.tier_mix()
        report.excluded_fraction = dataset.excluded_fraction()
        report.pinned_fraction = dataset.pinned_fraction()
        report.exclusion_reasons = dataset.exclusion_reasons()
        t1 = dataset.objective_examples()
        report.diversity = DiversityReport(
            distinct_repo_classes=len({i.example.repo_class for i in t1 if i.example.repo_class}),
            distinct_intent_classes=len(
                {i.example.intent_class for i in t1 if i.example.intent_class}
            ),
            minimum_repos=minimum_repos,
            minimum_intents=minimum_intents,
        )
    report.pair_budgets = list(pair_budgets)
    report.abstention = abstention
    report.verifier_precision = dict(verifier_precision or {})

    if report.t1_count < t1_required:
        report.blockers.append(f"organic_verifier_labels: {report.t1_count} < {t1_required}")
    if report.diversity is not None and not report.diversity.met:
        report.blockers.append("t1_diversity: below minimum distinct repos or intents")
    if not report.verifier_precision:
        report.blockers.append("label_precision: no verifier precision measured")
    else:
        below = [
            k
            for k, v in report.verifier_precision.items()
            if not v.meets(verifier_precision_threshold)
        ]
        if below:
            report.blockers.append(
                "label_precision: verifier(s) below threshold " + ",".join(below)
            )
    for budget in report.pair_budgets:
        if budget.shortfall > 0:
            report.blockers.append(
                f"pair_budget[{budget.slice_id}]: {budget.current}/{budget.required}"
            )
    if abstention is not None and abstention.blocker:
        report.blockers.append("abstention_rate: outside declared bounds (EVL-009)")
    if abstention is None:
        report.blockers.append("abstention_gate: not calibrated")
    if not graduated_artifact:
        report.blockers.append("learned_router_authority: no graduated artifact (ADRL-LRN-007)")
    return report
