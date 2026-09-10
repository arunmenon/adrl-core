"""Evidence tiers and pooling rules. Primary: ADRL-LRN-001.
Also implements: ADRL-EVL-005 (register additions of 2026-09-03).

Secondary: ADRL-MEM-002 (censoring), ADRL-MEM-003 (indeterminate, tree drift), ADRL-MEM-004
(only task_capability is capability evidence), ADRL-LRN-002 (T5), ADRL-LRN-008 (explore).

Only T1 enters the estimator objective and the holdout. Lower tiers are declared weak signal
with the tier recorded per example. Organic, counterfactual and exploration families never
pool: a TieredDataset carries exactly one family and refuses to merge across families.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from adrl.config.models import LearningContract
from adrl.core.enums import EvidenceTier, FailureType, OutcomeState, Rung, VerificationResult
from adrl.core.ids import RouteId, SessionId
from adrl.ledger.store import LedgerStore

TIERS_VERSION = "evidence-tiers-v1"

ExampleSource = Literal["organic", "simulator", "benchmark", "counterfactual", "explore"]
Family = Literal["organic", "synthetic", "counterfactual", "explore"]

_FAMILY_BY_SOURCE: dict[str, Family] = {
    "organic": "organic",
    "simulator": "synthetic",
    "benchmark": "synthetic",
    "counterfactual": "counterfactual",
    "explore": "explore",
}


class PoolingError(ValueError):
    """Raised when evidence families or tiers would be pooled (ADRL-LRN-001 clause 2)."""


@dataclass(frozen=True, slots=True)
class VerifierPrecision:
    """Measured verifier precision that conditions T1 status (ADRL-LRN-001 clause 3)."""

    verifier_version: str
    repeat_run_agreement: float
    flake_rate: float
    tree_drift_rate: float
    runs: int = 0

    def meets(self, threshold: float) -> bool:
        return (
            self.repeat_run_agreement >= threshold
            and self.flake_rate <= (1.0 - threshold)
            and self.tree_drift_rate <= (1.0 - threshold)
        )


@dataclass(frozen=True, slots=True)
class Example:
    """One routed turn with everything the tier rules need. Content-free."""

    route_id: RouteId
    session_hmac: SessionId
    decision_ts: str
    rung: Rung
    features: Mapping[str, Any]
    features_version: str
    source: ExampleSource
    outcome_state: OutcomeState
    failure_type: FailureType | None
    verification: VerificationResult | None
    tree_drift: bool
    verifier_version: str | None
    harness_reported_success: bool | None
    propensity: float = 1.0
    explore_version: str | None = None
    pinned: bool = False
    privacy_suppressed: bool = False
    slice_id: str = "all"
    repo_class: str | None = None
    intent_class: str | None = None

    @property
    def family(self) -> Family:
        return _FAMILY_BY_SOURCE[self.source]

    @property
    def verified_success(self) -> bool | None:
        """Verified label: pass is success, fail is failure, anything else is unknown."""
        if self.verification is VerificationResult.PASS:
            return True
        if self.verification is VerificationResult.FAIL:
            return False
        return None

    @property
    def label(self) -> int | None:
        """Binary outcome for the estimator: verified when present, else proxy."""
        verified = self.verified_success
        if verified is not None:
            return 1 if verified else 0
        if self.harness_reported_success is None:
            return None
        return 1 if self.harness_reported_success else 0


@dataclass(frozen=True, slots=True)
class TierAssignment:
    tier: EvidenceTier | None
    reason: str


def assign_tier(
    example: Example,
    contract: LearningContract,
    verifier_precision: Mapping[str, VerifierPrecision] | None = None,
) -> TierAssignment:
    """Assign the evidence tier per ADRL-LRN-001; None means the example is excluded."""
    if example.source == "counterfactual":
        return TierAssignment(EvidenceTier.T5, "counterfactual pair")
    if example.source == "explore" or example.explore_version is not None:
        return TierAssignment(EvidenceTier.EXPLORE, "logged exploration with propensity")
    if example.source in ("simulator", "benchmark"):
        return TierAssignment(EvidenceTier.T4, f"{example.source} evidence")

    if example.failure_type is not None and not example.failure_type.is_capability_evidence:
        return TierAssignment(
            None, f"excluded failure type {example.failure_type.value} (ADRL-MEM-004)"
        )

    verified = example.verification is not None and (
        example.verification is not VerificationResult.INDETERMINATE
    )
    if verified and not example.tree_drift:
        if example.outcome_state is OutcomeState.CLOSED_FINAL:
            precision = None
            if verifier_precision is not None and example.verifier_version is not None:
                precision = verifier_precision.get(example.verifier_version)
            if precision is None:
                return TierAssignment(EvidenceTier.T2, "verifier precision not measured")
            if not precision.meets(contract.verifier_precision_threshold):
                return TierAssignment(EvidenceTier.T2, "verifier precision below threshold")
            return TierAssignment(EvidenceTier.T1, "verified, task_capability, closed_final")
        if example.outcome_state is OutcomeState.CLOSED_TURN:
            return TierAssignment(EvidenceTier.T2, "verified but closed_turn only (censored)")
        return TierAssignment(None, "verified but outcome still pending")
    if verified and example.tree_drift:
        return TierAssignment(None, "tree drift excludes the verification (ADRL-MEM-003)")
    if example.harness_reported_success is not None:
        return TierAssignment(EvidenceTier.T3, "proxy label from harness report")
    return TierAssignment(None, "no verification and no proxy signal")


@dataclass(frozen=True, slots=True)
class TieredExample:
    example: Example
    tier: EvidenceTier
    reason: str


@dataclass(slots=True)
class TieredDataset:
    """Examples of exactly one family; merges across families raise PoolingError."""

    family: Family
    examples: list[TieredExample] = field(default_factory=list)
    excluded: list[tuple[Example, str]] = field(default_factory=list)
    tiers_version: str = TIERS_VERSION

    @classmethod
    def build(
        cls,
        examples: Iterable[Example],
        contract: LearningContract,
        verifier_precision: Mapping[str, VerifierPrecision] | None = None,
        family: Family | None = None,
    ) -> TieredDataset:
        items = list(examples)
        families = {e.family for e in items}
        if family is None:
            if len(families) > 1:
                raise PoolingError(
                    "examples span families "
                    + ",".join(sorted(families))
                    + "; build one per family"
                )
            family = next(iter(families)) if families else "organic"
        assert family is not None
        dataset = cls(family=family)
        for example in items:
            if example.family != family:
                raise PoolingError(f"example {example.route_id} is {example.family}, not {family}")
            assignment = assign_tier(example, contract, verifier_precision)
            if assignment.tier is None:
                dataset.excluded.append((example, assignment.reason))
            else:
                dataset.examples.append(TieredExample(example, assignment.tier, assignment.reason))
        return dataset

    def merge(self, other: TieredDataset) -> TieredDataset:
        if other.family != self.family:
            raise PoolingError(f"cannot pool {self.family} with {other.family} (ADRL-LRN-001)")
        merged = TieredDataset(family=self.family)
        merged.examples = [*self.examples, *other.examples]
        merged.excluded = [*self.excluded, *other.excluded]
        return merged

    @property
    def tier_set(self) -> frozenset[EvidenceTier]:
        return frozenset(item.tier for item in self.examples)

    def objective_examples(self) -> list[TieredExample]:
        """Only T1 enters the objective (ADRL-LRN-001 clause 1)."""
        return [item for item in self.examples if item.tier.enters_objective]

    def weak_signal_examples(self) -> list[TieredExample]:
        return [item for item in self.examples if not item.tier.enters_objective]

    def tier_mix(self) -> dict[str, int]:
        counts = Counter(item.tier.value for item in self.examples)
        return {tier.value: counts.get(tier.value, 0) for tier in EvidenceTier}

    def exclusion_reasons(self) -> dict[str, int]:
        return dict(Counter(reason for _, reason in self.excluded))

    def excluded_fraction(self) -> float:
        total = len(self.examples) + len(self.excluded)
        return len(self.excluded) / total if total else 0.0

    def pinned_fraction(self) -> float:
        total = len(self.examples) + len(self.excluded)
        pinned = sum(1 for item in self.examples if item.example.pinned) + sum(
            1 for example, _ in self.excluded if example.pinned
        )
        return pinned / total if total else 0.0


def assert_holdout_is_t1(items: Sequence[TieredExample]) -> None:
    """The evaluation holdout is T1-only (ADRL-LRN-001 clause 2)."""
    offending = sorted({item.tier.value for item in items if not item.tier.enters_objective})
    if offending:
        raise PoolingError("holdout contains non-T1 tiers: " + ",".join(offending))


def verifier_precision_from_runs(
    verifier_version: str,
    run_results: Sequence[Sequence[VerificationResult]],
    tree_drift_flags: Sequence[bool] = (),
) -> VerifierPrecision:
    """Compute precision from repeated runs of the same verification (run x10 follow-up).

    repeat_run_agreement is the fraction of task groups whose non-indeterminate runs agree;
    flake_rate is the fraction of groups with at least one disagreement or indeterminate run.
    """
    groups = [list(group) for group in run_results if group]
    if not groups:
        return VerifierPrecision(verifier_version, 0.0, 1.0, 0.0, 0)
    agreeing = 0
    flaky = 0
    for group in groups:
        decided = [r for r in group if r is not VerificationResult.INDETERMINATE]
        if decided and len(set(decided)) == 1 and len(decided) == len(group):
            agreeing += 1
        else:
            flaky += 1
    drift_rate = (
        sum(1 for flag in tree_drift_flags if flag) / len(tree_drift_flags)
        if tree_drift_flags
        else 0.0
    )
    return VerifierPrecision(
        verifier_version=verifier_version,
        repeat_run_agreement=agreeing / len(groups),
        flake_rate=flaky / len(groups),
        tree_drift_rate=drift_rate,
        runs=sum(len(g) for g in groups),
    )


# ledger reader --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventNames:
    """Event type names the reader looks for; the ledger builder owns the real names."""

    outcome: str = "outcome"
    verification: str = "verification"
    label: str = "label"
    counterfactual: str = "counterfactual"


def _payload(row: sqlite3.Row) -> dict[str, Any]:
    try:
        data = json.loads(row["payload_json"])
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _enum_or_none(enum_cls: Any, value: Any) -> Any:
    if value is None:
        return None
    try:
        return enum_cls(value)
    except ValueError:
        return None


class LedgerExampleReader:
    """Build examples from decisions plus their events, tolerating unknown fields."""

    def __init__(self, store: LedgerStore, names: EventNames | None = None) -> None:
        self._store = store
        self._names = names or EventNames()

    def read(self, *, limit: int | None = None) -> list[Example]:
        sql = "SELECT * FROM decisions ORDER BY ts, route_id"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        examples: list[Example] = []
        for row in self._store.read(sql):
            examples.append(self._example_from_row(row))
        return examples

    def _example_from_row(self, row: sqlite3.Row) -> Example:
        events = self._store.read_events(row["route_id"])
        outcome_state = OutcomeState.PENDING
        failure_type: FailureType | None = None
        source: ExampleSource = "organic"
        harness_success: bool | None = None
        verification: VerificationResult | None = None
        tree_drift = False
        verifier_version: str | None = None
        for event in events:
            kind = event["event_type"]
            payload = _payload(event)
            if kind == self._names.outcome:
                state = _enum_or_none(OutcomeState, payload.get("state"))
                if state is not None:
                    outcome_state = state
                failure = _enum_or_none(FailureType, payload.get("failure_type"))
                if failure is not None:
                    failure_type = failure
                if payload.get("source") in _FAMILY_BY_SOURCE:
                    source = payload["source"]
                if "harness_reported_success" in payload:
                    harness_success = bool(payload["harness_reported_success"])
            elif kind == self._names.label:
                failure = _enum_or_none(FailureType, payload.get("failure_type"))
                if failure is not None:
                    failure_type = failure
            elif kind == self._names.verification:
                result = _enum_or_none(VerificationResult, payload.get("result"))
                if result is not None and result is not VerificationResult.INDETERMINATE:
                    verification = result
                    tree_drift = bool(payload.get("tree_drift", False))
                    verifier_version = payload.get("verifier_version")
                elif verification is None and result is not None:
                    verification = result
            elif kind == self._names.counterfactual:
                source = "counterfactual"
        try:
            features = json.loads(row["features_json"])
        except (TypeError, ValueError):
            features = {}
        try:
            context = json.loads(row["context_json"])
        except (TypeError, ValueError):
            context = {}
        explore_version = row["explore_version"]
        if explore_version is not None and source == "organic":
            source = "explore"
        return Example(
            route_id=RouteId(row["route_id"]),
            session_hmac=SessionId(row["session_hmac"]),
            decision_ts=row["ts"],
            rung=Rung(row["decided_rung"]),
            features=features if isinstance(features, dict) else {},
            features_version=row["features_version"],
            source=source,
            outcome_state=outcome_state,
            failure_type=failure_type,
            verification=verification,
            tree_drift=tree_drift,
            verifier_version=verifier_version,
            harness_reported_success=harness_success,
            propensity=float(row["propensity"]),
            explore_version=explore_version,
            pinned=bool(context.get("pinned", False)),
            privacy_suppressed=bool(context.get("privacy_suppressed", False)),
            repo_class=features.get("repo_class") if isinstance(features, dict) else None,
            intent_class=features.get("intent_class") if isinstance(features, dict) else None,
        )
