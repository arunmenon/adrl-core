"""Cause-typed labels on failure-types-v2. Primary: ADRL-MEM-004.

Secondary: ADRL-MEM-002 (censoring), ADRL-MEM-003 (verification precedence), ADRL-LRN-001.

Label confidence is a documented, coarse scale rather than a probability:
  1.00 verified by a deterministic verifier, no tree drift
  0.90 verified failure with no other recorded cause (cause attributed to capability)
  0.60 deterministic trip-wire or typed cause recorded by the cascade
  0.30 proxy signal only (harness reported success, no verifier)
  0.00 nothing determinable (unverifiable)
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from adrl.core.enums import (
    FAILURE_TYPES_VERSION,
    FailureType,
    OutcomeState,
    VerificationResult,
    resolve_primary,
)
from adrl.ledger.events import (
    LATE_EVIDENCE_EVENT,
    OUTCOME_EVENT,
    VERIFICATION_EVENT,
    StoredEvent,
)
from adrl.ledger.upcast import upcast_event

LABEL_RULE_VERSION = "label-rule-v1"

EXCLUDED_TYPES: frozenset[FailureType] = frozenset(
    {
        FailureType.INFRASTRUCTURE,
        FailureType.POLICY_CONSTRAINT,
        FailureType.CONTEXT_FEASIBILITY,
        FailureType.USER_ABORT,
        FailureType.UNVERIFIABLE,
    }
)


@dataclass(frozen=True, slots=True)
class Label:
    result: str
    failure_type: FailureType | None
    secondary_type: FailureType | None
    label_confidence: float
    source_event_id: int | None
    basis: str
    label_rule_version: str = LABEL_RULE_VERSION
    failure_types_version: str = FAILURE_TYPES_VERSION

    @property
    def is_capability_evidence(self) -> bool:
        """Only verified successes and task_capability failures speak to a rung's ability."""
        if self.result == "success":
            return self.basis == "verifier"
        return self.failure_type is FailureType.TASK_CAPABILITY

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "failure_type": self.failure_type.value if self.failure_type else None,
            "secondary_type": self.secondary_type.value if self.secondary_type else None,
            "label_confidence": self.label_confidence,
            "source_event_id": self.source_event_id,
            "basis": self.basis,
            "label_rule_version": self.label_rule_version,
            "failure_types_version": self.failure_types_version,
        }


UNVERIFIABLE_LABEL = Label(
    result="excluded",
    failure_type=FailureType.UNVERIFIABLE,
    secondary_type=None,
    label_confidence=0.0,
    source_event_id=None,
    basis="none",
)


def _candidates(payloads: Iterable[dict[str, Any]]) -> list[tuple[int | None, FailureType]]:
    found: list[tuple[int | None, FailureType]] = []
    for payload in payloads:
        for cause in payload.get("causes", []) or []:
            if not isinstance(cause, dict):
                continue
            try:
                ft = FailureType(str(cause.get("failure_type")))
            except ValueError:
                ft = FailureType.UNVERIFIABLE
            index = cause.get("action_index")
            found.append((int(index) if index is not None else None, ft))
        raw = payload.get("failure_type")
        if raw is not None:
            try:
                found.append((None, FailureType(str(raw))))
            except ValueError:
                found.append((None, FailureType.UNVERIFIABLE))
    return found


def _order_causes(
    candidates: Sequence[tuple[int | None, FailureType]],
) -> tuple[FailureType, FailureType | None] | None:
    """Primary is the cause that occurred first in the action sequence (ADRL-MEM-004 clause 2).

    When no action indexes are recorded the CAS-002 precedence rule decides.
    """
    real = [(i, ft) for i, ft in candidates if ft is not FailureType.UNVERIFIABLE]
    if not real:
        return None
    indexed = [(i, ft) for i, ft in real if i is not None]
    if indexed and len(indexed) == len(real):
        ordered = [ft for _, ft in sorted(indexed, key=lambda item: item[0])]
        primary = ordered[0]
        secondary = next((ft for ft in ordered[1:] if ft is not primary), None)
        return primary, secondary
    return resolve_primary([ft for _, ft in real])


def _latest_verification(events: Sequence[StoredEvent]) -> StoredEvent | None:
    usable: list[StoredEvent] = []
    for event in events:
        if event.event_type != VERIFICATION_EVENT:
            continue
        payload = event.payload
        if payload.get("tree_drift"):
            continue
        if str(payload.get("result")) == VerificationResult.INDETERMINATE.value:
            continue
        usable.append(event)
    return usable[-1] if usable else None


def derive_label(events: Sequence[StoredEvent]) -> Label:
    """Derive the current label from a route's events (already in ledger order)."""
    upcast = [StoredEvent(e.seq, e.ts, upcast_event(e.event)) for e in events]
    outcome_payloads = [dict(e.payload) for e in upcast if e.event_type == OUTCOME_EVENT]
    late_payloads = [dict(e.payload) for e in upcast if e.event_type == LATE_EVIDENCE_EVENT]
    late_events = [e for e in upcast if e.event_type == LATE_EVIDENCE_EVENT]

    verification = _latest_verification(upcast)
    if verification is not None:
        result = str(verification.payload.get("result"))
        if result == VerificationResult.PASS.value:
            return Label("success", None, None, 1.0, verification.seq, "verifier")
        causes = _candidates([dict(verification.payload), *outcome_payloads, *late_payloads])
        ordered = _order_causes(causes)
        if ordered is None:
            return Label(
                "failure", FailureType.TASK_CAPABILITY, None, 0.9, verification.seq, "verifier"
            )
        primary, secondary = ordered
        return Label(
            "excluded" if primary in EXCLUDED_TYPES else "failure",
            primary,
            secondary,
            1.0,
            verification.seq,
            "verifier",
        )

    causes = _candidates([*outcome_payloads, *late_payloads])
    ordered = _order_causes(causes)
    if ordered is not None:
        primary, secondary = ordered
        source = late_events[-1].seq if late_events else _last_outcome_seq(upcast)
        return Label(
            "excluded" if primary in EXCLUDED_TYPES else "failure",
            primary,
            secondary,
            0.6,
            source,
            "tripwire",
        )

    for payload in reversed(outcome_payloads):
        if payload.get("harness_reported_success") is True:
            return Label("success", None, None, 0.3, _last_outcome_seq(upcast), "proxy")
    return UNVERIFIABLE_LABEL


def _last_outcome_seq(events: Sequence[StoredEvent]) -> int | None:
    for event in reversed(events):
        if event.event_type == OUTCOME_EVENT:
            return event.seq
    return None


def outcome_state(events: Sequence[StoredEvent]) -> OutcomeState | None:
    state: OutcomeState | None = None
    for event in events:
        if event.event_type != OUTCOME_EVENT:
            continue
        try:
            state = OutcomeState(str(event.payload.get("state")))
        except ValueError:
            continue
    return state


def is_countable(events: Sequence[StoredEvent]) -> bool:
    """Censoring: only closed_final outcomes may be counted as labels (ADRL-MEM-002)."""
    return outcome_state(events) is OutcomeState.CLOSED_FINAL
