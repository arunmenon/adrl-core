"""Typed event constructors and producer sequencing. Primary: ADRL-MEM-001.

Secondary: ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-004, ADRL-MEM-009, ADRL-MEM-010.

Every event is idempotent under (route_id, event_type, producer, producer_seq). Producers with a
natural order use ProducerSequencer; producers whose events have a logical identity (a closing
rule, a verification job) derive producer_seq from that identity with producer_seq_for so a
retried write is a no-op rather than a duplicate.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from adrl.core.enums import FAILURE_TYPES_VERSION, FailureType, OutcomeState, VerificationResult
from adrl.core.ids import RouteId
from adrl.core.types import LedgerEvent
from adrl.ledger.store import LedgerStore

EVENTS_SCHEMA_VERSION = "events-v1"

# Route-level event types (events table).
OUTCOME_EVENT = "outcome"
LATE_EVIDENCE_EVENT = "late_evidence"
VERIFICATION_EVENT = "verification"
COUNTERFACTUAL_EVENT = "counterfactual"
LABEL_EVENT = "label"
LABEL_CORRECTION_EVENT = "label_correction"
SHADOW_RETRIEVAL_EVENT = "shadow_retrieval"
MEMORY_DEGRADED_EVENT = "memory_degraded"

# Lineage-level event types (lineage_events table).
ERASED_EVENT = "erased"
STICKY_EVENT = "sticky"
VERIFIER_FAILED_EVENT = "verifier_failed"
PIN_EVENT = "pinned"
RELEASE_EVENT = "released"
EPISODE_BOUNDARY_EVENT = "episode_boundary"
PROJECTION_REBUILD_EVENT = "projection_rebuild"

# Producers.
PRODUCER_PROXY = "proxy"
PRODUCER_CASCADE = "cascade"
PRODUCER_CLOSER = "closer"
PRODUCER_VERIFIER = "verifier"
PRODUCER_LABELER = "labeler"
PRODUCER_COUNTERFACTUAL = "counterfactual_runner"
PRODUCER_RETRIEVAL = "shadow_retrieval"
PRODUCER_CORRECTION = "correction_detector"
PRODUCER_MEMORY = "memory_facade"


def producer_seq_for(*parts: str) -> int:
    """Stable 31-bit producer_seq derived from a logical identity."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") & 0x7FFFFFFF


class ProducerSequencer:
    """Monotonic producer_seq per (producer, route_id) for producers with a natural order."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, str], int] = {}

    def next(self, producer: str, route_id: RouteId) -> int:
        key = (producer, str(route_id))
        value = self._counters.get(key, 0) + 1
        self._counters[key] = value
        return value

    def observe(self, producer: str, route_id: RouteId, seen: int) -> None:
        """Advance the counter past a value already present in the ledger."""
        key = (producer, str(route_id))
        if seen > self._counters.get(key, 0):
            self._counters[key] = seen


@dataclass(frozen=True, slots=True)
class StoredEvent:
    """A ledger event as read back, with its global sequence and timestamp."""

    seq: int
    ts: str
    event: LedgerEvent

    @property
    def event_type(self) -> str:
        return self.event.event_type

    @property
    def payload(self) -> Mapping[str, Any]:
        return self.event.payload

    @property
    def route_id(self) -> RouteId:
        return self.event.route_id


def stored_event_from_row(row: sqlite3.Row) -> StoredEvent:
    return StoredEvent(
        seq=int(row["seq"]),
        ts=str(row["ts"]),
        event=LedgerEvent(
            route_id=RouteId(str(row["route_id"])),
            event_type=str(row["event_type"]),
            producer=str(row["producer"]),
            producer_seq=int(row["producer_seq"]),
            payload=json.loads(str(row["payload_json"])),
            schema_version=str(row["schema_version"]),
        ),
    )


def read_stored_events(
    store: LedgerStore, route_id: RouteId, event_type: str | None = None
) -> list[StoredEvent]:
    return [stored_event_from_row(r) for r in store.read_events(str(route_id), event_type)]


def read_events_of_type(
    store: LedgerStore, event_type: str, *, after_seq: int = 0
) -> list[StoredEvent]:
    rows = store.read(
        "SELECT * FROM events WHERE event_type=? AND seq>? ORDER BY seq", (event_type, after_seq)
    )
    return [stored_event_from_row(r) for r in rows]


# Constructors -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CauseCandidate:
    """One plausible failure cause with its position in the action sequence (ADRL-MEM-004)."""

    failure_type: FailureType
    action_index: int | None = None
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "failure_type": self.failure_type.value,
            "action_index": self.action_index,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class OutcomeFields:
    """Optional facts a producer attaches to an outcome transition."""

    served_rung: str | None = None
    served_model: str | None = None
    session_hmac: str | None = None
    lineage_hmac: str | None = None
    turn_index: int | None = None
    harness_reported_success: bool | None = None
    causes: tuple[CauseCandidate, ...] = ()
    touched_paths: tuple[str, ...] = field(default_factory=tuple)
    tree_identity: Mapping[str, Any] | None = None
    escalated_to_route_id: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "served_rung": self.served_rung,
            "served_model": self.served_model,
            "session_hmac": self.session_hmac,
            "lineage_hmac": self.lineage_hmac,
            "turn_index": self.turn_index,
            "harness_reported_success": self.harness_reported_success,
            "causes": [c.as_dict() for c in self.causes],
            "touched_paths": list(self.touched_paths),
            "tree_identity": dict(self.tree_identity) if self.tree_identity else None,
            "escalated_to_route_id": self.escalated_to_route_id,
        }
        payload.update(dict(self.extra))
        return payload


def outcome_event(
    route_id: RouteId,
    state: OutcomeState,
    producer: str,
    producer_seq: int,
    fields: OutcomeFields | None = None,
    *,
    rule_id: str | None = None,
    trigger: str | None = None,
    label: Mapping[str, Any] | None = None,
) -> LedgerEvent:
    payload = (fields or OutcomeFields()).as_payload()
    payload["state"] = state.value
    payload["failure_types_version"] = FAILURE_TYPES_VERSION
    if rule_id is not None:
        payload["rule_id"] = rule_id
    if trigger is not None:
        payload["trigger"] = trigger
    if label is not None:
        payload["label"] = dict(label)
    return LedgerEvent(
        route_id, OUTCOME_EVENT, producer, producer_seq, payload, EVENTS_SCHEMA_VERSION
    )


def late_evidence_event(
    route_id: RouteId,
    source: str,
    producer: str,
    producer_seq: int,
    detail: Mapping[str, Any],
    *,
    causes: Sequence[CauseCandidate] = (),
) -> LedgerEvent:
    payload: dict[str, Any] = {
        "source": source,
        "detail": dict(detail),
        "causes": [c.as_dict() for c in causes],
        "failure_types_version": FAILURE_TYPES_VERSION,
    }
    return LedgerEvent(
        route_id, LATE_EVIDENCE_EVENT, producer, producer_seq, payload, EVENTS_SCHEMA_VERSION
    )


def verification_event(
    route_id: RouteId,
    producer_seq: int,
    *,
    verifier_version: str,
    argv: Sequence[Sequence[str]],
    protected_path_policy_version: str,
    tree_identity: Mapping[str, Any],
    result: VerificationResult,
    started_at: str,
    finished_at: str,
    tree_drift: bool,
    checks: Sequence[Mapping[str, Any]],
    unverifiable_reason: str | None = None,
    job_id: str | None = None,
    causes: Sequence[CauseCandidate] = (),
) -> LedgerEvent:
    payload: dict[str, Any] = {
        "verifier_version": verifier_version,
        "argv": [list(a) for a in argv],
        "protected_path_policy_version": protected_path_policy_version,
        "tree_identity": dict(tree_identity),
        "result": result.value,
        "started_at": started_at,
        "finished_at": finished_at,
        "tree_drift": tree_drift,
        "checks": [dict(c) for c in checks],
        "unverifiable_reason": unverifiable_reason,
        "job_id": job_id,
        "causes": [c.as_dict() for c in causes],
        "failure_types_version": FAILURE_TYPES_VERSION,
    }
    return LedgerEvent(
        route_id,
        VERIFICATION_EVENT,
        PRODUCER_VERIFIER,
        producer_seq,
        payload,
        EVENTS_SCHEMA_VERSION,
    )


def counterfactual_event(
    route_id: RouteId, pair_id: str, producer_seq: int, detail: Mapping[str, Any]
) -> LedgerEvent:
    payload: dict[str, Any] = {"pair_id": pair_id, "tier": "T5", **dict(detail)}
    return LedgerEvent(
        route_id,
        COUNTERFACTUAL_EVENT,
        PRODUCER_COUNTERFACTUAL,
        producer_seq,
        payload,
        EVENTS_SCHEMA_VERSION,
    )


def label_event(
    route_id: RouteId,
    producer_seq: int,
    label: Mapping[str, Any],
    *,
    supersedes_seq: int | None = None,
) -> LedgerEvent:
    payload: dict[str, Any] = dict(label)
    payload["supersedes_seq"] = supersedes_seq
    payload["failure_types_version"] = FAILURE_TYPES_VERSION
    event_type = LABEL_EVENT if supersedes_seq is None else LABEL_CORRECTION_EVENT
    return LedgerEvent(
        route_id, event_type, PRODUCER_LABELER, producer_seq, payload, EVENTS_SCHEMA_VERSION
    )


def memory_degraded_event(
    route_id: RouteId, reason: str, operation: str, producer_seq: int
) -> LedgerEvent:
    return LedgerEvent(
        route_id,
        MEMORY_DEGRADED_EVENT,
        PRODUCER_MEMORY,
        producer_seq,
        {"reason": reason, "operation": operation},
        EVENTS_SCHEMA_VERSION,
    )
