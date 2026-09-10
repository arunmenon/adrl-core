"""Per-band rule precision on verified outcomes. Primary: ADRL-RTG-003.

A band whose measured precision falls below the versioned threshold loses its clear status and
routes through the advisor until re-qualified. Reads the ledger only; never writes.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from adrl.core.enums import FailureType, OutcomeState
from adrl.ledger.store import LedgerStore

RULE_HEALTH_VERSION = "rule-health-v1"


@dataclass(frozen=True, slots=True)
class BandPrecision:
    band_id: str
    verified: int
    completed_without_escalation: int

    @property
    def precision(self) -> float | None:
        return None if self.verified == 0 else self.completed_without_escalation / self.verified


@dataclass(frozen=True, slots=True)
class RuleHealthSnapshot:
    version: str
    threshold: float
    by_band: Mapping[str, BandPrecision]
    minimum_verified: int = 20
    demoted: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def empty(cls, threshold: float) -> RuleHealthSnapshot:
        return cls(RULE_HEALTH_VERSION, threshold, {})

    def as_report(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "threshold": self.threshold,
            "minimum_verified": self.minimum_verified,
            "demoted": sorted(self.demoted),
            "bands": {
                b: {
                    "verified": p.verified,
                    "completed_without_escalation": p.completed_without_escalation,
                    "precision": p.precision,
                }
                for b, p in self.by_band.items()
            },
        }


def compute_rule_health(
    store: LedgerStore, *, threshold: float, minimum_verified: int = 20
) -> RuleHealthSnapshot:
    """Precision = closed_final verified successes without escalation / verified closed_final."""
    decisions = store.read(
        "SELECT route_id, context_json FROM decisions WHERE request_class = 'user_turn'"
    )
    band_of: dict[str, str] = {}
    for row in decisions:
        context = json.loads(row["context_json"])
        band = context.get("band_id")
        if isinstance(band, str):
            band_of[row["route_id"]] = band
    escalated: set[str] = set()
    for row in store.read("SELECT DISTINCT route_id FROM events WHERE event_type = 'escalation'"):
        escalated.add(row["route_id"])
    counts: dict[str, list[int]] = {}
    for row in store.read(
        "SELECT route_id, payload_json FROM events WHERE event_type = ? ORDER BY seq",
        (OutcomeState.CLOSED_FINAL.value,),
    ):
        band = band_of.get(row["route_id"])
        if band is None:
            continue
        payload = json.loads(row["payload_json"])
        if not payload.get("verified"):
            continue
        failure_type = payload.get("failure_type")
        success = bool(payload.get("success"))
        if not success and failure_type != FailureType.TASK_CAPABILITY.value:
            continue
        bucket = counts.setdefault(band, [0, 0])
        bucket[0] += 1
        if success and row["route_id"] not in escalated:
            bucket[1] += 1
    by_band = {b: BandPrecision(b, v, c) for b, (v, c) in counts.items()}
    demoted = frozenset(
        b
        for b, p in by_band.items()
        if p.verified >= minimum_verified and p.precision is not None and p.precision < threshold
    )
    return RuleHealthSnapshot(RULE_HEALTH_VERSION, threshold, by_band, minimum_verified, demoted)
