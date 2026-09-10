"""Learning readiness counts on censored, cause-clean labels. Primary: ADRL-MEM-004.

Secondary: ADRL-MEM-002 (censoring), ADRL-MEM-006 (degraded windows), ADRL-FND-005,
ADRL-EVL-004, ADRL-EVL-009.
Only task_capability evidence at closed_final counts; excluded types are reported next to the
count, never averaged into it. A non-zero memory_degraded count blocks the window.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from adrl.core.enums import FailureType, OutcomeState
from adrl.core.ids import RouteId
from adrl.ledger.events import MEMORY_DEGRADED_EVENT, OUTCOME_EVENT, read_stored_events
from adrl.ledger.labels import derive_label
from adrl.ledger.store import LedgerStore

READINESS_VERSION = "readiness-count-v1"


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    version: str
    closed_final_count: int
    censored_count: int
    capability_evidence_count: int
    verified_success_count: int
    task_capability_failure_count: int
    excluded_by_type: dict[str, int]
    excluded_fraction: float
    distinct_bands: int
    distinct_repo_classes: int
    memory_degraded_count: int
    window_blocked: bool
    blockers: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "closed_final_count": self.closed_final_count,
            "censored_count": self.censored_count,
            "capability_evidence_count": self.capability_evidence_count,
            "verified_success_count": self.verified_success_count,
            "task_capability_failure_count": self.task_capability_failure_count,
            "excluded_by_type": dict(self.excluded_by_type),
            "excluded_fraction": self.excluded_fraction,
            "distinct_bands": self.distinct_bands,
            "distinct_repo_classes": self.distinct_repo_classes,
            "memory_degraded_count": self.memory_degraded_count,
            "window_blocked": self.window_blocked,
            "blockers": list(self.blockers),
        }


def learning_readiness(store: LedgerStore) -> ReadinessReport:
    routes = store.read("SELECT DISTINCT route_id FROM events WHERE event_type=?", (OUTCOME_EVENT,))
    closed_final = 0
    censored = 0
    verified_success = 0
    capability_failure = 0
    excluded: Counter[str] = Counter()
    bands: set[str] = set()
    repos: set[str] = set()
    for row in routes:
        route_id = RouteId(str(row["route_id"]))
        events = read_stored_events(store, route_id)
        state = None
        for event in events:
            if event.event_type == OUTCOME_EVENT:
                state = str(event.payload.get("state"))
        if state != OutcomeState.CLOSED_FINAL.value:
            censored += 1
            continue
        closed_final += 1
        label = derive_label(events)
        if label.is_capability_evidence:
            if label.result == "success":
                verified_success += 1
            else:
                capability_failure += 1
            decision = store.read_decision(str(route_id))
            if decision is not None:
                features = json.loads(str(decision["features_json"]))
                if features.get("band_id"):
                    bands.add(str(features["band_id"]))
                if features.get("repo_class"):
                    repos.add(str(features["repo_class"]))
        else:
            excluded[(label.failure_type or FailureType.UNVERIFIABLE).value] += 1
    degraded = int(
        store.read("SELECT COUNT(*) AS c FROM events WHERE event_type=?", (MEMORY_DEGRADED_EVENT,))[
            0
        ]["c"]
    )
    evidence = verified_success + capability_failure
    blockers: list[str] = []
    if degraded:
        blockers.append("memory_degraded_nonzero")
    if closed_final and evidence == 0:
        blockers.append("no_capability_evidence")
    return ReadinessReport(
        version=READINESS_VERSION,
        closed_final_count=closed_final,
        censored_count=censored,
        capability_evidence_count=evidence,
        verified_success_count=verified_success,
        task_capability_failure_count=capability_failure,
        excluded_by_type=dict(excluded),
        excluded_fraction=(sum(excluded.values()) / closed_final) if closed_final else 0.0,
        distinct_bands=len(bands),
        distinct_repo_classes=len(repos),
        memory_degraded_count=degraded,
        window_blocked=bool(blockers),
        blockers=tuple(blockers),
    )
