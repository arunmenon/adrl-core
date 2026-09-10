"""Rebuild every projection from events. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-007.

Replay is idempotent: it reads events, derives outcome and label state in memory, rebuilds the
retrieval index and appends one projection stamp. It never writes an event.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from adrl.core.ids import RouteId
from adrl.ledger.events import OUTCOME_EVENT, read_stored_events
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.outcomes import OutcomeProjection, project_outcome
from adrl.ledger.projections import NumpyIndex
from adrl.ledger.store import LedgerStore


@dataclass(frozen=True, slots=True)
class ReplayReport:
    routes: int
    outcomes: dict[RouteId, OutcomeProjection]
    index_rows: int
    seconds: float
    stamp: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        states: dict[str, int] = {}
        for projection in self.outcomes.values():
            key = projection.state.value if projection.state else "none"
            states[key] = states.get(key, 0) + 1
        return {
            "routes": self.routes,
            "states": states,
            "index_rows": self.index_rows,
            "seconds": round(self.seconds, 4),
            "stamp": self.stamp,
        }


def replay_outcomes(store: LedgerStore) -> dict[RouteId, OutcomeProjection]:
    rows = store.read("SELECT DISTINCT route_id FROM events WHERE event_type=?", (OUTCOME_EVENT,))
    out: dict[RouteId, OutcomeProjection] = {}
    for row in rows:
        route_id = RouteId(str(row["route_id"]))
        out[route_id] = project_outcome(route_id, read_stored_events(store, route_id))
    return out


async def replay(store: LedgerStore, keystore: FileKeyStore, embedder_version: str) -> ReplayReport:
    started = time.perf_counter()
    outcomes = replay_outcomes(store)
    index = NumpyIndex(store, keystore, embedder_version)
    stamp = index.rebuild()
    await index.persist_stamp()
    elapsed = time.perf_counter() - started
    return ReplayReport(len(outcomes), outcomes, index.size, elapsed, stamp.as_record())
