"""Advisory retrieval that writes only to the ledger. Primary: ADRL-MEM-008.

Secondary: ADRL-MEM-007 (stale and invalid projections), ADRL-MEM-005 (suppressed fraction).
Nothing here is imported by routing or the proxy; tools/check_ledger_discipline.py enforces it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from adrl.core.enums import ProjectionState
from adrl.core.ids import RouteId
from adrl.ledger.events import (
    PRODUCER_RETRIEVAL,
    SHADOW_RETRIEVAL_EVENT,
    producer_seq_for,
    read_stored_events,
)
from adrl.ledger.labels import derive_label
from adrl.ledger.projections import Neighbour, NumpyIndex
from adrl.ledger.store import LedgerStore

SHADOW_RETRIEVAL_VERSION = "shadow-retrieval-v1"


@dataclass(frozen=True, slots=True)
class ShadowAdvice:
    route_id: RouteId
    projection_state: ProjectionState
    neighbours: tuple[Neighbour, ...]
    neighbour_local_success_rate: float | None
    abstained: bool
    reason: str | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "version": SHADOW_RETRIEVAL_VERSION,
            "projection_state": self.projection_state.value,
            "neighbours": [
                {"route_id": str(n.route_id), "similarity": n.similarity} for n in self.neighbours
            ],
            "neighbour_local_success_rate": self.neighbour_local_success_rate,
            "abstained": self.abstained,
            "reason": self.reason,
        }


class ShadowRetriever:
    def __init__(self, store: LedgerStore, index: NumpyIndex, *, k: int = 5) -> None:
        self._store = store
        self._index = index
        self._k = k

    def _neighbour_rate(self, neighbours: Sequence[Neighbour]) -> float | None:
        counted = 0
        successes = 0
        for neighbour in neighbours:
            events = read_stored_events(self._store, neighbour.route_id)
            label = derive_label(events)
            decision = self._store.read_decision(str(neighbour.route_id))
            if decision is None or not label.is_capability_evidence:
                continue
            if str(decision["decided_rung"]) != "local":
                continue
            counted += 1
            if label.result == "success":
                successes += 1
        return (successes / counted) if counted else None

    async def advise(self, route_id: RouteId, vector: Sequence[float]) -> ShadowAdvice:
        state = self._index.state()
        if state is ProjectionState.INVALID:
            advice = ShadowAdvice(route_id, state, (), None, True, "projection_invalid")
        else:
            neighbours = tuple(self._index.query(vector, self._k, exclude=route_id))
            advice = ShadowAdvice(
                route_id,
                state,
                neighbours,
                self._neighbour_rate(neighbours),
                False,
                "stale_labelled" if state is ProjectionState.STALE else None,
            )
        stamp = self._index.stamp
        await self._store.write_through(
            LedgerStore.insert_event(
                str(route_id),
                SHADOW_RETRIEVAL_EVENT,
                PRODUCER_RETRIEVAL,
                producer_seq_for(str(route_id), str(stamp.high_water_seq if stamp else 0)),
                advice.as_payload(),
                "events-v1",
            )
        )
        return advice

    def suppressed_fraction(self) -> float:
        """Share of decisions with no embedding (private, pinned or shredded)."""
        total = int(self._store.read("SELECT COUNT(*) AS c FROM decisions")[0]["c"])
        if not total:
            return 0.0
        embedded = int(
            self._store.read(
                "SELECT COUNT(DISTINCT d.route_id) AS c FROM decisions d "
                "JOIN embeddings e ON e.route_id = d.route_id"
            )[0]["c"]
        )
        return 1.0 - embedded / total
