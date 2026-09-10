"""Provider-backed routing state. Primary: ADRL-MEM-006. Secondary: ADRL-SAF-002, ADRL-CAS-006.

Sticky route and pin state are lineage_events rows; the in-memory cache is rebuilt from the
ledger on start. An unknown lineage returns None so the cascade records state_loss=true rather
than pretending continuity. Pin state is never cleared here: only the audited release path in
the gates package appends a release event, and even then a later finding re-pins.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from adrl.core.enums import PinLookup, Rung
from adrl.core.ids import LineageId, RouteId
from adrl.core.ports import LineageEvent, StickyState
from adrl.ledger.events import PIN_EVENT, RELEASE_EVENT, STICKY_EVENT
from adrl.ledger.store import LedgerStore

STATE_SCHEMA_VERSION = "state-v1"


def pin_lookup_from_events(events: Sequence[LineageEvent]) -> PinLookup:
    """Pinned unless every pinning finding has an audited release (ADRL-SAF-002 clause 3)."""
    active: set[str] = set()
    released: set[str] = set()
    pinned = False
    for event in events:
        if event.event_type == PIN_EVENT:
            active.add(str(event.payload.get("finding_id", "")))
            pinned = True
        elif event.event_type == RELEASE_EVENT:
            released.add(str(event.payload.get("finding_id", "")))
    if not pinned:
        return PinLookup.UNPINNED
    if active and active <= released:
        return PinLookup.UNPINNED
    return PinLookup.PINNED


def sticky_from_payload(lineage: LineageId, payload: dict[str, Any]) -> StickyState:
    last = payload.get("last_served_at")
    return StickyState(
        lineage_hmac=lineage,
        route_id=RouteId(str(payload["route_id"])),
        rung=Rung(str(payload["rung"])),
        escalated=bool(payload.get("escalated", False)),
        served_model=payload.get("served_model"),
        served_provider=payload.get("served_provider"),
        served_source=str(payload.get("served_source", "assumed_intended")),
        turn_index=int(payload.get("turn_index", 0)),
        last_served_at=datetime.fromisoformat(str(last)) if last else None,
        state_loss=False,
    )


def sticky_to_payload(state: StickyState) -> dict[str, Any]:
    return {
        "route_id": str(state.route_id),
        "rung": state.rung.value,
        "escalated": state.escalated,
        "served_model": state.served_model,
        "served_provider": state.served_provider,
        "served_source": state.served_source,
        "turn_index": state.turn_index,
        "last_served_at": state.last_served_at.isoformat() if state.last_served_at else None,
        "schema_version": STATE_SCHEMA_VERSION,
    }


class SqliteStateProvider:
    """StateProvider over the ledger store with a cache rebuilt on load_all."""

    def __init__(self, store: LedgerStore) -> None:
        self._store = store
        self._sticky: dict[LineageId, StickyState] = {}
        self._pins: dict[LineageId, PinLookup] = {}
        self._loaded = False

    @property
    def loaded(self) -> bool:
        return self._loaded

    async def load_all(self) -> int:
        return self.load_now()

    def load_now(self) -> int:
        """Synchronous rebuild of the cache; the composition root calls it before serving."""
        rows = self._store.read(
            "SELECT lineage_hmac, event_type, payload_json FROM lineage_events "
            "WHERE event_type IN (?,?,?) ORDER BY seq",
            (STICKY_EVENT, PIN_EVENT, RELEASE_EVENT),
        )
        by_lineage: dict[LineageId, list[LineageEvent]] = {}
        for row in rows:
            lineage = LineageId(str(row["lineage_hmac"]))
            payload = json.loads(str(row["payload_json"]))
            event_type = str(row["event_type"])
            if event_type == STICKY_EVENT:
                self._sticky[lineage] = sticky_from_payload(lineage, payload)
            else:
                by_lineage.setdefault(lineage, []).append(
                    LineageEvent(lineage, event_type, payload)
                )
        for lineage, events in by_lineage.items():
            self._pins[lineage] = pin_lookup_from_events(events)
        self._loaded = True
        return len(self._sticky) + len(self._pins)

    async def get_sticky(self, lineage: LineageId) -> StickyState | None:
        return self._sticky.get(lineage)

    async def set_sticky(self, state: StickyState) -> None:
        await self._store.write_through(
            LedgerStore.insert_lineage_event(
                state.lineage_hmac, STICKY_EVENT, sticky_to_payload(state)
            )
        )
        self._sticky[state.lineage_hmac] = state

    async def get_pin(self, lineage: LineageId) -> PinLookup:
        cached = self._pins.get(lineage)
        if cached is not None:
            return cached
        rows = self._store.read_lineage_events(str(lineage))
        events = [
            LineageEvent(lineage, str(r["event_type"]), json.loads(str(r["payload_json"])))
            for r in rows
            if str(r["event_type"]) in (PIN_EVENT, RELEASE_EVENT)
        ]
        lookup = pin_lookup_from_events(events)
        if events:
            self._pins[lineage] = lookup
        return lookup

    async def set_pin(self, lineage: LineageId, finding_id: str, detector_id: str) -> None:
        await self._store.write_through(
            LedgerStore.insert_lineage_event(
                lineage,
                PIN_EVENT,
                {
                    "finding_id": finding_id,
                    "detector_id": detector_id,
                    "schema_version": STATE_SCHEMA_VERSION,
                },
            )
        )
        self._pins[lineage] = PinLookup.PINNED

    def note_release(self, lineage: LineageId, finding_id: str) -> None:
        """Refresh the cache after the gates package appended a release event."""
        self._pins.pop(lineage, None)
