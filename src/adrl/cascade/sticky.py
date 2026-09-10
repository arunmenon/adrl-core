"""Sticky state within an episode. Primary: ADRL-CAS-005. Secondary: ADRL-CAS-006, ADRL-SEM-005.
Also implements: ADRL-OPS-006 (served identity, not intended).

State goes through the StateProvider port. MemoryStateProvider is the single-process fallback
and is the documented OPS-001 multi-worker blocker; the SQLite provider lives in adrl.ledger.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from adrl.core.enums import EpisodeSignal, PinLookup, Rung
from adrl.core.ids import LineageId, RouteId
from adrl.core.ports import StickyState
from adrl.core.types import ServedIdentity

RATCHET_RELEASE_SIGNALS: frozenset[EpisodeSignal] = frozenset(EpisodeSignal)


class MemoryStateProvider:
    """In-memory StateProvider. Constraint: single process; state is lost on restart."""

    def __init__(self) -> None:
        self._sticky: dict[LineageId, StickyState] = {}
        self._pins: dict[LineageId, tuple[str, str]] = {}

    async def get_sticky(self, lineage: LineageId) -> StickyState | None:
        return self._sticky.get(lineage)

    async def set_sticky(self, state: StickyState) -> None:
        self._sticky[state.lineage_hmac] = state

    async def get_pin(self, lineage: LineageId) -> PinLookup:
        return PinLookup.PINNED if lineage in self._pins else PinLookup.UNPINNED

    async def set_pin(self, lineage: LineageId, finding_id: str, detector_id: str) -> None:
        self._pins[lineage] = (finding_id, detector_id)

    async def load_all(self) -> int:
        return len(self._sticky)


def family_of_model(model: str | None, rung: Rung, default: str) -> str:
    if rung is Rung.LOCAL:
        return "local"
    if model is None:
        return default
    lowered = model.lower()
    if "claude" in lowered or "anthropic" in lowered:
        return "anthropic"
    if lowered.startswith(("gpt", "o1", "o3", "o4", "openai")) or "/gpt" in lowered:
        return "openai"
    if lowered.startswith(("gemini", "google")):
        return "google"
    return default


def new_sticky(
    lineage: LineageId,
    route_id: RouteId,
    rung: Rung,
    *,
    previous: StickyState | None,
    escalated: bool = False,
) -> StickyState:
    return StickyState(
        lineage_hmac=lineage,
        route_id=route_id,
        rung=rung,
        escalated=escalated,
        served_model=None,
        served_provider=None,
        served_source="assumed_intended",
        turn_index=(previous.turn_index + 1) if previous else 1,
        last_served_at=None,
        state_loss=False,
    )


def with_served(
    sticky: StickyState, served: ServedIdentity, at: datetime
) -> tuple[StickyState, bool]:
    """Record the served identity. Returns (state, within_rung_model_changed)."""
    changed = (
        sticky.served_model is not None
        and served.model is not None
        and served.model != sticky.served_model
        and served.rung is sticky.rung
    )
    return (
        StickyState(
            lineage_hmac=sticky.lineage_hmac,
            route_id=sticky.route_id,
            rung=served.rung,
            escalated=sticky.escalated,
            served_model=served.model,
            served_provider=served.provider,
            served_source=served.source.value,
            turn_index=sticky.turn_index,
            last_served_at=at,
            state_loss=sticky.state_loss,
        ),
        changed,
    )


def escalate(sticky: StickyState, to_rung: Rung, route_id: RouteId | None = None) -> StickyState:
    return StickyState(
        lineage_hmac=sticky.lineage_hmac,
        route_id=route_id or sticky.route_id,
        rung=to_rung,
        escalated=True,
        served_model=None,
        served_provider=None,
        served_source="assumed_intended",
        turn_index=sticky.turn_index,
        last_served_at=None,
        state_loss=sticky.state_loss,
    )


def release_ratchet(sticky: StickyState, signal: EpisodeSignal) -> StickyState:
    """An enumerated episode boundary releases only the escalation ratchet, never a pin."""
    if signal not in RATCHET_RELEASE_SIGNALS:
        return sticky
    return StickyState(
        lineage_hmac=sticky.lineage_hmac,
        route_id=sticky.route_id,
        rung=sticky.rung,
        escalated=False,
        served_model=sticky.served_model,
        served_provider=sticky.served_provider,
        served_source=sticky.served_source,
        turn_index=sticky.turn_index,
        last_served_at=sticky.last_served_at,
        state_loss=sticky.state_loss,
    )


def mark_state_loss(sticky: StickyState) -> StickyState:
    return StickyState(
        lineage_hmac=sticky.lineage_hmac,
        route_id=sticky.route_id,
        rung=sticky.rung,
        escalated=sticky.escalated,
        served_model=sticky.served_model,
        served_provider=sticky.served_provider,
        served_source=sticky.served_source,
        turn_index=sticky.turn_index,
        last_served_at=sticky.last_served_at,
        state_loss=True,
    )


def sticky_record(sticky: StickyState) -> dict[str, Any]:
    return {
        "route_id": sticky.route_id,
        "rung": sticky.rung.value,
        "escalated": sticky.escalated,
        "served_model": sticky.served_model,
        "served_provider": sticky.served_provider,
        "served_source": sticky.served_source,
        "turn_index": sticky.turn_index,
        "state_loss": sticky.state_loss,
    }
