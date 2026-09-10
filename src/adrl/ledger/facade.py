"""Fail-safe memory facade. Primary: ADRL-MEM-006. Secondary: ADRL-MEM-001, ADRL-SAF-002.

Provider unavailable means the router continues on the deterministic safe policy; every decision
that could not be persisted emits memory_degraded telemetry. Under degraded mode a pin lookup
returns UNKNOWN, which callers must treat as pinned.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import structlog

from adrl.core.enums import PinLookup
from adrl.core.ids import LineageId, RouteId
from adrl.core.ports import LedgerHealth, LedgerPort, LineageEvent
from adrl.core.types import Decision, LedgerEvent
from adrl.ledger.store import LedgerStore
from adrl.telemetry.metrics import MEMORY_DEGRADED_TOTAL

log = structlog.get_logger(__name__)

PIN_EVENT = "pinned"
RELEASE_EVENT = "released"


class SqliteLedgerProvider:
    """LedgerPort over the SQLite store."""

    def __init__(self, store: LedgerStore) -> None:
        self._store = store

    async def append_decision(self, decision: Decision, context: Mapping[str, Any]) -> bool:
        return bool(
            await self._store.write_through(LedgerStore.insert_decision(decision.as_row(), context))
        )

    async def append_event(self, event: LedgerEvent) -> bool:
        return bool(
            await self._store.write_through(
                LedgerStore.insert_event(
                    event.route_id,
                    event.event_type,
                    event.producer,
                    event.producer_seq,
                    event.payload,
                    event.schema_version,
                )
            )
        )

    async def append_lineage_event(self, event: LineageEvent) -> int:
        return int(
            await self._store.write_through(
                LedgerStore.insert_lineage_event(
                    event.lineage_hmac, event.event_type, event.payload
                )
            )
        )

    async def read_lineage_events(
        self, lineage: LineageId, event_type: str | None = None
    ) -> Sequence[LineageEvent]:
        rows = self._store.read_lineage_events(lineage, event_type)
        return [
            LineageEvent(
                lineage_hmac=LineageId(str(r["lineage_hmac"])),
                event_type=str(r["event_type"]),
                payload=json.loads(str(r["payload_json"])),
                ts=str(r["ts"]),
                seq=int(r["seq"]),
            )
            for r in rows
        ]

    async def read_events(
        self, route_id: RouteId, event_type: str | None = None
    ) -> Sequence[LedgerEvent]:
        rows = self._store.read_events(route_id, event_type)
        return [
            LedgerEvent(
                route_id=RouteId(str(r["route_id"])),
                event_type=str(r["event_type"]),
                producer=str(r["producer"]),
                producer_seq=int(r["producer_seq"]),
                payload=json.loads(str(r["payload_json"])),
                schema_version=str(r["schema_version"]),
            )
            for r in rows
        ]

    async def health(self) -> LedgerHealth:
        return LedgerHealth(available=True, data_version=self._store.data_version())


class NullProvider:
    """Accepts nothing and remembers nothing; every call is a degraded event."""

    def __init__(self, reason: str = "provider_unavailable") -> None:
        self.reason = reason

    async def append_decision(self, decision: Decision, context: Mapping[str, Any]) -> bool:
        return False

    async def append_event(self, event: LedgerEvent) -> bool:
        return False

    async def append_lineage_event(self, event: LineageEvent) -> int:
        return 0

    async def read_lineage_events(
        self, lineage: LineageId, event_type: str | None = None
    ) -> Sequence[LineageEvent]:
        return []

    async def read_events(
        self, route_id: RouteId, event_type: str | None = None
    ) -> Sequence[LedgerEvent]:
        return []

    async def health(self) -> LedgerHealth:
        return LedgerHealth(available=False, degraded_reason=self.reason)


class MemoryFacade:
    """LedgerPort that never raises to the caller and reports every degradation."""

    def __init__(self, provider: LedgerPort, *, fallback: NullProvider | None = None) -> None:
        self._primary = provider
        self._fallback = fallback or NullProvider()
        self._degraded_reason: str | None = None
        self.degraded_count = 0
        self.degraded_episodes = 0
        self.recovered_count = 0

    @property
    def degraded(self) -> bool:
        """True only while the latest provider call failed (ADRL-MEM-006: never sticky)."""
        return self._degraded_reason is not None

    @property
    def degraded_reason(self) -> str | None:
        return self._degraded_reason

    def _note_degraded(self, reason: str, op: str) -> None:
        if self._degraded_reason is None:
            self.degraded_episodes += 1
        self._degraded_reason = reason
        self.degraded_count += 1
        MEMORY_DEGRADED_TOTAL.labels(reason=reason).inc()
        log.warning("memory_degraded", reason=reason, operation=op)

    def _note_recovered(self, op: str) -> None:
        """A successful provider call ends the degraded episode."""
        if self._degraded_reason is not None:
            log.info("memory_recovered", operation=op, after=self._degraded_reason)
            self._degraded_reason = None
            self.recovered_count += 1

    async def _run(self, op: str, primary_call: Any, fallback_call: Any) -> Any:
        try:
            result = await primary_call()
        except Exception as exc:
            self._note_degraded(type(exc).__name__, op)
            return await fallback_call()
        self._note_recovered(op)
        return result

    async def append_decision(self, decision: Decision, context: Mapping[str, Any]) -> bool:
        ok = await self._run(
            "append_decision",
            lambda: self._primary.append_decision(decision, context),
            lambda: self._fallback.append_decision(decision, context),
        )
        if not ok and not self.degraded:
            return False
        return bool(ok)

    async def append_event(self, event: LedgerEvent) -> bool:
        return bool(
            await self._run(
                "append_event",
                lambda: self._primary.append_event(event),
                lambda: self._fallback.append_event(event),
            )
        )

    async def append_lineage_event(self, event: LineageEvent) -> int:
        return int(
            await self._run(
                "append_lineage_event",
                lambda: self._primary.append_lineage_event(event),
                lambda: self._fallback.append_lineage_event(event),
            )
        )

    async def read_lineage_events(
        self, lineage: LineageId, event_type: str | None = None
    ) -> Sequence[LineageEvent]:
        result: Sequence[LineageEvent] = await self._run(
            "read_lineage_events",
            lambda: self._primary.read_lineage_events(lineage, event_type),
            lambda: self._fallback.read_lineage_events(lineage, event_type),
        )
        return result

    async def read_events(
        self, route_id: RouteId, event_type: str | None = None
    ) -> Sequence[LedgerEvent]:
        result: Sequence[LedgerEvent] = await self._run(
            "read_events",
            lambda: self._primary.read_events(route_id, event_type),
            lambda: self._fallback.read_events(route_id, event_type),
        )
        return result

    async def health(self) -> LedgerHealth:
        try:
            health = await self._primary.health()
        except Exception as exc:
            self._note_degraded(type(exc).__name__, "health")
            return LedgerHealth(available=False, degraded_reason=self._degraded_reason)
        self._note_recovered("health")
        return health

    async def pin_state(self, lineage: LineageId) -> PinLookup:
        """Pin lookup from the ledger; unknown under degradation is treated as pinned."""
        try:
            events = await self._primary.read_lineage_events(lineage)
        except Exception as exc:
            self._note_degraded(type(exc).__name__, "pin_state")
            return PinLookup.UNKNOWN
        self._note_recovered("pin_state")
        pinned = False
        released_findings: set[str] = set()
        active_findings: set[str] = set()
        for event in events:
            if event.event_type == PIN_EVENT:
                active_findings.add(str(event.payload.get("finding_id", "")))
                pinned = True
            elif event.event_type == RELEASE_EVENT:
                released_findings.add(str(event.payload.get("finding_id", "")))
        if pinned and active_findings and active_findings <= released_findings:
            return PinLookup.UNPINNED
        return PinLookup.PINNED if pinned else PinLookup.UNPINNED
