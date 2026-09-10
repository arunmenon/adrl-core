"""Durable, one-way, lineage-scoped privacy pin. Primary: ADRL-SAF-002.
Also implements: ADRL-OPS-005 (register additions of 2026-09-03).

Pin state is written through to the evidence ledger and to the egress ledger before the pinning
request proceeds, reloaded on start, and inherited down the agent lineage. The only release is the
audited human path in :meth:`PinRegistry.release`; nothing else in the code base clears a pin.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog

from adrl.core.enums import PinLookup, ReleaseReason
from adrl.core.errors import GateFailure, LedgerAppendFailure
from adrl.core.ids import LineageId, SessionId
from adrl.core.ports import EgressEvent, EgressLedgerPort, LineageEvent
from adrl.core.types import Finding, RequestContext
from adrl.gates.suppression import LoggingSuppressionSink, SuppressionSink
from adrl.ledger.facade import PIN_EVENT, RELEASE_EVENT, MemoryFacade
from adrl.telemetry.metrics import PIN_WRITE_FAILED_TOTAL, SHADOW_FINDING_TOTAL

log = structlog.get_logger(__name__)

PIN_WRITE_ATTEMPTS = 2
SHADOW_FINDING_EVENT = "shadow_finding"
PROMOTION_SOURCE = "shadow_promotion"


@dataclass(frozen=True, slots=True)
class PinRecord:
    lineage: LineageId
    finding_id: str
    detector_id: str
    span_hash: str
    released: bool = False


class ReleaseRefused(GateFailure):
    """Release is disabled by policy for this lineage (restricted repository)."""


class PinRegistry:
    """In-memory view over ledger-backed pin state, with inheritance and audited release."""

    def __init__(
        self,
        facade: MemoryFacade,
        egress: EgressLedgerPort,
        *,
        deployment_tag: str,
        suppression: SuppressionSink | None = None,
    ) -> None:
        self._facade = facade
        self._egress = egress
        self._deployment_tag = deployment_tag
        self._suppression = suppression or LoggingSuppressionSink()
        self._pins: dict[LineageId, dict[str, PinRecord]] = {}
        self._known: set[LineageId] = set()
        self._agent_lineages: dict[str, LineageId] = {}
        # findings whose durable write failed: pinned in this process, retried on every lookup
        self._undurable: dict[LineageId, list[tuple[RequestContext, Finding]]] = {}
        self._data_version: int | None = None

    @property
    def facade(self) -> MemoryFacade:
        return self._facade

    async def _invalidate_if_ledger_changed(self) -> None:
        """Drop the cache when another connection committed (a release from another process)."""
        health = await self._facade.health()
        version = health.data_version
        if version is None:
            return
        if self._data_version is not None and version != self._data_version:
            self._known.clear()
            for lineage in list(self._pins):
                if lineage not in self._undurable:
                    self._pins.pop(lineage, None)
        self._data_version = version

    # lineage bookkeeping ---------------------------------------------------------------

    def observe(self, ctx: RequestContext) -> None:
        """Remember which lineage an agent id belongs to so descendants can find ancestors."""
        if ctx.agent_id is not None:
            self._agent_lineages[ctx.agent_id] = ctx.lineage_hmac

    def ancestors(self, ctx: RequestContext) -> tuple[LineageId, ...]:
        """Ancestor lineages in order from nearest parent to session root."""
        if ctx.agent_id is None:
            return ()
        chain: list[LineageId] = []
        parent = ctx.parent_agent_id
        seen: set[str] = set()
        while parent is not None and parent not in seen:
            seen.add(parent)
            lineage = self._agent_lineages.get(parent)
            if lineage is None:
                break
            chain.append(lineage)
            parent = None
        root = LineageId(str(ctx.session_hmac))
        if root not in chain and root != ctx.lineage_hmac:
            chain.append(root)
        return tuple(chain)

    # lookups ---------------------------------------------------------------------------

    async def _load(self, lineage: LineageId) -> None:
        if lineage in self._known:
            return
        lookup = await self._facade.pin_state(lineage)
        records: dict[str, PinRecord] = self._pins.setdefault(lineage, {})
        for _ctx, finding in self._undurable.get(lineage, ()):
            records.setdefault(
                finding.finding_id,
                PinRecord(lineage, finding.finding_id, finding.detector_id, finding.span_hash),
            )
        if lookup is PinLookup.UNKNOWN:
            records.setdefault(
                "unknown", PinRecord(lineage, "unknown", "ledger_unavailable", "", False)
            )
            return
        released: set[str] = set()
        for event in await self._facade.read_lineage_events(lineage):
            if event.event_type == RELEASE_EVENT:
                released.add(str(event.payload.get("finding_id", "")))
        for event in await self._facade.read_lineage_events(lineage, PIN_EVENT):
            finding_id = str(event.payload.get("finding_id", ""))
            records[finding_id] = PinRecord(
                lineage,
                finding_id,
                str(event.payload.get("detector_id", "")),
                str(event.payload.get("span_hash", "")),
                released=finding_id in released,
            )
        self._known.add(lineage)

    def _active(self, lineage: LineageId) -> list[PinRecord]:
        return [r for r in self._pins.get(lineage, {}).values() if not r.released]

    async def is_pinned(self, lineage: LineageId) -> bool:
        await self._invalidate_if_ledger_changed()
        await self._load(lineage)
        return bool(self._active(lineage))

    async def _retry_undurable(self, lineage: LineageId) -> None:
        pending = self._undurable.get(lineage)
        if not pending:
            return
        remaining: list[tuple[RequestContext, Finding]] = []
        for pending_ctx, finding in pending:
            try:
                await self._write_durably(pending_ctx, finding)
            except GateFailure:
                remaining.append((pending_ctx, finding))
        if remaining:
            self._undurable[lineage] = remaining
        else:
            self._undurable.pop(lineage, None)
            log.info("pin_durable_write_recovered", lineage=str(lineage)[:12])

    async def effective_pin(self, ctx: RequestContext) -> PinRecord | None:
        """The lineage's own pin, else the nearest ancestor pin (ADRL-SEM-006)."""
        self.observe(ctx)
        await self._invalidate_if_ledger_changed()
        await self._retry_undurable(ctx.lineage_hmac)
        await self._load(ctx.lineage_hmac)
        own = self._active(ctx.lineage_hmac)
        if own:
            return own[0]
        for ancestor in self.ancestors(ctx):
            await self._load(ancestor)
            inherited = self._active(ancestor)
            if inherited:
                return inherited[0]
        return None

    # pinning ---------------------------------------------------------------------------

    async def pin(self, ctx: RequestContext, finding: Finding) -> PinRecord:
        """Write-through pin.

        The in-memory record is set before any I/O so this process treats the lineage as
        pinned whatever happens next. A durable-write failure raises GateFailure after
        remembering the finding for retry; the caller fails the request closed (ADRL-SAF-002
        clause 1: the pin is written before the pinning request is forwarded, never after).
        """
        record = PinRecord(
            ctx.lineage_hmac, finding.finding_id, finding.detector_id, finding.span_hash
        )
        self._pins.setdefault(ctx.lineage_hmac, {})[finding.finding_id] = record
        self._known.add(ctx.lineage_hmac)
        try:
            await self._write_durably(ctx, finding)
        except GateFailure:
            PIN_WRITE_FAILED_TOTAL.inc()
            self._undurable.setdefault(ctx.lineage_hmac, []).append((ctx, finding))
            log.error(
                "pin_durable_write_failed",
                detector=finding.detector_id,
                finding=finding.finding_id,
                degraded=self._facade.degraded_reason,
            )
            raise
        log.info("lineage_pinned", detector=finding.detector_id, finding=finding.finding_id)
        await self._suppression.suppress_lineage(
            ctx.lineage_hmac, ctx.session_hmac, f"pinned:{finding.detector_id}"
        )
        return record

    async def _write_durably(self, ctx: RequestContext, finding: Finding) -> None:
        payload: dict[str, Any] = {
            "finding_id": finding.finding_id,
            "detector_id": finding.detector_id,
            "tier": finding.tier.value,
            "span_hash": finding.span_hash,
            "content_type": finding.content_type,
            "corroboration": finding.corroboration,
            "request_class": ctx.request_class.value,
        }
        seq = 0
        for _attempt in range(PIN_WRITE_ATTEMPTS):
            seq = await self._facade.append_lineage_event(
                LineageEvent(lineage_hmac=ctx.lineage_hmac, event_type=PIN_EVENT, payload=payload)
            )
            if seq > 0 and not self._facade.degraded:
                break
        if seq <= 0 or self._facade.degraded:
            raise GateFailure("pin could not be written durably; lineage is fail-closed")
        try:
            self._egress.append(
                EgressEvent(
                    lineage_hmac=str(ctx.lineage_hmac),
                    request_class=ctx.request_class.value,
                    content_bearing=ctx.content_bearing,
                    destination_rung=None,
                    deployment_tag=self._deployment_tag,
                    gate_verdicts=[{"gate": "secret_scan", "pinned": True}],
                    detector_tier=finding.tier.value,
                    span_hashes=[finding.span_hash],
                    actor="adrl",
                    reason=finding.detector_id,
                    event_kind="pin",
                )
            )
        except LedgerAppendFailure as exc:
            raise GateFailure(f"pin egress record failed: {exc.detail}") from exc

    # observe-mode shadow namespace ---------------------------------------------------------

    async def record_shadow(self, ctx: RequestContext, finding: Finding) -> int:
        """Record a would-pin finding without pinning (gate observe mode).

        Shadow findings live in their own lineage-event namespace; `pin_state` and `_load`
        never read them, so switching the gate to enforce does not pin retroactively.
        """
        SHADOW_FINDING_TOTAL.labels(detector=finding.detector_id).inc()
        payload: dict[str, Any] = {
            "finding_id": finding.finding_id,
            "detector_id": finding.detector_id,
            "tier": finding.tier.value,
            "span_hash": finding.span_hash,
            "content_type": finding.content_type,
            "corroboration": finding.corroboration,
            "request_class": ctx.request_class.value,
            "session_hmac": str(ctx.session_hmac),
            "would_pin": True,
        }
        seq = await self._facade.append_lineage_event(
            LineageEvent(
                lineage_hmac=ctx.lineage_hmac, event_type=SHADOW_FINDING_EVENT, payload=payload
            )
        )
        log.info("shadow_finding", detector=finding.detector_id, finding=finding.finding_id)
        return seq

    async def shadow_findings(self, lineage: LineageId) -> list[Mapping[str, Any]]:
        events = await self._facade.read_lineage_events(lineage, SHADOW_FINDING_EVENT)
        return [event.payload for event in events]

    async def promote_shadow(
        self, lineage: LineageId, finding_id: str, actor: str, *, session: SessionId | None = None
    ) -> PinRecord:
        """Audited promotion of one shadow finding into an authoritative pin.

        This is the only path from the shadow namespace to a pin. It writes the same durable
        records as a live pin (lineage event, egress row) plus the actor, then applies the
        retroactive suppression a live pin would have applied.
        """
        await self._invalidate_if_ledger_changed()
        await self._load(lineage)
        existing = self._pins.get(lineage, {}).get(finding_id)
        if existing is not None and not existing.released:
            return existing
        candidate = next(
            (s for s in await self.shadow_findings(lineage) if s.get("finding_id") == finding_id),
            None,
        )
        if candidate is None:
            raise GateFailure(f"no shadow finding {finding_id!r} on this lineage")
        payload: dict[str, Any] = {
            "finding_id": finding_id,
            "detector_id": str(candidate.get("detector_id", "")),
            "tier": str(candidate.get("tier", "")),
            "span_hash": str(candidate.get("span_hash", "")),
            "content_type": candidate.get("content_type"),
            "corroboration": candidate.get("corroboration"),
            "request_class": str(candidate.get("request_class", "")),
            "source": PROMOTION_SOURCE,
            "actor": actor,
        }
        seq = await self._facade.append_lineage_event(
            LineageEvent(lineage_hmac=lineage, event_type=PIN_EVENT, payload=payload)
        )
        if seq <= 0 or self._facade.degraded:
            raise GateFailure("promotion could not be recorded; nothing was pinned")
        try:
            self._egress.append(
                EgressEvent(
                    lineage_hmac=str(lineage),
                    request_class="promotion",
                    content_bearing=False,
                    destination_rung=None,
                    deployment_tag=self._deployment_tag,
                    gate_verdicts=[{"gate": "secret_scan", "pinned": True, "promoted": True}],
                    detector_tier=str(candidate.get("tier")) if candidate.get("tier") else None,
                    span_hashes=[str(candidate.get("span_hash", ""))],
                    actor=actor,
                    reason=str(candidate.get("detector_id", "")),
                    event_kind="pin",
                )
            )
        except LedgerAppendFailure as exc:
            raise GateFailure(f"promotion egress record failed: {exc.detail}") from exc
        record = PinRecord(
            lineage, finding_id, payload["detector_id"], payload["span_hash"], released=False
        )
        self._pins.setdefault(lineage, {})[finding_id] = record
        self._known.add(lineage)
        shadow_session = candidate.get("session_hmac")
        target_session = session or (
            SessionId(str(shadow_session)) if shadow_session else SessionId(str(lineage))
        )
        await self._suppression.suppress_lineage(lineage, target_session, f"promoted:{actor}")
        log.info("shadow_finding_promoted", finding=finding_id, actor=actor)
        return record

    # audited human release --------------------------------------------------------------

    async def release(
        self,
        lineage: LineageId,
        finding_id: str,
        reason: ReleaseReason,
        actor: str,
        *,
        release_permitted: bool,
        session: SessionId | None = None,
    ) -> PinRecord:
        """Audited, reason-coded, per-finding human release (ADRL-SAF-002 clause 3)."""
        if not release_permitted:
            raise ReleaseRefused("release is disabled by policy for restricted repositories")
        await self._invalidate_if_ledger_changed()
        await self._load(lineage)
        record = self._pins.get(lineage, {}).get(finding_id)
        if record is None:
            raise GateFailure(f"no pin with finding {finding_id!r} on this lineage")
        if record.released:
            return record
        payload: Mapping[str, Any] = {
            "finding_id": finding_id,
            "detector_id": record.detector_id,
            "span_hash": record.span_hash,
            "reason": reason.value,
            "actor": actor,
        }
        seq = await self._facade.append_lineage_event(
            LineageEvent(lineage_hmac=lineage, event_type=RELEASE_EVENT, payload=payload)
        )
        if seq <= 0 or self._facade.degraded:
            raise GateFailure("release could not be recorded; pin stays in force")
        self._egress.append(
            EgressEvent(
                lineage_hmac=str(lineage),
                request_class="release",
                content_bearing=False,
                destination_rung=None,
                deployment_tag=self._deployment_tag,
                gate_verdicts=[{"gate": "release", "finding_id": finding_id}],
                detector_tier=None,
                span_hashes=[record.span_hash],
                actor=actor,
                reason=reason.value,
                event_kind="release",
            )
        )
        released = PinRecord(lineage, finding_id, record.detector_id, record.span_hash, True)
        self._pins[lineage][finding_id] = released
        log.info("pin_released", finding=finding_id, reason=reason.value, actor=actor)
        return released

    def active_pins(self, lineage: LineageId) -> tuple[PinRecord, ...]:
        return tuple(self._active(lineage))
