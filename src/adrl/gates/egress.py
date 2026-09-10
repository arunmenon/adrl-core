"""Write-ahead egress recording for the gate stage. Primary: ADRL-SAF-009.

The gate verdict is appended before forwarding. An append failure on a pinned lineage is a gate
failure (fail-closed); on an unpinned lineage the request is forwarded with `ledger_degraded`.
The proxy calls :meth:`EgressWriter.record_forward` with the destination rung and byte count
immediately before dispatch, because the rung is chosen after the gates run.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import structlog

from adrl.core.enums import FailureClass
from adrl.core.errors import LedgerAppendFailure
from adrl.core.ports import EgressEvent, EgressLedgerPort
from adrl.core.types import Finding, GateVerdict, RequestContext
from adrl.telemetry.metrics import LEDGER_DEGRADED_TOTAL

log = structlog.get_logger(__name__)


class EgressWriter:
    def __init__(self, ledger: EgressLedgerPort, *, deployment_tag: str) -> None:
        self._ledger = ledger
        self._tag = deployment_tag

    @property
    def ledger(self) -> EgressLedgerPort:
        return self._ledger

    def _append(self, event: EgressEvent, *, pinned: bool) -> bool:
        """True when recorded. Raises on a pinned lineage; degrades on an unpinned one."""
        try:
            self._ledger.append(event)
            return True
        except LedgerAppendFailure:
            if pinned:
                raise
            LEDGER_DEGRADED_TOTAL.inc()
            log.error("egress_ledger_degraded", event_kind=event.event_kind)
            return False

    def record_verdict(
        self,
        ctx: RequestContext,
        verdicts: Sequence[GateVerdict],
        findings: Sequence[Finding],
        *,
        pinned: bool,
        unscanned: bool,
        block_code: str | None,
    ) -> bool:
        tiers = {f.tier.value for f in findings if f.pins}
        records: list[dict[str, Any]] = [v.as_record() for v in verdicts]
        records.append({"unscanned": unscanned, "block": block_code})
        return self._append(
            EgressEvent(
                lineage_hmac=str(ctx.lineage_hmac),
                request_class=ctx.request_class.value,
                content_bearing=ctx.content_bearing,
                destination_rung=None,
                deployment_tag=self._tag,
                gate_verdicts=records,
                detector_tier=sorted(tiers)[0] if tiers else None,
                span_hashes=[f.span_hash for f in findings if f.pins],
                bytes_out=0,
                actor="adrl",
                reason=block_code,
                event_kind="gate_verdict",
            ),
            pinned=pinned,
        )

    def record_forward(
        self,
        ctx: RequestContext,
        *,
        destination_rung: str,
        bytes_out: int,
        pinned: bool,
        verdict_summary: Sequence[dict[str, Any]] = (),
    ) -> bool:
        """Called by the proxy right before dispatch (write-ahead of the actual egress)."""
        return self._append(
            EgressEvent(
                lineage_hmac=str(ctx.lineage_hmac),
                request_class=ctx.request_class.value,
                content_bearing=ctx.content_bearing,
                destination_rung=destination_rung,
                deployment_tag=self._tag,
                gate_verdicts=list(verdict_summary),
                bytes_out=bytes_out,
                actor="adrl",
                event_kind="forward",
            ),
            pinned=pinned,
        )

    def record_fail_open(
        self, ctx: RequestContext, failure_class: FailureClass, reason: str, *, pinned: bool
    ) -> bool:
        return self._append(
            EgressEvent(
                lineage_hmac=str(ctx.lineage_hmac),
                request_class=ctx.request_class.value,
                content_bearing=ctx.content_bearing,
                destination_rung=None,
                deployment_tag=self._tag,
                gate_verdicts=[{"failure_class": failure_class.value, "pinned": pinned}],
                actor="adrl",
                reason=reason,
                event_kind="fail_open",
            ),
            pinned=pinned,
        )

    def record_bypass(self, lineage_hmac: str, actor: str, reason: str) -> bool:
        return self._append(
            EgressEvent(
                lineage_hmac=lineage_hmac,
                request_class="bypass",
                content_bearing=False,
                destination_rung=None,
                deployment_tag=self._tag,
                gate_verdicts=[],
                actor=actor,
                reason=reason,
                event_kind="operator_bypass",
            ),
            pinned=False,
        )


def audit_lineage(ledger: Any, lineage_hmac: str) -> dict[str, Any]:
    """Did this lineage's content ever leave the machine, when, to which deployment, confirmed?

    ``left_machine`` is answered from recorded trust zones (ADRL-SAF-009); ``confirmed`` is
    true only when a gateway receipt names the deployment. Unconfirmed rows are intended
    destinations without a receipt: the honest answer there is "sent, not confirmed".
    """
    rows = ledger.lineage_left_machine(lineage_hmac)
    confirmed = [r for r in rows if r.get("confirmed")]
    unconfirmed = [r for r in rows if not r.get("confirmed")]
    return {
        "lineage": lineage_hmac,
        "left_machine": bool(rows),
        "confirmed_by_receipt": bool(confirmed),
        "unconfirmed_count": len(unconfirmed),
        "first_egress_ts": rows[0]["ts"] if rows else None,
        "deployment_tags": sorted({str(r["deployment_tag"]) for r in rows}),
        "deployments": sorted(
            {str(r.get("deployment_id")) for r in rows if r.get("deployment_id")}
        ),
        "trust_zones": sorted({str(r.get("trust_zone")) for r in rows if r.get("trust_zone")}),
        "geos": sorted({str(r.get("geo")) for r in rows if r.get("geo")}),
        "legacy_label_rows": sum(1 for r in rows if r.get("basis") == "rung_label_legacy"),
        "events": rows,
    }
