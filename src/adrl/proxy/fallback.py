"""Fail to last-known-safe. Primary: ADRL-FND-004. Secondary: ADRL-SAF-001, ADRL-SAF-009.
Also implements: ADRL-OPS-008 (register additions of 2026-09-03).

Routing-path failures fail open to the upstream gateway (unpinned) or the local rung (pinned).
Gate-path failures fail open with the unscanned mark (unpinned) or fail closed (pinned). Proxy-path
failures have no in-process fallback. Every automatic fail-open is recorded with its class and the
unscanned mark can never widen the permitted set or release a pin.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import structlog

from adrl.core.enums import FailureClass, RoutingMode, Rung
from adrl.core.errors import ErrorCode
from adrl.core.ports import EgressEvent, LedgerPort, LineageEvent
from adrl.core.types import PermittedSet, RequestContext
from adrl.telemetry.metrics import FAIL_OPEN_TOTAL, UNSCANNED_TOTAL

log = structlog.get_logger(__name__)

FAIL_OPEN_EVENT = "fail_open"
BYPASS_EVENT = "operator_bypass"


class FallbackAction(StrEnum):
    FORWARD_UPSTREAM = "forward_upstream"
    FORWARD_LOCAL = "forward_local"
    BLOCK = "block"
    SURFACE = "surface"


@dataclass(frozen=True, slots=True)
class FailureResolution:
    failure_class: FailureClass
    action: FallbackAction
    pinned: bool
    unscanned: bool
    code: ErrorCode | None
    mode: RoutingMode

    @property
    def permitted(self) -> PermittedSet:
        """The set a fallback may use; it never widens beyond pin state (ADRL-SAF-001)."""
        if self.pinned:
            return PermittedSet.local_only()
        return PermittedSet.all()

    @property
    def rung(self) -> Rung | None:
        if self.action is FallbackAction.FORWARD_LOCAL:
            return Rung.LOCAL
        if self.action is FallbackAction.FORWARD_UPSTREAM:
            return None
        return None


def resolve_failure(
    failure_class: FailureClass, *, pinned: bool, mode: RoutingMode
) -> FailureResolution:
    """Decide what happens after a failure of the given class for this pin state."""
    if failure_class is FailureClass.PROXY_PATH:
        return FailureResolution(
            failure_class, FallbackAction.SURFACE, pinned, False, ErrorCode.TERMINAL_FAILURE, mode
        )
    if pinned:
        if failure_class is FailureClass.GATE_PATH:
            return FailureResolution(
                failure_class, FallbackAction.BLOCK, True, False, ErrorCode.GATE_UNAVAILABLE, mode
            )
        return FailureResolution(
            failure_class, FallbackAction.FORWARD_LOCAL, True, False, None, mode
        )
    if mode is RoutingMode.OFF:
        return FailureResolution(
            failure_class, FallbackAction.SURFACE, False, False, ErrorCode.TERMINAL_FAILURE, mode
        )
    unscanned = failure_class is FailureClass.GATE_PATH
    return FailureResolution(
        failure_class, FallbackAction.FORWARD_UPSTREAM, False, unscanned, None, mode
    )


class FallbackRecorder:
    """Records every automatic fail-open and operator bypass in both ledgers."""

    def __init__(
        self,
        ledger: LedgerPort,
        egress: Any | None,
        *,
        deployment_tag: str,
        producer: str = "proxy",
    ) -> None:
        self._ledger = ledger
        self._egress = egress
        self._deployment_tag = deployment_tag
        self._producer = producer

    async def record(
        self,
        ctx: RequestContext,
        resolution: FailureResolution,
        *,
        exception: BaseException | None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        FAIL_OPEN_TOTAL.labels(
            failure_class=resolution.failure_class.value, pinned=str(resolution.pinned).lower()
        ).inc()
        if resolution.unscanned:
            UNSCANNED_TOTAL.inc()
        payload: dict[str, Any] = {
            "failure_class": resolution.failure_class.value,
            "action": resolution.action.value,
            "pinned": resolution.pinned,
            "unscanned": resolution.unscanned,
            "mode": resolution.mode.value,
            "exception": type(exception).__name__ if exception is not None else None,
            "request_class": ctx.request_class.value,
        }
        if detail:
            payload.update(dict(detail))
        log.warning("fail_open", **payload)
        await self._ledger.append_lineage_event(
            LineageEvent(lineage_hmac=ctx.lineage_hmac, event_type=FAIL_OPEN_EVENT, payload=payload)
        )
        if self._egress is not None:
            try:
                self._egress.append(
                    EgressEvent(
                        lineage_hmac=ctx.lineage_hmac,
                        request_class=ctx.request_class.value,
                        content_bearing=ctx.content_bearing,
                        destination_rung=(
                            resolution.rung.value if resolution.rung is not None else None
                        ),
                        deployment_tag=self._deployment_tag,
                        gate_verdicts=[payload],
                        actor="adrl",
                        reason=resolution.failure_class.value,
                        event_kind=FAIL_OPEN_EVENT,
                    )
                )
            except Exception as exc:  # egress failure during a fallback is itself recorded
                log.error("fail_open_egress_append_failed", error=str(exc))

    async def record_bypass(self, ctx: RequestContext, *, actor: str, reason: str) -> None:
        """Operator bypass is audited and never releases a pin (ADRL-FND-004 clause 3)."""
        payload = {"actor": actor, "reason": reason, "pin_released": False}
        await self._ledger.append_lineage_event(
            LineageEvent(lineage_hmac=ctx.lineage_hmac, event_type=BYPASS_EVENT, payload=payload)
        )
        if self._egress is not None:
            self._egress.append(
                EgressEvent(
                    lineage_hmac=ctx.lineage_hmac,
                    request_class=ctx.request_class.value,
                    content_bearing=ctx.content_bearing,
                    destination_rung=None,
                    deployment_tag=self._deployment_tag,
                    gate_verdicts=[payload],
                    actor=actor,
                    reason=reason,
                    event_kind=BYPASS_EVENT,
                )
            )
