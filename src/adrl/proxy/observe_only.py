"""Observe-only stage implementations. Primary: ADRL-FND-001. Secondary: ADRL-SEM-006, ADRL-MEM-006.

Real, not mock: these are the stages the proxy runs when a package has not been installed. The
gate reads pin state from the ledger and marks every request unscanned (no scanner is present);
the router honours the harness-requested model; the cascade tracks boundaries and sticky state
without ever escalating.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from adrl.config.loaders import ConfigBundle
from adrl.core.enums import Rung
from adrl.core.errors import ErrorCode
from adrl.core.ids import mint_route_id
from adrl.core.ports import StickyState
from adrl.core.types import (
    Decision,
    DeploymentSet,
    Finding,
    GateVerdict,
    HandoffNote,
    PermittedSet,
    RequestContext,
)
from adrl.ledger.facade import MemoryFacade
from adrl.proxy.stages import DispatchPlanLike
from adrl.wire.observe import ResponseObservation
from adrl.wire.parse import estimate_chars, last_assistant_message, tool_result_ids, tool_use_ids

OBSERVE_ONLY_ESTIMATOR = "harness-requested"
OBSERVE_ONLY_ESTIMATOR_VERSION = "observe-only-v1"
FEATURES_VERSION = "features-observe-v1"


@dataclass(frozen=True, slots=True)
class ObserveOnlyGateOutcome:
    permitted: PermittedSet
    verdicts: tuple[GateVerdict, ...]
    pinned: bool
    unscanned: bool
    findings: tuple[Finding, ...]
    block: ErrorCode | None
    repo_class: str | None
    residency: str | None
    latency_s: float
    permitted_deployments: DeploymentSet | None = None


class ObserveOnlyGate:
    """Pin state from the ledger, everything else unscanned (ADRL-SAF-001 without a scanner)."""

    def __init__(self, facade: MemoryFacade) -> None:
        self._facade = facade

    async def evaluate(self, ctx: RequestContext) -> ObserveOnlyGateOutcome:
        started = time.monotonic()
        lookup = await self._facade.pin_state(ctx.lineage_hmac)
        pinned = lookup.effective_pinned
        permitted = PermittedSet.local_only() if pinned else PermittedSet.all()
        verdict = GateVerdict(
            gate="observe_only",
            permitted_after=permitted,
            unscanned=True,
            reason="no scanner installed" if not pinned else f"pin lookup {lookup.value}",
            pinned=pinned,
        )
        return ObserveOnlyGateOutcome(
            permitted=permitted,
            verdicts=(verdict,),
            pinned=pinned,
            unscanned=True,
            findings=(),
            block=None,
            repo_class=None,
            residency=None,
            latency_s=time.monotonic() - started,
        )


def rung_for_requested_model(model: str, bundle: ConfigBundle) -> Rung:
    """Frontier for harness model names and unknowns; a rung alias maps to its rung."""
    group_rung = bundle.rungs.group_to_rung.get(model)
    if group_rung is not None:
        return group_rung
    return Rung.FRONTIER


class InheritOnlyRouter:
    """Honours the harness-requested model inside the permitted set (ADRL-SEM-006 interim)."""

    def __init__(self, bundle: ConfigBundle) -> None:
        self._bundle = bundle

    async def decide(self, ctx: RequestContext, gate: Any, sticky: StickyState | None) -> Decision:
        requested = rung_for_requested_model(ctx.requested_model, self._bundle)
        permitted: PermittedSet = gate.permitted
        if requested in permitted:
            rung = requested
        else:
            highest = permitted.highest
            rung = highest if highest is not None else Rung.LOCAL
        features = {
            "request_class": ctx.request_class.value,
            "content_chars": estimate_chars(ctx.json),
            "message_count": len(ctx.json.get("messages") or []),
            "tools_present": bool(ctx.json.get("tools")),
            "is_subagent": ctx.is_subagent,
            "interaction_mode": ctx.interaction_mode.value,
        }
        return Decision(
            route_id=mint_route_id(),
            rung=rung,
            permitted=permitted,
            estimator=OBSERVE_ONLY_ESTIMATOR,
            estimator_version=OBSERVE_ONLY_ESTIMATOR_VERSION,
            policy_version=self._bundle.policy.version,
            objective_version=self._bundle.policy.objective_version,
            cascade_feasible=False,
            cascade_reason="observe_only",
            features=features,
            features_version=FEATURES_VERSION,
        )


@dataclass(frozen=True, slots=True)
class PassthroughPlan:
    rung: Rung
    is_boundary: bool
    escalated: bool
    from_rung: Rung | None
    handoff: HandoffNote | None
    pair_rule: Any
    block: ErrorCode | None
    sticky: StickyState


@dataclass(frozen=True, slots=True)
class PassthroughEvents:
    fired_wires: Sequence[str]
    outcome_events: Sequence[Any]
    sticky: StickyState | None


def is_action_boundary(body: Any) -> bool:
    """Every tool_use id of the last assistant message answered (ADRL-CAS-003)."""
    last_assistant = last_assistant_message(body)
    if last_assistant is None:
        return False
    expected = tool_use_ids(last_assistant)
    if not expected:
        return False
    messages = body.get("messages") or []
    last = messages[-1] if messages else None
    if not isinstance(last, dict) or last.get("role") != "user":
        return False
    return expected <= tool_result_ids(last)


class PassthroughCascade:
    """Boundary and sticky bookkeeping; never escalates (ADRL-CAS-005 posture without wires)."""

    async def plan(
        self,
        ctx: RequestContext,
        decision: Decision,
        gate: Any,
        sticky: StickyState | None,
    ) -> PassthroughPlan:
        turn_index = (sticky.turn_index + 1) if sticky is not None else 0
        state = StickyState(
            lineage_hmac=ctx.lineage_hmac,
            route_id=decision.route_id,
            rung=decision.rung,
            escalated=False,
            served_model=None,
            served_provider=None,
            served_source="assumed_intended",
            turn_index=turn_index,
            last_served_at=None,
        )
        return PassthroughPlan(
            rung=decision.rung,
            is_boundary=is_action_boundary(ctx.json),
            escalated=False,
            from_rung=None,
            handoff=None,
            pair_rule=None,
            block=None,
            sticky=state,
        )

    async def observe(
        self, ctx: RequestContext, plan: DispatchPlanLike, obs: ResponseObservation
    ) -> PassthroughEvents:
        updated = StickyState(
            lineage_hmac=plan.sticky.lineage_hmac,
            route_id=plan.sticky.route_id,
            rung=obs.served.rung,
            escalated=plan.sticky.escalated,
            served_model=obs.served.model,
            served_provider=obs.served.provider,
            served_source=obs.served.source.value,
            turn_index=plan.sticky.turn_index,
            last_served_at=datetime.now(UTC),
        )
        return PassthroughEvents(fired_wires=(), outcome_events=(), sticky=updated)
