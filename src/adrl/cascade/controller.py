"""ADRL-CAS-003: plan dispatch, observe responses, escalate at boundaries.

Secondary: ADRL-CAS-001/004/005/006/007/008, ADRL-SEM-006, ADRL-MEM-001/002/004.
ADRL makes exactly one attempt per request and never re-issues a request whose response had
begun streaming tool content; terminal failures are Anthropic error objects, never synthetic
assistant content.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from adrl.cascade.boundary import assess_boundary
from adrl.cascade.handoff import (
    TransformResult,
    latest_assistant_has_thinking,
    needs_thinking_suppression,
    transform,
)
from adrl.cascade.sticky import (
    MemoryStateProvider,
    escalate,
    family_of_model,
    mark_state_loss,
    new_sticky,
    release_ratchet,
    sticky_record,
    with_served,
)
from adrl.cascade.tripwires import TRIPWIRE_EVENT, TripwireEvaluator, WireClass, WireHit
from adrl.config.loaders import ConfigBundle
from adrl.config.models import ProviderPairRule
from adrl.config.settings import Settings
from adrl.core.enums import (
    EpisodeSignal,
    FailureType,
    OutcomeState,
    RequestClass,
    Rung,
    VerificationResult,
    resolve_primary,
)
from adrl.core.errors import VENDOR_PROMPT_TOO_LONG_PHRASE, ErrorCode, render_error
from adrl.core.ids import LineageId, RouteId
from adrl.core.ports import LedgerPort, StateProvider, StickyState
from adrl.core.types import Decision, HandoffNote, LedgerEvent, PermittedSet, RequestContext
from adrl.ledger.events import VERIFIER_FAILED_EVENT, OutcomeFields, outcome_event
from adrl.routing.registry import RungRegistry
from adrl.routing.side_effects import (
    UNTRUSTED,
    TrustPolicy,
    executed_side_effects_since_turn_start,
    load_trust_policy,
)
from adrl.telemetry.metrics import EVENT_DROPPED_TOTAL

if TYPE_CHECKING:
    from adrl.gates.pipeline import GateOutcome
    from adrl.wire.observe import ResponseObservation

log = structlog.get_logger(__name__)

PRODUCER = "cascade"
ESCALATION_EVENT = "escalation"
INFRASTRUCTURE_EVENT = "infrastructure"
POLICY_CONSTRAINT_EVENT = "policy_constraint"
SUBAGENT_EVENT = "subagent_passthrough"
BOUNDARY_CANDIDATE_EVENT = "boundary_candidate"


@dataclass(frozen=True, slots=True)
class DispatchPlan:
    rung: Rung
    is_boundary: bool
    escalated: bool
    from_rung: Rung | None
    handoff: HandoffNote | None
    pair_rule: ProviderPairRule | None
    block: ErrorCode | None
    sticky: StickyState
    route_id: RouteId = field(default=RouteId(""))
    transform: TransformResult | None = None
    subagent: bool = False
    state_loss: bool = False
    policy_constrained: bool = False
    pinned: bool = False
    thinking_suppressed: bool = False
    """The request must go out without the thinking parameter (ADRL-CAS-004 handoff rule)."""
    deployment_id: str | None = None
    """Attested deployment chosen for dispatch (ADRL-SAF-008); set by the proxy."""
    model_alias: str | None = None
    """Model name sent to the gateway for that deployment; None on the frontier passthrough."""

    @property
    def body(self) -> dict[str, Any] | None:
        """Transformed transcript when an escalation handoff applied; None means original bytes."""
        return self.transform.body if self.transform is not None else None


@dataclass(frozen=True, slots=True)
class CascadeEvents:
    fired: tuple[WireHit, ...]
    events: tuple[LedgerEvent, ...]
    sticky: StickyState
    infrastructure_event: bool = False
    escalation_pending: bool = False
    surfaced_error: dict[str, Any] | None = None
    failure_type: FailureType | None = None
    emitted: bool = False

    @property
    def fired_wires(self) -> tuple[str, ...]:
        """Wire names, as the proxy's CascadeEventsLike stage protocol reads them."""
        return tuple(hit.wire.value for hit in self.fired)

    @property
    def outcome_events(self) -> tuple[LedgerEvent, ...]:
        """Events the proxy must append; empty when the controller already appended them."""
        return () if self.emitted else self.events


@dataclass(frozen=True, slots=True)
class PendingEscalation:
    route_id: RouteId
    from_rung: Rung
    hits: tuple[WireHit, ...]


class CascadeController:
    """Process-local pending-escalation map; sticky state through the StateProvider port."""

    def __init__(
        self,
        bundle: ConfigBundle,
        state: StateProvider,
        *,
        registry: RungRegistry | None = None,
        ledger: LedgerPort | None = None,
        evaluator: TripwireEvaluator | None = None,
        trust: TrustPolicy | None = None,
        now: Any = None,
    ) -> None:
        self._bundle = bundle
        self._trust = trust or UNTRUSTED
        self._state = state
        self._registry = registry or RungRegistry(bundle.rungs)
        self._ledger = ledger
        self._evaluator = evaluator or TripwireEvaluator(bundle.tripwires, bundle.policy)
        self._now = now or (lambda: datetime.now(UTC))
        self._pending: dict[LineageId, PendingEscalation] = {}
        self._seq: dict[RouteId, itertools.count[int]] = {}
        self._verifier_consumed: dict[LineageId, int] = {}

    @classmethod
    def from_components(
        cls,
        *,
        bundle: ConfigBundle,
        settings: Settings,
        ledger: LedgerPort | None,
        state: StateProvider | None,
    ) -> CascadeController:
        """Build the controller from config; an absent state provider means process-local."""
        if state is None:
            log.warning("cascade_state_process_local", detail="sticky state lost on restart")
            state = MemoryStateProvider()
        return cls(
            bundle,
            state,
            registry=RungRegistry(bundle.rungs),
            ledger=ledger,
            evaluator=TripwireEvaluator(bundle.tripwires, bundle.policy),
            trust=load_trust_policy(settings.config_dir),
        )

    # events ----------------------------------------------------------------------------

    async def _seed_seq(self, route_id: RouteId) -> None:
        """Continue the producer sequence from the ledger so a restart never reuses a key."""
        if route_id in self._seq or not route_id:
            return
        start = 1
        if self._ledger is not None:
            try:
                stored = await self._ledger.read_events(route_id)
            except Exception as exc:
                log.warning("seq_seed_failed", error=type(exc).__name__)
                stored = []
            highest = max((e.producer_seq for e in stored if e.producer == PRODUCER), default=0)
            start = highest + 1
        self._seq[route_id] = itertools.count(start)

    def _event(self, route_id: RouteId, event_type: str, payload: Mapping[str, Any]) -> LedgerEvent:
        counter = self._seq.setdefault(route_id, itertools.count(1))
        return LedgerEvent(
            route_id=route_id,
            event_type=event_type,
            producer=PRODUCER,
            producer_seq=next(counter),
            payload=dict(payload),
        )

    def _outcome(
        self,
        ctx: RequestContext,
        route_id: RouteId,
        state: OutcomeState,
        payload: Mapping[str, Any],
    ) -> LedgerEvent:
        counter = self._seq.setdefault(route_id, itertools.count(1))
        return outcome_event(
            route_id,
            state,
            PRODUCER,
            next(counter),
            OutcomeFields(
                session_hmac=str(ctx.session_hmac),
                lineage_hmac=str(ctx.lineage_hmac),
                served_rung=payload.get("rung"),
                extra=payload,
            ),
        )

    async def _emit(self, events: list[LedgerEvent]) -> None:
        if self._ledger is None:
            return
        for event in events:
            stored = await self._ledger.append_event(event)
            if not stored:
                EVENT_DROPPED_TOTAL.labels(producer=PRODUCER).inc()
                log.warning(
                    "event_dropped",
                    route_id=str(event.route_id),
                    event_type=event.event_type,
                    producer_seq=event.producer_seq,
                )

    # plan ------------------------------------------------------------------------------

    async def plan(
        self, ctx: RequestContext, decision: Decision, gate: GateOutcome, sticky: StickyState | None
    ) -> DispatchPlan:
        events: list[LedgerEvent] = []
        boundary = assess_boundary(ctx.json)
        permitted = gate.permitted
        if sticky is not None:
            await self._seed_seq(sticky.route_id)
        await self._seed_seq(decision.route_id)
        if gate.block is not None or permitted.is_empty:
            block = gate.block or ErrorCode.PINNED_CLOUD_DENIED
            base = sticky or new_sticky(
                ctx.lineage_hmac, decision.route_id, decision.rung, previous=None
            )
            return DispatchPlan(
                base.rung,
                boundary.is_boundary,
                False,
                None,
                None,
                None,
                block,
                base,
                decision.route_id,
            )

        if ctx.is_subagent:
            plan = await self._plan_subagent(
                ctx, decision, gate, sticky, boundary.is_boundary, events
            )
            return replace(plan, pinned=gate.pinned)

        if ctx.request_class is RequestClass.USER_TURN:
            plan = await self._plan_user_turn(ctx, decision, gate, sticky, boundary, events)
        else:
            plan = await self._plan_inherit(ctx, decision, gate, sticky, boundary, events)
        await self._emit(events)
        return replace(plan, pinned=gate.pinned)

    async def _plan_user_turn(
        self,
        ctx: RequestContext,
        decision: Decision,
        gate: GateOutcome,
        sticky: StickyState | None,
        boundary: Any,
        events: list[LedgerEvent],
    ) -> DispatchPlan:
        permitted = gate.permitted
        if sticky is not None:
            events.append(
                self._outcome(
                    ctx,
                    sticky.route_id,
                    OutcomeState.CLOSED_TURN,
                    {
                        "reason": "next_user_turn",
                        "rung": sticky.rung.value,
                        "escalated": sticky.escalated,
                        "served_model": sticky.served_model,
                        "served_source": sticky.served_source,
                    },
                )
            )
            self._pending.pop(ctx.lineage_hmac, None)
        rung = decision.rung
        constrained = False
        if sticky is not None and sticky.escalated and sticky.rung > rung:
            rung = sticky.rung
        if rung not in permitted:
            highest = permitted.highest
            assert highest is not None
            constrained = True
            events.append(
                self._event(
                    decision.route_id,
                    POLICY_CONSTRAINT_EVENT,
                    {
                        "reason": "gate_precedes_stickiness",
                        "requested_rung": rung.value,
                        "served_rung": highest.value,
                    },
                )
            )
            rung = highest
        new = new_sticky(
            ctx.lineage_hmac,
            decision.route_id,
            rung,
            previous=sticky,
            escalated=bool(sticky and sticky.escalated and rung > decision.rung),
        )
        await self._state.set_sticky(new)
        events.append(
            self._outcome(
                ctx,
                decision.route_id,
                OutcomeState.PENDING,
                {"rung": rung.value, "decided_rung": decision.rung.value, "state_loss": False},
            )
        )
        return DispatchPlan(
            rung,
            True,
            False,
            None,
            None,
            None,
            None,
            new,
            decision.route_id,
            policy_constrained=constrained,
        )

    async def _plan_inherit(
        self,
        ctx: RequestContext,
        decision: Decision,
        gate: GateOutcome,
        sticky: StickyState | None,
        boundary: Any,
        events: list[LedgerEvent],
    ) -> DispatchPlan:
        permitted = gate.permitted
        state_loss = False
        if sticky is None:
            state_loss = ctx.request_class is RequestClass.CONTINUATION
            sticky = (
                mark_state_loss(
                    new_sticky(ctx.lineage_hmac, decision.route_id, decision.rung, previous=None)
                )
                if state_loss
                else new_sticky(ctx.lineage_hmac, decision.route_id, decision.rung, previous=None)
            )
            await self._state.set_sticky(sticky)
            events.append(
                self._outcome(
                    ctx,
                    decision.route_id,
                    OutcomeState.PENDING,
                    {
                        "rung": sticky.rung.value,
                        "decided_rung": decision.rung.value,
                        "state_loss": state_loss,
                        "request_class": ctx.request_class.value,
                    },
                )
            )
        rung = sticky.rung
        constrained = False
        if rung not in permitted:
            highest = permitted.highest
            assert highest is not None
            constrained = True
            events.append(
                self._event(
                    sticky.route_id,
                    POLICY_CONSTRAINT_EVENT,
                    {
                        "reason": "gate_precedes_stickiness",
                        "requested_rung": rung.value,
                        "served_rung": highest.value,
                    },
                )
            )
            rung = highest
            sticky = _retarget(sticky, rung)
            await self._state.set_sticky(sticky)
        if boundary.is_boundary and not gate.pinned:
            await self._ingest_verifier_signal(ctx, sticky, rung, events)
        pending = self._pending.get(ctx.lineage_hmac)
        if pending is not None and boundary.is_boundary and not gate.pinned:
            target = self._registry.next_higher(rung, permitted)
            if target is not None:
                return await self._escalate(ctx, sticky, pending, rung, target, events, state_loss)
        suppressed = (
            sticky.escalated
            and self._registry.family_for(rung) == "anthropic"
            and needs_thinking_suppression(ctx.json)
        )
        return DispatchPlan(
            rung,
            boundary.is_boundary,
            False,
            None,
            None,
            None,
            None,
            sticky,
            sticky.route_id,
            state_loss=state_loss,
            policy_constrained=constrained,
            thinking_suppressed=suppressed,
        )

    async def _ingest_verifier_signal(
        self, ctx: RequestContext, sticky: StickyState, rung: Rung, events: list[LedgerEvent]
    ) -> None:
        """Wire class (e): verifier failures recorded on the lineage arm an escalation."""
        if self._ledger is None:
            return
        try:
            signals = await self._ledger.read_lineage_events(
                ctx.lineage_hmac, VERIFIER_FAILED_EVENT
            )
        except Exception as exc:
            log.warning("verifier_signal_read_failed", error=type(exc).__name__)
            return
        consumed = self._verifier_consumed.get(ctx.lineage_hmac, 0)
        fresh = [s for s in signals if (s.seq or 0) > consumed]
        if not fresh:
            return
        self._verifier_consumed[ctx.lineage_hmac] = max((s.seq or 0) for s in fresh)
        hit = self._evaluator.verifier_failure(rung)
        if hit is None:
            return
        events.append(self._event(sticky.route_id, TRIPWIRE_EVENT, hit.as_record()))
        if ctx.lineage_hmac not in self._pending:
            self._pending[ctx.lineage_hmac] = PendingEscalation(sticky.route_id, rung, (hit,))

    async def _escalate(
        self,
        ctx: RequestContext,
        sticky: StickyState,
        pending: PendingEscalation,
        from_rung: Rung,
        to_rung: Rung,
        events: list[LedgerEvent],
        state_loss: bool,
    ) -> DispatchPlan:
        source_family = family_of_model(
            sticky.served_model, from_rung, self._registry.family_for(from_rung)
        )
        target_family = self._registry.family_for(to_rung)
        thinking = isinstance(ctx.json.get("thinking"), Mapping)
        source_has_thinking = latest_assistant_has_thinking(ctx.json)
        rule = self._bundle.provider_pairs.rule_for(
            source_family, target_family, thinking, source_has_thinking=source_has_thinking
        )
        side_effects = executed_side_effects_since_turn_start(ctx.json, trust=self._trust)
        verifier_result = None
        for hit in pending.hits:
            if hit.wire is WireClass.VERIFIER_FAILURE:
                verifier_result = VerificationResult.FAIL
        note = HandoffNote(
            cause=",".join(h.wire.value for h in pending.hits),
            from_rung=from_rung,
            to_rung=to_rung,
            executed_side_effects=side_effects,
            verifier_result=verifier_result,
        )
        result = transform(ctx.json, rule, note)
        new = escalate(sticky, to_rung)
        await self._state.set_sticky(new)
        self._pending.pop(ctx.lineage_hmac, None)
        events.append(
            self._event(
                sticky.route_id,
                ESCALATION_EVENT,
                {
                    "from_rung": from_rung.value,
                    "to_rung": to_rung.value,
                    "cause": note.cause,
                    "pair_rule": rule.model_dump(),
                    "handoff_schema": note.schema_version,
                    "side_effects_before_escalation": bool(side_effects),
                    "source_has_thinking": source_has_thinking,
                    "thinking_disabled_for_handoff": bool(thinking and result.thinking_disabled),
                    **result.as_record(),
                },
            )
        )
        log.info("escalation", from_rung=from_rung.value, to_rung=to_rung.value, cause=note.cause)
        return DispatchPlan(
            to_rung,
            True,
            True,
            from_rung,
            note,
            rule,
            None,
            new,
            sticky.route_id,
            transform=result,
            state_loss=state_loss,
            thinking_suppressed=bool(thinking and result.thinking_disabled),
        )

    async def _plan_subagent(
        self,
        ctx: RequestContext,
        decision: Decision,
        gate: GateOutcome,
        sticky: StickyState | None,
        is_boundary: bool,
        events: list[LedgerEvent],
    ) -> DispatchPlan:
        """SEM-006 interim: constrained passthrough at the requested model, pin inherited."""
        permitted = gate.permitted
        requested = self._registry.rung_for_model_name(ctx.requested_model)
        rung = (
            requested
            if requested is not None and requested in permitted
            else (
                permitted.highest
                if requested is None or requested > (permitted.highest or Rung.LOCAL)
                else permitted.lowest
            )
        )
        assert rung is not None
        if sticky is None:
            sticky = new_sticky(ctx.lineage_hmac, decision.route_id, rung, previous=None)
            await self._state.set_sticky(sticky)
        elif sticky.rung is not rung:
            sticky = _retarget(sticky, rung)
            await self._state.set_sticky(sticky)
        events.append(
            self._event(
                sticky.route_id,
                SUBAGENT_EVENT,
                {
                    "subagent": True,
                    "requested_model": ctx.requested_model,
                    "served_rung": rung.value,
                    "pinned": gate.pinned,
                    "agent_id_present": ctx.agent_id is not None,
                },
            )
        )
        await self._emit(events)
        return DispatchPlan(
            rung, is_boundary, False, None, None, None, None, sticky, sticky.route_id, subagent=True
        )

    # observe ---------------------------------------------------------------------------

    async def observe(
        self, ctx: RequestContext, plan: DispatchPlan, obs: ResponseObservation
    ) -> CascadeEvents:
        events: list[LedgerEvent] = []
        sticky = plan.sticky
        infra = False
        now = self._now()
        await self._seed_seq(sticky.route_id)
        if obs.status < 400 and obs.served is not None:
            sticky, changed = with_served(sticky, obs.served, now)
            if changed:
                infra = True
                events.append(
                    self._event(
                        sticky.route_id,
                        INFRASTRUCTURE_EVENT,
                        {
                            "reason": "within_rung_model_change",
                            "served_model": obs.served.model,
                            "previous_model": plan.sticky.served_model,
                            "cache_cold": True,
                        },
                    )
                )
            await self._state.set_sticky(sticky)
        if plan.subagent:
            await self._emit(events)
            return CascadeEvents((), tuple(events), sticky, infra, emitted=self._ledger is not None)
        if obs.status >= 400 or not obs.completed:
            return await self._observe_failure(ctx, plan, obs, sticky, events, infra)
        fired = (
            () if plan.escalated else self._evaluator.evaluate(ctx.json, plan.rung, observation=obs)
        )
        pending = False
        for hit in fired:
            events.append(self._event(sticky.route_id, TRIPWIRE_EVENT, hit.as_record()))
        if fired and not plan.pinned:
            higher = self._registry.next_higher(plan.rung, PermittedSet.all())
            if higher is not None:
                self._pending[ctx.lineage_hmac] = PendingEscalation(
                    sticky.route_id, plan.rung, fired
                )
                pending = True
        await self._emit(events)
        return CascadeEvents(
            fired, tuple(events), sticky, infra, pending, emitted=self._ledger is not None
        )

    async def _observe_failure(
        self,
        ctx: RequestContext,
        plan: DispatchPlan,
        obs: ResponseObservation,
        sticky: StickyState,
        events: list[LedgerEvent],
        infra: bool,
    ) -> CascadeEvents:
        candidates: list[FailureType] = []
        message = ""
        if obs.error and isinstance(obs.error.get("error"), Mapping):
            message = str(obs.error["error"].get("message", ""))
        if VENDOR_PROMPT_TOO_LONG_PHRASE in message.lower() or (
            "context" in message.lower() and "long" in message.lower()
        ):
            candidates.append(FailureType.CONTEXT_FEASIBILITY)
        if obs.status == 429 or obs.status >= 500 or not obs.completed:
            candidates.append(FailureType.INFRASTRUCTURE)
        if plan.policy_constrained:
            candidates.append(FailureType.POLICY_CONSTRAINT)
        if plan.sticky.served_source == "assumed_intended" and not candidates:
            candidates = [FailureType.UNVERIFIABLE]
        primary, secondary = resolve_primary(candidates)
        partial = obs.streamed_tool_content and not obs.completed
        code = ErrorCode.PARTIAL_STREAM_FAILURE if partial else ErrorCode.TERMINAL_FAILURE
        detail = f"failure_type={primary.value} rung={plan.rung.value} status={obs.status}"
        surfaced = render_error(code, detail)
        events.append(
            self._outcome(
                ctx,
                sticky.route_id,
                OutcomeState.CLOSED_TURN,
                {
                    "reason": "terminal_failure",
                    "failure_type": primary.value,
                    "secondary_type": secondary.value if secondary else None,
                    "rung": plan.rung.value,
                    "status": obs.status,
                    "partial_stream": partial,
                    "surfaced": True,
                    "gateway_attempts_observed": 1,
                    "served_source": sticky.served_source,
                },
            )
        )
        self._pending.pop(ctx.lineage_hmac, None)
        await self._emit(events)
        return CascadeEvents(
            (), tuple(events), sticky, infra, False, surfaced, primary, self._ledger is not None
        )

    # episode boundaries ----------------------------------------------------------------

    async def episode_boundary(
        self, lineage: LineageId, signal: EpisodeSignal
    ) -> StickyState | None:
        """Release only the escalation ratchet (ADRL-SEM-005); pins are never touched here."""
        sticky = await self._state.get_sticky(lineage)
        if sticky is None:
            return None
        released = release_ratchet(sticky, signal)
        await self._state.set_sticky(released)
        self._pending.pop(lineage, None)
        await self._emit(
            [
                self._event(
                    sticky.route_id,
                    BOUNDARY_CANDIDATE_EVENT,
                    {
                        "signal": signal.value,
                        "released": sticky.escalated,
                        "sticky": sticky_record(released),
                    },
                )
            ]
        )
        return released

    def pending_for(self, lineage: LineageId) -> PendingEscalation | None:
        return self._pending.get(lineage)


def _retarget(sticky: StickyState, rung: Rung) -> StickyState:
    return StickyState(
        lineage_hmac=sticky.lineage_hmac,
        route_id=sticky.route_id,
        rung=rung,
        escalated=sticky.escalated,
        served_model=None,
        served_provider=None,
        served_source="assumed_intended",
        turn_index=sticky.turn_index,
        last_served_at=None,
        state_loss=sticky.state_loss,
    )
