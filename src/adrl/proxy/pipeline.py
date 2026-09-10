"""The per-request pipeline. Primary: ADRL-FND-003.
Also implements: ADRL-TRU-002 (register additions of 2026-09-03).

Secondary: ADRL-FND-001 (byte-exact relay), ADRL-FND-004 (fail-open by class and pin state),
ADRL-SAF-001 (gates on every class), ADRL-SAF-009 (egress write-ahead), ADRL-SEM-003
(continuations inherit), ADRL-SEM-004 (utility on pinned lineages), ADRL-SEM-006 (pin
inheritance materialised per lineage), ADRL-CAS-006 (served identity recorded),
ADRL-MEM-001/002 (forwarded outcome identity).

Order per request: parse, identity, pin lookup, classify, gate, sticky lookup, route-or-inherit,
cascade plan, egress write-ahead, ledger decision (write-through), dispatch once, relay while
observing, cascade observe, ledger events (write-behind). The per-lineage lock is held from the
gate through the decision write and again briefly when the response has been observed.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from adrl.config.checks import check_live_rung_has_evidence
from adrl.config.loaders import ConfigBundle
from adrl.config.settings import Settings
from adrl.core.enums import FailureClass, GateMode, RequestClass, RoutingMode, Rung, UtilityKind
from adrl.core.errors import VENDOR_PROMPT_TOO_LONG_PHRASE, ErrorCode, LedgerAppendFailure
from adrl.core.ids import LineageId, RouteId
from adrl.core.ports import EgressEvent, LineageEvent, StateProvider, StickyState, Tokenizer
from adrl.core.types import (
    Decision,
    DeploymentInfo,
    DeploymentSet,
    Finding,
    GateVerdict,
    LedgerEvent,
    PermittedSet,
    RequestContext,
)
from adrl.gates.deployments import DeploymentPolicy, egress_fields
from adrl.ledger.egress import EgressLedger
from adrl.ledger.facade import PIN_EVENT, MemoryFacade
from adrl.proxy.claude_experiment import ClaudeExperimentClient
from adrl.proxy.errors import (
    JSON_HEADERS,
    block_message,
)
from adrl.proxy.fallback import FailureResolution, FallbackAction, FallbackRecorder, resolve_failure
from adrl.proxy.observe_only import ObserveOnlyGateOutcome
from adrl.proxy.stages import (
    CascadeStage,
    DispatchPlanLike,
    GateOutcomeLike,
    GateStage,
    RouteStage,
    TranscriptTransform,
)
from adrl.proxy.upstream import HttpxGatewayClient, UpstreamUnreachableError, read_all, relay
from adrl.telemetry.logging import bind_request
from adrl.telemetry.metrics import (
    EVENT_DROPPED_TOTAL,
    GATE_LATENCY_SECONDS,
    LEDGER_DEGRADED_TOTAL,
    REQUESTS_TOTAL,
)
from adrl.wire.adapters import ClaudeCodeAdapter, HarnessAdapter, IdentitySignals
from adrl.wire.classify import Classification, UnclassifiableError
from adrl.wire.identity import Identity, IdentityResolver, LineageLocks
from adrl.wire.observe import ResponseObservation
from adrl.wire.parse import (
    forward_headers,
    parse_request,
    response_headers,
)
from adrl.wire.profiles.base import ProtocolProfile, ProtocolResponse, RequestView
from adrl.wire.profiles.messages import MessagesProfile

log = structlog.get_logger(__name__)

PRODUCER = "proxy"
INHERITED_ESTIMATOR = "inherited"
INHERITED_ESTIMATOR_VERSION = "sticky-v1"
FALLBACK_ESTIMATOR = "fail_open"
FALLBACK_ESTIMATOR_VERSION = "fnd-004-v1"
AGENT_PARENT_EVENT = "agent_parent"
ALLOWLISTED_ERROR_PHRASES: tuple[str, ...] = (
    VENDOR_PROMPT_TOO_LONG_PHRASE,
    "prompt is too long",
    "rate limit",
    "overloaded",
    "thinking",
    "context",
    "invalid_request",
)


def _content_free_error(error: Mapping[str, Any], status: int, key: bytes) -> dict[str, Any]:
    """Record an upstream error without its wording (ADRL-SAF-009, MEM-005).

    Vendor validation errors quote prompt fragments; only the error type, the status, a keyed
    hash and length of the message, and an allow-listed phrase match are kept.
    """
    inner = error.get("error", error)
    inner_map = inner if isinstance(inner, Mapping) else {}
    message = str(inner_map.get("message", ""))
    lowered = message.lower()
    phrase = next((p for p in ALLOWLISTED_ERROR_PHRASES if p in lowered), None)
    return {
        "type": inner_map.get("type"),
        "status": status,
        "message_hmac": hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()[:32],
        "message_length": len(message),
        "phrase": phrase,
    }


Finalizer = Callable[[], Awaitable[None]]


@dataclass
class ProxyResponse:
    status: int
    headers: dict[str, str]
    body: bytes | None = None
    stream: AsyncIterator[bytes] | None = None
    after: Finalizer | None = None
    route_id: str | None = None

    @property
    def is_stream(self) -> bool:
        return self.stream is not None


@dataclass(frozen=True, slots=True)
class _Turn:
    ctx: RequestContext
    gate: GateOutcomeLike
    decision: Decision
    plan: DispatchPlanLike
    target_rung: Rung
    body: bytes
    fresh_decision: bool
    state_loss: bool
    resolution: FailureResolution | None
    ledger_degraded: bool
    forward_original: bool
    deployment: DeploymentInfo | None = None


@dataclass
class _RouteSeq:
    """Per-route producer sequence continued from the ledger (ADRL-MEM-001 idempotency).

    The key (route_id, event_type, producer, producer_seq) must never be reused, so the first
    event for a route_id in this process starts after the highest sequence already stored.
    """

    counters: dict[str, int] = field(default_factory=dict)

    async def next(self, ledger: MemoryFacade, route_id: str) -> int:
        if route_id not in self.counters:
            try:
                stored = await ledger.read_events(RouteId(route_id))
            except Exception:
                stored = []
            self.counters[route_id] = max(
                (e.producer_seq for e in stored if e.producer == PRODUCER), default=0
            )
        self.counters[route_id] += 1
        return self.counters[route_id]


class Pipeline:
    def __init__(
        self,
        *,
        settings: Settings,
        bundle: ConfigBundle,
        ledger: MemoryFacade,
        egress: EgressLedger | None,
        gateway: HttpxGatewayClient,
        gate: GateStage,
        router: RouteStage,
        cascade: CascadeStage,
        state: StateProvider | None,
        identity: IdentityResolver,
        locks: LineageLocks | None = None,
        transcript_transform: TranscriptTransform | None = None,
        tokenizer: Tokenizer | None = None,
        profile: ProtocolProfile | None = None,
        adapter: HarnessAdapter | None = None,
    ) -> None:
        self._settings = settings
        self._bundle = bundle
        self._ledger = ledger
        self._egress = egress
        self._gateway = gateway
        self._claude_experiment = gateway if isinstance(gateway, ClaudeExperimentClient) else None
        if self._claude_experiment is not None:
            if (
                settings.routing_mode is not RoutingMode.LIVE
                or settings.gate_mode is not GateMode.ENFORCE
            ):
                raise ValueError(
                    "Claude experiment requires explicit LIVE routing and enforcing gates"
                )
            if not check_live_rung_has_evidence(bundle, settings).ok:
                raise ValueError("Claude experiment cannot bypass LIVE admission")
        self._gate = gate
        self._router = router
        self._cascade = cascade
        self._state = state
        self._identity = identity
        self._locks = locks or LineageLocks()
        self._transform = transcript_transform
        self._tokenizer = tokenizer
        self._profile: ProtocolProfile = profile or MessagesProfile()
        self._adapter: HarnessAdapter = adapter or ClaudeCodeAdapter()
        self._recorder = FallbackRecorder(ledger, egress, deployment_tag=settings.deployment_tag)
        self._deployments = DeploymentPolicy(bundle.endpoint_inventory)
        self._seq = _RouteSeq()
        self._background: set[asyncio.Task[Any]] = set()
        self._persisted_parents: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ public entry point

    async def handle(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        peer: tuple[str, int] | None,
        *,
        query: str = "",
    ) -> ProxyResponse:
        if self._claude_experiment is not None and query:
            return self._error_response(
                ErrorCode.CAPABILITY_REJECTED, "experiment query not admitted"
            )
        if not self._profile.handles(method, path, headers):
            return await self._forward_non_api(parse_request(method, path, headers, body, query))
        parsed = self._profile.parse(method, path, headers, body, query)
        signals = self._adapter.identity_signals(parsed)
        is_pre_warm = self._profile.is_pre_warm(parsed)
        root = await self._prime_parents(signals, peer, is_pre_warm=is_pre_warm)
        identity = self._identity.resolve_signals(signals, peer, is_pre_warm=is_pre_warm)
        await self._persist_parent(identity, root)

        # Pin lookup and classification run under the per-lineage lock so a request racing the
        # pinning request resolves its gate failure against the pinned state (ADRL-FND-004).
        lock = self._locks.get(identity.lineage_hmac)
        async with lock:
            pinned_before = await self._effective_pin(identity)
            try:
                classification = self._profile.classify(
                    parsed,
                    self._bundle.utility_fingerprints,
                    pinned=self._enforcing and pinned_before,
                )
            except UnclassifiableError as exc:
                return self._error_response(exc.code, exc.detail)
            ctx = self._context(parsed, identity, classification)
            bind_request(lineage=ctx.lineage_hmac, request_class=ctx.request_class.value)
            prepared = await self._prepare(ctx, classification, pinned_before)
        if isinstance(prepared, ProxyResponse):
            return prepared
        return await self._dispatch(prepared)

    async def _prime_parents(
        self, signals: IdentitySignals, peer: tuple[str, int] | None, *, is_pre_warm: bool
    ) -> LineageId | None:
        """Rebuild the agent chain from persisted parent links after a restart (ADRL-SEM-006)."""
        if not signals.agent_id:
            return None
        root = self._identity.session_root_from_signals(signals, peer, is_pre_warm=is_pre_warm)
        if self._identity.needs_priming(root):
            try:
                events = await self._ledger.read_lineage_events(root, AGENT_PARENT_EVENT)
            except Exception as exc:
                log.warning("agent_parent_read_failed", error=type(exc).__name__)
                events = []
            self._identity.prime_parents(
                root,
                [
                    (str(e.payload.get("agent_id", "")), str(e.payload.get("parent_agent_id", "")))
                    for e in events
                ],
            )
        return root

    async def _persist_parent(self, identity: Identity, root: LineageId | None) -> None:
        if root is None or identity.agent_id is None or identity.parent_agent_id is None:
            return
        pair = (identity.agent_id, identity.parent_agent_id)
        if pair in self._persisted_parents:
            return
        self._persisted_parents.add(pair)
        try:
            await self._ledger.append_lineage_event(
                LineageEvent(
                    lineage_hmac=root,
                    event_type=AGENT_PARENT_EVENT,
                    payload={"agent_id": pair[0], "parent_agent_id": pair[1]},
                )
            )
        except Exception as exc:
            log.warning("agent_parent_persist_failed", error=type(exc).__name__)

    async def drain(self) -> None:
        """Wait for write-behind ledger work; used by tests and shutdown."""
        if self._background:
            await asyncio.gather(*list(self._background), return_exceptions=True)

    # ------------------------------------------------------------------ preparation under lock

    async def _prepare(
        self, ctx: RequestContext, classification: Classification, pinned_before: bool
    ) -> _Turn | ProxyResponse:
        gate, gate_resolution = await self._run_gate(ctx, pinned_before)
        if isinstance(gate, ProxyResponse):
            return gate
        pinned = self._enforcing and gate.pinned

        if gate.block is not None and self._enforcing:
            return await self._blocked(ctx, gate, gate.block)

        if ctx.request_class is RequestClass.UTILITY and pinned:
            serve_empty = bool(getattr(gate, "serve_empty_utility", False))
            if ctx.utility_kind is UtilityKind.COSMETIC and (
                serve_empty or Rung.LOCAL not in gate.permitted
            ):
                await self._record_egress(ctx, gate, None, 0, kind="empty_utility")
                return self._protocol_response(self._profile.empty_utility(ctx))

        if pinned and gate.permitted.is_empty:
            return await self._blocked(ctx, gate, ErrorCode.PINNED_CLOUD_DENIED)

        if ctx.request_class is RequestClass.PASSTHROUGH and self._profile.is_token_count(ctx.path):
            if pinned or bool(getattr(gate, "serve_local_estimate", False)):
                return await self._count_tokens_locally(ctx, gate)

        sticky, sticky_failure = await self._sticky(ctx)
        state_loss = sticky is None and classification.inherits_route
        resolution = gate_resolution or sticky_failure

        decision: Decision | None = None
        fresh = (
            classification.is_routed
            or (classification.request_class is RequestClass.SUBAGENT)
            or sticky is None
        )
        if resolution is None:
            if fresh:
                try:
                    decision = await self._router.decide(ctx, gate, sticky)
                except Exception as exc:
                    resolution = resolve_failure(
                        FailureClass.ROUTING_PATH, pinned=pinned, mode=self._settings.fallback_mode
                    )
                    await self._recorder.record(ctx, resolution, exception=exc)
            else:
                assert sticky is not None
                decision = self._inherited_decision(ctx, gate, sticky)
        if resolution is not None and resolution.action in (
            FallbackAction.BLOCK,
            FallbackAction.SURFACE,
        ):
            return self._error_response(
                resolution.code or ErrorCode.TERMINAL_FAILURE,
                f"{resolution.failure_class.value} failure; last-known-safe is to refuse",
            )
        if decision is None:
            assert resolution is not None
            decision = self._fallback_decision(ctx, gate, resolution)

        try:
            plan = await self._cascade.plan(ctx, decision, gate, sticky)
        except Exception as exc:
            plan_resolution = resolve_failure(
                FailureClass.ROUTING_PATH, pinned=pinned, mode=self._settings.fallback_mode
            )
            await self._recorder.record(ctx, plan_resolution, exception=exc)
            if plan_resolution.action in (FallbackAction.BLOCK, FallbackAction.SURFACE):
                return self._error_response(
                    plan_resolution.code or ErrorCode.TERMINAL_FAILURE, "cascade stage failed"
                )
            resolution = plan_resolution
            decision = self._fallback_decision(ctx, gate, plan_resolution)
            plan = _FallbackPlan.for_decision(
                ctx, decision, sticky, is_boundary=self._profile.is_action_boundary(ctx.json)
            )
        if plan.block is not None and self._enforcing:
            return await self._blocked(ctx, gate, plan.block)

        target_rung, forward_original = self._target(ctx, gate, plan, resolution)
        if pinned and target_rung is not Rung.LOCAL:
            return await self._blocked(ctx, gate, ErrorCode.PINNED_CLOUD_DENIED)
        deployment, deployment_block = self._choose_deployment(
            ctx, gate, target_rung, forward_original
        )
        if deployment_block is not None:
            return await self._blocked(ctx, gate, deployment_block)
        plan = _with_deployment(plan, deployment, forward_original)

        body = self._body_for(ctx, plan, target_rung, forward_original, deployment)
        if self._claude_experiment is not None:
            # Do not force a cloud model after fallback, pinning or an escalated transform.
            permitted = getattr(gate, "permitted_deployments", None)
            if (
                resolution is not None
                or pinned
                or target_rung is not Rung.FRONTIER
                or not forward_original
                or permitted is None
            ):
                return await self._blocked(ctx, gate, ErrorCode.CAPABILITY_REJECTED)
            try:
                body, deployment = self._claude_experiment.selection.prepare(
                    ctx.body, lineage=str(ctx.lineage_hmac), permitted=permitted, pinned=pinned
                )
            except ValueError:
                return await self._blocked(ctx, gate, ErrorCode.CAPABILITY_REJECTED)
            if self._deployments.catalog.get(deployment.deployment_id) != deployment:
                return await self._blocked(ctx, gate, ErrorCode.CAPABILITY_REJECTED)
            decision = dataclasses.replace(
                decision,
                estimator="experiment_forced_claude",
                estimator_version=self._claude_experiment.config.version,
                features={
                    **decision.features,
                    "experiment_config_hash": self._claude_experiment.config.fingerprint,
                    "experiment_model": deployment.model,
                },
            )
            forward_original = False
            plan = _with_deployment(plan, deployment, False)
        ledger_degraded = await self._record_egress(
            ctx, gate, target_rung, len(body), deployment=deployment, receipt_source="intended"
        )
        if ledger_degraded is None:
            return await self._blocked(ctx, gate, ErrorCode.EGRESS_LEDGER_UNAVAILABLE)

        if fresh and resolution is None:
            await self._ledger.append_decision(
                decision, self._decision_context(ctx, gate, state_loss)
            )
        if self._state is not None:
            try:
                await self._state.set_sticky(plan.sticky)
            except Exception as exc:
                log.warning("sticky_write_failed", error=str(exc))
        self._write_behind(
            ctx,
            decision.route_id,
            "request",
            {
                "request_class": ctx.request_class.value,
                "target_rung": target_rung.value,
                "deployment_id": deployment.deployment_id if deployment else None,
                "decided_rung": decision.rung.value,
                "is_boundary": plan.is_boundary,
                "escalated": plan.escalated,
                "forward_original": forward_original,
                "unscanned": gate.unscanned,
                "pinned": gate.pinned,
                "fail_open": resolution.failure_class.value if resolution else None,
                "state_loss": state_loss,
                "routing_mode": self._settings.routing_mode.value,
                "experiment_config_hash": (
                    self._claude_experiment.config.fingerprint if self._claude_experiment else None
                ),
                "experiment_selected_model": deployment.model
                if self._claude_experiment and deployment
                else None,
            },
        )
        return _Turn(
            ctx=ctx,
            gate=gate,
            decision=decision,
            plan=plan,
            target_rung=target_rung,
            body=body,
            fresh_decision=fresh,
            state_loss=state_loss,
            resolution=resolution,
            ledger_degraded=ledger_degraded,
            forward_original=forward_original,
            deployment=deployment,
        )

    def _choose_deployment(
        self,
        ctx: RequestContext,
        gate: GateOutcomeLike,
        rung: Rung,
        forward_original: bool,
    ) -> tuple[DeploymentInfo | None, ErrorCode | None]:
        """Pick the attested deployment for the rung inside the permitted set (ADRL-SAF-008).

        A rung label never reaches the gateway on its own: the alias sent is the deployment id.
        A pinned lineage may only reach a ``local_host`` deployment, whatever the label says.
        """
        policy = self._deployments
        permitted = getattr(gate, "permitted_deployments", None)
        if permitted is None:
            permitted = policy.permitted_for(
                permitted_rungs=gate.permitted.rungs,
                pinned=self._enforcing and gate.pinned,
                residency=gate.residency,
            )
        if forward_original and rung not in permitted.rungs():
            # Routing is not live: the rung ceiling is advisory here (the harness's own model
            # is forwarded), but the pin and residency still bind at the deployment level.
            log.info("rung_ceiling_advisory_passthrough", rung=rung.value)
            permitted = policy.permitted_for(
                permitted_rungs=frozenset(Rung),
                pinned=self._enforcing and gate.pinned,
                residency=gate.residency,
            )
        if not self._enforcing and permitted.is_empty:
            log.warning("deployment_set_empty_observe_mode", rung=rung.value)
            permitted = policy.universe()
        if forward_original:
            deployment = policy.frontier_for_model(permitted, ctx.requested_model)
        else:
            spec = self._bundle.rungs.rungs.get(rung)
            members = spec.members if spec is not None else ()
            deployment = policy.choose(permitted, rung, rung_member_order=tuple(members))
        if deployment is None:
            if self._enforcing and gate.pinned:
                return None, ErrorCode.PINNED_CLOUD_DENIED
            log.warning(
                "no_permitted_deployment",
                rung=rung.value,
                residency=gate.residency,
                permitted=permitted.as_list(),
            )
            return None, ErrorCode.CAPABILITY_REJECTED
        if self._enforcing and gate.pinned and not deployment.is_local_host:
            log.error(
                "pinned_lineage_non_local_deployment",
                deployment=deployment.deployment_id,
                trust_zone=deployment.trust_zone,
            )
            return None, ErrorCode.PINNED_CLOUD_DENIED
        return deployment, None

    def _with_receipt(
        self, turn: _Turn, obs: ResponseObservation, headers: Mapping[str, str]
    ) -> ResponseObservation:
        """Attach the gateway's destination receipt to the observation (ADRL-RTG-008)."""
        if self._claude_experiment is not None:
            served = dataclasses.replace(
                obs.served,
                provider="anthropic",
                api_base_host="api.anthropic.com",
                deployment_id=None,
                trust_zone=None,
                geo=None,
            )
            if served.model != self._claude_experiment.config.target_model:
                self._claude_experiment.stopped = True
            return dataclasses.replace(obs, served=served)
        served = self._deployments.served_identity(obs.served, headers, turn.deployment)
        return dataclasses.replace(obs, served=served)

    # ------------------------------------------------------------------ dispatch and relay

    async def _dispatch(self, turn: _Turn) -> ProxyResponse:
        ctx = turn.ctx
        headers = forward_headers(ctx.headers)
        headers["content-type"] = "application/json"
        try:
            response = await self._gateway.send(
                turn.body, headers, path=ctx.path, rung=turn.target_rung
            )
        except UpstreamUnreachableError as exc:
            self._write_behind(
                ctx,
                turn.decision.route_id,
                "upstream_unreachable",
                {"rung": turn.target_rung.value, "error": type(exc).__name__},
            )
            return self._error_response(
                ErrorCode.TERMINAL_FAILURE, str(exc), turn.decision.route_id
            )

        status = response.status_code
        out_headers = response_headers(response.headers)
        observer = self._profile.stream_observer(
            status=status,
            headers={} if self._claude_experiment else response.headers,
            intended_rung=turn.target_rung,
            requested_model=ctx.requested_model,
            rungs=self._bundle.rungs,
            hash_key=self._identity.hmac_key,
        )
        content_type = str(response.headers.get("content-type", "")).lower()
        if status >= 400 or not ctx.is_stream or "text/event-stream" not in content_type:
            raw = await read_all(response)
            obs = self._profile.observe_response(
                raw,
                status=status,
                headers={} if self._claude_experiment else response.headers,
                intended_rung=turn.target_rung,
                requested_model=ctx.requested_model,
                rungs=self._bundle.rungs,
                hash_key=self._identity.hmac_key,
            )
            obs = self._with_receipt(turn, obs, response.headers)
            await self._finalize(turn, obs)
            return ProxyResponse(
                status=status, headers=out_headers, body=raw, route_id=turn.decision.route_id
            )

        response_headers_snapshot = dict(response.headers)

        async def after() -> None:
            await self._finalize(
                turn, self._with_receipt(turn, observer.finish(), response_headers_snapshot)
            )

        return ProxyResponse(
            status=status,
            headers=out_headers,
            stream=relay(response, observer),
            after=after,
            route_id=turn.decision.route_id,
        )

    async def _finalize(self, turn: _Turn, obs: ResponseObservation) -> None:
        ctx = turn.ctx
        REQUESTS_TOTAL.labels(
            request_class=ctx.request_class.value, rung=obs.served.rung.value
        ).inc()
        lock = self._locks.get(ctx.lineage_hmac)
        try:
            async with lock:
                events = await self._cascade.observe(ctx, turn.plan, obs)
                if self._state is not None and events.sticky is not None:
                    await self._state.set_sticky(events.sticky)
                payload: dict[str, Any] = {
                    "status": obs.status,
                    "served_rung": obs.served.rung.value,
                    "served_model": obs.served.model,
                    "served_provider": obs.served.provider,
                    "served_source": obs.served.source.value,
                    "served_deployment_id": obs.served.deployment_id,
                    "served_trust_zone": obs.served.trust_zone,
                    "served_geo": obs.served.geo,
                    "receipt_confirmed": obs.served.receipt_confirmed,
                    "intended_rung": turn.target_rung.value,
                    "intended_deployment_id": (
                        turn.deployment.deployment_id if turn.deployment else None
                    ),
                    "stop_reason": obs.stop_reason,
                    "streamed_tool_content": obs.streamed_tool_content,
                    "completed": obs.completed,
                    "malformed_tool_json": obs.malformed_tool_json,
                    "tool_uses": [dataclasses.asdict(t) for t in obs.tool_uses],
                    "bytes_relayed": obs.bytes_relayed,
                    "fired_wires": list(events.fired_wires),
                }
                if obs.usage is not None:
                    payload["usage"] = {
                        "input_tokens": obs.usage.input_tokens,
                        "output_tokens": obs.usage.output_tokens,
                        "cache_read_input_tokens": obs.usage.cache_read_input_tokens,
                        "cache_creation_input_tokens": obs.usage.cache_creation_input_tokens,
                    }
                if obs.error is not None:
                    payload["error"] = _content_free_error(
                        obs.error, obs.status, self._identity.hmac_key
                    )
                event_type = "upstream_error" if obs.status >= 400 else "served"
                await self._append_event(ctx, turn.decision.route_id, event_type, payload)
                await self._record_receipt(turn, obs)
                for outcome_event in events.outcome_events:
                    # Preserve the cascade's route and idempotency identity on continuations.
                    if not isinstance(outcome_event, LedgerEvent):
                        raise TypeError("cascade must return LedgerEvent instances")
                    if not await self._ledger.append_event(outcome_event):
                        EVENT_DROPPED_TOTAL.labels(producer=outcome_event.producer).inc()
                        log.warning(
                            "event_dropped",
                            route_id=outcome_event.route_id,
                            event_type=outcome_event.event_type,
                            producer=outcome_event.producer,
                            producer_seq=outcome_event.producer_seq,
                        )
        except Exception as exc:
            log.error("finalize_failed", error=str(exc), route_id=turn.decision.route_id)

    # ------------------------------------------------------------------ helpers

    @property
    def _enforcing(self) -> bool:
        return self._settings.gate_mode is GateMode.ENFORCE

    def _context(
        self, parsed: RequestView, identity: Identity, classification: Classification
    ) -> RequestContext:
        return RequestContext(
            body=parsed.body,
            json=parsed.json,
            headers=parsed.headers,
            path=parsed.path,
            request_class=classification.request_class,
            content_bearing=classification.content_bearing,
            interaction_mode=classification.interaction_mode,
            session_hmac=identity.session_hmac,
            lineage_hmac=identity.lineage_hmac,
            requested_model=parsed.requested_model,
            is_stream=parsed.is_stream,
            max_tokens=parsed.max_tokens,
            agent_id=identity.agent_id,
            parent_agent_id=identity.parent_agent_id,
            utility_kind=classification.utility_kind,
            session_key_source=identity.source,
            fingerprint_id=classification.fingerprint_id,
            protocol_profile_id=self._profile.profile_id,
            protocol_profile_version=self._profile.version,
            harness_adapter_id=self._adapter.adapter_id,
            harness_adapter_version=self._adapter.version,
        )

    async def _effective_pin(self, identity: Identity) -> bool:
        """Own pin, or an ancestor's, materialised as an inherited pin event (ADRL-SEM-006)."""
        own = await self._ledger.pin_state(identity.lineage_hmac)
        if own.effective_pinned:
            return True
        for ancestor in identity.ancestor_lineages:
            state = await self._ledger.pin_state(ancestor)
            if state.effective_pinned:
                await self._ledger.append_lineage_event(
                    LineageEvent(
                        lineage_hmac=identity.lineage_hmac,
                        event_type=PIN_EVENT,
                        payload={
                            "finding_id": f"inherited:{ancestor}",
                            "detector_id": "inherited",
                            "inherited_from": ancestor,
                        },
                    )
                )
                return True
        return False

    async def _run_gate(
        self, ctx: RequestContext, pinned_before: bool
    ) -> tuple[GateOutcomeLike | ProxyResponse, FailureResolution | None]:
        try:
            gate = await self._gate.evaluate(ctx)
        except Exception as exc:
            resolution = resolve_failure(
                FailureClass.GATE_PATH, pinned=pinned_before, mode=self._settings.fallback_mode
            )
            await self._recorder.record(ctx, resolution, exception=exc)
            if resolution.action in (FallbackAction.BLOCK, FallbackAction.SURFACE):
                return (
                    self._error_response(
                        resolution.code or ErrorCode.GATE_UNAVAILABLE,
                        "gate unavailable on a pinned lineage; failing closed",
                    ),
                    resolution,
                )
            synthetic = ObserveOnlyGateOutcome(
                permitted=resolution.permitted,
                verdicts=(
                    GateVerdict(
                        gate="fail_open",
                        permitted_after=resolution.permitted,
                        unscanned=True,
                        reason=type(exc).__name__,
                        pinned=pinned_before,
                    ),
                ),
                pinned=pinned_before,
                unscanned=True,
                findings=(),
                block=None,
                repo_class=None,
                residency=None,
                latency_s=0.0,
            )
            return synthetic, resolution
        GATE_LATENCY_SECONDS.labels(request_class=ctx.request_class.value).observe(gate.latency_s)
        if pinned_before and not gate.pinned:
            # The gate never sees an inherited pin; the pipeline owns lineage inheritance.
            gate = _PinnedOverlay(gate)
        return gate, None

    async def _sticky(
        self, ctx: RequestContext
    ) -> tuple[StickyState | None, FailureResolution | None]:
        if self._state is None:
            return None, None
        try:
            return await self._state.get_sticky(ctx.lineage_hmac), None
        except Exception as exc:
            resolution = resolve_failure(
                FailureClass.ROUTING_PATH,
                pinned=await self._pin_flag(ctx),
                mode=self._settings.fallback_mode,
            )
            await self._recorder.record(ctx, resolution, exception=exc)
            return None, resolution

    async def _pin_flag(self, ctx: RequestContext) -> bool:
        return (await self._ledger.pin_state(ctx.lineage_hmac)).effective_pinned

    def _inherited_decision(
        self, ctx: RequestContext, gate: GateOutcomeLike, sticky: StickyState
    ) -> Decision:
        rung = sticky.rung
        reason = "inherited"
        if rung not in gate.permitted:
            highest = gate.permitted.highest
            rung = highest if highest is not None else Rung.LOCAL
            reason = "inherited_tightened"
        return Decision(
            route_id=sticky.route_id,
            rung=rung,
            permitted=gate.permitted,
            estimator=INHERITED_ESTIMATOR,
            estimator_version=INHERITED_ESTIMATOR_VERSION,
            policy_version=self._bundle.policy.version,
            objective_version=self._bundle.policy.objective_version,
            cascade_feasible=False,
            cascade_reason=reason,
            features={"request_class": ctx.request_class.value},
            features_version="features-inherited-v1",
        )

    def _fallback_decision(
        self, ctx: RequestContext, gate: GateOutcomeLike, resolution: FailureResolution
    ) -> Decision:
        from adrl.core.ids import mint_route_id

        rung = Rung.LOCAL if resolution.action is FallbackAction.FORWARD_LOCAL else Rung.FRONTIER
        return Decision(
            route_id=mint_route_id(),
            rung=rung,
            permitted=resolution.permitted,
            estimator=FALLBACK_ESTIMATOR,
            estimator_version=FALLBACK_ESTIMATOR_VERSION,
            policy_version=self._bundle.policy.version,
            objective_version=self._bundle.policy.objective_version,
            cascade_feasible=False,
            cascade_reason=resolution.failure_class.value,
            features={"request_class": ctx.request_class.value},
            features_version="features-fallback-v1",
        )

    def _target(
        self,
        ctx: RequestContext,
        gate: GateOutcomeLike,
        plan: DispatchPlanLike,
        resolution: FailureResolution | None,
    ) -> tuple[Rung, bool]:
        """Effective destination and whether the original bytes are forwarded."""
        pinned = self._enforcing and gate.pinned
        if resolution is not None:
            if resolution.action is FallbackAction.FORWARD_LOCAL:
                return Rung.LOCAL, False
            return Rung.FRONTIER, True
        if self._settings.routing_mode is RoutingMode.LIVE:
            rung = plan.rung
            suppressed = bool(getattr(plan, "thinking_suppressed", False))
            original = rung is Rung.FRONTIER and not plan.escalated and not suppressed
            return rung, original
        if pinned:
            return Rung.LOCAL, False
        return Rung.FRONTIER, True

    def _body_for(
        self,
        ctx: RequestContext,
        plan: DispatchPlanLike,
        rung: Rung,
        forward_original: bool,
        deployment: DeploymentInfo | None = None,
    ) -> bytes:
        if forward_original:
            return ctx.body
        body: dict[str, Any] = dict(ctx.json)
        if plan.escalated and self._transform is not None:
            body = self._transform(body, plan.pair_rule, plan.handoff)
        alias = (
            deployment.deployment_id
            if deployment is not None
            else self._bundle.rungs.alias_for(rung)
        )
        return self._profile.serialize(
            body,
            rung=rung,
            alias=alias,
            bundle=self._bundle,
            suppress_thinking=bool(getattr(plan, "thinking_suppressed", False)),
        )

    async def _record_egress(
        self,
        ctx: RequestContext,
        gate: GateOutcomeLike,
        rung: Rung | None,
        bytes_out: int,
        *,
        kind: str = "forward",
        deployment: DeploymentInfo | None = None,
        receipt_source: str | None = None,
    ) -> bool | None:
        """Write-ahead egress record. Returns degraded flag, or None when a pinned append failed."""
        if self._egress is None:
            return False
        findings: tuple[Finding, ...] = tuple(gate.findings)
        tier = findings[0].tier.value if findings else None
        try:
            self._egress.append(
                EgressEvent(
                    lineage_hmac=ctx.lineage_hmac,
                    request_class=ctx.request_class.value,
                    content_bearing=ctx.content_bearing,
                    destination_rung=rung.value if rung is not None else None,
                    deployment_tag=self._settings.deployment_tag,
                    gate_verdicts=[v.as_record() for v in gate.verdicts],
                    detector_tier=tier,
                    span_hashes=[f.span_hash for f in findings],
                    bytes_out=bytes_out,
                    actor="adrl",
                    reason=None,
                    event_kind=kind,
                    **egress_fields(deployment, receipt_source or "intended"),
                )
            )
        except LedgerAppendFailure as exc:
            if self._enforcing and gate.pinned:
                log.error("egress_append_failed_pinned", error=str(exc))
                return None
            LEDGER_DEGRADED_TOTAL.inc()
            log.warning("egress_append_failed_unpinned", error=str(exc))
            return True
        return False

    async def _record_receipt(self, turn: _Turn, obs: ResponseObservation) -> None:
        """Append the actual destination as a content-free egress row (ADRL-SAF-009).

        This row, not the write-ahead ``forward`` row, is what the audit trusts. A missing
        receipt is recorded as ``assumed_intended`` so the audit can say "unconfirmed".
        """
        if self._egress is None:
            return
        served = obs.served
        deployment = self._deployments.catalog.get(served.deployment_id or "")
        if (
            self._claude_experiment is None
            and deployment is None
            and turn.deployment is not None
            and served.deployment_id is None
        ):
            deployment = turn.deployment
        fields = egress_fields(deployment, served.source.value)
        if served.deployment_id is None and served.api_base_host is not None:
            fields["api_base_host"] = served.api_base_host
        try:
            self._egress.append(
                EgressEvent(
                    lineage_hmac=turn.ctx.lineage_hmac,
                    request_class=turn.ctx.request_class.value,
                    content_bearing=turn.ctx.content_bearing,
                    destination_rung=served.rung.value,
                    deployment_tag=self._settings.deployment_tag,
                    gate_verdicts=[{"status": obs.status, "intended_rung": turn.target_rung.value}],
                    bytes_out=obs.bytes_relayed,
                    actor="gateway",
                    reason=None,
                    event_kind="served_receipt",
                    **fields,
                )
            )
        except LedgerAppendFailure as exc:
            LEDGER_DEGRADED_TOTAL.inc()
            log.error("egress_receipt_append_failed", error=str(exc))

    async def _blocked(
        self, ctx: RequestContext, gate: GateOutcomeLike, code: ErrorCode
    ) -> ProxyResponse:
        detector = gate.findings[0].detector_id if gate.findings else None
        if detector is None and gate.pinned:
            pins = await self._ledger.read_lineage_events(ctx.lineage_hmac, PIN_EVENT)
            if pins:
                detector = str(pins[-1].payload.get("detector_id") or "") or None
        executed_tool = self._profile.executed_tool(ctx)
        await self._record_egress(ctx, gate, None, 0, kind="block")
        await self._ledger.append_lineage_event(
            LineageEvent(
                lineage_hmac=ctx.lineage_hmac,
                event_type="block",
                payload={"code": code.value, "request_class": ctx.request_class.value},
            )
        )
        rendered = getattr(gate, "block_response", None)
        if rendered is not None and getattr(rendered, "code", None) is code:
            return ProxyResponse(
                status=int(rendered.status),
                headers={**JSON_HEADERS, **dict(getattr(rendered, "headers", {}) or {})},
                body=(
                    rendered.bytes
                    if isinstance(getattr(rendered, "bytes", None), bytes)
                    else json.dumps(rendered.body).encode("utf-8")
                ),
            )
        return self._error_response(
            code, block_message(code, detector=detector, executed_tool=executed_tool)
        )

    async def _count_tokens_locally(
        self, ctx: RequestContext, gate: GateOutcomeLike
    ) -> ProxyResponse:
        """A pinned lineage's count_tokens body never leaves the machine (ADRL-SEM-001)."""
        feasibility = getattr(self._gate, "feasibility", None)
        estimate_fn = getattr(feasibility, "estimate_count_tokens", None)
        if callable(estimate_fn):
            estimate = int(estimate_fn(ctx.json)["input_tokens"])
            await self._record_egress(ctx, gate, Rung.LOCAL, 0, kind="count_tokens_local")
            return self._protocol_response(self._profile.count_tokens_response(max(1, estimate)))
        estimate = self._profile.estimate_count_tokens(
            ctx, self._tokenizer, ratio=self._bundle.rungs.rungs[Rung.LOCAL].tokenizer_ratio
        )
        await self._record_egress(ctx, gate, Rung.LOCAL, 0, kind="count_tokens_local")
        return self._protocol_response(self._profile.count_tokens_response(estimate))

    async def _forward_non_api(self, parsed: RequestView) -> ProxyResponse:
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        try:
            response = await self._gateway.forward(
                parsed.method, path, forward_headers(parsed.headers), parsed.body
            )
        except UpstreamUnreachableError as exc:
            return self._error_response(ErrorCode.TERMINAL_FAILURE, str(exc))
        raw = await read_all(response)
        return ProxyResponse(
            status=response.status_code, headers=response_headers(response.headers), body=raw
        )

    def _decision_context(
        self, ctx: RequestContext, gate: GateOutcomeLike, state_loss: bool
    ) -> dict[str, Any]:
        return {
            "session_hmac": ctx.session_hmac,
            "lineage_hmac": ctx.lineage_hmac,
            "request_class": ctx.request_class.value,
            "content_bearing": ctx.content_bearing,
            "interaction_mode": ctx.interaction_mode.value,
            "requested_model": ctx.requested_model,
            "is_subagent": ctx.is_subagent,
            "session_key_source": ctx.session_key_source,
            "fingerprint_id": ctx.fingerprint_id,
            "pinned": gate.pinned,
            "unscanned": gate.unscanned,
            "gate_verdicts": [v.as_record() for v in gate.verdicts],
            "repo_class": gate.repo_class,
            "residency": gate.residency,
            "permitted_deployment_ids": _deployment_ids(gate),
            "state_loss": state_loss,
            "routing_mode": self._settings.routing_mode.value,
            "gate_mode": self._settings.gate_mode.value,
            "config_versions": self._bundle.versions,
            "protocol_profile_id": ctx.protocol_profile_id,
            "protocol_profile_version": ctx.protocol_profile_version,
            "harness_adapter_id": ctx.harness_adapter_id,
            "harness_adapter_version": ctx.harness_adapter_version,
            "protocol_operation_supported": ctx.path in self._profile.endpoints,
        }

    async def _append_event(
        self, ctx: RequestContext, route_id: str, event_type: str, payload: Mapping[str, Any]
    ) -> None:
        producer_seq = await self._seq.next(self._ledger, route_id)
        stored = await self._ledger.append_event(
            LedgerEvent(
                route_id=RouteId(route_id),
                event_type=event_type,
                producer=PRODUCER,
                producer_seq=producer_seq,
                payload=payload,
            )
        )
        if not stored:
            EVENT_DROPPED_TOTAL.labels(producer=PRODUCER).inc()
            log.warning(
                "event_dropped",
                route_id=route_id,
                event_type=event_type,
                producer_seq=producer_seq,
                degraded=self._ledger.degraded,
            )

    def _write_behind(
        self, ctx: RequestContext, route_id: str, event_type: str, payload: Mapping[str, Any]
    ) -> None:
        task = asyncio.create_task(self._append_event(ctx, route_id, event_type, payload))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    @staticmethod
    def _protocol_response(
        response: ProtocolResponse, route_id: str | None = None
    ) -> ProxyResponse:
        return ProxyResponse(
            status=response.status,
            headers=dict(response.headers),
            body=response.body,
            route_id=route_id,
        )

    def _error_response(
        self, code: ErrorCode, detail: str, route_id: str | None = None
    ) -> ProxyResponse:
        return self._protocol_response(self._profile.error(code, detail), route_id)


class _PinnedOverlay:
    """A gate outcome re-read as pinned because an ancestor lineage is pinned (ADRL-SEM-006)."""

    def __init__(self, inner: GateOutcomeLike) -> None:
        self._inner = inner
        self.permitted: PermittedSet = inner.permitted.tighten({Rung.LOCAL} & inner.permitted.rungs)
        self.verdicts: tuple[GateVerdict, ...] = (
            *inner.verdicts,
            GateVerdict(
                gate="inherited_pin",
                permitted_after=self.permitted,
                reason="ancestor lineage pinned",
                pinned=True,
            ),
        )
        self.pinned = True
        self.unscanned = inner.unscanned
        self.findings = inner.findings
        self.block = inner.block
        self.repo_class = inner.repo_class
        self.residency = inner.residency
        self.latency_s = inner.latency_s
        inherited = getattr(inner, "permitted_deployments", None)
        self.permitted_deployments: DeploymentSet | None = (
            inherited.local_host_only() if inherited is not None else None
        )


@dataclass(frozen=True, slots=True)
class _FallbackPlan:
    rung: Rung
    is_boundary: bool
    escalated: bool
    from_rung: Rung | None
    handoff: Any
    pair_rule: Any
    block: ErrorCode | None
    sticky: StickyState

    @classmethod
    def for_decision(
        cls,
        ctx: RequestContext,
        decision: Decision,
        sticky: StickyState | None,
        *,
        is_boundary: bool,
    ) -> _FallbackPlan:
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
            state_loss=sticky is None,
        )
        return cls(
            rung=decision.rung,
            is_boundary=is_boundary,
            escalated=False,
            from_rung=None,
            handoff=None,
            pair_rule=None,
            block=None,
            sticky=state,
        )


def _deployment_ids(gate: GateOutcomeLike) -> list[str] | None:
    deployments = getattr(gate, "permitted_deployments", None)
    return deployments.as_list() if deployments is not None else None


def _with_deployment(
    plan: DispatchPlanLike, deployment: DeploymentInfo | None, forward_original: bool
) -> DispatchPlanLike:
    """Record the chosen deployment on the plan when the plan type carries the fields."""
    candidate: Any = plan
    if deployment is None or not dataclasses.is_dataclass(candidate):
        return plan
    names = {f.name for f in dataclasses.fields(candidate)}
    if "deployment_id" not in names:
        return plan
    alias = None if forward_original else deployment.deployment_id
    replace_fn: Any = dataclasses.replace
    replaced: Any = replace_fn(candidate, deployment_id=deployment.deployment_id, model_alias=alias)
    return replaced  # type: ignore[no-any-return]
