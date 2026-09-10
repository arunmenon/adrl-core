"""Ordered hard gates on every request. Primary: ADRL-SAF-001.
Also implements: ADRL-OPS-005 (register additions of 2026-09-03).

Secondary: ADRL-SAF-002, ADRL-SAF-003, ADRL-SAF-005, ADRL-SAF-006, ADRL-SAF-008, ADRL-SAF-009,
ADRL-FND-004. Order: repository ceiling, new-content secret scan, feasibility. Each stage only
tightens the permitted set. A gate exception on a pinned lineage is fail-closed; on an unpinned
lineage the request is marked `unscanned` and continues with the set unchanged. The egress verdict
is written before the outcome is returned. Routing chooses only inside the returned set.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

import structlog

from adrl.config.loaders import ConfigBundle
from adrl.config.settings import Settings
from adrl.core.enums import DetectorTier, FailureClass, GateMode, RequestClass, Rung, UtilityKind
from adrl.core.errors import ErrorCode, GateFailure, LedgerAppendFailure
from adrl.core.ports import ContentBlock, EgressLedgerPort, LineageEvent, SecretScanner
from adrl.core.types import DeploymentSet, Finding, GateVerdict, PermittedSet, RequestContext
from adrl.gates import block as blocks_mod
from adrl.gates.block import BlockResponse
from adrl.gates.content import ScanBlock, extract_blocks
from adrl.gates.coverage import ScanCoverage
from adrl.gates.deployments import DeploymentPolicy
from adrl.gates.detectors import load_detectors
from adrl.gates.egress import EgressWriter
from adrl.gates.feasibility import (
    FeasibilityFilter,
    FeasibilityVerdict,
    GatewayHealth,
    StaticHealth,
    tokenizer_for_rung,
)
from adrl.gates.pin import PinRecord, PinRegistry
from adrl.gates.repo_class import RepoClassification, RepoClassifier
from adrl.gates.secrets import TieredSecretScanner
from adrl.gates.suppression import SuppressionSink
from adrl.gates.workload import ASSERTIONS_DIR, AssertionVerifier
from adrl.ledger.facade import MemoryFacade
from adrl.telemetry.metrics import FAIL_OPEN_TOTAL, GATE_LATENCY_SECONDS, UNSCANNED_TOTAL

log = structlog.get_logger(__name__)

GATE_REPO = "repo_class"


def _narrow(permitted: PermittedSet, allowed: Iterable[Rung]) -> PermittedSet:
    """Intersect; tighten() raises on widening, so callers always pass the intersection."""
    return permitted.tighten(permitted.rungs & frozenset(allowed))


GATE_SECRETS = "secret_scan"
GATE_FEASIBILITY = "feasibility"
FAIL_OPEN_EVENT = "fail_open"
PIN_WRITE_FAILED_REASON = "pin_write_failed"


@dataclass(frozen=True, slots=True)
class GateOutcome:
    """Result of the gate stage for one request."""

    permitted: PermittedSet
    verdicts: tuple[GateVerdict, ...]
    pinned: bool
    unscanned: bool
    findings: tuple[Finding, ...]
    block: ErrorCode | None
    repo_class: str | None
    residency: str | None
    latency_s: float
    would_block: ErrorCode | None = None
    block_response: BlockResponse | None = None
    pin_record: PinRecord | None = None
    release_permitted: bool = True
    feasibility: FeasibilityVerdict | None = None
    ledger_degraded: bool = False
    mode: GateMode = GateMode.ENFORCE
    serve_local_estimate: bool = False
    serve_empty_utility: bool = False
    permitted_deployments: DeploymentSet | None = None
    """Attested deployments this request may reach (ADRL-SAF-008); rungs are a projection."""
    would_pin: bool = False
    """Observe mode: a pinning finding was recorded as a shadow finding, nothing was pinned."""
    shadow_findings: tuple[Finding, ...] = ()

    @property
    def is_blocked(self) -> bool:
        return self.block is not None

    def summary(self) -> list[dict[str, Any]]:
        return [v.as_record() for v in self.verdicts]


class GatePipeline:
    def __init__(
        self,
        *,
        classifier: RepoClassifier,
        scanner: SecretScanner,
        coverage: ScanCoverage,
        pins: PinRegistry,
        feasibility: FeasibilityFilter,
        egress: EgressWriter,
        hmac_key: bytes,
        mode: GateMode = GateMode.ENFORCE,
        p99_budget_s: float = 0.05,
        deployments: DeploymentPolicy | None = None,
    ) -> None:
        self._deployments = deployments
        self._classifier = classifier
        self._scanner = scanner
        self._coverage = coverage
        self._pins = pins
        self._feasibility = feasibility
        self._egress = egress
        self._hmac_key = hmac_key
        self._mode = mode
        self._p99_budget_s = p99_budget_s
        self.latency_samples: list[float] = []

    @classmethod
    def from_components(
        cls,
        *,
        bundle: ConfigBundle,
        settings: Settings,
        ledger: MemoryFacade,
        egress: EgressLedgerPort,
        hmac_key: bytes,
        suppression: SuppressionSink | None = None,
        health: GatewayHealth | None = None,
        state: Any | None = None,
    ) -> GatePipeline:
        """Build every gate from config and settings with real adapters (composition root)."""
        detectors = load_detectors(settings.resolved_config_path("detectors.yaml"))
        scanner = TieredSecretScanner(detectors, span_key=hmac_key)
        tokenizers = {
            rung: tokenizer_for_rung(
                spec.tokenizer_id,
                settings.local_tokenizer_path if rung is Rung.LOCAL else None,
            )
            for rung, spec in bundle.rungs.rungs.items()
        }
        feasibility = FeasibilityFilter(
            bundle.rungs,
            tokenizers,
            health or StaticHealth(),
            safety_margin_tokens=bundle.policy.cascade_safety_margin_tokens,
        )
        pins = PinRegistry(
            ledger, egress, deployment_tag=settings.deployment_tag, suppression=suppression
        )
        if suppression is None:
            log.warning("pin_suppression_logging_only", detail="no erasure service injected")
        return cls(
            classifier=RepoClassifier(
                bundle.repo_classification,
                ledger,
                assertions=AssertionVerifier(hmac_key, settings.keystore_path / ASSERTIONS_DIR),
                path_secret=hmac_key,
            ),
            scanner=scanner,
            coverage=ScanCoverage(ledger),
            pins=pins,
            feasibility=feasibility,
            egress=EgressWriter(egress, deployment_tag=settings.deployment_tag),
            deployments=DeploymentPolicy(bundle.endpoint_inventory),
            hmac_key=hmac_key,
            mode=settings.gate_mode,
            p99_budget_s=settings.gate_p99_budget_s,
        )

    @property
    def feasibility(self) -> FeasibilityFilter:
        return self._feasibility

    @property
    def mode(self) -> GateMode:
        return self._mode

    @property
    def pins(self) -> PinRegistry:
        return self._pins

    # ---------------------------------------------------------------------------------------

    async def evaluate(self, ctx: RequestContext) -> GateOutcome:
        """Run the rung gates, then project the result onto attested deployments."""
        outcome = await self._evaluate_rungs(ctx)
        if self._deployments is None:
            return outcome
        deployments = self._deployments.permitted_for(
            permitted_rungs=outcome.permitted.rungs,
            pinned=outcome.pinned,
            residency=outcome.residency,
        )
        return dataclasses.replace(outcome, permitted_deployments=deployments)

    @property
    def deployments(self) -> DeploymentPolicy | None:
        return self._deployments

    async def _evaluate_rungs(self, ctx: RequestContext) -> GateOutcome:
        started = time.perf_counter()
        verdicts: list[GateVerdict] = []
        findings: list[Finding] = []
        unscanned = False
        permitted = PermittedSet.all()
        block: BlockResponse | None = None
        classification: RepoClassification | None = None
        feasibility: FeasibilityVerdict | None = None
        pin_record: PinRecord | None = None
        would_pin = False
        shadow_findings: list[Finding] = []

        # pin state before anything else: it decides the failure semantics of every gate
        try:
            pin_record = await self._pins.effective_pin(ctx)
        except Exception as exc:
            log.error("pin_lookup_failed", error=type(exc).__name__)
            pin_record = PinRecord(ctx.lineage_hmac, "unknown", "ledger_unavailable", "")
        pinned = pin_record is not None
        pinned_before = pinned
        if pinned:
            permitted = _narrow(permitted, [Rung.LOCAL])

        all_blocks = extract_blocks(ctx.json, self._hmac_key)

        # gate a: repository and data class ceiling (ADRL-SAF-008)
        try:
            classification = await self._classifier.classify(ctx, all_blocks)
            permitted = _narrow(permitted, classification.allowed_rungs)
            verdicts.append(
                GateVerdict(
                    GATE_REPO,
                    permitted,
                    reason=f"{classification.class_id}:{classification.source}",
                    pinned=pinned,
                )
            )
        except Exception as exc:
            unscanned, block = await self._gate_failed(
                ctx, GATE_REPO, exc, pinned, permitted, verdicts
            )
            if block is not None:
                return await self._finish(
                    ctx,
                    started,
                    permitted,
                    verdicts,
                    findings,
                    pinned,
                    unscanned,
                    block,
                    classification,
                    feasibility,
                    pin_record,
                )

        # gate b: secret scan on new content (ADRL-SAF-003)
        pinning: list[Finding] = []
        try:
            new_findings, scanned_unscannable = await self._scan_new_content(ctx, all_blocks)
            findings.extend(new_findings)
            if scanned_unscannable:
                unscanned = True
            pinning = [f for f in new_findings if f.pins]
            if pinning and self._mode is GateMode.OBSERVE:
                # observe mode is observational: the finding lands in the shadow namespace,
                # nothing is pinned, narrowed or shredded, and enforce mode later never
                # promotes it on its own (audited promotion only)
                shadow_findings.extend(pinning)
                for finding in pinning:
                    await self._pins.record_shadow(ctx, finding)
                would_pin = True
                pinning = []
            if pinning:
                # the permitted set narrows BEFORE any durable write (ADRL-SAF-002 clause 1):
                # whatever the ledger does next, this request can only go local or be blocked
                pinned = True
                permitted = _narrow(permitted, [Rung.LOCAL])
            verdicts.append(
                GateVerdict(
                    GATE_SECRETS,
                    permitted,
                    findings=tuple(new_findings),
                    reason="shadow_finding" if would_pin else None,
                    unscanned=scanned_unscannable,
                    pinned=pinned,
                )
            )
        except Exception as exc:
            unscanned, block = await self._gate_failed(
                ctx, GATE_SECRETS, exc, pinned, permitted, verdicts
            )
            if block is not None:
                return await self._finish(
                    ctx,
                    started,
                    permitted,
                    verdicts,
                    findings,
                    pinned,
                    unscanned,
                    block,
                    classification,
                    feasibility,
                    pin_record,
                )

        # gate b, durable write: a pinning finding is written through before the request may
        # proceed; a write failure is fail-closed, never `unscanned` (ADRL-SAF-002, FND-004)
        if pinning:
            write_new = not pinned_before or (
                pin_record is not None and pin_record.finding_id != "unknown"
            )
            if write_new:
                try:
                    written = await self._pins.pin(ctx, pinning[0])
                    if pin_record is None:
                        pin_record = written
                except Exception as exc:
                    log.error(
                        "pin_write_failed_fail_closed",
                        error=type(exc).__name__,
                        detector=pinning[0].detector_id,
                    )
                    if pin_record is None:
                        pin_record = PinRecord(
                            ctx.lineage_hmac,
                            pinning[0].finding_id,
                            pinning[0].detector_id,
                            pinning[0].span_hash,
                        )
                    write_reason = f"{PIN_WRITE_FAILED_REASON}:{type(exc).__name__}"
                    verdicts.append(
                        GateVerdict(GATE_SECRETS, permitted, reason=write_reason, pinned=True)
                    )
                    return await self._finish(
                        ctx,
                        started,
                        permitted,
                        verdicts,
                        findings,
                        True,
                        unscanned,
                        blocks_mod.gate_unavailable(ctx, write_reason),
                        classification,
                        feasibility,
                        pin_record,
                    )

        # gate c: feasibility (ADRL-SAF-006)
        try:
            feasibility = await self._feasibility.evaluate(ctx.json, permitted)
            permitted = feasibility.permitted_after
            reason = ",".join(f"{r.value}={why}" for r, why in feasibility.removed.items()) or None
            verdicts.append(GateVerdict(GATE_FEASIBILITY, permitted, reason=reason, pinned=pinned))
        except Exception as exc:
            unscanned, block = await self._gate_failed(
                ctx, GATE_FEASIBILITY, exc, pinned, permitted, verdicts
            )
            if block is not None:
                return await self._finish(
                    ctx,
                    started,
                    permitted,
                    verdicts,
                    findings,
                    pinned,
                    unscanned,
                    block,
                    classification,
                    feasibility,
                    pin_record,
                )

        # empty set resolution (ADRL-SAF-004 / SAF-005)
        if permitted.is_empty:
            block = self._empty_set_block(ctx, pinned, pin_record, classification, feasibility)

        return await self._finish(
            ctx,
            started,
            permitted,
            verdicts,
            findings,
            pinned,
            unscanned,
            block,
            classification,
            feasibility,
            pin_record,
            would_pin=would_pin,
            shadow_findings=shadow_findings,
        )

    # helpers ---------------------------------------------------------------------------------

    async def _scan_new_content(
        self, ctx: RequestContext, all_blocks: Sequence[ScanBlock]
    ) -> tuple[list[Finding], bool]:
        new_blocks = await self._coverage.new_blocks(ctx.lineage_hmac, all_blocks)
        unscannable = any(not b.scannable for b in new_blocks)
        scannable = [b for b in new_blocks if b.scannable and b.text]
        if not scannable:
            await self._coverage.mark_scanned(ctx.lineage_hmac, new_blocks)
            return [], unscannable
        tail = self._coverage.tail(ctx.lineage_hmac)
        content: list[ContentBlock] = []
        for b in scannable:
            # the previous block's tail is prepended to every new block so a token split across
            # two reads is seen whole; findings are de-duplicated by (detector, span hash)
            text = (tail + b.text) if tail else b.text
            content.append(ContentBlock(b.key, b.content_type, text, b.path_hint))
        findings = list(self._scanner.scan(content))
        if tail:
            # The carried tail exists so a high-confidence token split across two reads is seen
            # whole. Two artefacts of the join are discarded: a token that sits entirely inside
            # the tail (already scanned with its own block), and a generic-tier match that only
            # appears once tail and new text are fused (a token that never existed on the wire).
            already = {
                (f.detector_id, f.span_hash)
                for f in self._scanner.scan([ContentBlock("tail", "text", tail, None)])
            }
            fresh_only = {
                (f.detector_id, f.span_hash)
                for f in self._scanner.scan(
                    [ContentBlock(b.key, b.content_type, b.text, b.path_hint) for b in scannable]
                )
            }
            findings = [
                f
                for f in findings
                if (f.detector_id, f.span_hash) not in already
                and (
                    (f.detector_id, f.span_hash) in fresh_only
                    or f.tier is DetectorTier.HIGH_CONFIDENCE
                )
            ]
        await self._coverage.mark_scanned(ctx.lineage_hmac, new_blocks)
        return findings, unscannable

    async def _gate_failed(
        self,
        ctx: RequestContext,
        gate: str,
        exc: Exception,
        pinned: bool,
        permitted: PermittedSet,
        verdicts: list[GateVerdict],
    ) -> tuple[bool, BlockResponse | None]:
        """A gate-internal exception: fail closed when pinned, else fail open marked unscanned.

        Every fail-open is recorded in both ledgers with the real pin state and the same
        payload shape the proxy's FallbackRecorder writes (ADRL-FND-004 clause 2).
        """
        reason = f"{gate}:{type(exc).__name__}"
        log.error("gate_failed", gate=gate, error=type(exc).__name__, pinned=pinned)
        FAIL_OPEN_TOTAL.labels(
            failure_class=FailureClass.GATE_PATH.value, pinned=str(pinned).lower()
        ).inc()
        try:
            self._egress.record_fail_open(ctx, FailureClass.GATE_PATH, reason, pinned=pinned)
        except LedgerAppendFailure:
            pass
        payload = {
            "failure_class": FailureClass.GATE_PATH.value,
            "action": "block" if pinned else "forward_upstream",
            "pinned": pinned,
            "unscanned": not pinned,
            "mode": self._mode.value,
            "exception": type(exc).__name__,
            "gate": gate,
            "request_class": ctx.request_class.value,
        }
        try:
            await self._pins.facade.append_lineage_event(
                LineageEvent(
                    lineage_hmac=ctx.lineage_hmac, event_type=FAIL_OPEN_EVENT, payload=payload
                )
            )
        except Exception as ledger_exc:
            log.error("fail_open_record_failed", error=type(ledger_exc).__name__)
        verdicts.append(GateVerdict(gate, permitted, unscanned=True, reason=reason, pinned=pinned))
        if pinned:
            return True, blocks_mod.gate_unavailable(ctx, reason)
        UNSCANNED_TOTAL.inc()
        return True, None

    def _empty_set_block(
        self,
        ctx: RequestContext,
        pinned: bool,
        pin_record: PinRecord | None,
        classification: RepoClassification | None,
        feasibility: FeasibilityVerdict | None,
    ) -> BlockResponse:
        release_ok = classification.release_permitted if classification else True
        detector = pin_record.detector_id if pin_record else None
        finding = pin_record.finding_id if pin_record else None
        if feasibility is not None and feasibility.removed.get(Rung.LOCAL) == "context_infeasible":
            ceiling = self._feasibility_ceiling()
            executed = None
            if ctx.request_class is RequestClass.CONTINUATION:
                executed = blocks_mod.executed_tool_name(ctx)
            return blocks_mod.prompt_too_long(
                ctx,
                input_estimate=feasibility.estimates_by_rung.get(
                    Rung.LOCAL, feasibility.input_estimate
                ),
                ceiling=ceiling,
                executed_tool=executed,
                release_permitted=release_ok,
            )
        if (
            pinned
            and feasibility is not None
            and feasibility.removed.get(Rung.LOCAL) == "unhealthy"
        ):
            return blocks_mod.pinned_local_unavailable(ctx, detector, release_ok)
        if pinned:
            return blocks_mod.pinned_cloud_denied(ctx, detector, finding, release_ok)
        return blocks_mod.prompt_too_long(
            ctx,
            input_estimate=feasibility.input_estimate if feasibility else 0,
            ceiling=self._feasibility_ceiling(),
            release_permitted=release_ok,
        )

    def _feasibility_ceiling(self) -> int:
        rungs = self._feasibility._rungs
        local = rungs.rungs.get(Rung.LOCAL)
        return local.boundary.context_ceiling if local else 0

    async def _finish(
        self,
        ctx: RequestContext,
        started: float,
        permitted: PermittedSet,
        verdicts: list[GateVerdict],
        findings: list[Finding],
        pinned: bool,
        unscanned: bool,
        block: BlockResponse | None,
        classification: RepoClassification | None,
        feasibility: FeasibilityVerdict | None,
        pin_record: PinRecord | None,
        *,
        would_pin: bool = False,
        shadow_findings: Sequence[Finding] = (),
    ) -> GateOutcome:
        ledger_degraded = False
        block_code = block.code if block else None
        try:
            recorded = self._egress.record_verdict(
                ctx,
                verdicts,
                findings,
                pinned=pinned,
                unscanned=unscanned,
                block_code=block_code.value if block_code else None,
            )
            ledger_degraded = not recorded
        except LedgerAppendFailure:
            block = blocks_mod.egress_ledger_unavailable(ctx)
            block_code = block.code
            permitted = _narrow(permitted, [])

        serve_local_estimate = pinned and ctx.request_class is RequestClass.PASSTHROUGH
        serve_empty_utility = (
            pinned
            and ctx.request_class is RequestClass.UTILITY
            and ctx.utility_kind is UtilityKind.COSMETIC
            and block is not None
        )
        if serve_empty_utility:
            block = None
            block_code = None

        enforce = self._mode is GateMode.ENFORCE
        latency = time.perf_counter() - started
        self.latency_samples.append(latency)
        GATE_LATENCY_SECONDS.labels(request_class=ctx.request_class.value).observe(latency)
        if latency > self._p99_budget_s:
            log.warning("gate_latency_over_budget", latency_s=round(latency, 4))
        outcome = GateOutcome(
            permitted=permitted,
            verdicts=tuple(verdicts),
            pinned=pinned,
            unscanned=unscanned,
            findings=tuple(findings),
            block=block_code if enforce else None,
            repo_class=classification.class_id if classification else None,
            residency=classification.residency if classification else None,
            latency_s=latency,
            would_block=block_code if not enforce else None,
            block_response=block,
            pin_record=pin_record,
            release_permitted=classification.release_permitted if classification else True,
            feasibility=feasibility,
            ledger_degraded=ledger_degraded,
            mode=self._mode,
            serve_local_estimate=serve_local_estimate,
            serve_empty_utility=serve_empty_utility,
            would_pin=would_pin,
            shadow_findings=tuple(shadow_findings),
        )
        log.info(
            "gate_outcome",
            permitted=permitted.as_list(),
            pinned=pinned,
            unscanned=unscanned,
            block=block_code.value if block_code else None,
            latency_ms=round(latency * 1000, 2),
        )
        return outcome

    def p99_latency(self) -> float | None:
        if not self.latency_samples:
            return None
        ordered = sorted(self.latency_samples)
        return ordered[min(len(ordered) - 1, int(0.99 * len(ordered)))]


class GateBlocked(GateFailure):
    """Raised by callers that prefer exceptions to inspecting `GateOutcome.block`."""
