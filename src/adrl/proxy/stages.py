"""Stage protocols the pipeline composes. Primary: ADRL-FND-002.

Secondary: ADRL-SAF-001 (gate stage), ADRL-RTG-002 (route stage), ADRL-CAS-005 (cascade stage).
Structural protocols so the proxy is testable before the gates, routing and cascade packages
exist; each package's real class satisfies its protocol.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from adrl.core.enums import Rung
from adrl.core.errors import ErrorCode
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
from adrl.wire.observe import ResponseObservation


@runtime_checkable
class GateOutcomeLike(Protocol):
    @property
    def permitted(self) -> PermittedSet: ...

    @property
    def verdicts(self) -> tuple[GateVerdict, ...]: ...

    @property
    def pinned(self) -> bool: ...

    @property
    def unscanned(self) -> bool: ...

    @property
    def findings(self) -> tuple[Finding, ...]: ...

    @property
    def block(self) -> ErrorCode | None: ...

    @property
    def repo_class(self) -> str | None: ...

    @property
    def residency(self) -> str | None: ...

    @property
    def latency_s(self) -> float: ...

    @property
    def permitted_deployments(self) -> DeploymentSet | None: ...


@runtime_checkable
class GateStage(Protocol):
    async def evaluate(self, ctx: RequestContext) -> GateOutcomeLike: ...


@runtime_checkable
class RouteStage(Protocol):
    async def decide(
        self, ctx: RequestContext, gate: GateOutcomeLike, sticky: StickyState | None
    ) -> Decision: ...


@runtime_checkable
class DispatchPlanLike(Protocol):
    @property
    def rung(self) -> Rung: ...

    @property
    def is_boundary(self) -> bool: ...

    @property
    def escalated(self) -> bool: ...

    @property
    def from_rung(self) -> Rung | None: ...

    @property
    def handoff(self) -> HandoffNote | None: ...

    @property
    def pair_rule(self) -> Any: ...

    @property
    def block(self) -> ErrorCode | None: ...

    @property
    def sticky(self) -> StickyState: ...


@runtime_checkable
class CascadeEventsLike(Protocol):
    @property
    def fired_wires(self) -> Sequence[str]: ...

    @property
    def outcome_events(self) -> Sequence[Any]: ...

    @property
    def sticky(self) -> StickyState | None: ...


@runtime_checkable
class CascadeStage(Protocol):
    async def plan(
        self,
        ctx: RequestContext,
        decision: Decision,
        gate: GateOutcomeLike,
        sticky: StickyState | None,
    ) -> DispatchPlanLike: ...

    async def observe(
        self, ctx: RequestContext, plan: DispatchPlanLike, obs: ResponseObservation
    ) -> CascadeEventsLike: ...


@runtime_checkable
class TranscriptTransform(Protocol):
    """cascade.handoff.transform_transcript signature (ADRL-CAS-004)."""

    def __call__(
        self, body: dict[str, Any], rule: Any, note: HandoffNote | None
    ) -> dict[str, Any]: ...
