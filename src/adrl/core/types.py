"""Value objects shared across packages. Primary: ADRL-SEM-001.
Also implements: ADRL-TRU-002 (register additions of 2026-09-03).

Secondary: ADRL-SAF-001, ADRL-RTG-002, ADRL-CAS-004, ADRL-CAS-006, ADRL-RTG-009.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from adrl.core.enums import (
    DetectorTier,
    InteractionMode,
    RequestClass,
    Rung,
    ServedSource,
    SideEffectClass,
    UtilityKind,
    VerificationResult,
)
from adrl.core.errors import PermittedSetWidened
from adrl.core.ids import LineageId, RouteId, SessionId

HANDOFF_NOTE_SCHEMA_VERSION = "handoff-note-v1"
HANDOFF_NOTE_DELIMITER = "<<<ADRL-HANDOFF-NOTE-V1>>>"


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Everything the pipeline knows about one inbound request after classification."""

    body: bytes
    json: Mapping[str, Any]
    headers: Mapping[str, str]
    path: str
    request_class: RequestClass
    content_bearing: bool
    interaction_mode: InteractionMode
    session_hmac: SessionId
    lineage_hmac: LineageId
    requested_model: str
    is_stream: bool
    max_tokens: int | None
    agent_id: str | None = None
    parent_agent_id: str | None = None
    utility_kind: UtilityKind | None = None
    session_key_source: str = "header"
    fingerprint_id: str | None = None
    protocol_profile_id: str | None = None
    protocol_profile_version: str | None = None
    harness_adapter_id: str | None = None
    harness_adapter_version: str | None = None

    @property
    def is_subagent(self) -> bool:
        return self.agent_id is not None


@dataclass(frozen=True, slots=True)
class PermittedSet:
    """A set of permitted rungs that can only shrink (ADRL-SAF-001)."""

    rungs: frozenset[Rung]

    @classmethod
    def all(cls) -> PermittedSet:
        return cls(frozenset(Rung))

    @classmethod
    def only(cls, *rungs: Rung) -> PermittedSet:
        return cls(frozenset(rungs))

    @classmethod
    def local_only(cls) -> PermittedSet:
        return cls(frozenset({Rung.LOCAL}))

    def tighten(self, allowed: Iterable[Rung]) -> PermittedSet:
        """Return the intersection; raise if the caller tried to add a rung."""
        proposed = frozenset(allowed)
        widened = proposed - self.rungs
        if widened:
            raise PermittedSetWidened(
                "permitted set may only tighten; attempted to add "
                + ",".join(sorted(r.value for r in widened))
            )
        return PermittedSet(self.rungs & proposed)

    def remove(self, *rungs: Rung) -> PermittedSet:
        return PermittedSet(self.rungs - frozenset(rungs))

    @property
    def is_empty(self) -> bool:
        return not self.rungs

    @property
    def highest(self) -> Rung | None:
        return max(self.rungs) if self.rungs else None

    @property
    def lowest(self) -> Rung | None:
        return min(self.rungs) if self.rungs else None

    def __contains__(self, rung: object) -> bool:
        return rung in self.rungs

    def __iter__(self) -> Any:
        return iter(sorted(self.rungs))

    def as_list(self) -> list[str]:
        return [r.value for r in sorted(self.rungs)]


@dataclass(frozen=True, slots=True)
class DeploymentInfo:
    """One attested gateway deployment (ADRL-SAF-008 residency, ADRL-FND-002 rung-closed)."""

    deployment_id: str
    rung: Rung
    model_group: str
    provider: str
    trust_zone: str
    geo: str
    api_base_host: str | None = None
    data_use_profile: str | None = None
    model: str | None = None

    @property
    def is_local_host(self) -> bool:
        return self.trust_zone == LOCAL_HOST_ZONE


LOCAL_HOST_ZONE = "local_host"


@dataclass(frozen=True, slots=True)
class DeploymentSet:
    """Permitted deployments, the object ADRL actually constrains; it can only shrink.

    A rung label is a projection of this set (``rungs()``); the pin, the repository ceiling
    and residency all act here, on attested deployments, never on labels (ADRL-SAF-001,
    ADRL-SAF-008).
    """

    ids: frozenset[str]
    catalog: Mapping[str, DeploymentInfo]

    @classmethod
    def all_of(cls, catalog: Mapping[str, DeploymentInfo]) -> DeploymentSet:
        return cls(frozenset(catalog), dict(catalog))

    def _keep(self, keep: Iterable[str]) -> DeploymentSet:
        return DeploymentSet(self.ids & frozenset(keep), self.catalog)

    def tighten(self, allowed: Iterable[str]) -> DeploymentSet:
        proposed = frozenset(allowed)
        widened = proposed - self.ids
        if widened:
            raise PermittedSetWidened(
                "deployment set may only tighten; attempted to add " + ",".join(sorted(widened))
            )
        return self._keep(proposed)

    def only_rungs(self, rungs: Iterable[Rung]) -> DeploymentSet:
        wanted = frozenset(rungs)
        return self._keep(i for i in self.ids if self.catalog[i].rung in wanted)

    def only_trust_zone(self, *zones: str) -> DeploymentSet:
        return self._keep(i for i in self.ids if self.catalog[i].trust_zone in zones)

    def only_geo(self, geo: str, *, keep_local_host: bool = True) -> DeploymentSet:
        """Residency: keep deployments in ``geo``; the local host never leaves the machine."""
        return self._keep(
            i
            for i in self.ids
            if self.catalog[i].geo == geo or (keep_local_host and self.catalog[i].is_local_host)
        )

    def local_host_only(self) -> DeploymentSet:
        return self.only_trust_zone(LOCAL_HOST_ZONE)

    def rungs(self) -> frozenset[Rung]:
        return frozenset(self.catalog[i].rung for i in self.ids)

    def to_permitted(self) -> PermittedSet:
        return PermittedSet(self.rungs())

    def for_rung(self, rung: Rung) -> tuple[DeploymentInfo, ...]:
        return tuple(
            sorted(
                (self.catalog[i] for i in self.ids if self.catalog[i].rung is rung),
                key=lambda d: d.deployment_id,
            )
        )

    def get(self, deployment_id: str) -> DeploymentInfo | None:
        return self.catalog.get(deployment_id) if deployment_id in self.ids else None

    @property
    def is_empty(self) -> bool:
        return not self.ids

    def __contains__(self, deployment_id: object) -> bool:
        return deployment_id in self.ids

    def as_list(self) -> list[str]:
        return sorted(self.ids)


@dataclass(frozen=True, slots=True)
class Finding:
    """One detector finding (ADRL-SAF-003). Content-free: only a span hash is kept."""

    detector_id: str
    tier: DetectorTier
    span_hash: str
    finding_id: str
    content_type: str
    corroboration: str | None = None
    shadow: bool = False

    @property
    def pins(self) -> bool:
        return not self.shadow


@dataclass(frozen=True, slots=True)
class GateVerdict:
    """Output of one gate stage (ADRL-SAF-001)."""

    gate: str
    permitted_after: PermittedSet
    findings: tuple[Finding, ...] = ()
    unscanned: bool = False
    reason: str | None = None
    pinned: bool = False

    def as_record(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "permitted_after": self.permitted_after.as_list(),
            "findings": [f.finding_id for f in self.findings],
            "unscanned": self.unscanned,
            "reason": self.reason,
            "pinned": self.pinned,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """One routing decision row (ADRL-RTG-002, ADRL-LRN-004, ADRL-LRN-008)."""

    route_id: RouteId
    rung: Rung
    permitted: PermittedSet
    estimator: str
    estimator_version: str
    policy_version: str
    objective_version: str
    cascade_feasible: bool
    cascade_reason: str | None
    features: Mapping[str, Any]
    features_version: str
    propensity: float = 1.0
    explore_version: str | None = None
    no_rung_met_threshold: bool = False
    classifier_provenance: Mapping[str, Any] | None = None

    def as_row(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "decided_rung": self.rung.value,
            "permitted_set": self.permitted.as_list(),
            "estimator": self.estimator,
            "estimator_version": self.estimator_version,
            "policy_version": self.policy_version,
            "objective_version": self.objective_version,
            "cascade_feasible": self.cascade_feasible,
            "cascade_reason": self.cascade_reason,
            "features": dict(self.features),
            "features_version": self.features_version,
            "propensity": self.propensity,
            "explore_version": self.explore_version,
            "no_rung_met_threshold": self.no_rung_met_threshold,
            "classifier_provenance": (
                dict(self.classifier_provenance) if self.classifier_provenance else None
            ),
        }


@dataclass(frozen=True, slots=True)
class ServedIdentity:
    """Served rung, model and provider with provenance (ADRL-CAS-006, ADRL-RTG-008)."""

    rung: Rung
    model: str | None
    provider: str | None
    source: ServedSource
    deployment_id: str | None = None
    api_base_host: str | None = None
    trust_zone: str | None = None
    geo: str | None = None

    @classmethod
    def assumed(
        cls, rung: Rung, requested_model: str, deployment: DeploymentInfo | None = None
    ) -> ServedIdentity:
        return cls(
            rung=rung,
            model=requested_model,
            provider=deployment.provider if deployment else None,
            source=ServedSource.ASSUMED_INTENDED,
            deployment_id=deployment.deployment_id if deployment else None,
            api_base_host=deployment.api_base_host if deployment else None,
            trust_zone=deployment.trust_zone if deployment else None,
            geo=deployment.geo if deployment else None,
        )

    @property
    def receipt_confirmed(self) -> bool:
        """True only when the gateway itself reported the deployment it served."""
        return self.source is ServedSource.GATEWAY_REPORTED and self.deployment_id is not None


@dataclass(frozen=True, slots=True)
class Usage:
    """Token usage including cache fields (ADRL-RTG-009)."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    @classmethod
    def from_anthropic(cls, usage: Mapping[str, Any] | None) -> Usage:
        if not usage:
            return cls()
        return cls(
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            cache_read_input_tokens=int(usage.get("cache_read_input_tokens") or 0),
            cache_creation_input_tokens=int(usage.get("cache_creation_input_tokens") or 0),
        )

    def merged(self, other: Usage) -> Usage:
        """Combine message_start usage with message_delta usage (later values win when set)."""
        return Usage(
            input_tokens=other.input_tokens or self.input_tokens,
            output_tokens=other.output_tokens or self.output_tokens,
            cache_read_input_tokens=other.cache_read_input_tokens or self.cache_read_input_tokens,
            cache_creation_input_tokens=(
                other.cache_creation_input_tokens or self.cache_creation_input_tokens
            ),
        )


@dataclass(frozen=True, slots=True)
class SideEffectRecord:
    """One executed side-effecting tool call since turn start (ADRL-CAS-003)."""

    tool: str
    target: str
    status: str
    side_effect_class: SideEffectClass


@dataclass(frozen=True, slots=True)
class HandoffNote:
    """Mechanical handoff note, schema v1 (ADRL-CAS-004).

    Generated from ledger fields only. No free text and no model-generated field.
    """

    cause: str
    from_rung: Rung
    to_rung: Rung
    executed_side_effects: tuple[SideEffectRecord, ...] = ()
    verifier_result: VerificationResult | None = None
    schema_version: str = HANDOFF_NOTE_SCHEMA_VERSION

    def render(self) -> str:
        lines = [
            HANDOFF_NOTE_DELIMITER,
            f"schema: {self.schema_version}",
            f"cause: {self.cause}",
            f"from_rung: {self.from_rung.value}",
            f"to_rung: {self.to_rung.value}",
            f"executed_side_effects: {len(self.executed_side_effects)}",
        ]
        for record in self.executed_side_effects:
            lines.append(
                f"- tool={record.tool} target={record.target} status={record.status} "
                f"class={record.side_effect_class.value}"
            )
        if self.verifier_result is not None:
            lines.append(f"verifier_result: {self.verifier_result.value}")
        lines.append(HANDOFF_NOTE_DELIMITER)
        return "\n".join(lines)

    def as_content_block(self) -> dict[str, str]:
        return {"type": "text", "text": self.render()}


@dataclass(frozen=True, slots=True)
class LedgerEvent:
    """One append-only event (ADRL-MEM-001)."""

    route_id: RouteId
    event_type: str
    producer: str
    producer_seq: int
    payload: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = "events-v1"


def left_machine(trust_zone: str | None, destination_rung: str | None) -> bool | None:
    """Truth for the egress audit (ADRL-TRU-002): the recorded trust zone, never the label.

    Returns None when neither a trust zone nor a rung was recorded (legacy rows).
    """
    if trust_zone is not None:
        return trust_zone != LOCAL_HOST_ZONE
    if destination_rung is not None:
        return destination_rung != "local"
    return None
