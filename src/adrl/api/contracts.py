"""Versioned product records. Primary: ADRL-SEM-007. Secondary: ADRL-MEM-001, ADRL-TRU-001.

The local product services authenticate signed launcher assertions. Reject unknown fields
rather than accepting
caller-supplied authority or arbitrary content as event metadata.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StringConstraints,
    model_validator,
)

SCHEMA_VERSION: Final = "adrl-api-v1-preview.4"
OpaqueId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")]
SequenceNumber = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]


class IntegrationMode(StrEnum):
    GATEWAY = "gateway"
    OBSERVE = "observe"


class ApiRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class VersionRef(ApiRecord):
    id: OpaqueId
    version: OpaqueId


class ProfileCapability(ApiRecord):
    profile: VersionRef
    endpoints: tuple[str, ...]
    transport: Literal["http"]
    validation: Literal["offline_fixtures", "real_harness"]


class AdapterCapability(ApiRecord):
    adapter: VersionRef
    identity: Literal["correlation_only", "authenticated_binding"]
    tool_events: Literal["not_implemented", "implemented"]
    tested_harness_versions: tuple[str, ...]
    integration_modes: tuple[IntegrationMode, ...] = (
        IntegrationMode.GATEWAY,
        IntegrationMode.OBSERVE,
    )


class Capabilities(ApiRecord):
    schema_version: Literal["adrl-api-v1-preview.4"] = SCHEMA_VERSION
    scope: Literal["distribution"] = "distribution"
    profiles: tuple[ProfileCapability, ...]
    adapters: tuple[AdapterCapability, ...]
    effective_enforcement: Literal["requires_session_and_runtime_checks"]
    unclassified_traffic: Literal["legacy_forwarding_without_profile_guarantees"]
    product_operations: tuple[str, ...]


class SessionRequest(ApiRecord):
    schema_version: Literal["adrl-api-v1-preview.4"] = SCHEMA_VERSION
    adapter: VersionRef
    profile: VersionRef
    workload_ref: OpaqueId
    integration_mode: IntegrationMode = IntegrationMode.GATEWAY
    parent_session_id: OpaqueId | None = None


class CoverageFact(ApiRecord):
    dimension: Literal[
        "request_interception",
        "identity_binding",
        "content_inspection",
        "dispatch_enforcement",
        "tool_events",
        "lineage",
        "served_destination",
        "outcome_verification",
    ]
    status: Literal["enforced", "observed", "unavailable", "unknown"]
    evidence_ref: OpaqueId | None = None


class SessionStatus(ApiRecord):
    schema_version: Literal["adrl-api-v1-preview.4"] = SCHEMA_VERSION
    session_id: OpaqueId
    workload_ref: OpaqueId
    integration_mode: IntegrationMode = IntegrationMode.GATEWAY
    policy: VersionRef
    adapter: VersionRef
    profile: VersionRef
    parent_session_id: OpaqueId | None = None
    coverage: tuple[CoverageFact, ...]


class SessionBinding(ApiRecord):
    session: SessionStatus
    credential_ref: OpaqueId
    expires_at: AwareDatetime


class EventBase(ApiRecord):
    # Existing encrypted envelopes and pending outboxes keep their original version.
    schema_version: Literal[
        "adrl-api-v1-preview.2", "adrl-api-v1-preview.3", "adrl-api-v1-preview.4"
    ] = SCHEMA_VERSION
    event_id: UUID
    session_id: OpaqueId
    route_id: OpaqueId | None = None
    producer_seq: SequenceNumber
    occurred_at: AwareDatetime


class ToolResult(ApiRecord):
    tool_call_ref: OpaqueId
    outcome: Literal["completed", "failed", "cancelled", "unknown"]
    output_ref: OpaqueId | None = None


class ToolEvent(EventBase):
    event_type: Literal["tool.completed"]
    payload: ToolResult


class TaskClosure(ApiRecord):
    task_ref: OpaqueId
    reported_outcome: Literal["accepted", "failed", "abandoned", "unknown"]


class ClosureEvent(EventBase):
    event_type: Literal["session.closed"]
    payload: TaskClosure


class CompactionResult(ApiRecord):
    before_state_ref: OpaqueId
    after_state_ref: OpaqueId


class CompactionEvent(EventBase):
    event_type: Literal["session.compacted"]
    payload: CompactionResult


class VerificationResult(ApiRecord):
    task_ref: OpaqueId
    snapshot_ref: OpaqueId
    verifier: VersionRef
    result: Literal["passed", "failed", "indeterminate"]
    evidence_ref: OpaqueId


class VerificationEvent(EventBase):
    event_type: Literal["verification.completed"]
    payload: VerificationResult


class EventRequest(
    RootModel[
        Annotated[
            ToolEvent | ClosureEvent | CompactionEvent | VerificationEvent,
            Field(discriminator="event_type"),
        ]
    ]
):
    """Producer identity is derived from authentication, never from these claims."""


class EventAcknowledgement(ApiRecord):
    event_id: UUID
    producer_id: OpaqueId
    recorded_at: AwareDatetime
    ledger_sequence: SequenceNumber
    status: Literal["recorded", "duplicate"]
    sequence_status: Literal["next", "gap", "late"]


class ProductError(ApiRecord):
    code: Literal[
        "not_implemented",
        "unauthenticated",
        "forbidden",
        "unsupported_capability",
        "event_conflict",
        "temporarily_unavailable",
        "invalid_request",
    ]
    message: str


class VerifierCheck(ApiRecord):
    name: OpaqueId
    result: Literal["passed", "failed", "indeterminate"]
    command_ref: OpaqueId
    executable_ref: OpaqueId | None = None
    exit_code: int | None = None
    duration_s: float = Field(ge=0, allow_inf_nan=False)
    stdout_ref: OpaqueId | None = None
    stderr_ref: OpaqueId | None = None
    reason: OpaqueId | None = None


class SessionVerification(ApiRecord):
    schema_version: Literal["session-verification-v1"] = "session-verification-v1"
    sandbox_implementation: VersionRef
    job_id: OpaqueId
    task_ref: OpaqueId
    authority: Literal["local_operator_verifier"] = "local_operator_verifier"
    origin: Literal["pilot"] = "pilot"
    eligible_for_learning: Literal[False] = False
    phase: Literal["started", "finished"]
    verifier: VersionRef
    plan_ref: OpaqueId
    source_snapshot_ref: OpaqueId | None = None
    executed_snapshot_ref: OpaqueId | None = None
    snapshot_unchanged: bool | None = None
    result: Literal["passed", "failed", "indeterminate"] | None = None
    reason: OpaqueId | None = None
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    checks: tuple[VerifierCheck, ...] = ()

    @model_validator(mode="after")
    def valid_phase(self) -> SessionVerification:
        if self.phase == "started":
            if self.finished_at is not None or self.result is not None or self.checks:
                raise ValueError("A started receipt cannot contain a result.")
        elif self.finished_at is None or self.result is None:
            raise ValueError("A finished receipt requires its result and time.")
        if self.result in {"passed", "failed"}:
            if (
                not self.source_snapshot_ref
                or not self.executed_snapshot_ref
                or not self.snapshot_unchanged
                or not self.checks
            ):
                raise ValueError("Conclusive verification needs checks on an unchanged snapshot.")
            if any(check.result == "indeterminate" for check in self.checks):
                raise ValueError("Indeterminate checks cannot yield a conclusive result.")
            if self.result == "passed" and any(c.result != "passed" for c in self.checks):
                raise ValueError("All checks must pass.")
            if self.result == "failed" and not any(c.result == "failed" for c in self.checks):
                raise ValueError("A failed result requires a failed check.")
        return self


class TimelineEntry(ApiRecord):
    ledger_sequence: SequenceNumber
    record_ref: OpaqueId
    route_id: OpaqueId | None = None
    kind: Literal["decision", "dispatch", "observation", "verification", "correction"]
    evidence_ref: OpaqueId
    recorded_at: AwareDatetime
    event_type: OpaqueId | None = None
    observation: EventRequest | None = None
    verification: SessionVerification | None = None
    payload_state: Literal["reference_only", "available", "erased"] = "reference_only"


class TimelinePage(ApiRecord):
    session_id: OpaqueId
    entries: tuple[TimelineEntry, ...]
    next_cursor: OpaqueId | None = None


class DispatchEvidence(ApiRecord):
    attempt_id: OpaqueId
    intended_deployment_ref: OpaqueId
    served_deployment_ref: OpaqueId | None = None
    confidence: Literal["unknown", "assumed_intended", "model_reported", "gateway_reported"]
    evidence_ref: OpaqueId


class DecisionExplanation(ApiRecord):
    route_id: OpaqueId
    session_id: OpaqueId
    policy: VersionRef
    profile: VersionRef
    adapter: VersionRef
    reason_codes: tuple[OpaqueId, ...]
    attempts: tuple[DispatchEvidence, ...]
    decided_rung: OpaqueId
    evidence_gaps: tuple[OpaqueId, ...] = ()


def distribution_capabilities() -> Capabilities:
    """Describe shipped code; this is not a runtime policy or provider-health attestation."""
    from adrl.wire.adapters import ClaudeCodeAdapter
    from adrl.wire.profiles.messages import MessagesProfile

    profile = MessagesProfile()
    adapter = ClaudeCodeAdapter()
    return Capabilities(
        profiles=(
            ProfileCapability(
                profile=VersionRef(id=profile.profile_id, version=profile.version),
                endpoints=profile.endpoints,
                transport="http",
                validation="offline_fixtures",
            ),
        ),
        adapters=(
            AdapterCapability(
                adapter=VersionRef(id=adapter.adapter_id, version=adapter.version),
                identity="authenticated_binding",
                tool_events="implemented",
                tested_harness_versions=(),
            ),
        ),
        effective_enforcement="requires_session_and_runtime_checks",
        unclassified_traffic="legacy_forwarding_without_profile_guarantees",
        product_operations=(
            "GET /adrl/v1/capabilities",
            "POST /adrl/v1/sessions",
            "GET /adrl/v1/sessions/{session_id}",
            "POST /adrl/v1/events",
            "GET /adrl/v1/sessions/{session_id}/timeline",
            "GET /adrl/v1/decisions/{route_id}",
        ),
    )
