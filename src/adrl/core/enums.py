"""Versioned enums and state sets shared across buckets. Primary: ADRL-CAS-002.

Every enum here is named in at least one decision. Adding a member is a new version with an
upcaster (ADRL-MEM-001); removing or merging members is prohibited (ADRL-MEM-004).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from enum import Enum, StrEnum

REQUEST_CLASSES_VERSION = "request-classes-v1"
FAILURE_TYPES_VERSION = "failure-types-v2"
FAILURE_CLASSES_VERSION = "failure-classes-v1"
EPISODE_SIGNALS_VERSION = "episode-signals-v1"


class Rung(StrEnum):
    """Capability rungs, ordered from cheapest to most capable (ADRL-RTG-001)."""

    LOCAL = "local"
    CHEAP_CLOUD = "cheap_cloud"
    FRONTIER = "frontier"

    @property
    def rank(self) -> int:
        return _RUNG_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Rung):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Rung):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Rung):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Rung):
            return NotImplemented
        return self.rank >= other.rank

    def __hash__(self) -> int:
        return hash(self.value)

    @classmethod
    def ordered(cls) -> tuple[Rung, ...]:
        return (cls.LOCAL, cls.CHEAP_CLOUD, cls.FRONTIER)

    @property
    def is_cloud(self) -> bool:
        return self is not Rung.LOCAL


_RUNG_RANK: dict[Rung, int] = {Rung.LOCAL: 0, Rung.CHEAP_CLOUD: 1, Rung.FRONTIER: 2}


class RequestClass(StrEnum):
    """Six mechanical request classes (ADRL-SEM-001)."""

    USER_TURN = "user_turn"
    CONTINUATION = "continuation"
    UTILITY = "utility"
    SUBAGENT = "subagent"
    PRE_WARM = "pre_warm"
    PASSTHROUGH = "passthrough"


class UtilityKind(StrEnum):
    """Utility call split by content exposure (ADRL-SEM-004)."""

    COSMETIC = "cosmetic"
    CONTEXT_BEARING = "context_bearing"


class InteractionMode(StrEnum):
    """Latency weighting mode (ADRL-RTG-005)."""

    INTERACTIVE = "interactive"
    BACKGROUND_SUBAGENT = "background_subagent"
    UTILITY = "utility"


class FailureType(StrEnum):
    """failure-types-v2 (ADRL-CAS-002, ADRL-MEM-004)."""

    TASK_CAPABILITY = "task_capability"
    HARNESS_DIALECT = "harness_dialect"
    INFRASTRUCTURE = "infrastructure"
    POLICY_CONSTRAINT = "policy_constraint"
    CONTEXT_FEASIBILITY = "context_feasibility"
    USER_ABORT = "user_abort"
    UNVERIFIABLE = "unverifiable"

    @property
    def is_capability_evidence(self) -> bool:
        """Only task_capability is evidence about a rung's ability (ADRL-MEM-004)."""
        return self is FailureType.TASK_CAPABILITY


FAILURE_TYPE_PRECEDENCE: tuple[FailureType, ...] = (
    FailureType.POLICY_CONSTRAINT,
    FailureType.CONTEXT_FEASIBILITY,
    FailureType.INFRASTRUCTURE,
    FailureType.HARNESS_DIALECT,
    FailureType.TASK_CAPABILITY,
)


def resolve_primary(
    candidates: Iterable[FailureType],
) -> tuple[FailureType, FailureType | None]:
    """Resolve several plausible causes to (primary, secondary) per ADRL-CAS-002.

    Precedence: policy_constraint > context_feasibility > infrastructure > harness_dialect >
    task_capability. user_abort and unverifiable are excluded labels: user_abort wins over
    everything when present because the run never completed; an empty or all-unverifiable set
    resolves to unverifiable and never to task_capability by default.
    """
    present = list(dict.fromkeys(candidates))
    if FailureType.USER_ABORT in present:
        rest = [c for c in present if c is not FailureType.USER_ABORT]
        secondary = _first_by_precedence(rest)
        return FailureType.USER_ABORT, secondary
    ranked = [c for c in FAILURE_TYPE_PRECEDENCE if c in present]
    if not ranked:
        return FailureType.UNVERIFIABLE, None
    primary = ranked[0]
    secondary = ranked[1] if len(ranked) > 1 else None
    return primary, secondary


def _first_by_precedence(candidates: Sequence[FailureType]) -> FailureType | None:
    for cause in FAILURE_TYPE_PRECEDENCE:
        if cause in candidates:
            return cause
    return None


class FailureClass(StrEnum):
    """Fail-open failure classes (ADRL-FND-004)."""

    ROUTING_PATH = "routing_path"
    GATE_PATH = "gate_path"
    PROXY_PATH = "proxy_path"


class OutcomeState(StrEnum):
    """Three-state outcome lifecycle (ADRL-MEM-002)."""

    PENDING = "pending"
    CLOSED_TURN = "closed_turn"
    CLOSED_FINAL = "closed_final"


class VerificationResult(StrEnum):
    """Verification event result (ADRL-MEM-003)."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class ServedSource(StrEnum):
    """Provenance of the served model identity (ADRL-CAS-006)."""

    GATEWAY_REPORTED = "gateway_reported"
    PROXY_OBSERVED = "proxy_observed"
    ASSUMED_INTENDED = "assumed_intended"


class SideEffectClass(StrEnum):
    """Mechanical side-effect class of a tool call (ADRL-RTG-004, ADRL-CAS-003)."""

    READ_ONLY = "read_only"
    IDEMPOTENT = "idempotent"
    DESTRUCTIVE = "destructive"


class ReleaseReason(StrEnum):
    """Audited human pin release reason codes (ADRL-SAF-002)."""

    FALSE_POSITIVE = "false_positive"
    TEST_FIXTURE = "test_fixture"


class DetectorTier(StrEnum):
    """Secret and PII detector tiers by measured precision (ADRL-SAF-003, ADRL-SAF-008)."""

    HIGH_CONFIDENCE = "high_confidence"
    GENERIC = "generic"
    PII = "pii"


class EvidenceTier(StrEnum):
    """Evidence tiers (ADRL-LRN-001, ADRL-LRN-008)."""

    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"
    EXPLORE = "explore"

    @property
    def enters_objective(self) -> bool:
        return self is EvidenceTier.T1


class AbstainReason(StrEnum):
    """Abstention reason codes (ADRL-LRN-006)."""

    UNCERTAIN = "uncertain"
    OOD = "ood"
    DEGRADED_MEMORY = "degraded_memory"
    PRIVACY_SUPPRESSED = "privacy_suppressed"


class GateMode(StrEnum):
    ENFORCE = "enforce"
    OBSERVE = "observe"


class RoutingMode(StrEnum):
    OFF = "off"
    SHADOW = "shadow"
    LIVE = "live"


class ProjectionState(StrEnum):
    """Projection validity (ADRL-MEM-007)."""

    VALID = "valid"
    STALE = "stale"
    INVALID = "invalid"


class EpisodeSignal(StrEnum):
    """Enumerated episode boundary signals, ordered by confidence (ADRL-SEM-005)."""

    NEW_SESSION_KEY = "new_session_key"
    CLEAR = "clear"
    NEW_TOPIC_NO_OPEN_TOOLS = "new_topic_no_open_tools"
    VERIFIED_TURN_NEW_FILES = "verified_turn_new_files"


class PinLookup(Enum):
    """Result of a pin lookup; unknown is treated as pinned (ADRL-MEM-006)."""

    PINNED = "pinned"
    UNPINNED = "unpinned"
    UNKNOWN = "unknown"

    @property
    def effective_pinned(self) -> bool:
        return self is not PinLookup.UNPINNED
