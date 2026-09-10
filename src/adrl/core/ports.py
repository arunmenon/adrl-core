"""Port interfaces every adapter implements. Primary: ADRL-MEM-006.

Secondary: ADRL-FND-002 (gateway), ADRL-SAF-003 (scanner), ADRL-SAF-006 (tokenizer),
ADRL-SAF-007 (sandbox), ADRL-MEM-005 (embedder), ADRL-MEM-010 (keystore).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from adrl.core.enums import PinLookup, Rung
from adrl.core.ids import LineageId, RouteId, SessionId
from adrl.core.types import Decision, Finding, LedgerEvent


@dataclass(frozen=True, slots=True)
class LineageEvent:
    lineage_hmac: LineageId
    event_type: str
    payload: Mapping[str, Any]
    ts: str = ""
    seq: int | None = None


@dataclass(frozen=True, slots=True)
class LedgerHealth:
    available: bool
    degraded_reason: str | None = None
    data_version: int | None = None


@runtime_checkable
class LedgerPort(Protocol):
    """Evidence ledger (ADRL-MEM-001). Append-only; reads tolerate unknown fields."""

    async def append_decision(self, decision: Decision, context: Mapping[str, Any]) -> bool: ...

    async def append_event(self, event: LedgerEvent) -> bool: ...

    async def append_lineage_event(self, event: LineageEvent) -> int: ...

    async def read_lineage_events(
        self, lineage: LineageId, event_type: str | None = None
    ) -> Sequence[LineageEvent]: ...

    async def read_events(
        self, route_id: RouteId, event_type: str | None = None
    ) -> Sequence[LedgerEvent]: ...

    async def health(self) -> LedgerHealth: ...


@dataclass(frozen=True, slots=True)
class EgressEvent:
    """Content-free record of a request leaving the machine or a gate verdict (ADRL-SAF-009)."""

    lineage_hmac: str
    request_class: str
    content_bearing: bool
    destination_rung: str | None
    deployment_tag: str
    gate_verdicts: Sequence[Mapping[str, Any]]
    detector_tier: str | None = None
    span_hashes: Sequence[str] = ()
    bytes_out: int = 0
    actor: str = "adrl"
    reason: str | None = None
    event_kind: str = "forward"
    deployment_id: str | None = None
    trust_zone: str | None = None
    geo: str | None = None
    api_base_host: str | None = None
    receipt_source: str | None = None
    """intended (write-ahead), gateway_reported, proxy_observed or assumed_intended."""


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    detail: str | None = None


@runtime_checkable
class EgressLedgerPort(Protocol):
    """Write-ahead, hash-chained egress ledger (ADRL-SAF-009). Not behind the fail-safe facade."""

    def append(self, event: EgressEvent) -> int: ...

    def verify_chain(self) -> ChainVerification: ...

    def checkpoint(self) -> int: ...


@dataclass(frozen=True, slots=True)
class StickyState:
    """Sticky route for one lineage (ADRL-SEM-003, ADRL-CAS-005, ADRL-CAS-006)."""

    lineage_hmac: LineageId
    route_id: RouteId
    rung: Rung
    escalated: bool
    served_model: str | None
    served_provider: str | None
    served_source: str
    turn_index: int
    last_served_at: datetime | None
    state_loss: bool = False


@runtime_checkable
class StateProvider(Protocol):
    """Routing state that must survive a decision (ADRL-MEM-006, ADRL-SAF-002)."""

    async def get_sticky(self, lineage: LineageId) -> StickyState | None: ...

    async def set_sticky(self, state: StickyState) -> None: ...

    async def get_pin(self, lineage: LineageId) -> PinLookup: ...

    async def set_pin(self, lineage: LineageId, finding_id: str, detector_id: str) -> None: ...

    async def load_all(self) -> int: ...


@dataclass(frozen=True, slots=True)
class ContentBlock:
    """A unit of scannable content with its position in the transcript."""

    block_id: str
    content_type: str
    text: str
    path_hint: str | None = None


@runtime_checkable
class SecretScanner(Protocol):
    """Tiered secret scanner over new content (ADRL-SAF-003)."""

    def scan(self, blocks: Sequence[ContentBlock]) -> Sequence[Finding]: ...

    @property
    def ruleset_version(self) -> str: ...


@runtime_checkable
class Tokenizer(Protocol):
    """Local token counter used by the feasibility filter (ADRL-SAF-006)."""

    def count(self, text: str) -> int: ...

    @property
    def tokenizer_id(self) -> str: ...


@runtime_checkable
class StreamingResponse(Protocol):
    """Handle on an upstream response whose bytes are relayed verbatim (ADRL-FND-001)."""

    @property
    def status_code(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def aiter_raw(self) -> AsyncIterator[bytes]: ...

    async def aclose(self) -> None: ...


@runtime_checkable
class GatewayClient(Protocol):
    """Exactly one attempt per request at the chosen rung (ADRL-CAS-007, ADRL-FND-002)."""

    async def send(
        self,
        body: bytes,
        headers: Mapping[str, str],
        *,
        path: str,
        rung: Rung,
        timeout_s: float | None = None,
    ) -> StreamingResponse: ...

    async def health(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class SandboxResult:
    available: bool
    exit_code: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    duration_s: float = 0.0
    unavailable_reason: str | None = None


@runtime_checkable
class SandboxRunner(Protocol):
    """OS-enforced, no-egress execution of an allow-listed command (ADRL-SAF-007)."""

    def run(
        self,
        argv: Sequence[str],
        snapshot_dir: str,
        allow_list: Sequence[str],
        *,
        timeout_s: float,
    ) -> SandboxResult: ...

    @property
    def platform_id(self) -> str: ...


@runtime_checkable
class Embedder(Protocol):
    """Local embedding model; outputs are prompt-class data (ADRL-MEM-005)."""

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...

    @property
    def embedder_version(self) -> str: ...

    @property
    def dimension(self) -> int: ...


@runtime_checkable
class KeyStore(Protocol):
    """Per-session encryption keys for crypto-shredding (ADRL-MEM-010)."""

    def create_session_key(self, session: SessionId) -> bytes: ...

    def get_session_key(self, session: SessionId) -> bytes | None: ...

    def shred_session_key(self, session: SessionId, reason: str) -> bool: ...

    def hmac_key(self) -> bytes: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...
