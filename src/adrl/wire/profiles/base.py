"""Protocol interpretation ports. Primary: ADRL-SEM-007. Secondary: ADRL-FND-001."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from adrl.config.loaders import ConfigBundle
from adrl.config.models import RungsConfig, UtilityFingerprintsConfig
from adrl.core.enums import Rung
from adrl.core.errors import ErrorCode
from adrl.core.ports import Tokenizer
from adrl.core.types import RequestContext
from adrl.wire.classify import Classification
from adrl.wire.observe import ResponseObservation


class RequestView(Protocol):
    """Native inspection view. The original body remains authoritative.

    max_tokens is the existing engine's output-budget field, not a required wire key.
    A future profile must project its own semantics rather than translate the raw JSON.
    """

    @property
    def method(self) -> str: ...

    @property
    def path(self) -> str: ...

    @property
    def query(self) -> str: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    @property
    def body(self) -> bytes: ...

    @property
    def json(self) -> Mapping[str, Any]: ...

    @property
    def parse_ok(self) -> bool: ...

    @property
    def requested_model(self) -> str: ...

    @property
    def is_stream(self) -> bool: ...

    @property
    def max_tokens(self) -> int | None: ...


class StreamObserver(Protocol):
    """Observe exactly the chunks the transport relays."""

    def feed(self, chunk: bytes) -> None: ...

    def finish(self) -> ResponseObservation: ...


@dataclass(frozen=True, slots=True)
class ProtocolResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class ProtocolProfile(Protocol):
    """Extraction boundary, not admission authority for additional wire formats.

    Gate and cascade implementations still need profile-specific conformance before a
    second profile is installed. The initial runtime admits only Messages.
    """

    @property
    def profile_id(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def endpoints(self) -> tuple[str, ...]: ...

    def handles(self, method: str, path: str, headers: Mapping[str, str]) -> bool: ...

    def parse(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes, query: str = ""
    ) -> RequestView: ...

    def is_token_count(self, path: str) -> bool: ...

    def is_pre_warm(self, request: RequestView) -> bool: ...

    def classify(
        self, request: RequestView, config: UtilityFingerprintsConfig, *, pinned: bool
    ) -> Classification: ...

    def serialize(
        self,
        body: dict[str, Any],
        *,
        rung: Rung,
        alias: str,
        bundle: ConfigBundle,
        suppress_thinking: bool,
    ) -> bytes: ...

    def stream_observer(
        self,
        *,
        status: int,
        headers: Mapping[str, str],
        intended_rung: Rung,
        requested_model: str,
        rungs: RungsConfig,
        hash_key: bytes,
    ) -> StreamObserver: ...

    def observe_response(
        self,
        body: bytes,
        *,
        status: int,
        headers: Mapping[str, str],
        intended_rung: Rung,
        requested_model: str,
        rungs: RungsConfig,
        hash_key: bytes,
    ) -> ResponseObservation: ...

    def error(self, code: ErrorCode, detail: str) -> ProtocolResponse: ...

    def empty_utility(self, ctx: RequestContext) -> ProtocolResponse: ...

    def count_tokens_response(self, count: int) -> ProtocolResponse: ...

    def estimate_count_tokens(
        self, ctx: RequestContext, tokenizer: Tokenizer | None, *, ratio: float
    ) -> int: ...

    def is_action_boundary(self, body: Mapping[str, Any]) -> bool: ...

    def executed_tool(self, ctx: RequestContext) -> str | None: ...
