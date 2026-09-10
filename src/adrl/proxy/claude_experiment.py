"""Initial-choice Claude experiment. Primary: ADRL-SEM-007.

Secondary: ADRL-FND-001/005, ADRL-TRU-002, ADRL-CAS-006/007.
Explicit constructor-only candidate, not a launch profile or rung admission.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections.abc import AsyncIterator, Mapping
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from adrl.core.enums import Rung
from adrl.core.types import DeploymentInfo, DeploymentSet
from adrl.proxy.upstream import HttpxGatewayClient, HttpxStreamingResponse, UpstreamUnreachableError
from adrl.wire.parse import forward_headers

ANTHROPIC_ORIGIN = "https://api.anthropic.com"


class ClaudeExperimentConfig(BaseModel):
    """Frozen, finite candidate; configuring it does not grant execution authority."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    version: Literal["claude-initial-choice-v1"] = "claude-initial-choice-v1"
    source_model: str = Field(pattern=r"^claude-[a-z0-9-]+$")
    target_model: str = Field(pattern=r"^claude-[a-z0-9-]+$")
    target_deployment: str = Field(min_length=1)
    messages_limit: int = Field(default=8, ge=1, le=8)
    count_tokens_limit: int = Field(default=4, ge=0, le=4)
    body_bytes_limit: int = Field(default=262144, ge=1, le=262144)
    output_tokens_limit: int = Field(default=4096, ge=1, le=4096)
    request_seconds: float = Field(default=90.0, gt=0, le=90)
    session_seconds: float = Field(default=3600.0, gt=0, le=3600)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_body(raw: bytes) -> dict[str, Any]:
    """Reject ambiguous inputs before a model-only transformation."""
    value = json.loads(raw, object_pairs_hook=_object)
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    return value


class ClaudeSelection:
    """One initial selection, pinned to one lineage for this process lifetime."""

    def __init__(self, config: ClaudeExperimentConfig) -> None:
        self.config = config
        self.lineage: str | None = None

    def prepare(
        self, raw: bytes, *, lineage: str, permitted: DeploymentSet, pinned: bool
    ) -> tuple[bytes, DeploymentInfo]:
        deployment = permitted.get(self.config.target_deployment)
        if (
            pinned
            or deployment is None
            or deployment.rung is not Rung.FRONTIER
            or deployment.api_base_host != "api.anthropic.com"
            or deployment.provider != "anthropic"
            or deployment.model != self.config.target_model
            or deployment.is_local_host
        ):
            raise ValueError("experiment target is not a permitted direct Claude deployment")
        body = parse_body(raw)
        if body.get("model") != self.config.source_model:
            raise ValueError("unexpected requested model")
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages required")
        if self.lineage is None:
            if any(not isinstance(m, dict) or m.get("role") != "user" for m in messages):
                raise ValueError("initial-choice experiment requires fresh user-only history")
            # A tool result with no assistant history is not a fresh user task.
            if any(
                isinstance(m.get("content"), list)
                and any(
                    isinstance(b, dict) and b.get("type") == "tool_result" for b in m["content"]
                )
                for m in messages
            ):
                raise ValueError("initial tool results are not admitted")
        elif self.lineage != lineage:
            raise ValueError("experiment is bound to another lineage")
        body["model"] = self.config.target_model
        encoded = json.dumps(body, separators=(",", ":"), allow_nan=False).encode()
        self.lineage = lineage
        return encoded, deployment


class _BoundedResponse(HttpxStreamingResponse):
    def __init__(self, response: httpx.Response, owner: ClaudeExperimentClient, deadline: float):
        super().__init__(response)
        self._owner = owner
        self._deadline = deadline
        self._closed = False

    async def aiter_raw(self) -> AsyncIterator[bytes]:
        try:
            async with asyncio.timeout(max(0, self._deadline - time.monotonic())):
                async for chunk in self._response.aiter_raw():
                    yield chunk
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                await super().aclose()
            finally:
                self._owner.active = False


class ClaudeExperimentClient(HttpxGatewayClient):
    """Finite direct transport. Not exposed by app settings or the normal launcher.

    Counters are process-local; restart-safe run custody is a live-launch prerequisite.
    Injected clients are for isolated offline validation and must not widen transport policy.
    """

    def __init__(self, config: ClaudeExperimentConfig, *, client: httpx.AsyncClient | None = None):
        super().__init__(ANTHROPIC_ORIGIN, client=client, timeout_s=config.request_seconds)
        self.config = config
        self.selection = ClaudeSelection(config)
        self.attempts = {"/v1/messages": 0, "/v1/messages/count_tokens": 0}
        self.active = False
        self.started = time.monotonic()
        self.stopped = False

    async def send(
        self,
        body: bytes,
        headers: Mapping[str, str],
        *,
        path: str,
        rung: Rung,
        timeout_s: float | None = None,
    ) -> HttpxStreamingResponse:
        if rung is not Rung.FRONTIER:
            raise UpstreamUnreachableError("experiment only admits frontier Claude")
        return await self.forward("POST", path, headers, body)

    async def forward(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes
    ) -> HttpxStreamingResponse:
        try:
            if (
                self.stopped
                or self.active
                or time.monotonic() - self.started >= self.config.session_seconds
            ):
                raise ValueError("experiment inactive, expired or already forwarding")
            if method != "POST" or path not in self.attempts:
                raise ValueError("experiment operation not admitted")
            if len(body) > self.config.body_bytes_limit:
                raise ValueError("experiment body limit")
            if any(k.lower() == "x-api-key" for k in headers):
                raise ValueError("experiment does not admit API-key billing")
            data = parse_body(body)
            if data.get("model") not in {self.config.source_model, self.config.target_model}:
                raise ValueError("experiment model not admitted")
            limit = self.config.count_tokens_limit
            if path == "/v1/messages":
                limit = self.config.messages_limit
                tokens = data.get("max_tokens")
                if type(tokens) is not int or not 0 < tokens <= self.config.output_tokens_limit:
                    raise ValueError("experiment output limit")
            if self.attempts[path] >= limit:
                raise ValueError("experiment attempt limit")
        except (ValueError, TypeError) as exc:
            raise UpstreamUnreachableError(str(exc)) from exc
        self.active = True
        self.attempts[path] += 1  # Reserve before any await; failures consume attempts.
        deadline = min(
            self.started + self.config.session_seconds,
            time.monotonic() + self.config.request_seconds,
        )
        safe_headers = forward_headers(headers)
        # HTTP routing/framing must come from the fixed URL and actual rewritten bytes.
        safe_headers = {
            k: v for k, v in safe_headers.items() if k.lower() not in {"host", "content-length"}
        }
        request = self.client.build_request(
            "POST", ANTHROPIC_ORIGIN + path, headers=safe_headers, content=body
        )
        try:
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                response = await self.client.send(request, stream=True, follow_redirects=False)
            return _BoundedResponse(response, self, deadline)
        except (httpx.TransportError, TimeoutError) as exc:
            self.active = False
            raise UpstreamUnreachableError("bounded experiment transport failed") from exc
        except BaseException:
            self.active = False
            raise

    async def health(self) -> Mapping[str, Any]:
        return {"available": False, "reason": "experiment health forwarding disabled"}

    async def aclose(self) -> None:
        self.stopped = True
        await super().aclose()
