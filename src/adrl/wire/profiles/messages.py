"""Messages protocol interpretation. Primary: ADRL-SEM-007. Secondary: ADRL-FND-001.

Owns existing Messages interpretation, rewrites and response rendering. The current
classifier's Claude Code fingerprints remain versioned configuration, not universal rules.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from adrl.config.loaders import ConfigBundle
from adrl.config.models import RungsConfig, UtilityFingerprintsConfig
from adrl.core.enums import RequestClass, Rung
from adrl.core.errors import ErrorCode
from adrl.core.ports import Tokenizer
from adrl.core.types import RequestContext
from adrl.wire.classify import PRE_WARM_MAX_TOKENS, Classification, classify
from adrl.wire.observe import ResponseObservation, SseObserver, observe_json
from adrl.wire.parse import (
    COUNT_TOKENS_PATH,
    MESSAGES_PATH,
    ParsedRequest,
    content_blocks,
    estimate_chars,
    last_assistant_message,
    last_message,
    parse_request,
    system_text,
    tool_result_ids,
    tool_use_ids,
)
from adrl.wire.profiles.base import ProtocolResponse, RequestView, StreamObserver
from adrl.wire.profiles.messages_responses import (
    JSON_HEADERS,
    count_tokens_response,
    empty_utility_response,
    error_body,
)
from adrl.wire.rewrite import serialise, strip_for_rung


@dataclass(frozen=True, slots=True)
class MessagesProfile:
    profile_id: str = "anthropic-messages-v1"
    version: str = "1"
    endpoints: tuple[str, ...] = (MESSAGES_PATH, COUNT_TOKENS_PATH)

    def handles(self, method: str, path: str, headers: Mapping[str, str]) -> bool:
        """Preserve legacy prefix dispatch; endpoints lists only supported operations.

        Unknown suffixes still receive the old non-API classification. Rejecting unknown
        content-bearing operations is a separate policy change, not part of extraction.
        """
        return path.startswith(MESSAGES_PATH)

    def parse(
        self, method: str, path: str, headers: Mapping[str, str], body: bytes, query: str = ""
    ) -> ParsedRequest:
        return parse_request(method, path, headers, body, query)

    def is_token_count(self, path: str) -> bool:
        return path.endswith("/count_tokens")

    def is_pre_warm(self, request: RequestView) -> bool:
        return request.max_tokens is not None and request.max_tokens <= PRE_WARM_MAX_TOKENS

    def classify(
        self, request: RequestView, config: UtilityFingerprintsConfig, *, pinned: bool
    ) -> Classification:
        if not isinstance(request, ParsedRequest):
            raise TypeError("anthropic-messages-v1 requires its native ParsedRequest view")
        return classify(request, config, pinned=pinned)

    def serialize(
        self,
        body: dict[str, Any],
        *,
        rung: Rung,
        alias: str,
        bundle: ConfigBundle,
        suppress_thinking: bool,
    ) -> bytes:
        if suppress_thinking:
            body = dict(body)
            body.pop("thinking", None)
        if rung is not Rung.FRONTIER:
            body = strip_for_rung(body, rung, alias, bundle)
        return serialise(body)

    def stream_observer(
        self,
        *,
        status: int,
        headers: Mapping[str, str],
        intended_rung: Rung,
        requested_model: str,
        rungs: RungsConfig,
        hash_key: bytes,
    ) -> StreamObserver:
        return SseObserver(
            status=status,
            headers=headers,
            intended_rung=intended_rung,
            requested_model=requested_model,
            rungs=rungs,
            hash_key=hash_key,
        )

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
    ) -> ResponseObservation:
        return observe_json(
            body,
            status=status,
            headers=headers,
            intended_rung=intended_rung,
            requested_model=requested_model,
            rungs=rungs,
            hash_key=hash_key,
        )

    def error(self, code: ErrorCode, detail: str) -> ProtocolResponse:
        return ProtocolResponse(code.http_status, dict(JSON_HEADERS), error_body(code, detail))

    def empty_utility(self, ctx: RequestContext) -> ProtocolResponse:
        return ProtocolResponse(*empty_utility_response(ctx))

    def count_tokens_response(self, count: int) -> ProtocolResponse:
        return ProtocolResponse(*count_tokens_response(count))

    def estimate_count_tokens(
        self, ctx: RequestContext, tokenizer: Tokenizer | None, *, ratio: float
    ) -> int:
        text = system_text(ctx.json)
        chars = estimate_chars(ctx.json)
        tokens = (
            tokenizer.count(text) + max(0, chars - len(text)) // 4
            if tokenizer is not None
            else chars // 4
        )
        return max(1, math.ceil(tokens * ratio))

    def is_action_boundary(self, body: Mapping[str, Any]) -> bool:
        assistant = last_assistant_message(body)
        if assistant is None:
            return False
        expected = tool_use_ids(assistant)
        last = last_message(body)
        if not expected or last is None or last.get("role") != "user":
            return False
        return expected <= tool_result_ids(last)

    def executed_tool(self, ctx: RequestContext) -> str | None:
        if ctx.request_class is not RequestClass.CONTINUATION or not self.is_action_boundary(
            ctx.json
        ):
            return None
        names = [
            str(block.get("tool_use_id"))
            for block in content_blocks(last_message(ctx.json))
            if block.get("type") == "tool_result"
        ]
        return names[0] if names else None
