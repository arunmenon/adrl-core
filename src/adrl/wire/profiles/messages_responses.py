"""Messages errors and synthetic responses. Primary: ADRL-CAS-007. Secondary: ADRL-SEM-007.

Secondary: ADRL-SAF-004, ADRL-SAF-005, ADRL-SEM-004. Every terminal failure is an Anthropic
Messages API error object; the only non-error synthetic response is the empty-but-valid answer to
a cosmetic utility call on a pinned lineage, which is a documented developer-visible surface.
"""

from __future__ import annotations

import json
from typing import Any

from adrl.core.errors import VENDOR_PROMPT_TOO_LONG_PHRASE, AdrlError, ErrorCode, render_error
from adrl.core.types import RequestContext
from adrl.telemetry.metrics import BLOCK_TOTAL

JSON_HEADERS = {"content-type": "application/json"}

RECOVERY_TEXT = (
    "Recovery: continue locally with reduced context (/compact), request an audited pin release "
    "where policy permits, or stop."
)


def error_body(code: ErrorCode, detail: str, *, request_id: str | None = None) -> bytes:
    BLOCK_TOTAL.labels(code=code.value).inc()
    return json.dumps(render_error(code, detail, request_id=request_id)).encode("utf-8")


def error_from_exception(exc: AdrlError) -> tuple[int, bytes]:
    return exc.code.http_status, error_body(exc.code, exc.detail)


def block_message(code: ErrorCode, *, detector: str | None, executed_tool: str | None) -> str:
    parts: list[str] = []
    if code is ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG:
        parts.append(VENDOR_PROMPT_TOO_LONG_PHRASE + " for the privacy-pinned local rung")
    else:
        parts.append("this session is privacy-pinned and the request cannot leave the machine")
    if detector:
        parts.append(f"pinned by detector {detector}")
    if executed_tool:
        parts.append(f"the blocked request carries the result of executed tool {executed_tool}")
    parts.append(RECOVERY_TEXT)
    return "; ".join(parts)


def empty_utility_response(ctx: RequestContext) -> tuple[int, dict[str, str], bytes]:
    """Empty-but-valid message for a cosmetic utility call that cannot be served (ADRL-SEM-004)."""
    body: dict[str, Any] = {
        "id": "msg_adrl_empty",
        "type": "message",
        "role": "assistant",
        "model": ctx.requested_model,
        "content": [{"type": "text", "text": ""}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
    return 200, dict(JSON_HEADERS), json.dumps(body).encode("utf-8")


def count_tokens_response(input_tokens: int) -> tuple[int, dict[str, str], bytes]:
    return 200, dict(JSON_HEADERS), json.dumps({"input_tokens": int(input_tokens)}).encode()
