"""Fail-loud and block contract. Primary: ADRL-SAF-004. Secondary: ADRL-SAF-005, ADRL-SEM-004.

Blocks are non-retried 4xx Anthropic error objects that name the pin, the detector and the
recovery options. They never mention ANTHROPIC_BASE_URL or suggest disabling ADRL. A pinned
lineage whose request overflows the local window gets the vendor's too-long wording so the
harness auto-compacts. Cosmetic utility calls on a pinned lineage get an empty valid message.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from adrl.config.models import RungsConfig
from adrl.core.enums import Rung
from adrl.core.errors import VENDOR_PROMPT_TOO_LONG_PHRASE, ErrorCode, render_error
from adrl.core.types import PermittedSet, RequestContext
from adrl.telemetry.metrics import BLOCK_TOTAL

FORBIDDEN_WORDS = ("ANTHROPIC_BASE_URL", "disable ADRL", "bypass")


@dataclass(frozen=True, slots=True)
class BlockResponse:
    status: int
    body: dict[str, Any]
    code: ErrorCode

    @property
    def bytes(self) -> bytes:
        return json.dumps(self.body).encode("utf-8")


def _recovery_text(release_permitted: bool) -> str:
    options = ["continue locally with reduced context (run /compact)"]
    if release_permitted:
        options.append(
            "ask an operator for an audited release of the finding (adrl release --finding <id>)"
        )
    options.append("stop this session")
    return "Recovery options: " + "; ".join(options) + "."


def pinned_cloud_denied(
    ctx: RequestContext, detector_id: str | None, finding_id: str | None, release_permitted: bool
) -> BlockResponse:
    detail = (
        "this session is privacy-pinned to the local rung"
        + (f" by detector {detector_id}" if detector_id else "")
        + (f" (finding {finding_id})" if finding_id else "")
        + " and no local model can serve this request. "
        + _recovery_text(release_permitted)
    )
    return _block(ErrorCode.PINNED_CLOUD_DENIED, detail)


def pinned_local_unavailable(
    ctx: RequestContext, detector_id: str | None, release_permitted: bool
) -> BlockResponse:
    detail = (
        "this session is privacy-pinned to the local rung"
        + (f" by detector {detector_id}" if detector_id else "")
        + " and the local rung is unavailable. "
        + _recovery_text(release_permitted)
    )
    return _block(ErrorCode.PINNED_LOCAL_UNAVAILABLE, detail)


def prompt_too_long(
    ctx: RequestContext,
    *,
    input_estimate: int,
    ceiling: int,
    executed_tool: str | None = None,
    release_permitted: bool = True,
) -> BlockResponse:
    """SAF-005 block: vendor wording plus the stable token so the harness auto-compacts."""
    detail = (
        f"{VENDOR_PROMPT_TOO_LONG_PHRASE}: {input_estimate} tokens > {ceiling} maximum on the "
        "privacy-pinned local rung. "
    )
    if executed_tool:
        detail += f"The tool {executed_tool} already ran; its result is what could not be sent. "
    detail += _recovery_text(release_permitted)
    return _block(ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG, detail)


def gate_unavailable(ctx: RequestContext, reason: str) -> BlockResponse:
    detail = (
        f"a hard gate could not run ({reason}) and this session is privacy-pinned, so the request "
        "was not forwarded. " + _recovery_text(False)
    )
    return _block(ErrorCode.GATE_UNAVAILABLE, detail)


def egress_ledger_unavailable(ctx: RequestContext) -> BlockResponse:
    detail = (
        "the egress ledger could not record this request and the session is privacy-pinned, so "
        "the request was not forwarded. " + _recovery_text(False)
    )
    return _block(ErrorCode.EGRESS_LEDGER_UNAVAILABLE, detail)


def unclassifiable_pinned(ctx: RequestContext) -> BlockResponse:
    detail = "the request could not be classified and the session is privacy-pinned. "
    return _block(ErrorCode.UNCLASSIFIABLE_PINNED, detail + _recovery_text(False))


def _block(code: ErrorCode, detail: str) -> BlockResponse:
    for word in FORBIDDEN_WORDS:
        if word.lower() in detail.lower():
            raise ValueError(f"block message must not mention {word!r}")
    BLOCK_TOTAL.labels(code=code.value).inc()
    return BlockResponse(code.http_status, render_error(code, detail), code)


def continuation_block_allowed(is_action_boundary: bool) -> bool:
    """Blocks on continuations are issued only at an action boundary (ADRL-SAF-005 clause 3)."""
    return is_action_boundary


def executed_tool_name(ctx: RequestContext) -> str | None:
    """Name of the tool whose result is the final block of the request, if any."""
    messages = ctx.json.get("messages")
    if not isinstance(messages, list) or not messages:
        return None
    last = messages[-1]
    if not isinstance(last, dict):
        return None
    content = last.get("content")
    if not isinstance(content, list):
        return None
    result_ids = [
        b.get("tool_use_id")
        for b in content
        if isinstance(b, dict) and b.get("type") == "tool_result"
    ]
    if not result_ids:
        return None
    for message in reversed(messages[:-1]):
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                if block.get("id") in result_ids:
                    return str(block.get("name", "tool"))
    return "tool"


def prefer_larger_local(permitted: PermittedSet, rungs: RungsConfig) -> Sequence[str]:
    """Intra-local escalation order (ADRL-SAF-004 clause 3), empty if local is not permitted."""
    if Rung.LOCAL not in permitted:
        return ()
    spec = rungs.rungs[Rung.LOCAL]
    return spec.intra_rung_escalation_order or spec.members


def empty_utility_message(ctx: RequestContext) -> dict[str, Any]:
    """Empty-but-valid message for a cosmetic utility call on a pinned lineage (ADRL-SEM-004)."""
    return {
        "id": "msg_adrl_empty",
        "type": "message",
        "role": "assistant",
        "model": ctx.requested_model,
        "content": [{"type": "text", "text": ""}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
    }


def empty_utility_sse(ctx: RequestContext) -> bytes:
    """Streamed equivalent of :func:`empty_utility_message`."""
    message = empty_utility_message(ctx)
    start = dict(message)
    start["content"] = []
    start["stop_reason"] = None
    events = [
        ("message_start", {"type": "message_start", "message": start}),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 0},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]
    return b"".join(
        f"event: {name}\ndata: {json.dumps(data)}\n\n".encode() for name, data in events
    )
