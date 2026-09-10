"""Error hierarchy and the published error-code table. Primary: ADRL-CAS-007.

Secondary: ADRL-SAF-004, ADRL-SAF-005. Terminal failures are rendered as Anthropic Messages API
error objects with a stable ADRL code in the message. They are never synthetic assistant content.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

ERROR_CODES_VERSION = "error-codes-v1"


class ErrorCode(StrEnum):
    """Stable, published ADRL error codes carried in the error message prefix."""

    CAPABILITY_REJECTED = "capability_rejected"
    CAPABILITY_REJECTED_PROMPT_TOO_LONG = "capability_rejected: prompt_too_long"
    PINNED_LOCAL_UNAVAILABLE = "pinned_local_unavailable"
    PINNED_CLOUD_DENIED = "pinned_cloud_denied"
    GATE_UNAVAILABLE = "gate_unavailable"
    EGRESS_LEDGER_UNAVAILABLE = "egress_ledger_unavailable"
    TERMINAL_FAILURE = "terminal_failure"
    PARTIAL_STREAM_FAILURE = "partial_stream_failure"
    UNCLASSIFIABLE_PINNED = "unclassifiable_pinned"

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS[self]

    @property
    def anthropic_type(self) -> str:
        return _ANTHROPIC_TYPE[self]


_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.CAPABILITY_REJECTED: 400,
    ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG: 400,
    ErrorCode.PINNED_LOCAL_UNAVAILABLE: 400,
    ErrorCode.PINNED_CLOUD_DENIED: 400,
    ErrorCode.GATE_UNAVAILABLE: 400,
    ErrorCode.EGRESS_LEDGER_UNAVAILABLE: 400,
    ErrorCode.TERMINAL_FAILURE: 400,
    ErrorCode.PARTIAL_STREAM_FAILURE: 400,
    ErrorCode.UNCLASSIFIABLE_PINNED: 400,
}

_ANTHROPIC_TYPE: dict[ErrorCode, str] = {
    ErrorCode.CAPABILITY_REJECTED: "invalid_request_error",
    ErrorCode.CAPABILITY_REJECTED_PROMPT_TOO_LONG: "invalid_request_error",
    ErrorCode.PINNED_LOCAL_UNAVAILABLE: "invalid_request_error",
    ErrorCode.PINNED_CLOUD_DENIED: "permission_error",
    ErrorCode.GATE_UNAVAILABLE: "invalid_request_error",
    ErrorCode.EGRESS_LEDGER_UNAVAILABLE: "invalid_request_error",
    ErrorCode.TERMINAL_FAILURE: "api_error",
    ErrorCode.PARTIAL_STREAM_FAILURE: "api_error",
    ErrorCode.UNCLASSIFIABLE_PINNED: "invalid_request_error",
}

VENDOR_PROMPT_TOO_LONG_PHRASE = "prompt is too long"


def render_error(code: ErrorCode, detail: str, *, request_id: str | None = None) -> dict[str, Any]:
    """Render an Anthropic Messages API error object.

    All ADRL codes map to 4xx so the harness dead-ends instead of retrying (ADRL-SAF-004).
    The message starts with the stable code so tooling can match on it.
    """
    body: dict[str, Any] = {
        "type": "error",
        "error": {"type": code.anthropic_type, "message": f"{code.value}: {detail}"},
    }
    if request_id is not None:
        body["request_id"] = request_id
    return body


class AdrlError(Exception):
    """Base class for every ADRL-raised error."""

    code: ErrorCode = ErrorCode.TERMINAL_FAILURE

    def __init__(self, detail: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        if code is not None:
            self.code = code

    def render(self) -> dict[str, Any]:
        return render_error(self.code, self.detail)


class GateFailure(AdrlError):
    """A hard gate could not run; resolution depends on pin state (ADRL-FND-004)."""

    code = ErrorCode.GATE_UNAVAILABLE


class PinnedBlock(AdrlError):
    """A pinned lineage cannot be served; surfaced loud and non-retried (ADRL-SAF-004/005)."""

    code = ErrorCode.PINNED_CLOUD_DENIED


class LedgerAppendFailure(AdrlError):
    """An append to a ledger failed (ADRL-SAF-009, ADRL-MEM-001)."""

    code = ErrorCode.EGRESS_LEDGER_UNAVAILABLE


class ConfigError(AdrlError):
    """Configuration is invalid; raised at load time, never at request time."""

    code = ErrorCode.TERMINAL_FAILURE


class PermittedSetWidened(AdrlError):
    """An attempt was made to widen a permitted rung set (ADRL-SAF-001)."""

    code = ErrorCode.TERMINAL_FAILURE
