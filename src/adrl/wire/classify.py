"""Mechanical request classification. Primary: ADRL-SEM-001. Secondary: ADRL-SEM-004, ADRL-FND-003.

Signals are request shape and the harness's wire headers only; no model opinion and never the
requested model name. Header detection of subagent lineage is preferred; the body fingerprint is a
fallback whose disagreement with the header is counted.
"""

from __future__ import annotations

from dataclasses import dataclass

from adrl.config.models import UtilityFingerprint, UtilityFingerprintsConfig
from adrl.core.enums import InteractionMode, RequestClass, UtilityKind
from adrl.core.errors import AdrlError, ErrorCode
from adrl.telemetry.metrics import FINGERPRINT_DIVERGENCE_TOTAL
from adrl.wire.parse import (
    HEADER_AGENT_ID,
    HEADER_PARENT_AGENT_ID,
    ParsedRequest,
    content_blocks,
    has_tool_result,
    message_text,
)

CLASSIFIER_VERSION = "classifier-v1"

# Shape constants observed on Claude Code 2.1.2xx traffic; recorded here, revised by corpus.
SIDECAR_MAX_TOKENS = 8192
SIDECAR_MAX_MESSAGES = 2
PRE_WARM_MAX_TOKENS = 2
SYSTEM_HEAD_CHARS = 400
INTERRUPT_PREFIX = "[Request interrupted by user"


class UnclassifiableError(AdrlError):
    """A pinned lineage's request could not be classified; it must not default to cloud."""

    code = ErrorCode.UNCLASSIFIABLE_PINNED


@dataclass(frozen=True, slots=True)
class Classification:
    request_class: RequestClass
    content_bearing: bool
    interaction_mode: InteractionMode
    utility_kind: UtilityKind | None = None
    fingerprint_id: str | None = None
    subagent_by_header: bool = False
    subagent_by_fingerprint: bool = False
    is_api: bool = True
    classifier_version: str = CLASSIFIER_VERSION

    @property
    def is_routed(self) -> bool:
        """Only user turns receive a fresh rung decision (ADRL-FND-003)."""
        return self.request_class is RequestClass.USER_TURN

    @property
    def inherits_route(self) -> bool:
        return self.request_class in (RequestClass.CONTINUATION, RequestClass.PRE_WARM)


def _system_head(parsed: ParsedRequest) -> str:
    return parsed.system_text[:SYSTEM_HEAD_CHARS].lower()


def _first_user_text(parsed: ParsedRequest) -> str:
    for message in parsed.messages:
        if isinstance(message, dict) and message.get("role") == "user":
            return message_text(message).lower()[:SYSTEM_HEAD_CHARS]
    return ""


def _fingerprint_matches(fp: UtilityFingerprint, parsed: ParsedRequest) -> bool:
    if fp.requires_no_tools and parsed.tools:
        return False
    if fp.max_tokens_at_most is not None:
        max_tokens = parsed.max_tokens
        if max_tokens is None or max_tokens > fp.max_tokens_at_most:
            return False
    head = _system_head(parsed)
    user = _first_user_text(parsed)
    if fp.system_prefix_contains and not any(
        needle.lower() in head for needle in fp.system_prefix_contains
    ):
        return False
    if fp.user_prefix_contains and not any(
        needle.lower() in user for needle in fp.user_prefix_contains
    ):
        return False
    return bool(fp.system_prefix_contains or fp.user_prefix_contains)


def _match_utility(
    parsed: ParsedRequest, config: UtilityFingerprintsConfig
) -> tuple[str, UtilityKind] | None:
    for fp in config.fingerprints:
        if _fingerprint_matches(fp, parsed):
            return fp.fingerprint_id, UtilityKind(fp.kind)
    max_tokens = parsed.max_tokens
    if (
        not parsed.tools
        and max_tokens is not None
        and max_tokens <= SIDECAR_MAX_TOKENS
        and len(parsed.messages) <= SIDECAR_MAX_MESSAGES
    ):
        return "sidecar", UtilityKind.COSMETIC
    return None


def _subagent_by_fingerprint(parsed: ParsedRequest, config: UtilityFingerprintsConfig) -> bool:
    needles = config.subagent_system_contains
    if not needles:
        return False
    head = _system_head(parsed)
    return any(str(n).lower() in head for n in needles)


def latest_message_is_developer_authored(parsed: ParsedRequest) -> bool:
    """True when the final message is user-role text with no tool_result (ADRL-FND-003)."""
    last = parsed.last_message
    if last is None or last.get("role") != "user":
        return False
    blocks = content_blocks(last)
    if not blocks:
        return False
    return all(b.get("type") == "text" for b in blocks)


def classify(
    parsed: ParsedRequest, config: UtilityFingerprintsConfig, *, pinned: bool = False
) -> Classification:
    """Classify by shape and headers. Raises UnclassifiableError on a pinned lineage only."""
    agent_id = parsed.header(HEADER_AGENT_ID) or parsed.header(HEADER_PARENT_AGENT_ID)
    by_header = agent_id is not None
    by_fingerprint = parsed.is_api and _subagent_by_fingerprint(parsed, config)
    if parsed.is_api and (by_header != by_fingerprint) and config.subagent_system_contains:
        FINGERPRINT_DIVERGENCE_TOTAL.labels(
            header_class="subagent" if by_header else "none",
            fingerprint_class="subagent" if by_fingerprint else "none",
        ).inc()
    mode = InteractionMode.BACKGROUND_SUBAGENT if by_header else InteractionMode.INTERACTIVE

    if parsed.is_count_tokens:
        return Classification(
            RequestClass.PASSTHROUGH,
            content_bearing=bool(parsed.messages) or bool(parsed.system_text),
            interaction_mode=mode,
            fingerprint_id="count_tokens",
            subagent_by_header=by_header,
            subagent_by_fingerprint=by_fingerprint,
        )
    if not parsed.is_messages:
        return Classification(
            RequestClass.PASSTHROUGH,
            content_bearing=False,
            interaction_mode=mode,
            fingerprint_id="non_api",
            subagent_by_header=by_header,
            subagent_by_fingerprint=by_fingerprint,
            is_api=False,
        )
    if not parsed.parse_ok or not parsed.messages:
        if pinned:
            raise UnclassifiableError("request body could not be classified on a pinned lineage")
        return Classification(
            RequestClass.PASSTHROUGH,
            content_bearing=bool(parsed.body),
            interaction_mode=mode,
            fingerprint_id="unparseable",
            subagent_by_header=by_header,
            subagent_by_fingerprint=by_fingerprint,
        )

    max_tokens = parsed.max_tokens
    if max_tokens is not None and max_tokens <= PRE_WARM_MAX_TOKENS:
        return Classification(
            RequestClass.PRE_WARM,
            content_bearing=True,
            interaction_mode=mode,
            fingerprint_id="pre_warm",
            subagent_by_header=by_header,
            subagent_by_fingerprint=by_fingerprint,
        )
    utility = _match_utility(parsed, config)
    if utility is not None:
        fingerprint_id, kind = utility
        return Classification(
            RequestClass.UTILITY,
            content_bearing=True,
            interaction_mode=InteractionMode.UTILITY,
            utility_kind=kind,
            fingerprint_id=fingerprint_id,
            subagent_by_header=by_header,
            subagent_by_fingerprint=by_fingerprint,
        )
    if has_tool_result(parsed.last_message):
        return Classification(
            RequestClass.CONTINUATION,
            content_bearing=True,
            interaction_mode=mode,
            subagent_by_header=by_header,
            subagent_by_fingerprint=by_fingerprint,
        )
    if by_header:
        return Classification(
            RequestClass.SUBAGENT,
            content_bearing=True,
            interaction_mode=InteractionMode.BACKGROUND_SUBAGENT,
            subagent_by_header=True,
            subagent_by_fingerprint=by_fingerprint,
        )
    return Classification(
        RequestClass.USER_TURN,
        content_bearing=True,
        interaction_mode=InteractionMode.INTERACTIVE,
        subagent_by_header=False,
        subagent_by_fingerprint=by_fingerprint,
    )


def previous_turn_interrupted(parsed: ParsedRequest, window: int = 3) -> bool:
    """Harness interrupt marker in the last few messages (escalate-on-retry signal)."""
    for message in parsed.messages[-window:]:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str) and content.startswith(INTERRUPT_PREFIX):
            return True
        for block in content_blocks(message):
            text = block.get("text")
            if isinstance(text, str) and text.startswith(INTERRUPT_PREFIX):
                return True
    return False
