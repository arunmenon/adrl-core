"""Pre-decision feature snapshot features-v2. Primary: ADRL-LRN-004. Secondary: ADRL-RTG-003.

Every feature is computed from the request alone at the decision boundary. Nothing that is
known only after the decision (served rung, outcomes, verification, escalation, close
timestamps) can appear here; `assert_no_denied_fields` enforces the deny-list by construction.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from adrl.core.enums import InteractionMode, SideEffectClass
from adrl.core.types import RequestContext
from adrl.routing.side_effects import (
    UNTRUSTED,
    TrustPolicy,
    classify_tool,
    max_available_side_effect,
    tool_definitions,
    turn_start_index,
)

FEATURES_VERSION = "features-v2"
CHARS_PER_TOKEN = 4

DENY_LIST_EXACT: frozenset[str] = frozenset(
    {"served_rung", "served_model", "served_provider", "escalated", "decision", "route_id"}
)
DENY_LIST_PREFIXES: tuple[str, ...] = ("served_", "outcome_", "verified_", "closed_", "escalat")

VERB_CLASSES: tuple[tuple[str, float, re.Pattern[str]], ...] = (
    (
        "trivial",
        0.10,
        re.compile(
            r"\b(rename|typos?|misspellings?|format|indent|indentation|whitespace|comment out)\b",
            re.I,
        ),
    ),
    (
        "explain",
        0.20,
        re.compile(r"\b(explain|what does|what is|why does|describe|summari[sz]e|show me)\b", re.I),
    ),
    (
        "small_edit",
        0.35,
        re.compile(
            r"\b(change|update|tweak|adjust|replace|bump|add a? ?(flag|param|field|log))\b", re.I
        ),
    ),
    ("write", 0.45, re.compile(r"\b(write|create|implement|add|build|generate|scaffold)\b", re.I)),
    (
        "fix",
        0.55,
        re.compile(
            r"\b(fix|debug|broken|failing|error|bug|crash|doesn'?t work|not working)\b", re.I
        ),
    ),
    (
        "hard",
        0.85,
        re.compile(
            r"\b(refactor|redesign|migrate|architect|rewrite|optimi[sz]e|concurren(?:cy|t)|"
            r"race condition|deadlock|security)\b",
            re.I,
        ),
    ),
)
UNKNOWN_VERB_SCORE = 0.5
MECHANICAL_REPAIR = re.compile(
    r"\b(?:fix|correct)\s+(?:(?:the|a|this|these|another)\s+)?"
    r"(?:(?:first|second|third|next|last|remaining|other)\s+)?"
    r"(?P<task>typos?|misspellings?|whitespace|indentation)\b",
    re.I,
)

BROAD_SCOPE = re.compile(
    r"\b(across|all|every|entire|whole|codebase|repo(sitory)?|end[- ]to[- ]end|multiple files)\b",
    re.I,
)
NARROW_SCOPE = re.compile(
    r"\b(this (line|function|file|method)|only|just|single|one file|in `?[\w./-]+\.\w+`?)\b", re.I
)
TERSE_CONTINUE = re.compile(
    r"^\s*(go ahead|do it|do so|go for it|ok(ay)?|ye(s|p|ah)|sure|lgtm|ship it|proceed|continue|"
    r"carry on|try now|and now|next|fine|please do|sounds good|do that|make it so)[.!]?\s*$",
    re.I,
)
DESTRUCTIVE_INTENT = re.compile(
    r"\b(deploy|release to prod|migration|migrate|git push|force[- ]push|rebase|drop (the )?table|"
    r"payments?|billing|checkout flow|rm -rf|del[e]te (the )?(database|branch|repo))\b",
    re.I,
)
INTERRUPT_MARKER = "[Request interrupted by user"
EDIT_FAIL_MARKER = "String to replace not found in file"
FILE_MENTION = re.compile(
    r"[\w./-]+\.(?:py|ts|tsx|js|jsx|go|rs|java|kt|rb|md|yaml|yml|json|toml|sql|sh)\b"
)

SCOPE_ADJUST: dict[str, float] = {"broad": 0.20, "narrow": -0.10, "none": 0.0}


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, Mapping):
                if block.get("type") == "text" and isinstance(block.get("text"), str):
                    parts.append(block["text"])
                elif block.get("type") == "tool_result":
                    parts.append(_text_of(block.get("content")))
        return "\n".join(parts)
    return ""


def _context_chars(body: Mapping[str, Any]) -> int:
    total = len(_text_of(body.get("system")))
    messages = body.get("messages")
    if isinstance(messages, list):
        for message in messages:
            total += len(_text_of(message.get("content")))
    return total


def _last_user_text(messages: Sequence[Mapping[str, Any]]) -> str:
    if not messages:
        return ""
    start = turn_start_index(messages)
    message = messages[start]
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b["text"]
            for b in content
            if isinstance(b, Mapping) and b.get("type") == "text" and isinstance(b.get("text"), str)
        )
    return ""


def verb_class(text: str) -> tuple[str, float]:
    """Strongest lexical signal wins, independent of clause or rule order.

    A mechanical repair phrase does not itself imply debugging. Preserve all
    remaining text so an additional implementation or hard action can still win.
    Quoting and negation are deliberately unresolved; they may over-route.
    """
    scanned = MECHANICAL_REPAIR.sub(r"\g<task>", text)
    small_spans = [
        match.span()
        for name, _, pattern in VERB_CLASSES
        if name == "small_edit"
        for match in pattern.finditer(scanned)
    ]
    # The "add" inside "add a flag" is one small-edit phrase, not another task.
    # Independent "implement"/"create" matches elsewhere still participate.
    matches = [
        (name, score)
        for name, score, pattern in VERB_CLASSES
        if any(
            name != "write"
            or not any(start <= match.start() and match.end() <= end for start, end in small_spans)
            for match in pattern.finditer(scanned)
        )
    ]
    return max(matches, key=lambda item: item[1]) if matches else ("unknown", UNKNOWN_VERB_SCORE)


def scope_hint(text: str) -> str:
    if BROAD_SCOPE.search(text):
        return "broad"
    if NARROW_SCOPE.search(text):
        return "narrow"
    return "none"


def _trajectory(messages: Sequence[Mapping[str, Any]], window: int = 12) -> dict[str, int | bool]:
    edit_failures = 0
    error_results = 0
    tool_results = 0
    for message in messages[-window:]:
        if message.get("role") != "user" or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if not isinstance(block, Mapping) or block.get("type") != "tool_result":
                continue
            tool_results += 1
            if block.get("is_error"):
                error_results += 1
                if EDIT_FAIL_MARKER in _text_of(block.get("content")):
                    edit_failures += 1
    interrupted = any(
        INTERRUPT_MARKER in _text_of(m.get("content"))
        for m in messages[-3:]
        if m.get("role") == "user"
    )
    return {
        "recent_edit_failures": edit_failures,
        "recent_error_results": error_results,
        "recent_tool_results": tool_results,
        "prev_turn_interrupted": interrupted,
    }


def _parallel_tool_calls(messages: Sequence[Mapping[str, Any]]) -> int:
    for message in reversed(messages):
        if message.get("role") == "assistant" and isinstance(message.get("content"), list):
            return sum(
                1
                for b in message["content"]
                if isinstance(b, Mapping) and b.get("type") == "tool_use"
            )
    return 0


def heuristic_score(
    base: float,
    scope: str,
    context_tokens: int,
    trajectory: Mapping[str, int | bool],
    large_context: float,
) -> float:
    score = base + SCOPE_ADJUST.get(scope, 0.0)
    if context_tokens > large_context:
        score += 0.10
    if int(trajectory["recent_edit_failures"]) >= 1:
        score += 0.15
    if int(trajectory["recent_error_results"]) >= 3:
        score += 0.10
    if bool(trajectory["prev_turn_interrupted"]):
        score += 0.30
    return max(0.0, min(1.0, score))


def task_classes(
    verb: str,
    scope: str,
    context_tokens: int,
    files_mentioned: int,
    thresholds: Mapping[str, float],
) -> tuple[str, ...]:
    """Task classes the turn belongs to, matched against rung boundaries (ADRL-RTG-001)."""
    classes: list[str] = []
    small_context = context_tokens <= thresholds.get("small_context_tokens", 8_000.0)
    if small_context:
        classes.append("small_context")
    if verb in {"trivial", "small_edit"} and scope != "broad":
        classes.append("mechanical_edit")
    if files_mentioned <= thresholds.get("small_diff_max_files", 2.0) and verb in {
        "trivial",
        "small_edit",
        "explain",
    }:
        classes.append("small_diff")
    elif verb in {"write", "fix"} and scope != "broad":
        classes.append("medium_diff")
    if not classes:
        classes.append("large_change")
    return tuple(classes)


def compute_features(
    ctx: RequestContext,
    thresholds: Mapping[str, float],
    *,
    trust: TrustPolicy = UNTRUSTED,
) -> dict[str, Any]:
    """Decision-time feature snapshot for one request.

    ``trust`` is the allow-list of MCP servers whose annotations are honoured (ADRL-CAS-009);
    the default trusts nobody.
    """
    body = ctx.json
    messages_raw = body.get("messages")
    messages: list[Mapping[str, Any]] = (
        [m for m in messages_raw if isinstance(m, Mapping)]
        if isinstance(messages_raw, list)
        else []
    )
    context_chars = _context_chars(body)
    context_tokens = context_chars // CHARS_PER_TOKEN
    user_text = _last_user_text(messages)
    verb, base = verb_class(user_text)
    scope = scope_hint(user_text)
    trajectory = _trajectory(messages)
    files_mentioned = len(set(FILE_MENTION.findall(user_text)))
    defs = tool_definitions(body)
    large_context = thresholds.get("large_context_tokens", 20_000.0)
    score = heuristic_score(base, scope, context_tokens, trajectory, large_context)
    destructive_intent = bool(DESTRUCTIVE_INTENT.search(user_text))
    available_worst = max_available_side_effect(body, trust=trust)
    expected_first_action = (
        SideEffectClass.DESTRUCTIVE
        if destructive_intent and available_worst is not SideEffectClass.READ_ONLY
        else classify_tool("read", {}, None, trust=trust)
        if verb == "explain"
        else SideEffectClass.IDEMPOTENT
        if available_worst is not SideEffectClass.READ_ONLY
        else SideEffectClass.READ_ONLY
    )
    features: dict[str, Any] = {
        "features_version": FEATURES_VERSION,
        "request_class": ctx.request_class.value,
        "interaction_mode": ctx.interaction_mode.value,
        "harness_id": "claude-code" if "x-claude-code-session-id" in ctx.headers else "unknown",
        "is_subagent": ctx.is_subagent,
        "context_chars": context_chars,
        "context_tokens_estimate": context_tokens,
        "n_messages": len(messages),
        "n_tools": len(defs),
        "last_user_text_len": len(user_text),
        "files_mentioned": files_mentioned,
        "verb_class": verb,
        "verb_base_score": base,
        "scope_hint": scope,
        "terse_continue": bool(TERSE_CONTINUE.match(user_text)),
        "heuristic_score": round(score, 4),
        "task_classes": list(
            task_classes(verb, scope, context_tokens, files_mentioned, thresholds)
        ),
        "destructive_intent": destructive_intent,
        "available_side_effect_max": available_worst.value,
        "expected_first_action_side_effect": expected_first_action.value,
        "parallel_tool_calls_last_assistant": _parallel_tool_calls(messages),
        "max_tokens": ctx.max_tokens,
        "is_stream": ctx.is_stream,
        "embedding_missing": True,
        "embedding_missing_reason": "not_computed_at_decision_time",
        **trajectory,
    }
    assert_no_denied_fields(features)
    return features


def assert_no_denied_fields(features: Mapping[str, Any]) -> None:
    """Enforce the LRN-004 deny-list by construction."""
    for key in features:
        if key in DENY_LIST_EXACT or key.startswith(DENY_LIST_PREFIXES):
            raise ValueError(f"feature {key!r} is on the pre-decision deny-list")


def interaction_mode_weight(mode: InteractionMode, weights: Mapping[str, float]) -> float:
    return float(weights.get(mode.value, 1.0))
