"""Deterministic post-call trip-wires. Primary: ADRL-CAS-001. Secondary: ADRL-CAS-002.

Wire classes (a) repeated or alternating tool calls, (b) schema or dialect-invalid calls typed
harness_dialect, (c) tool-error repetition, (d) attempt-budget exhaustion with no verifiable
progress, (e) deterministic verifier failure. Model-authored text is never a wire.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from adrl.config.models import PolicyConfig, TripwiresConfig, WireThresholds
from adrl.core.enums import FailureType, OutcomeState, Rung
from adrl.ledger.store import LedgerStore
from adrl.routing.side_effects import turn_start_index

if TYPE_CHECKING:
    from adrl.wire.observe import ResponseObservation

TRIPWIRE_EVENT = "tripwire_fired"

EDIT_FAIL_MARKER = "String to replace not found in file"
SCHEMA_ERROR_MARKERS: tuple[str, ...] = (
    "input validation error",
    "does not match the required schema",
    "invalid tool name",
    "InputValidationError",
)
READ_TOOLS: frozenset[str] = frozenset(
    {"read", "read_file", "readfile", "view", "view_file", "cat", "open_file", "glob", "grep"}
)
EDIT_TOOLS: frozenset[str] = frozenset(
    {
        "edit",
        "multiedit",
        "write",
        "str_replace",
        "str_replace_editor",
        "str_replace_based_edit_tool",
        "apply_patch",
        "create_file",
        "notebookedit",
    }
)
RESOURCE_KEYS: tuple[str, ...] = ("file_path", "path", "filename", "notebook_path", "file")


class WireClass(StrEnum):
    REPEATED_TOOL_CALLS = "a_repeated_tool_calls"
    INVALID_TOOL_CALLS = "b_invalid_tool_calls"
    TOOL_ERROR_REPEATS = "c_tool_error_repeats"
    ATTEMPT_BUDGET_EXHAUSTED = "d_attempt_budget_exhausted"
    VERIFIER_FAILURE = "e_verifier_failure"

    @property
    def failure_type(self) -> FailureType:
        return (
            FailureType.HARNESS_DIALECT
            if self is WireClass.INVALID_TOOL_CALLS
            else FailureType.TASK_CAPABILITY
        )


@dataclass(frozen=True, slots=True)
class WireHit:
    wire: WireClass
    rung: Rung
    threshold: int | bool
    observed: int
    failure_type: FailureType
    detail: str
    tripwires_version: str

    def as_record(self) -> dict[str, Any]:
        return {
            "wire": self.wire.value,
            "rung": self.rung.value,
            "threshold": self.threshold,
            "observed": self.observed,
            "failure_type": self.failure_type.value,
            "detail": self.detail,
            "tripwires_version": self.tripwires_version,
        }


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool_use_id: str
    name: str
    canonical: str
    input_parse_ok: bool


@dataclass(frozen=True, slots=True)
class ToolResultView:
    tool_use_id: str
    is_error: bool
    content_hash: str
    text: str


def canonical_call(name: str, tool_input: Any) -> str:
    """Canonical call form so replays agree on sameness (sorted keys, no trailing slash)."""

    def norm(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {k: norm(v) for k, v in sorted(value.items())}
        if isinstance(value, list):
            return [norm(v) for v in value]
        if isinstance(value, str):
            stripped = value.strip()
            return stripped[:-1] if len(stripped) > 1 and stripped.endswith("/") else stripped
        return value

    return name.lower() + ":" + json.dumps(norm(tool_input), sort_keys=True, separators=(",", ":"))


def _hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]  # noqa: S324


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(b.get("text", ""))
            for b in content
            if isinstance(b, Mapping) and b.get("type") == "text"
        )
    return ""


def turn_calls_and_results(
    body: Mapping[str, Any],
) -> tuple[list[ToolCall], dict[str, ToolResultView]]:
    messages_raw = body.get("messages")
    messages: list[Mapping[str, Any]] = (
        [m for m in messages_raw if isinstance(m, Mapping)]
        if isinstance(messages_raw, list)
        else []
    )
    start = turn_start_index(messages)
    calls: list[ToolCall] = []
    results: dict[str, ToolResultView] = {}
    for message in messages[start:]:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        if message.get("role") == "assistant":
            for block in content:
                if isinstance(block, Mapping) and block.get("type") == "tool_use":
                    tool_input = block.get("input")
                    calls.append(
                        ToolCall(
                            tool_use_id=str(block.get("id") or ""),
                            name=str(block.get("name") or ""),
                            canonical=canonical_call(str(block.get("name") or ""), tool_input),
                            input_parse_ok=isinstance(tool_input, Mapping),
                        )
                    )
        elif message.get("role") == "user":
            for block in content:
                if isinstance(block, Mapping) and block.get("type") == "tool_result":
                    text = _text_of(block.get("content"))
                    results[str(block.get("tool_use_id") or "")] = ToolResultView(
                        tool_use_id=str(block.get("tool_use_id") or ""),
                        is_error=bool(block.get("is_error")),
                        content_hash=_hash(text),
                        text=text,
                    )
    return calls, results


def _resource(call_canonical: str) -> str | None:
    try:
        payload = json.loads(call_canonical.split(":", 1)[1])
    except (ValueError, IndexError):
        return None
    if isinstance(payload, Mapping):
        for key in RESOURCE_KEYS:
            value = payload.get(key)
            if isinstance(value, str):
                return value
    return None


class TripwireEvaluator:
    def __init__(self, tripwires: TripwiresConfig, policy: PolicyConfig) -> None:
        self._config = tripwires
        self._policy = policy

    @property
    def version(self) -> str:
        return self._config.version

    def thresholds(self, rung: Rung) -> WireThresholds:
        return self._config.by_rung[rung]

    def verifier_failure(self, rung: Rung) -> WireHit | None:
        """Wire class (e): a deterministic verifier failure fires on its own (ADRL-CAS-001)."""
        if not self.thresholds(rung).verifier_failure:
            return None
        return WireHit(
            WireClass.VERIFIER_FAILURE,
            rung,
            True,
            1,
            FailureType.TASK_CAPABILITY,
            "deterministic verifier reported failure",
            self.version,
        )

    def evaluate(
        self,
        body: Mapping[str, Any],
        rung: Rung,
        *,
        observation: ResponseObservation | None = None,
        verifier_failed: bool = False,
        wall_clock_s: float | None = None,
    ) -> tuple[WireHit, ...]:
        t = self.thresholds(rung)
        calls, results = turn_calls_and_results(body)
        hits: list[WireHit] = []
        hits.extend(self._repeated(calls, results, rung, t))
        hits.extend(self._invalid(calls, results, rung, t, observation))
        hits.extend(self._error_repeats(calls, results, rung, t))
        hits.extend(self._attempt_budget(calls, results, rung, t, wall_clock_s))
        if verifier_failed and t.verifier_failure:
            hits.append(
                WireHit(
                    WireClass.VERIFIER_FAILURE,
                    rung,
                    True,
                    1,
                    FailureType.TASK_CAPABILITY,
                    "deterministic verifier reported failure",
                    self.version,
                )
            )
        return tuple(hits)

    def _repeated(
        self,
        calls: Sequence[ToolCall],
        results: Mapping[str, ToolResultView],
        rung: Rung,
        t: WireThresholds,
    ) -> list[WireHit]:
        if not calls:
            return []
        # identical consecutive calls, allowing a long-running command whose observation changes
        run = 1
        best = 1
        for prev, cur in itertools.pairwise(calls):
            if cur.canonical == prev.canonical and not self._observation_changed(
                prev, cur, results, t
            ):
                run += 1
            else:
                run = 1
            best = max(best, run)
        detail = "identical consecutive tool calls"
        # alternating A,B,A,B
        alt = 1
        for i in range(2, len(calls)):
            if (
                calls[i].canonical == calls[i - 2].canonical
                and calls[i].canonical != calls[i - 1].canonical
            ):
                alt += 1
            else:
                alt = 1
            if alt > best:
                best = alt
                detail = "alternating tool calls"
        if best >= t.repeated_tool_calls:
            return [
                WireHit(
                    WireClass.REPEATED_TOOL_CALLS,
                    rung,
                    t.repeated_tool_calls,
                    best,
                    FailureType.TASK_CAPABILITY,
                    detail,
                    self.version,
                )
            ]
        return []

    @staticmethod
    def _observation_changed(
        prev: ToolCall, cur: ToolCall, results: Mapping[str, ToolResultView], t: WireThresholds
    ) -> bool:
        a = results.get(prev.tool_use_id)
        b = results.get(cur.tool_use_id)
        if a is None or b is None:
            return False
        return a.content_hash != b.content_hash and not a.is_error and not b.is_error

    def _invalid(
        self,
        calls: Sequence[ToolCall],
        results: Mapping[str, ToolResultView],
        rung: Rung,
        t: WireThresholds,
        observation: ResponseObservation | None,
    ) -> list[WireHit]:
        count = sum(1 for c in calls if not c.input_parse_ok)
        for call in calls:
            result = results.get(call.tool_use_id)
            if result is None or not result.is_error:
                continue
            if EDIT_FAIL_MARKER in result.text or any(
                m in result.text for m in SCHEMA_ERROR_MARKERS
            ):
                count += 1
        if observation is not None and observation.malformed_tool_json:
            count += 1
        if count >= t.invalid_tool_calls:
            return [
                WireHit(
                    WireClass.INVALID_TOOL_CALLS,
                    rung,
                    t.invalid_tool_calls,
                    count,
                    FailureType.HARNESS_DIALECT,
                    "schema or dialect-invalid tool calls",
                    self.version,
                )
            ]
        return []

    def _error_repeats(
        self,
        calls: Sequence[ToolCall],
        results: Mapping[str, ToolResultView],
        rung: Rung,
        t: WireThresholds,
    ) -> list[WireHit]:
        run = 0
        best = 0
        last_name = None
        for call in calls:
            result = results.get(call.tool_use_id)
            if result is not None and result.is_error:
                run = run + 1 if call.name == last_name or last_name is None else 1
                last_name = call.name
            else:
                run = 0
                last_name = None
            best = max(best, run)
        if best >= t.tool_error_repeats:
            return [
                WireHit(
                    WireClass.TOOL_ERROR_REPEATS,
                    rung,
                    t.tool_error_repeats,
                    best,
                    FailureType.TASK_CAPABILITY,
                    "repeated tool errors",
                    self.version,
                )
            ]
        return []

    def _attempt_budget(
        self,
        calls: Sequence[ToolCall],
        results: Mapping[str, ToolResultView],
        rung: Rung,
        t: WireThresholds,
        wall_clock_s: float | None,
    ) -> list[WireHit]:
        if not t.attempt_budget_exhausted:
            return []
        budget = self._policy.local_attempt_budget
        exhausted = False
        observed = len(calls)
        if budget.unit == "tool_calls" and len(calls) >= budget.limit:
            exhausted = True
        if wall_clock_s is not None and wall_clock_s >= budget.wall_clock_cap_s:
            exhausted = True
            observed = int(wall_clock_s)
        if not exhausted:
            return []
        if self._made_progress(calls, results):
            return []
        return [
            WireHit(
                WireClass.ATTEMPT_BUDGET_EXHAUSTED,
                rung,
                budget.limit,
                observed,
                FailureType.TASK_CAPABILITY,
                "attempt budget exhausted with no verifiable progress",
                self.version,
            )
        ]

    @staticmethod
    def _made_progress(calls: Sequence[ToolCall], results: Mapping[str, ToolResultView]) -> bool:
        """Progress: a new file read, a successful edit or a new non-error output, recently."""
        seen_reads: set[str] = set()
        seen_hashes: set[str] = set()
        progress_at: list[int] = []
        for index, call in enumerate(calls):
            result = results.get(call.tool_use_id)
            if result is None or result.is_error:
                continue
            name = call.name.lower()
            resource = _resource(call.canonical)
            if name in READ_TOOLS and resource and resource not in seen_reads:
                seen_reads.add(resource)
                progress_at.append(index)
            elif name in EDIT_TOOLS:
                progress_at.append(index)
            elif result.content_hash not in seen_hashes:
                seen_hashes.add(result.content_hash)
                progress_at.append(index)
        if not progress_at:
            return False
        return progress_at[-1] >= (2 * len(calls)) // 3


def coverage_report(store: LedgerStore) -> dict[str, Any]:
    """Trip-wire miss rate and false-fire rate per rung over closed_final verified outcomes."""
    fired: dict[str, set[str]] = {}
    for row in store.read(
        "SELECT route_id, payload_json FROM events WHERE event_type = ?", (TRIPWIRE_EVENT,)
    ):
        payload = json.loads(row["payload_json"])
        fired.setdefault(row["route_id"], set()).add(str(payload.get("wire")))
    stats: dict[str, dict[str, int]] = {}
    for row in store.read(
        "SELECT route_id, payload_json FROM events WHERE event_type = ?",
        (OutcomeState.CLOSED_FINAL.value,),
    ):
        payload = json.loads(row["payload_json"])
        if not payload.get("verified"):
            continue
        rung = str(payload.get("rung") or "unknown")
        bucket = stats.setdefault(
            rung, {"verified_failures": 0, "missed": 0, "verified_successes": 0, "false_fires": 0}
        )
        had_wire = row["route_id"] in fired
        if payload.get("success"):
            bucket["verified_successes"] += 1
            if had_wire:
                bucket["false_fires"] += 1
        else:
            bucket["verified_failures"] += 1
            if not had_wire:
                bucket["missed"] += 1
    report: dict[str, Any] = {}
    for rung, b in stats.items():
        report[rung] = {
            **b,
            "miss_rate": (b["missed"] / b["verified_failures"]) if b["verified_failures"] else None,
            "false_fire_rate": (b["false_fires"] / b["verified_successes"])
            if b["verified_successes"]
            else None,
        }
    return report
