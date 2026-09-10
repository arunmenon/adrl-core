"""Response observation on the relayed byte stream. Primary: ADRL-CAS-006.
Also implements: ADRL-OPS-006 (served identity, not intended).
Also implements: ADRL-TRU-002 (register additions of 2026-09-03).

Secondary: ADRL-CAS-003 (first streamed tool content), ADRL-RTG-009 (cache usage),
ADRL-FND-001 (bytes are observed, never altered).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from adrl.config.models import RungsConfig
from adrl.core.enums import Rung, ServedSource
from adrl.core.types import ServedIdentity, Usage


@dataclass(frozen=True, slots=True)
class ToolUseSummary:
    id: str
    name: str
    input_hash: str
    input_size: int
    input_parse_ok: bool


@dataclass(frozen=True, slots=True)
class ResponseObservation:
    status: int
    served: ServedIdentity
    usage: Usage | None
    stop_reason: str | None
    streamed_tool_content: bool
    tool_uses: tuple[ToolUseSummary, ...]
    error: dict[str, Any] | None
    first_byte_at: float | None
    completed: bool
    malformed_tool_json: bool
    model_reported: str | None
    bytes_relayed: int = 0


@dataclass
class _ToolBlock:
    id: str
    name: str
    parts: list[str] = field(default_factory=list)
    initial_input: Any = None


def _hash_input(value: Any, key: bytes | None) -> str:
    """Keyed hash of a tool input (ADRL-MEM-005): never a plain digest a dictionary can invert."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    if key:
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()[:24]
    return "unkeyed:" + hashlib.sha256(canonical).hexdigest()[:16]


def served_identity(
    headers: Mapping[str, str],
    model_reported: str | None,
    *,
    intended_rung: Rung,
    requested_model: str,
    rungs: RungsConfig,
) -> ServedIdentity:
    """Gateway header first, then the model the response reported, else assumed intended."""
    header_name = rungs.gateway_served_model_header.lower()
    reported = None
    for key, value in headers.items():
        if key.lower() == header_name:
            reported = value
            break
    if reported:
        group = reported.split("/", 1)[0]
        model = reported.split("/", 1)[1] if "/" in reported else reported
        rung = rungs.group_to_rung.get(group, intended_rung)
        provider = _provider_for(model)
        return ServedIdentity(rung, model, provider, ServedSource.GATEWAY_REPORTED)
    if model_reported:
        return ServedIdentity(
            intended_rung,
            model_reported,
            _provider_for(model_reported),
            ServedSource.PROXY_OBSERVED,
        )
    return ServedIdentity.assumed(intended_rung, requested_model)


def _provider_for(model: str) -> str | None:
    lowered = model.lower()
    if lowered.startswith("claude"):
        return "anthropic"
    if lowered.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    if "/" in lowered:
        return lowered.split("/", 1)[0]
    return None


class SseObserver:
    """Consumes the same chunks the relay forwards and reconstructs what matters.

    Nothing here alters bytes. Partial lines across chunks are buffered. Unknown events are
    ignored. A tool_use block whose accumulated JSON does not parse is recorded as malformed so a
    dialect trip-wire can fire (ADRL-CAS-001).
    """

    def __init__(
        self,
        *,
        status: int,
        headers: Mapping[str, str],
        intended_rung: Rung,
        requested_model: str,
        rungs: RungsConfig,
        hash_key: bytes | None = None,
    ) -> None:
        self._hash_key = hash_key
        self._status = status
        self._headers = dict(headers)
        self._intended_rung = intended_rung
        self._requested_model = requested_model
        self._rungs = rungs
        self._buffer = b""
        self._usage: Usage | None = None
        self._stop_reason: str | None = None
        self._model: str | None = None
        self._streamed_tool = False
        self._tools: dict[int, _ToolBlock] = {}
        self._summaries: list[ToolUseSummary] = []
        self._error: dict[str, Any] | None = None
        self._first_byte_at: float | None = None
        self._completed = False
        self._malformed = False
        self._bytes = 0
        self._current_event: str | None = None

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        if self._first_byte_at is None:
            self._first_byte_at = time.monotonic()
        self._bytes += len(chunk)
        self._buffer += chunk
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                break
            line = self._buffer[:newline].rstrip(b"\r")
            self._buffer = self._buffer[newline + 1 :]
            self._line(line)

    def _line(self, line: bytes) -> None:
        if line.startswith(b"event:"):
            self._current_event = line[6:].strip().decode("utf-8", "replace")
            return
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return
        try:
            event = json.loads(payload)
        except ValueError:
            return
        if isinstance(event, dict):
            self._event(event)

    def _event(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "message_start":
            message = event.get("message") or {}
            if isinstance(message.get("model"), str):
                self._model = message["model"]
            self._usage = Usage.from_anthropic(message.get("usage"))
        elif kind == "content_block_start":
            block = event.get("content_block") or {}
            index = int(event.get("index", 0))
            if block.get("type") == "tool_use":
                self._streamed_tool = True
                self._tools[index] = _ToolBlock(
                    id=str(block.get("id", "")),
                    name=str(block.get("name", "")),
                    initial_input=block.get("input"),
                )
        elif kind == "content_block_delta":
            delta = event.get("delta") or {}
            index = int(event.get("index", 0))
            if delta.get("type") == "input_json_delta" and index in self._tools:
                self._tools[index].parts.append(str(delta.get("partial_json", "")))
        elif kind == "content_block_stop":
            index = int(event.get("index", 0))
            tool_block = self._tools.pop(index, None)
            if tool_block is not None:
                self._summaries.append(self._summarise(tool_block))
        elif kind == "message_delta":
            delta = event.get("delta") or {}
            if isinstance(delta.get("stop_reason"), str):
                self._stop_reason = delta["stop_reason"]
            usage = Usage.from_anthropic(event.get("usage"))
            self._usage = usage if self._usage is None else self._usage.merged(usage)
        elif kind == "message_stop":
            self._completed = True
        elif kind == "error":
            self._error = event

    def _summarise(self, block: _ToolBlock) -> ToolUseSummary:
        raw = "".join(block.parts)
        if raw:
            try:
                parsed: Any = json.loads(raw)
                ok = True
            except ValueError:
                parsed = raw
                ok = False
                self._malformed = True
        else:
            parsed = block.initial_input if block.initial_input is not None else {}
            ok = isinstance(parsed, dict)
        return ToolUseSummary(
            id=block.id,
            name=block.name,
            input_hash=_hash_input(parsed, self._hash_key),
            input_size=len(raw) if raw else len(json.dumps(parsed, default=str)),
            input_parse_ok=ok,
        )

    def finish(self) -> ResponseObservation:
        if self._buffer:
            self._line(self._buffer.rstrip(b"\r"))
            self._buffer = b""
        for block in list(self._tools.values()):
            self._summaries.append(self._summarise(block))
        self._tools.clear()
        return ResponseObservation(
            status=self._status,
            served=served_identity(
                self._headers,
                self._model,
                intended_rung=self._intended_rung,
                requested_model=self._requested_model,
                rungs=self._rungs,
            ),
            usage=self._usage,
            stop_reason=self._stop_reason,
            streamed_tool_content=self._streamed_tool,
            tool_uses=tuple(self._summaries),
            error=self._error,
            first_byte_at=self._first_byte_at,
            completed=self._completed,
            malformed_tool_json=self._malformed,
            model_reported=self._model,
            bytes_relayed=self._bytes,
        )


def observe_json(
    body: bytes,
    *,
    status: int,
    headers: Mapping[str, str],
    intended_rung: Rung,
    requested_model: str,
    rungs: RungsConfig,
    first_byte_at: float | None = None,
    hash_key: bytes | None = None,
) -> ResponseObservation:
    """Observation of a non-streaming response body."""
    try:
        data = json.loads(body) if body else {}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    error = data if data.get("type") == "error" else None
    model = data.get("model") if isinstance(data.get("model"), str) else None
    summaries: list[ToolUseSummary] = []
    streamed = False
    malformed = False
    for block in data.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            streamed = True
            tool_input = block.get("input")
            ok = isinstance(tool_input, dict)
            malformed = malformed or not ok
            summaries.append(
                ToolUseSummary(
                    id=str(block.get("id", "")),
                    name=str(block.get("name", "")),
                    input_hash=_hash_input(tool_input, hash_key),
                    input_size=len(json.dumps(tool_input, default=str)),
                    input_parse_ok=ok,
                )
            )
    return ResponseObservation(
        status=status,
        served=served_identity(
            headers,
            model,
            intended_rung=intended_rung,
            requested_model=requested_model,
            rungs=rungs,
        ),
        usage=Usage.from_anthropic(data.get("usage")) if "usage" in data else None,
        stop_reason=data.get("stop_reason") if isinstance(data.get("stop_reason"), str) else None,
        streamed_tool_content=streamed,
        tool_uses=tuple(summaries),
        error=error,
        first_byte_at=first_byte_at,
        completed=error is None and bool(data),
        malformed_tool_json=malformed,
        model_reported=model,
        bytes_relayed=len(body),
    )
