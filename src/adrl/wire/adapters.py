"""Harness identity evidence adapters. Primary: ADRL-SEM-002. Secondary: ADRL-SEM-007.

These are correlation signals, not authenticated workload assertions. Existing SAF/TRU
gates retain responsibility for authority. No OpenCode or Codex adapter is installed yet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from adrl.wire.parse import (
    HEADER_AGENT_ID,
    HEADER_PARENT_AGENT_ID,
    HEADER_SESSION_ID,
    system_text,
)
from adrl.wire.profiles.base import RequestView


@dataclass(frozen=True, slots=True)
class IdentitySignals:
    header_session_id: str | None
    metadata_session_id: str | None
    system_text: str
    agent_id: str | None
    parent_agent_id: str | None


class HarnessAdapter(Protocol):
    @property
    def adapter_id(self) -> str: ...

    @property
    def version(self) -> str: ...

    def identity_signals(self, request: RequestView) -> IdentitySignals: ...


def metadata_session_id(request: RequestView) -> str | None:
    """Preserve the current metadata fallback, including opaque non-JSON values."""
    metadata = request.json.get("metadata")
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get("user_id")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        decoded = json.loads(raw)
    except ValueError:
        return raw
    if isinstance(decoded, dict) and isinstance(decoded.get("session_id"), str):
        return str(decoded["session_id"])
    return raw


@dataclass(frozen=True, slots=True)
class ClaudeCodeAdapter:
    """The existing Claude Code correlation rules, extracted without changing identity."""

    adapter_id: str = "claude-code"
    version: str = "1"

    def identity_signals(self, request: RequestView) -> IdentitySignals:
        return IdentitySignals(
            header_session_id=request.headers.get(HEADER_SESSION_ID),
            metadata_session_id=metadata_session_id(request),
            system_text=system_text(request.json),
            agent_id=request.headers.get(HEADER_AGENT_ID),
            parent_agent_id=request.headers.get(HEADER_PARENT_AGENT_ID),
        )
