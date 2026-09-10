"""Retroactive suppression hook for pinned lineages. Primary: ADRL-SAF-003. Secondary: ADRL-MEM-005.

When a lineage is pinned, embeddings and keyed hashes already stored for earlier turns must be
shredded. The gates package only knows that this must happen; the ledger package owns the
erasure. This port is the seam between them.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import structlog

from adrl.core.ids import LineageId, SessionId

log = structlog.get_logger(__name__)


@runtime_checkable
class SuppressionSink(Protocol):
    async def suppress_lineage(self, lineage: LineageId, session: SessionId, reason: str) -> None:
        """Shred prompt-class artefacts for the lineage; must survive a crash mid-delete."""
        ...


class LoggingSuppressionSink:
    """Default sink until the ledger's erasure adapter is wired: records the obligation."""

    def __init__(self) -> None:
        self.calls: list[tuple[LineageId, SessionId, str]] = []

    async def suppress_lineage(self, lineage: LineageId, session: SessionId, reason: str) -> None:
        self.calls.append((lineage, session, reason))
        log.warning(
            "suppression_pending",
            lineage=lineage,
            reason=reason,
            note="no erasure adapter wired; TODO(ADRL-MEM-010) ledger builder provides one",
        )
