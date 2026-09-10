"""Per-lineage scan coverage so only new content is scanned. Primary: ADRL-SAF-003.

Coverage is a set of content-free block keys (position plus keyed hash) persisted as
`scan_coverage` lineage events, so a restart does not rescan a prefix that was already scanned.
"""

from __future__ import annotations

from collections.abc import Sequence

from adrl.core.ids import LineageId
from adrl.core.ports import LedgerPort, LineageEvent
from adrl.gates.content import ScanBlock

COVERAGE_EVENT = "scan_coverage"
TAIL_CHARS = 64


class ScanCoverage:
    """Tracks which block keys have been scanned for each lineage."""

    def __init__(self, ledger: LedgerPort) -> None:
        self._ledger = ledger
        self._covered: dict[LineageId, set[str]] = {}
        self._loaded: set[LineageId] = set()
        self._tails: dict[LineageId, str] = {}

    async def _ensure_loaded(self, lineage: LineageId) -> None:
        if lineage in self._loaded:
            return
        covered = self._covered.setdefault(lineage, set())
        for event in await self._ledger.read_lineage_events(lineage, COVERAGE_EVENT):
            keys = event.payload.get("keys", [])
            if isinstance(keys, list):
                covered.update(str(k) for k in keys)
        self._loaded.add(lineage)

    async def new_blocks(self, lineage: LineageId, blocks: Sequence[ScanBlock]) -> list[ScanBlock]:
        await self._ensure_loaded(lineage)
        covered = self._covered.setdefault(lineage, set())
        return [b for b in blocks if b.key not in covered]

    async def mark_scanned(self, lineage: LineageId, blocks: Sequence[ScanBlock]) -> None:
        if not blocks:
            return
        await self._ensure_loaded(lineage)
        covered = self._covered.setdefault(lineage, set())
        keys = [b.key for b in blocks if b.key not in covered]
        if not keys:
            return
        covered.update(keys)
        last_text = next((b.text for b in reversed(blocks) if b.text), "")
        if last_text:
            self._tails[lineage] = last_text[-TAIL_CHARS:]
        await self._ledger.append_lineage_event(
            LineageEvent(lineage_hmac=lineage, event_type=COVERAGE_EVENT, payload={"keys": keys})
        )

    def tail(self, lineage: LineageId) -> str:
        """Last characters of the previously scanned block, held in memory only.

        Prepended to the next scan so a token split across two reads is still seen whole. Never
        persisted.
        """
        return self._tails.get(lineage, "")

    def covered_count(self, lineage: LineageId) -> int:
        return len(self._covered.get(lineage, ()))
