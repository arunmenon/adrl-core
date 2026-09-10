"""Crypto-shredding by session and pin-triggered suppression. Primary: ADRL-MEM-010.
Also implements: ADRL-OPS-004 (register additions of 2026-09-03).

Secondary: ADRL-MEM-005 (retroactive suppression), ADRL-SAF-002, ADRL-MEM-007 (projection
invalidation). Erasing a session deletes its key and appends an erased event naming the session
and reason; the ledger rows remain, unreadable. The route_id skeleton is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

from adrl.core.ids import LineageId, SessionId
from adrl.ledger.embeddings import embedding_row_count
from adrl.ledger.events import ERASED_EVENT
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore

log = structlog.get_logger(__name__)

ERASURE_SCHEMA_VERSION = "erasure-v1"


@dataclass(frozen=True, slots=True)
class ErasureReceipt:
    session_hmac: SessionId
    reason: str
    key_shredded: bool
    embedding_rows: int
    erased_seq: int


class ErasureService:
    """Erasure by retention expiry, late pin, or explicit request. Only appends and removes keys."""

    def __init__(self, store: LedgerStore, keystore: FileKeyStore) -> None:
        self._store = store
        self._keystore = keystore

    async def erase_session(self, session: SessionId, reason: str) -> ErasureReceipt:
        rows = embedding_row_count(self._store, session)
        shredded = self._keystore.shred_session_key(session, reason)
        seq = int(
            await self._store.write_through(
                LedgerStore.insert_lineage_event(
                    str(session),
                    ERASED_EVENT,
                    {
                        "session_hmac": str(session),
                        "reason": reason,
                        "embedding_rows": rows,
                        "key_shredded": shredded,
                        "schema_version": ERASURE_SCHEMA_VERSION,
                    },
                )
            )
        )
        log.info("session_erased", reason=reason, embedding_rows=rows, key_shredded=shredded)
        return ErasureReceipt(session, reason, shredded, rows, seq)

    def sessions_for_lineage(self, lineage: LineageId) -> list[SessionId]:
        rows = self._store.read(
            "SELECT DISTINCT session_hmac FROM decisions WHERE lineage_hmac=? OR session_hmac=?",
            (str(lineage), str(lineage)),
        )
        sessions = {SessionId(str(r["session_hmac"])) for r in rows}
        embedded = self._store.read(
            "SELECT DISTINCT session_hmac FROM embeddings WHERE session_hmac=?", (str(lineage),)
        )
        sessions.update(SessionId(str(r["session_hmac"])) for r in embedded)
        if not sessions:
            sessions.add(SessionId(str(lineage)))
        return sorted(sessions)

    async def suppress(self, lineage: LineageId, session: SessionId | None, reason: str) -> int:
        """Shred prompt-class artefacts for every session under a lineage; returns rows shredded.

        The pin is lineage-scoped but the key is per session, so shredding is conservative:
        sibling lineages of the same session lose their vectors too, and the session never
        receives a new key.
        """
        sessions = set(self.sessions_for_lineage(lineage))
        if session is not None:
            sessions.add(session)
        total = 0
        for target in sorted(sessions):
            receipt = await self.erase_session(target, reason)
            total += receipt.embedding_rows
        return total

    async def suppress_lineage(
        self, lineage: LineageId, session: SessionId | None = None, reason: str = "privacy_pin"
    ) -> None:
        """SuppressionSink adapter for the gates package (ADRL-SAF-003 retroactive suppression)."""
        await self.suppress(lineage, session, reason)
