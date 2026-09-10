"""Retention sweep over two storage classes. Primary: ADRL-MEM-010.

Prompt-class artefacts expire after policy.retention_prompt_class_days from the session's last
decision; the sweep shreds the session key and appends an erased event. The evidence skeleton is
kept for policy.retention_skeleton_days; rows past that horizon are counted and reported, never
removed by this code, because row removal needs its own OPS decision on snapshotting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from adrl.config.models import PolicyConfig
from adrl.core.ids import SessionId
from adrl.ledger.erasure import ErasureReceipt, ErasureService
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore

RETENTION_REASON = "retention_expiry"


@dataclass(frozen=True, slots=True)
class SweepReport:
    now: str
    prompt_class_days: int
    skeleton_days: int
    erased: tuple[ErasureReceipt, ...] = field(default_factory=tuple)
    skeleton_expired_routes: int = 0


class RetentionSweeper:
    def __init__(self, store: LedgerStore, keystore: FileKeyStore, policy: PolicyConfig) -> None:
        self._store = store
        self._keystore = keystore
        self._policy = policy
        self._erasure = ErasureService(store, keystore)

    def expired_sessions(self, now: datetime) -> list[SessionId]:
        cutoff = (now - timedelta(days=self._policy.retention_prompt_class_days)).isoformat()
        rows = self._store.read(
            "SELECT session_hmac, MAX(ts) AS last_ts FROM ("
            "SELECT session_hmac, ts FROM embeddings UNION ALL "
            "SELECT session_hmac, ts FROM decisions) GROUP BY session_hmac HAVING last_ts < ?",
            (cutoff,),
        )
        out: list[SessionId] = []
        for row in rows:
            session = SessionId(str(row["session_hmac"]))
            if self._keystore.has_session_key(session):
                out.append(session)
        return out

    def skeleton_expired(self, now: datetime) -> int:
        cutoff = (now - timedelta(days=self._policy.retention_skeleton_days)).isoformat()
        row = self._store.read("SELECT COUNT(*) AS c FROM decisions WHERE ts < ?", (cutoff,))[0]
        return int(row["c"])

    async def sweep(self, *, now: datetime | None = None) -> SweepReport:
        current = now or datetime.now(UTC)
        receipts: list[ErasureReceipt] = []
        for session in self.expired_sessions(current):
            receipts.append(await self._erasure.erase_session(session, RETENTION_REASON))
        return SweepReport(
            now=current.isoformat(),
            prompt_class_days=self._policy.retention_prompt_class_days,
            skeleton_days=self._policy.retention_skeleton_days,
            erased=tuple(receipts),
            skeleton_expired_routes=self.skeleton_expired(current),
        )
