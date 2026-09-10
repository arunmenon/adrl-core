"""Rebuildable, stamped NumPy retrieval projection. Primary: ADRL-MEM-007.

Secondary: ADRL-MEM-010 (erasure reaches projections), ADRL-LRN-004 (as-of rebuilds).

Identity of a projection is (ledger high-water mark, embedder version, projection code version).
Stale is a labelled state, not an error; invalid means a stamp mismatch or an erasure the index
has not absorbed, and retrieval abstains. Cross-process change detection uses PRAGMA data_version
on the store's long-lived reader connection, never file timestamps.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from adrl.core.enums import ProjectionState
from adrl.core.ids import RouteId, SessionId
from adrl.ledger.embeddings import StoredVector, max_embedding_seq, read_vectors
from adrl.ledger.events import ERASED_EVENT
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore, utc_now_iso

PROJECTION_CODE_VERSION = "projection-v1"
PROJECTION_NAME = "numpy-knn"
EQUIVALENCE_TOLERANCE = 1e-9


@dataclass(frozen=True, slots=True)
class ProjectionStamp:
    high_water_seq: int
    embedder_version: str
    code_version: str
    erasure_seq: int

    def as_record(self) -> dict[str, Any]:
        return {
            "high_water_seq": self.high_water_seq,
            "embedder_version": self.embedder_version,
            "code_version": self.code_version,
            "erasure_seq": self.erasure_seq,
        }


def max_erasure_seq(store: LedgerStore) -> int:
    row = store.read(
        "SELECT MAX(seq) AS m FROM lineage_events WHERE event_type=?", (ERASED_EVENT,)
    )[0]
    return int(row["m"] or 0)


def erased_sessions_since(store: LedgerStore, after_seq: int) -> list[SessionId]:
    rows = store.read(
        "SELECT lineage_hmac FROM lineage_events WHERE event_type=? AND seq>? ORDER BY seq",
        (ERASED_EVENT, after_seq),
    )
    return [SessionId(str(r["lineage_hmac"])) for r in rows]


@dataclass(frozen=True, slots=True)
class Neighbour:
    route_id: RouteId
    similarity: float


class NumpyIndex:
    """In-memory cosine index over readable embeddings, with identity stamps."""

    def __init__(self, store: LedgerStore, keystore: FileKeyStore, embedder_version: str) -> None:
        self._store = store
        self._keystore = keystore
        self._embedder_version = embedder_version
        self._route_ids: list[RouteId] = []
        self._sessions: list[SessionId] = []
        self._matrix: np.ndarray = np.zeros((0, 0), dtype=np.float64)
        self._stamp: ProjectionStamp | None = None
        self._last_data_version: int | None = None

    # identity ----------------------------------------------------------------------------

    @property
    def stamp(self) -> ProjectionStamp | None:
        return self._stamp

    @property
    def size(self) -> int:
        return len(self._route_ids)

    @property
    def route_ids(self) -> tuple[RouteId, ...]:
        return tuple(self._route_ids)

    def vectors(self) -> np.ndarray:
        return self._matrix.copy()

    def state(self) -> ProjectionState:
        if self._stamp is None:
            return ProjectionState.INVALID
        if (
            self._stamp.embedder_version != self._embedder_version
            or self._stamp.code_version != PROJECTION_CODE_VERSION
            or max_erasure_seq(self._store) > self._stamp.erasure_seq
        ):
            return ProjectionState.INVALID
        if max_embedding_seq(self._store) > self._stamp.high_water_seq:
            return ProjectionState.STALE
        return ProjectionState.VALID

    def ledger_changed(self) -> bool:
        """Cross-process change detection through the reader connection (clause: data_version)."""
        current = self._store.data_version()
        changed = self._last_data_version is not None and current != self._last_data_version
        self._last_data_version = current
        return changed

    # building ----------------------------------------------------------------------------

    def _load(self, vectors: Sequence[StoredVector]) -> None:
        self._route_ids = [v.route_id for v in vectors]
        self._sessions = [v.session_hmac for v in vectors]
        if vectors:
            self._matrix = np.vstack([v.vector for v in vectors])
        else:
            self._matrix = np.zeros((0, 0), dtype=np.float64)

    def rebuild(self, *, as_of_seq: int | None = None) -> ProjectionStamp:
        """Full rebuild, optionally as of a ledger position (ADRL-LRN-004)."""
        high_water = as_of_seq if as_of_seq is not None else max_embedding_seq(self._store)
        vectors = read_vectors(
            self._store,
            self._keystore,
            up_to_seq=high_water,
            embedder_version=self._embedder_version,
        )
        self._load(vectors)
        self._stamp = ProjectionStamp(
            high_water,
            self._embedder_version,
            PROJECTION_CODE_VERSION,
            max_erasure_seq(self._store),
        )
        self._last_data_version = self._store.data_version()
        return self._stamp

    def refresh(self) -> ProjectionStamp:
        """Incremental refresh: append new vectors, drop erased sessions. Equivalent to rebuild."""
        if (
            self._stamp is None
            or self._stamp.embedder_version != self._embedder_version
            or self._stamp.code_version != PROJECTION_CODE_VERSION
        ):
            return self.rebuild()
        erased = set(erased_sessions_since(self._store, self._stamp.erasure_seq))
        keep = [i for i, s in enumerate(self._sessions) if s not in erased]
        if len(keep) != len(self._sessions):
            self._route_ids = [self._route_ids[i] for i in keep]
            self._sessions = [self._sessions[i] for i in keep]
            self._matrix = self._matrix[keep] if keep else np.zeros((0, 0), dtype=np.float64)
        new = read_vectors(
            self._store,
            self._keystore,
            after_seq=self._stamp.high_water_seq,
            embedder_version=self._embedder_version,
        )
        if new:
            rows = np.vstack([v.vector for v in new])
            self._matrix = rows if self._matrix.size == 0 else np.vstack([self._matrix, rows])
            self._route_ids.extend(v.route_id for v in new)
            self._sessions.extend(v.session_hmac for v in new)
        self._stamp = ProjectionStamp(
            max(self._stamp.high_water_seq, max_embedding_seq(self._store)),
            self._embedder_version,
            PROJECTION_CODE_VERSION,
            max_erasure_seq(self._store),
        )
        self._last_data_version = self._store.data_version()
        return self._stamp

    def equivalent(self, other: NumpyIndex, *, tolerance: float = EQUIVALENCE_TOLERANCE) -> bool:
        """Metric equivalence: same routes, cosine distance under tolerance for every row."""
        if self._route_ids != other._route_ids:
            return False
        if self._matrix.shape != other._matrix.shape:
            return False
        if self._matrix.size == 0:
            return True
        a = self._matrix / np.maximum(np.linalg.norm(self._matrix, axis=1, keepdims=True), 1e-12)
        b = other._matrix / np.maximum(np.linalg.norm(other._matrix, axis=1, keepdims=True), 1e-12)
        cosine_distance = 1.0 - np.sum(a * b, axis=1)
        return bool(np.all(cosine_distance <= tolerance))

    # persistence -------------------------------------------------------------------------

    async def persist_stamp(self) -> int:
        if self._stamp is None:
            return 0
        stamp = self._stamp
        state = self.state().value

        def write(conn: sqlite3.Connection) -> int:
            cursor = conn.execute(
                "INSERT INTO projections (name, high_water_seq, embedder_version, code_version, "
                "state, ts) VALUES (?,?,?,?,?,?)",
                (
                    PROJECTION_NAME,
                    stamp.high_water_seq,
                    stamp.embedder_version,
                    stamp.code_version,
                    state,
                    utc_now_iso(),
                ),
            )
            return int(cursor.lastrowid or 0)

        return int(await self._store.write_through(write))

    @staticmethod
    def stored_stamp_state(store: LedgerStore, embedder_version: str) -> ProjectionState:
        """Validity of the most recently persisted stamp, without loading vectors."""
        rows = store.read(
            "SELECT * FROM projections WHERE name=? ORDER BY seq DESC LIMIT 1", (PROJECTION_NAME,)
        )
        if not rows:
            return ProjectionState.INVALID
        row = rows[0]
        if (
            str(row["embedder_version"]) != embedder_version
            or str(row["code_version"]) != PROJECTION_CODE_VERSION
        ):
            return ProjectionState.INVALID
        erasures_after = store.read(
            "SELECT COUNT(*) AS c FROM lineage_events WHERE event_type=? AND ts>?",
            (ERASED_EVENT, str(row["ts"])),
        )[0]["c"]
        if int(erasures_after) > 0:
            return ProjectionState.INVALID
        if max_embedding_seq(store) > int(row["high_water_seq"]):
            return ProjectionState.STALE
        return ProjectionState.VALID

    # query -------------------------------------------------------------------------------

    def query(
        self, vector: Sequence[float], k: int = 5, *, exclude: RouteId | None = None
    ) -> list[Neighbour]:
        if self._matrix.size == 0:
            return []
        q = np.asarray(vector, dtype=np.float64)
        q_norm = float(np.linalg.norm(q))
        if q_norm == 0:
            return []
        norms = np.maximum(np.linalg.norm(self._matrix, axis=1), 1e-12)
        sims = (self._matrix @ q) / (norms * q_norm)
        order = np.argsort(-sims)
        out: list[Neighbour] = []
        for idx in order:
            route = self._route_ids[int(idx)]
            if exclude is not None and route == exclude:
                continue
            out.append(Neighbour(route, float(sims[int(idx)])))
            if len(out) >= k:
                break
        return out
