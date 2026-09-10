"""Embeddings and keyed instruction hashes as prompt-class data. Primary: ADRL-MEM-005.

Secondary: ADRL-MEM-010 (per-session encryption), ADRL-SAF-002 (pin suppression).

Nothing here is produced for a pinned or private turn. Vectors are encrypted under the session
key before they reach the ledger; a session whose key was shredded is unreadable and never gets
a new key. Instruction hashes are HMACs under the host-local secret and are stored encrypted as
well, so a database copy cannot dictionary-match short instructions.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
import structlog

from adrl.core.ids import RouteId, SessionId
from adrl.ledger import crypto
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore, utc_now_iso

log = structlog.get_logger(__name__)

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")


class HashingEmbedder:
    """Deterministic feature-hashing embedder for tests and hosts without a model download.

    Clearly not a semantic model: it exists so the storage, encryption, shredding and projection
    paths can be exercised without network access. Its version string marks every vector it made.
    """

    def __init__(self, dimension: int = 64) -> None:
        self._dimension = dimension

    @property
    def embedder_version(self) -> str:
        return f"hashing-test-v1:{self._dimension}"

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        out: list[list[float]] = []
        for text in texts:
            vec = np.zeros(self._dimension, dtype=np.float64)
            for token in _TOKEN.findall(text.lower()):
                digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
                idx = int.from_bytes(digest[:4], "big") % self._dimension
                sign = 1.0 if digest[4] & 1 else -1.0
                vec[idx] += sign
            norm = float(np.linalg.norm(vec))
            if norm > 0:
                vec /= norm
            out.append([float(x) for x in vec])
        return out


class Model2VecEmbedder:
    """Static embeddings via model2vec (optional extra); no torch."""

    def __init__(self, model_name: str = "minishlab/potion-base-8M") -> None:
        from model2vec import StaticModel

        self._model_name = model_name
        self._model = StaticModel.from_pretrained(model_name)
        self._dimension = int(self._model.dim)

    @property
    def embedder_version(self) -> str:
        return f"model2vec:{self._model_name}"

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        matrix = self._model.encode(list(texts))
        return [[float(x) for x in row] for row in np.asarray(matrix)]


def session_shredded(store: LedgerStore, session: SessionId) -> bool:
    rows = store.read(
        "SELECT action FROM session_keys WHERE session_hmac=? ORDER BY seq DESC LIMIT 1",
        (str(session),),
    )
    return bool(rows) and str(rows[0]["action"]) == "shredded"


@dataclass(frozen=True, slots=True)
class StoredVector:
    seq: int
    route_id: RouteId
    session_hmac: SessionId
    vector: np.ndarray
    embedder_version: str


class EmbeddingWriter:
    """Writes encrypted vectors; refuses pinned, private and shredded sessions."""

    def __init__(self, store: LedgerStore, keystore: FileKeyStore, embedder: Any) -> None:
        self._store = store
        self._keystore = keystore
        self._embedder = embedder

    @property
    def embedder_version(self) -> str:
        return str(self._embedder.embedder_version)

    def _key_for(self, session: SessionId) -> bytes | None:
        if session_shredded(self._store, session):
            return None
        return self._keystore.create_session_key(session)

    async def write(
        self,
        route_id: RouteId,
        session: SessionId,
        text: str,
        *,
        pinned: bool,
        private: bool = False,
    ) -> bool:
        if pinned or private:
            log.debug(
                "embedding_suppressed", route_id=str(route_id), pinned=pinned, private=private
            )
            return False
        key = self._key_for(session)
        if key is None:
            log.info("embedding_refused_shredded_session", route_id=str(route_id))
            return False
        vector = np.asarray(self._embedder.embed([text])[0], dtype=np.float32)
        nonce, ciphertext = crypto.encrypt(key, vector.tobytes(), aad=str(route_id).encode())
        version = self.embedder_version
        dimension = int(vector.shape[0])

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO embeddings (route_id, session_hmac, ciphertext, nonce, "
                "embedder_version, dimension, ts) VALUES (?,?,?,?,?,?,?)",
                (str(route_id), str(session), ciphertext, nonce, version, dimension, utc_now_iso()),
            )

        await self._store.write_through(write)
        return True


def read_vectors(
    store: LedgerStore,
    keystore: FileKeyStore,
    *,
    after_seq: int = 0,
    up_to_seq: int | None = None,
    embedder_version: str | None = None,
) -> list[StoredVector]:
    """Decrypt readable vectors in ledger order; sessions without a key are skipped."""
    params: list[Any] = [after_seq]
    sql = "SELECT * FROM embeddings WHERE seq>?"
    if up_to_seq is not None:
        sql += " AND seq<=?"
        params.append(up_to_seq)
    if embedder_version is not None:
        sql += " AND embedder_version=?"
        params.append(embedder_version)
    sql += " ORDER BY seq"
    keys: dict[str, bytes | None] = {}
    out: list[StoredVector] = []
    for row in store.read(sql, params):
        session = str(row["session_hmac"])
        if session not in keys:
            keys[session] = keystore.get_session_key(SessionId(session))
        key = keys[session]
        if key is None:
            continue
        route_id = str(row["route_id"])
        try:
            raw = crypto.decrypt(
                key, bytes(row["nonce"]), bytes(row["ciphertext"]), aad=route_id.encode()
            )
        except Exception:
            log.warning("embedding_unreadable", route_id=route_id)
            continue
        vector = np.frombuffer(raw, dtype=np.float32).astype(np.float64)
        out.append(
            StoredVector(
                int(row["seq"]),
                RouteId(route_id),
                SessionId(session),
                vector,
                str(row["embedder_version"]),
            )
        )
    return out


def max_embedding_seq(store: LedgerStore) -> int:
    row = store.read("SELECT MAX(seq) AS m FROM embeddings")[0]
    return int(row["m"] or 0)


def sessions_with_embeddings(store: LedgerStore) -> list[SessionId]:
    return [
        SessionId(str(r["session_hmac"]))
        for r in store.read("SELECT DISTINCT session_hmac FROM embeddings")
    ]


def embedding_row_count(store: LedgerStore, session: SessionId) -> int:
    return int(
        store.read("SELECT COUNT(*) AS c FROM embeddings WHERE session_hmac=?", (str(session),))[0][
            "c"
        ]
    )


class InstructionHasher:
    """Keyed instruction hashes (ADRL-MEM-005 clause 3), stored encrypted per session."""

    def __init__(self, store: LedgerStore, keystore: FileKeyStore) -> None:
        self._store = store
        self._keystore = keystore

    def hash(self, instruction: str) -> tuple[str, str]:
        return crypto.keyed_hash(
            self._keystore.hmac_key(), instruction
        ), self._keystore.hmac_key_id()

    async def write(
        self, route_id: RouteId, session: SessionId, instruction: str, *, pinned: bool
    ) -> str | None:
        if pinned or session_shredded(self._store, session):
            return None
        digest, hmac_id = self.hash(instruction)
        key = self._keystore.create_session_key(session)
        nonce, ciphertext = crypto.encrypt(key, digest.encode(), aad=str(route_id).encode())

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO instruction_hashes (route_id, session_hmac, hmac_key_id, ciphertext, "
                "nonce, ts) VALUES (?,?,?,?,?,?)",
                (str(route_id), str(session), hmac_id, ciphertext, nonce, utc_now_iso()),
            )

        await self._store.write_through(write)
        return digest

    def read(self, route_id: RouteId) -> str | None:
        rows = self._store.read(
            "SELECT * FROM instruction_hashes WHERE route_id=? ORDER BY seq DESC LIMIT 1",
            (str(route_id),),
        )
        if not rows:
            return None
        row = rows[0]
        key = self._keystore.get_session_key(SessionId(str(row["session_hmac"])))
        if key is None:
            return None
        return crypto.decrypt(
            key, bytes(row["nonce"]), bytes(row["ciphertext"]), aad=str(route_id).encode()
        ).decode()


def features_are_content_free(features: dict[str, Any]) -> bool:
    """CI helper: a feature snapshot must never carry instruction text (ADRL-MEM-005)."""
    blob = json.dumps(features)
    return len(blob) < 4096 and "instruction_text" not in features and "prompt" not in features
