"""Encrypted offline experiment history. Primary: ADRL-MEM-001.

Secondary: ADRL-MEM-005, ADRL-MEM-010, ADRL-LRN-005. Experiment keys have their own
namespace and lifecycle. They are not harness sessions, routing decisions or learning labels.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any
from uuid import uuid4

from pydantic import BaseModel

from adrl.core.ids import SessionId
from adrl.ledger import crypto
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore, utc_now_iso


class ExperimentArchive:
    def __init__(self, store: LedgerStore, keys: FileKeyStore) -> None:
        self.store = store
        self.keys = keys

    def identity(self, experiment_id: str) -> SessionId:
        return SessionId(crypto.keyed_hash(self.keys.hmac_key(), "improvement:" + experiment_id))

    def _erased(self, identity: SessionId) -> bool:
        return bool(
            self.store.read(
                "SELECT 1 FROM session_keys WHERE session_hmac=? AND action='shredded'",
                (identity,),
            )
        )

    def begin(self) -> str:
        experiment_id = str(uuid4())
        identity = self.identity(experiment_id)
        if self._erased(identity) or self.keys.get_session_key(identity) is not None:
            raise ValueError("Experiment identity already exists.")
        self.keys.create_session_key(identity)
        return experiment_id

    async def append(self, experiment_id: str, event_type: str, payload: BaseModel) -> None:
        identity = self.identity(experiment_id)
        key = self.keys.get_session_key(identity)
        if key is None or self._erased(identity):
            raise ValueError("Experiment evidence key is unavailable.")
        record_key = crypto.keyed_hash(key, str(uuid4()))
        aad = f"improvement:{identity}:{record_key}:{event_type}".encode()
        nonce, ciphertext = crypto.encrypt(key, payload.model_dump_json().encode(), aad=aad)

        def write(conn: sqlite3.Connection) -> None:
            if conn.execute(
                "SELECT 1 FROM session_keys WHERE session_hmac=? AND action='shredded'",
                (identity,),
            ).fetchone():
                raise ValueError("Experiment evidence was erased.")
            conn.execute(
                "INSERT INTO improvement_records "
                "(experiment_hmac,event_type,record_key,nonce,ciphertext,ts) VALUES (?,?,?,?,?,?)",
                (identity, event_type, record_key, nonce, ciphertext, utc_now_iso()),
            )

        await self.store.write_through(write)

    def read(self, experiment_id: str) -> list[dict[str, Any]]:
        identity = self.identity(experiment_id)
        key = None if self._erased(identity) else self.keys.get_session_key(identity)
        records = []
        for row in self.store.read(
            "SELECT * FROM improvement_records WHERE experiment_hmac=? ORDER BY seq", (identity,)
        ):
            payload = None
            if key is not None:
                aad = f"improvement:{identity}:{row['record_key']}:{row['event_type']}".encode()
                payload = json.loads(crypto.decrypt(key, row["nonce"], row["ciphertext"], aad=aad))
            records.append(
                {
                    "sequence": row["seq"],
                    "event_type": row["event_type"],
                    "recorded_at": row["ts"],
                    "payload_state": "available" if payload is not None else "erased",
                    "record": payload,
                }
            )
        return records

    def erase(self, experiment_id: str) -> bool:
        return self.keys.shred_session_key(
            self.identity(experiment_id), "operator_experiment_erasure"
        )
