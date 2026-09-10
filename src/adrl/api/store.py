"""Durable product intake. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-010.

Use the existing serialized SQLite writer. Public observations remain separate from internal
verified outcomes. Per-session encryption covers every caller-supplied payload field.
"""

from __future__ import annotations

import sqlite3
from typing import Any, cast

from adrl.api.auth import ApiError, Principal
from adrl.api.contracts import (
    EventAcknowledgement,
    EventRequest,
    SessionRequest,
    SessionVerification,
)
from adrl.core.ids import SessionId
from adrl.ledger import crypto
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.store import LedgerStore, utc_now_iso


class ProductStore:
    def __init__(self, ledger: LedgerStore, keys: FileKeyStore) -> None:
        self.ledger = ledger
        self.keys = keys

    def binding(self, session: SessionId) -> dict[str, Any] | None:
        rows = self.ledger.read("SELECT * FROM product_sessions WHERE session_hmac=?", (session,))
        return dict(rows[0]) if rows else None

    def was_erased(self, session: SessionId) -> bool:
        return (
            self.keys.is_revoked(session)
            or bool(
                self.ledger.read(
                    "SELECT seq FROM lineage_events "
                    "WHERE lineage_hmac=? AND event_type='erased' LIMIT 1",
                    (session,),
                )
            )
            or bool(
                self.ledger.read(
                    "SELECT seq FROM session_keys WHERE session_hmac=? "
                    "AND action='shredded' LIMIT 1",
                    (session,),
                )
            )
        )

    async def bind(
        self, principal: Principal, request: SessionRequest, policy: str, config_digest: str
    ) -> dict[str, Any]:
        material = (
            principal.session_hmac,
            principal.workload_ref,
            request.adapter.id,
            request.adapter.version,
            request.profile.id,
            request.profile.version,
            request.integration_mode.value,
            policy,
            config_digest,
        )

        def write(conn: sqlite3.Connection) -> dict[str, Any]:
            conn.execute(
                "INSERT OR IGNORE INTO product_sessions "
                "(session_hmac,workload_ref,adapter_id,adapter_version,profile_id,"
                "profile_version,integration_mode,policy_version,config_digest,ts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*material, utc_now_iso()),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM product_sessions WHERE session_hmac=?", (principal.session_hmac,)
                ).fetchone()
            )

        row = cast(dict[str, Any], await self.ledger.write_through(write))
        expected = dict(
            zip(
                (
                    "session_hmac",
                    "workload_ref",
                    "adapter_id",
                    "adapter_version",
                    "profile_id",
                    "profile_version",
                    "integration_mode",
                    "policy_version",
                    "config_digest",
                ),
                material,
                strict=True,
            )
        )
        if any(row[k] != value for k, value in expected.items()):
            raise ApiError(409, "event_conflict", "The session already has a different binding.")
        return row

    async def append(self, principal: Principal, event: EventRequest) -> EventAcknowledgement:
        key = self.keys.get_session_key(principal.session_hmac)
        if key is None or self.was_erased(principal.session_hmac):
            raise ApiError(403, "forbidden", "The session evidence key is unavailable or erased.")
        value = event.root
        producer = crypto.keyed_hash(self.keys.hmac_key(), f"api-producer:{principal.session_hmac}")
        event_key = crypto.keyed_hash(key, f"api-event:{value.event_id}")
        plaintext = event.model_dump_json().encode()
        aad = f"{principal.session_hmac}:{producer}:{event_key}".encode()
        nonce, ciphertext = crypto.encrypt(key, plaintext, aad=aad)

        def write(conn: sqlite3.Connection) -> tuple[str, dict[str, Any] | None]:
            if (
                conn.execute(
                    "SELECT seq FROM lineage_events "
                    "WHERE lineage_hmac=? AND event_type='erased' LIMIT 1",
                    (principal.session_hmac,),
                ).fetchone()
                is not None
            ):
                return "erased", None
            if (
                conn.execute(
                    "SELECT seq FROM session_keys "
                    "WHERE session_hmac=? AND action='shredded' LIMIT 1",
                    (principal.session_hmac,),
                ).fetchone()
                is not None
            ):
                return "erased", None
            prior = conn.execute(
                "SELECT * FROM product_events WHERE producer_id=? AND event_key=?",
                (producer, event_key),
            ).fetchone()
            if prior is not None:
                return "prior", dict(prior)
            if (
                conn.execute(
                    "SELECT seq FROM product_events WHERE producer_id=? AND producer_seq=?",
                    (producer, value.producer_seq),
                ).fetchone()
                is not None
            ):
                return "conflict", None
            high = conn.execute(
                "SELECT MAX(producer_seq) FROM product_events WHERE producer_id=?", (producer,)
            ).fetchone()[0]
            expected = 0 if high is None else int(high) + 1
            ordering = (
                "next"
                if value.producer_seq == expected
                else ("gap" if value.producer_seq > expected else "late")
            )
            cursor = conn.execute(
                "INSERT INTO product_events (session_hmac,producer_id,event_key,producer_seq,"
                "route_id,event_type,nonce,ciphertext,sequence_status,ts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    principal.session_hmac,
                    producer,
                    event_key,
                    value.producer_seq,
                    value.route_id,
                    value.event_type,
                    nonce,
                    ciphertext,
                    ordering,
                    utc_now_iso(),
                ),
            )
            return "new", dict(
                conn.execute(
                    "SELECT * FROM product_events WHERE seq=?", (cursor.lastrowid,)
                ).fetchone()
            )

        kind, row = cast(tuple[str, dict[str, Any] | None], await self.ledger.write_through(write))
        if kind == "erased":
            raise ApiError(403, "forbidden", "The session evidence key was erased.")
        if row is None:
            raise ApiError(409, "event_conflict", "Producer sequence already identifies an event.")
        if (
            kind == "prior"
            and crypto.decrypt(key, row["nonce"], row["ciphertext"], aad=aad) != plaintext
        ):
            raise ApiError(
                409, "event_conflict", "Event identity was reused with different content."
            )
        # Return the original acknowledgement on an identical retry, including its timestamp.
        return EventAcknowledgement.model_validate(
            {
                "event_id": value.event_id,
                "producer_id": producer,
                "recorded_at": row["ts"],
                "ledger_sequence": row["seq"],
                "status": "recorded",
                "sequence_status": row["sequence_status"],
            }
        )

    def observation(self, row: dict[str, Any]) -> EventRequest | None:
        session = SessionId(row["session_hmac"])
        key = self.keys.get_session_key(session)
        if key is None or self.was_erased(session):
            return None
        aad = f"{session}:{row['producer_id']}:{row['event_key']}".encode()
        return EventRequest.model_validate_json(
            crypto.decrypt(key, row["nonce"], row["ciphertext"], aad=aad)
        )

    async def append_verification(self, session: SessionId, receipt: SessionVerification) -> int:
        """Local operator path only. Never called by public event intake."""
        key = self.keys.get_session_key(session)
        if key is None or self.was_erased(session):
            raise ApiError(403, "forbidden", "Verification evidence key is unavailable.")
        job_key = crypto.keyed_hash(key, "verification:" + receipt.job_id)
        aad = f"verification:{session}:{job_key}:{receipt.phase}".encode()
        nonce, ciphertext = crypto.encrypt(key, receipt.model_dump_json().encode(), aad=aad)

        def write(conn: sqlite3.Connection) -> int:
            erased = conn.execute(
                "SELECT 1 FROM lineage_events WHERE lineage_hmac=? AND event_type='erased' "
                "UNION ALL SELECT 1 FROM session_keys WHERE session_hmac=? AND action='shredded'",
                (session, session),
            ).fetchone()
            if erased is not None:
                raise ApiError(403, "forbidden", "Verification evidence was erased.")
            cursor = conn.execute(
                "INSERT INTO product_verifications "
                "(session_hmac,job_key,phase,nonce,ciphertext,ts) VALUES (?,?,?,?,?,?)",
                (session, job_key, receipt.phase, nonce, ciphertext, utc_now_iso()),
            )
            assert cursor.lastrowid is not None
            return cursor.lastrowid

        return cast(int, await self.ledger.write_through(write))

    def verification(self, row: dict[str, Any]) -> SessionVerification | None:
        session = SessionId(row["session_hmac"])
        key = self.keys.get_session_key(session)
        if key is None or self.was_erased(session):
            return None
        aad = f"verification:{session}:{row['job_key']}:{row['phase']}".encode()
        return SessionVerification.model_validate_json(
            crypto.decrypt(key, row["nonce"], row["ciphertext"], aad=aad)
        )

    async def index_timeline(self, session: SessionId) -> None:
        """Append reference-only entries; late evidence gets a later index position.

        The index is rebuildable from its source tables. It is not an execution clock.
        """

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT OR IGNORE INTO product_timeline "
                "(session_hmac,source,source_seq,route_id,ts) "
                "SELECT session_hmac,'decision',rowid,route_id,ts FROM decisions "
                "WHERE session_hmac=? ORDER BY rowid",
                (session,),
            )
            conn.execute(
                "INSERT OR IGNORE INTO product_timeline "
                "(session_hmac,source,source_seq,route_id,ts) "
                "SELECT d.session_hmac,'internal',e.seq,e.route_id,e.ts FROM events e "
                "JOIN decisions d ON d.route_id=e.route_id WHERE d.session_hmac=? ORDER BY e.seq",
                (session,),
            )
            conn.execute(
                "INSERT OR IGNORE INTO product_timeline "
                "(session_hmac,source,source_seq,route_id,ts) "
                "SELECT session_hmac,'observation',seq,route_id,ts FROM product_events "
                "WHERE session_hmac=? ORDER BY seq",
                (session,),
            )

            conn.execute(
                "INSERT OR IGNORE INTO product_timeline "
                "(session_hmac,source,source_seq,route_id,ts) "
                "SELECT session_hmac,'local_verification',seq,NULL,ts FROM product_verifications "
                "WHERE session_hmac=? ORDER BY seq",
                (session,),
            )

        await self.ledger.write_through(write)
