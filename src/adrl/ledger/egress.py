"""Tamper-evident, content-free egress ledger. Primary: ADRL-SAF-009.
Also implements: ADRL-TRU-003 (register additions of 2026-09-03).

Separate file from the evidence ledger, synchronous=FULL, hash-chained rows, Ed25519 signed
checkpoints. Not behind the fail-safe memory facade: an append failure is raised to the gate.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from adrl.core.errors import LedgerAppendFailure
from adrl.core.ports import ChainVerification, EgressEvent
from adrl.core.types import left_machine
from adrl.ledger.anchoring import (
    AnchorRecord,
    AnchorVerification,
    CheckpointShipper,
    checkpoint_message,
    key_id_for,
    verify_anchor_signatures,
)
from adrl.telemetry.metrics import (
    EGRESS_CHECKPOINTS_TOTAL,
    EGRESS_NEWEST_ANCHOR_AGE_SECONDS,
    EGRESS_SHIP_FAILURES_TOTAL,
    EGRESS_UNSHIPPED_CHECKPOINTS,
)

log = structlog.get_logger(__name__)

GENESIS_DIGEST = "0" * 64
EGRESS_SCHEMA_VERSION = "egress-v2"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS egress_events (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    prev_digest        TEXT NOT NULL,
    ts                 TEXT NOT NULL,
    event_kind         TEXT NOT NULL,
    lineage_hmac       TEXT NOT NULL,
    request_class      TEXT NOT NULL,
    content_bearing    INTEGER NOT NULL,
    destination_rung   TEXT,
    deployment_tag     TEXT NOT NULL,
    gate_verdicts_json TEXT NOT NULL,
    detector_tier      TEXT,
    span_hashes_json   TEXT NOT NULL,
    bytes_out          INTEGER NOT NULL,
    actor              TEXT NOT NULL,
    reason             TEXT,
    schema_version     TEXT NOT NULL,
    digest             TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_seq    INTEGER NOT NULL,
    digest       TEXT NOT NULL,
    signature    TEXT NOT NULL,
    key_id       TEXT NOT NULL,
    ts           TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoint_shipments (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_seq  INTEGER NOT NULL,
    destination     TEXT NOT NULL,
    ts              TEXT NOT NULL
);
"""

_SCHEMA_ANCHORING = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Append-only acknowledgement columns on checkpoint_shipments: one row per attempt, status
# acked or failed; a checkpoint is shipped when an acked row exists for a destination.
_SHIPMENT_COLUMNS = (
    ("status", "TEXT NOT NULL DEFAULT 'acked'"),
    ("ack", "TEXT"),
)


@dataclass(frozen=True, slots=True)
class CheckpointVerification:
    """Result of verifying every checkpoint signature against a key set."""

    ok: bool
    checkpoints: int
    newest_seq: int | None = None
    detail: str | None = None

    def __bool__(self) -> bool:
        return self.ok


@dataclass(frozen=True, slots=True)
class ShipmentReport:
    shipped: int
    failed: int
    pending: int


# Columns added after egress-v1; applied additively on open, never by editing old rows.
_V2_COLUMNS: tuple[tuple[str, str], ...] = (
    ("deployment_id", "TEXT"),
    ("trust_zone", "TEXT"),
    ("geo", "TEXT"),
    ("api_base_host", "TEXT"),
    ("receipt_source", "TEXT"),
)

_ROW_FIELDS_V1 = (
    "prev_digest",
    "ts",
    "event_kind",
    "lineage_hmac",
    "request_class",
    "content_bearing",
    "destination_rung",
    "deployment_tag",
    "gate_verdicts_json",
    "detector_tier",
    "span_hashes_json",
    "bytes_out",
    "actor",
    "reason",
    "schema_version",
)
_ROW_FIELDS = (*_ROW_FIELDS_V1, *(name for name, _ in _V2_COLUMNS))


def _fields_for(schema_version: str) -> tuple[str, ...]:
    return _ROW_FIELDS_V1 if schema_version == "egress-v1" else _ROW_FIELDS


def _digest(row: dict[str, Any]) -> str:
    fields = _fields_for(str(row.get("schema_version", EGRESS_SCHEMA_VERSION)))
    payload = json.dumps({k: row[k] for k in fields}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _apply_additive_columns(conn: sqlite3.Connection) -> None:
    present = {str(r["name"]) for r in conn.execute("PRAGMA table_info(egress_events)")}
    for name, sql_type in _V2_COLUMNS:
        if name not in present:
            conn.execute(f"ALTER TABLE egress_events ADD COLUMN {name} {sql_type}")


class EgressLedger:
    """Append-only hash chain over content-free egress events."""

    def __init__(
        self,
        path: Path,
        *,
        signing_key: Ed25519PrivateKey | None = None,
        key_id: str | None = None,
        checkpoint_every: int = 0,
        shippers: Sequence[CheckpointShipper] = (),
    ) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._signing_key = signing_key
        if key_id is None:
            key_id = key_id_for(signing_key.public_key()) if signing_key is not None else "none"
        self._key_id = key_id
        self._last_digest = GENESIS_DIGEST
        self._checkpoint_every = max(0, int(checkpoint_every))
        self._shippers: tuple[CheckpointShipper, ...] = tuple(shippers)
        self._ledger_id = ""
        self._since_checkpoint = 0

    def open(self) -> None:
        if self._conn is not None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(_SCHEMA)
        conn.executescript(_SCHEMA_ANCHORING)
        _apply_additive_columns(conn)
        existing = {str(r["name"]) for r in conn.execute("PRAGMA table_info(checkpoint_shipments)")}
        for column, decl in _SHIPMENT_COLUMNS:
            if column not in existing:
                conn.execute(f"ALTER TABLE checkpoint_shipments ADD COLUMN {column} {decl}")
        row = conn.execute("SELECT digest FROM egress_events ORDER BY seq DESC LIMIT 1").fetchone()
        self._last_digest = str(row["digest"]) if row else GENESIS_DIGEST
        meta = conn.execute("SELECT value FROM meta WHERE key='ledger_id'").fetchone()
        if meta is None:
            self._ledger_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('ledger_id', ?)", (self._ledger_id,)
            )
        else:
            self._ledger_id = str(meta["value"])
        self._since_checkpoint = self._events_since_last_checkpoint(conn)
        self._conn = conn

    @staticmethod
    def _events_since_last_checkpoint(conn: sqlite3.Connection) -> int:
        last_cp = conn.execute("SELECT MAX(event_seq) AS s FROM checkpoints").fetchone()
        last_event = conn.execute("SELECT MAX(seq) AS s FROM egress_events").fetchone()
        cp_seq = int(last_cp["s"] or 0) if last_cp is not None else 0
        ev_seq = int(last_event["s"] or 0) if last_event is not None else 0
        return max(0, ev_seq - cp_seq)

    @property
    def ledger_id(self) -> str:
        return self._ledger_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def signing_enabled(self) -> bool:
        return self._signing_key is not None

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def last_digest(self) -> str:
        return self._last_digest

    def _require(self) -> sqlite3.Connection:
        if self._conn is None:
            raise LedgerAppendFailure("egress ledger is not open")
        return self._conn

    def append(self, event: EgressEvent) -> int:
        """Append one event. Raises LedgerAppendFailure; callers decide by pin state."""
        with self._lock:
            conn = self._require()
            row: dict[str, Any] = {
                "prev_digest": self._last_digest,
                "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
                "event_kind": event.event_kind,
                "lineage_hmac": event.lineage_hmac,
                "request_class": event.request_class,
                "content_bearing": 1 if event.content_bearing else 0,
                "destination_rung": event.destination_rung,
                "deployment_tag": event.deployment_tag,
                "gate_verdicts_json": json.dumps(
                    list(event.gate_verdicts), sort_keys=True, default=str
                ),
                "detector_tier": event.detector_tier,
                "span_hashes_json": json.dumps(list(event.span_hashes)),
                "bytes_out": int(event.bytes_out),
                "actor": event.actor,
                "reason": event.reason,
                "schema_version": EGRESS_SCHEMA_VERSION,
                "deployment_id": event.deployment_id,
                "trust_zone": event.trust_zone,
                "geo": event.geo,
                "api_base_host": event.api_base_host,
                "receipt_source": event.receipt_source,
            }
            row["digest"] = _digest(row)
            columns = ",".join((*_ROW_FIELDS, "digest"))
            placeholders = ",".join("?" for _ in _ROW_FIELDS) + ",?"
            values = (*(row[k] for k in _ROW_FIELDS), row["digest"])
            sql = "INSERT INTO egress_events (" + columns + ") VALUES (" + placeholders + ")"  # noqa: S608
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    sql,
                    values,
                )
                conn.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise LedgerAppendFailure(f"egress append failed: {exc}") from exc
            self._last_digest = row["digest"]
            seq = int(cursor.lastrowid or 0)
            self._since_checkpoint += 1
            if (
                self._checkpoint_every
                and self._signing_key is not None
                and self._since_checkpoint >= self._checkpoint_every
            ):
                self._checkpoint_locked(trigger="count")
            return seq

    def verify_chain(self) -> ChainVerification:
        with self._lock:
            conn = self._require()
            prev = GENESIS_DIGEST
            count = 0
            for db_row in conn.execute("SELECT * FROM egress_events ORDER BY seq"):
                row = dict(db_row)
                count += 1
                if row["prev_digest"] != prev:
                    return ChainVerification(False, count, int(row["seq"]), "prev_digest mismatch")
                if _digest(row) != row["digest"]:
                    return ChainVerification(False, count, int(row["seq"]), "digest mismatch")
                prev = str(row["digest"])
            for cp in conn.execute("SELECT * FROM checkpoints ORDER BY seq"):
                ref = conn.execute(
                    "SELECT digest FROM egress_events WHERE seq=?", (int(cp["event_seq"]),)
                ).fetchone()
                if ref is None or ref["digest"] != cp["digest"]:
                    return ChainVerification(
                        False,
                        count,
                        int(cp["event_seq"]),
                        "checkpoint refers to a missing or altered row",
                    )
            return ChainVerification(True, count)

    def checkpoint(self, *, trigger: str = "manual") -> int:
        """Sign the latest (seq, digest) and record it. Returns checkpoint seq, 0 if empty."""
        if self._signing_key is None:
            raise LedgerAppendFailure("no checkpoint signing key configured")
        with self._lock:
            self._require()
            return self._checkpoint_locked(trigger=trigger)

    def _checkpoint_locked(self, *, trigger: str) -> int:
        """Caller holds the lock. Writes a signed checkpoint over the newest row."""
        if self._signing_key is None:
            raise LedgerAppendFailure("no checkpoint signing key configured")
        conn = self._require()
        latest = conn.execute(
            "SELECT seq, digest FROM egress_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if latest is None:
            return 0
        event_seq = int(latest["seq"])
        digest = str(latest["digest"])
        message = checkpoint_message(self._ledger_id, event_seq, digest)
        signature = base64.b64encode(self._signing_key.sign(message)).decode()
        cursor = conn.execute(
            "INSERT INTO checkpoints (event_seq, digest, signature, key_id, ts) VALUES (?,?,?,?,?)",
            (
                event_seq,
                digest,
                signature,
                self._key_id,
                datetime.now(UTC).isoformat(timespec="microseconds"),
            ),
        )
        self._since_checkpoint = 0
        EGRESS_CHECKPOINTS_TOTAL.labels(trigger=trigger).inc()
        self._update_unshipped_gauge(conn)
        return int(cursor.lastrowid or 0)

    def checkpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._require()
            return [dict(r) for r in conn.execute("SELECT * FROM checkpoints ORDER BY seq")]

    def _record(self, cp: sqlite3.Row | dict[str, Any]) -> AnchorRecord:
        return AnchorRecord(
            ledger_id=self._ledger_id,
            checkpoint_seq=int(cp["seq"]),
            event_seq=int(cp["event_seq"]),
            digest=str(cp["digest"]),
            signature=str(cp["signature"]),
            key_id=str(cp["key_id"]),
            ts=str(cp["ts"]),
        )

    def _pending_shipments(self, conn: sqlite3.Connection) -> list[tuple[sqlite3.Row, str]]:
        pending: list[tuple[sqlite3.Row, str]] = []
        for cp in conn.execute("SELECT * FROM checkpoints ORDER BY seq"):
            for shipper in self._shippers:
                acked = conn.execute(
                    "SELECT 1 FROM checkpoint_shipments WHERE checkpoint_seq=? AND "
                    "destination=? AND status='acked' LIMIT 1",
                    (int(cp["seq"]), shipper.destination),
                ).fetchone()
                if acked is None:
                    pending.append((cp, shipper.destination))
        return pending

    def _update_unshipped_gauge(self, conn: sqlite3.Connection) -> None:
        if not self._shippers:
            return
        unshipped = {int(cp["seq"]) for cp, _ in self._pending_shipments(conn)}
        EGRESS_UNSHIPPED_CHECKPOINTS.set(len(unshipped))

    def ship_pending(self) -> ShipmentReport:
        """Deliver every checkpoint not yet acknowledged by each shipper; failures are retried."""
        with self._lock:
            conn = self._require()
            pending = self._pending_shipments(conn)
            shipped = failed = 0
            by_destination = {s.destination: s for s in self._shippers}
            for cp, destination in pending:
                shipper = by_destination[destination]
                record = self._record(cp)
                ts = datetime.now(UTC).isoformat(timespec="microseconds")
                try:
                    ack = shipper.ship(record)
                except Exception as exc:
                    failed += 1
                    EGRESS_SHIP_FAILURES_TOTAL.labels(destination=destination).inc()
                    log.warning(
                        "egress_checkpoint_ship_failed",
                        destination=destination,
                        checkpoint_seq=record.checkpoint_seq,
                        error=type(exc).__name__,
                    )
                    conn.execute(
                        "INSERT INTO checkpoint_shipments (checkpoint_seq, destination, ts, "
                        "status, ack) VALUES (?,?,?,?,?)",
                        (record.checkpoint_seq, destination, ts, "failed", type(exc).__name__),
                    )
                    continue
                shipped += 1
                conn.execute(
                    "INSERT INTO checkpoint_shipments (checkpoint_seq, destination, ts, "
                    "status, ack) VALUES (?,?,?,?,?)",
                    (record.checkpoint_seq, destination, ts, "acked", ack[:256]),
                )
            remaining = {int(cp["seq"]) for cp, _ in self._pending_shipments(conn)}
            if self._shippers:
                EGRESS_UNSHIPPED_CHECKPOINTS.set(len(remaining))
            self._refresh_anchor_age(conn)
            return ShipmentReport(shipped=shipped, failed=failed, pending=len(remaining))

    def _newest_ack(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        row: sqlite3.Row | None = conn.execute(
            "SELECT s.ts AS ts, c.event_seq AS event_seq, c.seq AS checkpoint_seq "
            "FROM checkpoint_shipments s JOIN checkpoints c ON c.seq = s.checkpoint_seq "
            "WHERE s.status='acked' ORDER BY c.seq DESC, s.seq DESC LIMIT 1"
        ).fetchone()
        return row

    def _refresh_anchor_age(self, conn: sqlite3.Connection) -> float | None:
        newest = self._newest_ack(conn)
        if newest is None:
            EGRESS_NEWEST_ANCHOR_AGE_SECONDS.set(-1)
            return None
        age = (datetime.now(UTC) - datetime.fromisoformat(str(newest["ts"]))).total_seconds()
        EGRESS_NEWEST_ANCHOR_AGE_SECONDS.set(age)
        return age

    def anchor_status(self) -> dict[str, Any]:
        """Health view: signing, unshipped checkpoints and the age of the newest anchor."""
        with self._lock:
            conn = self._require()
            newest = self._newest_ack(conn)
            unshipped = {int(cp["seq"]) for cp, _ in self._pending_shipments(conn)}
            age = self._refresh_anchor_age(conn)
            return {
                "signing": self._signing_key is not None,
                "key_id": self._key_id,
                "ledger_id": self._ledger_id,
                "checkpoint_every": self._checkpoint_every,
                "events_since_checkpoint": self._since_checkpoint,
                "shippers": [s.destination for s in self._shippers],
                "unshipped_checkpoints": len(unshipped),
                "newest_anchored_seq": int(newest["event_seq"]) if newest else None,
                "newest_anchor_age_s": age,
            }

    async def run_periodic(self, interval_s: float, stop: asyncio.Event) -> None:
        """Interval checkpoints plus shipment retries; runs until `stop` is set."""
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval_s)
                break
            except TimeoutError:
                pass
            try:
                if self._signing_key is not None and self._since_checkpoint > 0:
                    await asyncio.to_thread(self.checkpoint, trigger="interval")
                if self._shippers:
                    await asyncio.to_thread(self.ship_pending)
            except Exception as exc:
                log.warning("egress_periodic_failed", error=type(exc).__name__)

    def verify_checkpoints(
        self, keys: Ed25519PublicKey | Mapping[str, Ed25519PublicKey]
    ) -> CheckpointVerification:
        """Every checkpoint must verify under the key its key_id names (or the single key)."""
        with self._lock:
            conn = self._require()
            count = 0
            newest: int | None = None
            for cp in conn.execute("SELECT * FROM checkpoints ORDER BY seq"):
                count += 1
                public: Ed25519PublicKey | None
                if isinstance(keys, Ed25519PublicKey):
                    public = keys
                else:
                    public = keys.get(str(cp["key_id"]))
                if public is None:
                    return CheckpointVerification(
                        False, count, newest, f"unknown key id {cp['key_id']}"
                    )
                message = checkpoint_message(self._ledger_id, int(cp["event_seq"]), cp["digest"])
                try:
                    public.verify(base64.b64decode(cp["signature"]), message)
                except Exception:
                    return CheckpointVerification(
                        False, count, newest, f"bad signature on checkpoint {cp['seq']}"
                    )
                newest = int(cp["event_seq"])
            return CheckpointVerification(True, count, newest)

    def verify_against_anchors(
        self, anchors: Iterable[AnchorRecord], keys: Mapping[str, Ed25519PublicKey]
    ) -> AnchorVerification:
        """Detect deletion, edit or truncation of any row at or before an anchored checkpoint."""
        records = [a for a in anchors if a.ledger_id == self._ledger_id]
        signatures = verify_anchor_signatures(records, keys)
        if not signatures.ok:
            return signatures
        with self._lock:
            conn = self._require()
            newest_seq = conn.execute("SELECT MAX(seq) AS s FROM egress_events").fetchone()
            max_seq = int(newest_seq["s"] or 0) if newest_seq is not None else 0
            for record in records:
                if record.event_seq > max_seq:
                    return AnchorVerification(
                        False,
                        signatures.anchors,
                        signatures.newest_anchored_seq,
                        f"ledger truncated below anchored seq {record.event_seq}",
                    )
                row = conn.execute(
                    "SELECT * FROM egress_events WHERE seq=?", (record.event_seq,)
                ).fetchone()
                if (
                    row is None
                    or str(row["digest"]) != record.digest
                    or _digest(dict(row)) != record.digest
                ):
                    return AnchorVerification(
                        False,
                        signatures.anchors,
                        signatures.newest_anchored_seq,
                        f"row {record.event_seq} missing or altered against anchor",
                    )
        return signatures

    def count(self) -> int:
        with self._lock:
            conn = self._require()
            return int(conn.execute("SELECT COUNT(*) FROM egress_events").fetchone()[0])

    def events_for_lineage(
        self, lineage_hmac: str, event_kind: str | None = None
    ) -> list[dict[str, Any]]:
        """Every egress row for a lineage, optionally filtered by kind (content-free)."""
        with self._lock:
            conn = self._require()
            if event_kind is None:
                rows = conn.execute(
                    "SELECT * FROM egress_events WHERE lineage_hmac=? ORDER BY seq",
                    (lineage_hmac,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM egress_events WHERE lineage_hmac=? AND event_kind=? "
                    "ORDER BY seq",
                    (lineage_hmac, event_kind),
                ).fetchall()
            return [dict(r) for r in rows]

    def lineage_left_machine(self, lineage_hmac: str) -> list[dict[str, Any]]:
        """Answer ADRL-SAF-002 clause 4 from the recorded trust zone, never from a rung label.

        A row counts when content-bearing traffic reached a deployment whose recorded trust zone
        is not ``local_host``. A ``served_receipt`` row from the gateway is ``confirmed``; a
        write-ahead ``forward`` row with no receipt, or a receipt the gateway did not report, is
        ``confirmed=False`` so the audit can say "unconfirmed" instead of "no". Legacy
        ``egress-v1`` rows without a trust zone fall back to the rung label and are flagged.
        """
        with self._lock:
            conn = self._require()
            rows = conn.execute(
                "SELECT seq, ts, event_kind, destination_rung, deployment_tag, deployment_id, "
                "trust_zone, geo, api_base_host, receipt_source, gate_verdicts_json, "
                "schema_version FROM egress_events WHERE lineage_hmac=? AND content_bearing=1 "
                "AND event_kind IN ('forward', 'served_receipt') ORDER BY seq",
                (lineage_hmac,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for db_row in rows:
            row = dict(db_row)
            zone = row.get("trust_zone")
            left = left_machine(zone, row.get("destination_rung"))
            if left is None:
                continue
            basis = "trust_zone" if zone is not None else "rung_label_legacy"
            if not left:
                continue
            row["confirmed"] = (
                row["event_kind"] == "served_receipt"
                and row.get("receipt_source") == "gateway_reported"
            )
            row["basis"] = basis
            out.append(row)
        return out


def load_signing_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise LedgerAppendFailure("checkpoint signing key must be Ed25519")
    return key


def anchors_from_file(path: Path) -> list[AnchorRecord]:
    from adrl.ledger.anchoring import read_anchor_file

    return read_anchor_file(path)
