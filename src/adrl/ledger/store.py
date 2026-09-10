"""SQLite event store with one writer thread. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-006.

The single writer thread is the provider concurrency contract: one connection, WAL, busy
timeout, BEGIN IMMEDIATE for every write. Readers hold a separate long-lived connection and
expose PRAGMA data_version for cross-process change detection (ADRL-MEM-007). Nothing in this
module mutates or removes a row.
"""

from __future__ import annotations

import asyncio
import json
import queue
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adrl.core.errors import LedgerAppendFailure
from adrl.ledger.migrations import load_migrations

SCHEMA_VERSION = "ledger-v1"
_STOP = object()

WriteFn = Callable[[sqlite3.Connection], Any]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


class LedgerStore:
    """Owns adrl.db. Open once per process; share across the event loop."""

    def __init__(self, path: Path, *, busy_timeout_ms: int = 5000) -> None:
        self._path = path
        self._busy_timeout_ms = busy_timeout_ms
        self._queue: queue.Queue[tuple[WriteFn, Future[Any]] | object] = queue.Queue()
        self._writer: threading.Thread | None = None
        self._reader: sqlite3.Connection | None = None
        self._reader_lock = threading.Lock()
        self._opened = False

    # lifecycle -------------------------------------------------------------------------

    def open(self) -> None:
        if self._opened:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            self._apply_migrations(conn)
        finally:
            conn.close()
        self._reader = self._connect(read_only=True)
        self._writer = threading.Thread(
            target=self._writer_loop, name="adrl-ledger-writer", daemon=True
        )
        self._writer.start()
        self._opened = True

    def close(self) -> None:
        if not self._opened:
            return
        self._queue.put(_STOP)
        if self._writer is not None:
            self._writer.join(timeout=10)
        if self._reader is not None:
            self._reader.close()
        self._opened = False

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1000,
            check_same_thread=False,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={int(self._busy_timeout_ms)}")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        if read_only:
            conn.execute("PRAGMA query_only=ON")
        return conn

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        current = int(conn.execute("PRAGMA user_version").fetchone()[0])
        for migration in load_migrations():
            if migration.version <= current:
                continue
            script = (
                "BEGIN IMMEDIATE;\n"
                + migration.sql
                + f"\nPRAGMA user_version={migration.version};\nCOMMIT;"
            )
            try:
                conn.executescript(script)
            except sqlite3.Error:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def schema_user_version(self) -> int:
        return int(self._read_conn().execute("PRAGMA user_version").fetchone()[0])

    # writer thread ---------------------------------------------------------------------

    def _writer_loop(self) -> None:
        conn = self._connect()
        try:
            while True:
                item = self._queue.get()
                if item is _STOP:
                    break
                if not isinstance(item, tuple):
                    continue
                fn, future = item
                # Once started, HTTP cancellation must not cancel this writer future.
                # Otherwise set_result can terminate the sole writer after a committed append.
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    result = fn(conn)
                    conn.execute("COMMIT")
                except Exception as exc:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    future.set_exception(LedgerAppendFailure(str(exc)))
                else:
                    future.set_result(result)
        finally:
            conn.close()

    def submit(self, fn: WriteFn) -> Future[Any]:
        """Queue a write; the returned future resolves when it is committed (write-through)."""
        if not self._opened:
            raise LedgerAppendFailure("ledger store is not open")
        future: Future[Any] = Future()
        self._queue.put((fn, future))
        return future

    def enqueue(self, fn: WriteFn) -> None:
        """Queue a write without waiting (write-behind)."""
        self.submit(fn)

    async def write_through(self, fn: WriteFn) -> Any:
        return await asyncio.wrap_future(self.submit(fn))

    # typed appends ---------------------------------------------------------------------

    @staticmethod
    def insert_decision(row: Mapping[str, Any], context: Mapping[str, Any]) -> WriteFn:
        def write(conn: sqlite3.Connection) -> bool:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO decisions (route_id, ts, session_hmac, lineage_hmac, "
                "request_class, content_bearing, permitted_set, decided_rung, estimator, "
                "estimator_version, policy_version, objective_version, cascade_feasible, "
                "cascade_reason, features_json, features_version, propensity, explore_version, "
                "no_rung_met_threshold, classifier_provenance_json, context_json, schema_version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row["route_id"],
                    utc_now_iso(),
                    context["session_hmac"],
                    context["lineage_hmac"],
                    context["request_class"],
                    1 if context.get("content_bearing") else 0,
                    json.dumps(row["permitted_set"]),
                    row["decided_rung"],
                    row["estimator"],
                    row["estimator_version"],
                    row["policy_version"],
                    row["objective_version"],
                    1 if row["cascade_feasible"] else 0,
                    row.get("cascade_reason"),
                    json.dumps(row["features"], sort_keys=True),
                    row["features_version"],
                    float(row.get("propensity", 1.0)),
                    row.get("explore_version"),
                    1 if row.get("no_rung_met_threshold") else 0,
                    json.dumps(row.get("classifier_provenance"), sort_keys=True),
                    json.dumps(dict(context), sort_keys=True, default=str),
                    SCHEMA_VERSION,
                ),
            )
            return cursor.rowcount == 1

        return write

    @staticmethod
    def insert_event(
        route_id: str,
        event_type: str,
        producer: str,
        producer_seq: int,
        payload: Mapping[str, Any],
        schema_version: str,
    ) -> WriteFn:
        def write(conn: sqlite3.Connection) -> bool:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO events (route_id, event_type, producer, producer_seq, ts, "
                "schema_version, payload_json) VALUES (?,?,?,?,?,?,?)",
                (
                    route_id,
                    event_type,
                    producer,
                    producer_seq,
                    utc_now_iso(),
                    schema_version,
                    json.dumps(dict(payload), sort_keys=True, default=str),
                ),
            )
            return cursor.rowcount == 1

        return write

    @staticmethod
    def insert_lineage_event(
        lineage_hmac: str, event_type: str, payload: Mapping[str, Any]
    ) -> WriteFn:
        def write(conn: sqlite3.Connection) -> int:
            cursor = conn.execute(
                "INSERT INTO lineage_events (lineage_hmac, event_type, ts, payload_json) "
                "VALUES (?,?,?,?)",
                (
                    lineage_hmac,
                    event_type,
                    utc_now_iso(),
                    json.dumps(dict(payload), sort_keys=True, default=str),
                ),
            )
            return int(cursor.lastrowid or 0)

        return write

    # reads -----------------------------------------------------------------------------

    def _read_conn(self) -> sqlite3.Connection:
        if self._reader is None:
            raise LedgerAppendFailure("ledger store is not open")
        return self._reader

    def read(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._reader_lock:
            return list(self._read_conn().execute(sql, tuple(params)).fetchall())

    def data_version(self) -> int:
        with self._reader_lock:
            return int(self._read_conn().execute("PRAGMA data_version").fetchone()[0])

    def journal_mode(self) -> str:
        with self._reader_lock:
            return str(self._read_conn().execute("PRAGMA journal_mode").fetchone()[0])

    def read_events(self, route_id: str, event_type: str | None = None) -> list[sqlite3.Row]:
        if event_type is None:
            return self.read("SELECT * FROM events WHERE route_id=? ORDER BY seq", (route_id,))
        return self.read(
            "SELECT * FROM events WHERE route_id=? AND event_type=? ORDER BY seq",
            (route_id, event_type),
        )

    def read_lineage_events(
        self, lineage_hmac: str, event_type: str | None = None
    ) -> list[sqlite3.Row]:
        if event_type is None:
            return self.read(
                "SELECT * FROM lineage_events WHERE lineage_hmac=? ORDER BY seq", (lineage_hmac,)
            )
        return self.read(
            "SELECT * FROM lineage_events WHERE lineage_hmac=? AND event_type=? ORDER BY seq",
            (lineage_hmac, event_type),
        )

    def read_decision(self, route_id: str) -> sqlite3.Row | None:
        rows = self.read("SELECT * FROM decisions WHERE route_id=?", (route_id,))
        return rows[0] if rows else None
