"""Cancellation cannot kill the evidence writer. Primary: ADRL-MEM-001, ADRL-MEM-006."""

from __future__ import annotations

import asyncio
import sqlite3
import threading

import pytest

from adrl.ledger.store import LedgerStore


async def test_cancel_after_writer_started_preserves_commit_and_next_write(
    ledger_store: LedgerStore,
) -> None:
    started = threading.Event()
    release = threading.Event()

    def blocked(conn: sqlite3.Connection) -> int:
        started.set()
        assert release.wait(5)
        conn.execute(
            "INSERT INTO lineage_events (lineage_hmac,event_type,ts,payload_json) "
            "VALUES ('test','cancelled_client','now','{}')"
        )
        return 1

    pending = asyncio.create_task(ledger_store.write_through(blocked))
    assert await asyncio.to_thread(started.wait, 5)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    release.set()
    assert await asyncio.wait_for(ledger_store.write_through(lambda conn: 2), timeout=5) == 2
    assert len(ledger_store.read_lineage_events("test")) == 1
    assert ledger_store.read("PRAGMA synchronous")[0][0] == 2  # FULL
