"""Legacy product bindings retain gateway scope. Primary: ADRL-MEM-001, ADRL-SEM-007."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from adrl.api.contracts import SessionVerification, VersionRef
from adrl.api.store import ProductStore
from adrl.core.ids import SessionId
from adrl.ledger import crypto
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.migrations import load_migrations
from adrl.ledger.store import LedgerStore


def test_existing_binding_survives_mode_migration(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    connection = sqlite3.connect(path)
    try:
        for migration in load_migrations():
            if migration.version <= 3:
                connection.executescript(migration.sql)
        connection.execute(
            "INSERT INTO product_sessions VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "session",
                "repo",
                "claude-code",
                "1",
                "anthropic-messages-v1",
                "1",
                "1",
                "digest",
                "ts",
            ),
        )
        connection.execute("PRAGMA user_version=3")
        connection.commit()
    finally:
        connection.close()
    store = LedgerStore(path)
    store.open()
    try:
        row = dict(store.read("SELECT * FROM product_sessions")[0])
        assert row["integration_mode"] == "gateway"
        assert row["session_hmac"] == "session"
        assert row["config_digest"] == "digest"
        assert row["ts"] == "ts"
        assert store.schema_user_version() == 12
        assert not store.read("SELECT * FROM product_verifications")
        assert not store.read("SELECT * FROM product_captures")
    finally:
        store.close()


def test_version_six_receipt_still_decrypts_after_capture_migration(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    session = SessionId("a" * 64)
    keys = FileKeyStore(tmp_path / "keys")
    key = keys.create_session_key(session)
    receipt = SessionVerification(
        sandbox_implementation=VersionRef(id="fixture", version="1"),
        job_id="old-job",
        task_ref="old-task",
        phase="started",
        verifier=VersionRef(id="fixture-check", version="1"),
        plan_ref="old-plan",
        started_at=datetime.now(UTC),
    )
    job = crypto.keyed_hash(key, "verification:" + receipt.job_id)
    nonce, ciphertext = crypto.encrypt(
        key, receipt.model_dump_json().encode(), f"verification:{session}:{job}:started".encode()
    )
    with sqlite3.connect(path) as connection:
        for migration in load_migrations():
            if migration.version <= 6:
                connection.executescript(migration.sql)
        connection.execute(
            "INSERT INTO product_sessions "
            "(session_hmac,workload_ref,adapter_id,adapter_version,profile_id,profile_version,"
            "policy_version,config_digest,ts) VALUES (?,?,?,?,?,?,?,?,?)",
            (session, "fixture", "claude-code", "1", "anthropic-messages-v1", "1", "1", "d", "t"),
        )
        connection.execute(
            "INSERT INTO product_verifications "
            "(session_hmac,job_key,phase,nonce,ciphertext,ts) VALUES (?,?,?,?,?,?)",
            (session, job, "started", nonce, ciphertext, "old-time"),
        )
        connection.execute("PRAGMA user_version=6")
    store = LedgerStore(path)
    store.open()
    try:
        data = ProductStore(store, FileKeyStore(keys.root, store=store))
        row = dict(store.read("SELECT * FROM product_verifications")[0])
        assert store.schema_user_version() == 12
        assert row["ciphertext"] == ciphertext and row["ts"] == "old-time"
        assert data.verification(row) == receipt
        assert not store.read("SELECT * FROM product_captures")
    finally:
        store.close()
