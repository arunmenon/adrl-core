"""Local integration client and observation outbox. Primary: ADRL-SEM-007.

Secondary: ADRL-MEM-001, ADRL-MEM-005. Tool text never enters an envelope or outbox.
Only PostToolUse and PostToolUseFailure are mapped; other hooks remain uncovered.
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

import httpx
from pydantic import BaseModel, ConfigDict

from adrl.api.contracts import EventRequest, IntegrationMode, OpaqueId
from adrl.gates.workload import HEADER_SESSION_ID, HEADER_WORKLOAD_ASSERTION
from adrl.ledger import crypto


class Connection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    server: str
    session_id: OpaqueId
    token_file: Path
    integration_mode: IntegrationMode = IntegrationMode.GATEWAY

    def headers(self) -> dict[str, str]:
        validate_server(self.server)
        return {
            HEADER_WORKLOAD_ASSERTION: self.token_file.read_text().strip(),
            HEADER_SESSION_ID: self.session_id,
        }


def validate_server(server: str) -> str:
    value = urlsplit(server)
    try:
        local = ipaddress.ip_address(value.hostname or "").is_loopback
    except ValueError:
        local = False
    if (
        not local
        or value.scheme != "http"
        or value.username
        or value.password
        or value.query
        or value.fragment
        or value.path not in {"", "/"}
    ):
        raise ValueError("The preview requires a loopback HTTP URL without credentials or a path.")
    return server.rstrip("/")


def write_private(path: Path, payload: bytes) -> None:
    """Create a private file exclusively; do not overwrite a previous connection."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)


def call(connection: Connection, method: str, path: str, body: Any = None) -> dict[str, Any]:
    with httpx.Client(
        base_url=validate_server(connection.server), trust_env=False, timeout=3.0
    ) as client:
        response = client.request(method, path, headers=connection.headers(), json=body)
    if response.status_code != 200:
        raise ValueError(f"ADRL product request failed with HTTP {response.status_code}.")
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("ADRL returned an invalid product response.")
    return result


class ToolOutbox:
    def __init__(self, directory: Path, session_id: str) -> None:
        self.session_id = session_id
        self.key = (directory / "outbox.key").read_bytes()
        path = directory / "outbox.db"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY, delivery_key TEXT UNIQUE, "
            "nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)"
        )
        self.db.execute("CREATE TABLE IF NOT EXISTS acknowledgements (seq INTEGER PRIMARY KEY)")

    def close(self) -> None:
        self.db.close()

    def capture(self, hook: dict[str, Any]) -> int:
        if hook.get("session_id") != self.session_id:
            raise ValueError("Hook session differs from the bound session.")
        kind = hook.get("hook_event_name")
        tool = hook.get("tool_use_id")
        if (
            kind not in {"PostToolUse", "PostToolUseFailure"}
            or not isinstance(tool, str)
            or not tool
        ):
            raise ValueError("Unsupported tool hook or missing tool identity.")
        identity = crypto.keyed_hash(self.key, f"{self.session_id}:{kind}:{tool}")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT seq FROM outbox WHERE delivery_key=?", (identity,)
            ).fetchone()
            if prior is not None:
                self.db.execute("COMMIT")
                return int(prior["seq"])
            seq = int(self.db.execute("SELECT COALESCE(MAX(seq),-1)+1 FROM outbox").fetchone()[0])
            event = EventRequest.model_validate(
                {
                    "event_id": str(uuid5(NAMESPACE_URL, identity)),
                    "session_id": self.session_id,
                    "producer_seq": seq,
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "event_type": "tool.completed",
                    "payload": {
                        "tool_call_ref": crypto.keyed_hash(self.key, f"tool:{tool}"),
                        "outcome": "completed" if kind == "PostToolUse" else "failed",
                    },
                }
            )
            nonce, ciphertext = crypto.encrypt(
                self.key, event.model_dump_json().encode(), aad=identity.encode()
            )
            self.db.execute(
                "INSERT INTO outbox VALUES (?,?,?,?)", (seq, identity, nonce, ciphertext)
            )
            self.db.execute("COMMIT")
            return seq
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def pending(self, limit: int = 50) -> list[tuple[int, EventRequest]]:
        rows = self.db.execute(
            "SELECT o.* FROM outbox o LEFT JOIN acknowledgements a ON a.seq=o.seq "
            "WHERE a.seq IS NULL ORDER BY o.seq LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            (
                int(row["seq"]),
                EventRequest.model_validate_json(
                    crypto.decrypt(
                        self.key, row["nonce"], row["ciphertext"], aad=row["delivery_key"].encode()
                    )
                ),
            )
            for row in rows
        ]

    def acknowledge(self, seq: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO acknowledgements VALUES (?)", (seq,))


def flush(connection: Connection, outbox: ToolOutbox, *, limit: int = 50) -> int:
    count = 0
    for seq, event in outbox.pending(limit):
        result = call(connection, "POST", "/adrl/v1/events", event.model_dump(mode="json"))
        if result.get("event_id") != str(event.root.event_id) or result.get("status") != "recorded":
            raise ValueError("Unexpected event acknowledgement; observation retained for retry.")
        outbox.acknowledge(seq)
        count += 1
    return count
