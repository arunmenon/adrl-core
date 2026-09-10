"""Checkpoint key custody, off-device anchoring and anchor verification. Primary: ADRL-SAF-009.
Also implements: ADRL-TRU-003, ADRL-OPS-002, ADRL-OPS-007 (register additions of 2026-09-03).

The egress ledger signs a checkpoint every N entries and every T seconds with a key that is
separate from the manifest-signing key. Signed checkpoints are shipped to an anchor outside the
machine (an append-only file on an off-device mount, or an HTTP endpoint). A verifier holding
the public key set and the anchor file can detect deletion or edit of any row that precedes an
anchored checkpoint, including truncation of the ledger below the anchored sequence.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from adrl.core.errors import ConfigError

CHECKPOINT_MESSAGE_VERSION = "egress-checkpoint-v2"
DEV_KEY_MARKER = "dev"


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """Stable identifier derived from the public key, so rotation is a new id, not a rename."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def checkpoint_message(ledger_id: str, event_seq: int, digest: str) -> bytes:
    """The bytes a checkpoint signature covers; binds the digest to one ledger identity."""
    return f"{CHECKPOINT_MESSAGE_VERSION}|{ledger_id}|{event_seq}|{digest}".encode()


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError("checkpoint signing key must be Ed25519")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError("checkpoint public key must be Ed25519")
    return key


def load_public_keys(paths: Iterable[Path]) -> dict[str, Ed25519PublicKey]:
    """A key set keyed by key id; rotation means passing the old and the new key together."""
    keys: dict[str, Ed25519PublicKey] = {}
    for path in paths:
        public = load_public_key(path.read_bytes())
        keys[key_id_for(public)] = public
    return keys


def is_dev_key_path(path: Path) -> bool:
    """A key under a directory or file name containing 'dev' is a development key."""
    return any(DEV_KEY_MARKER in part.lower() for part in path.parts)


@dataclass(frozen=True, slots=True)
class CheckpointKey:
    private: Ed25519PrivateKey
    key_id: str
    path: Path
    dev: bool


def checkpoint_key_from_settings(settings: Any) -> CheckpointKey | None:
    """Load the checkpoint signing key named in settings, refusing a dev key without consent.

    Returns None when no key is configured; callers decide whether that is acceptable.
    """
    path: Path | None = getattr(settings, "checkpoint_signing_key_path", None)
    if path is None:
        return None
    dev = is_dev_key_path(path)
    if dev and not bool(getattr(settings, "dev_keys_allowed", False)):
        raise ConfigError(
            f"checkpoint signing key {path} is a development key; set ADRL_DEV_KEYS_ALLOWED=true "
            "only on a developer machine (ADRL-SAF-009)"
        )
    if not path.exists():
        raise ConfigError(f"checkpoint signing key not found: {path}")
    private = load_private_key(path.read_bytes())
    return CheckpointKey(
        private=private, key_id=key_id_for(private.public_key()), path=path, dev=dev
    )


def write_keypair(private_path: Path, public_path: Path) -> Ed25519PrivateKey:
    """Generate an Ed25519 keypair; the private file is created 0600 and never overwritten."""
    private = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """One shipped checkpoint as the anchor stores it; content-free."""

    ledger_id: str
    checkpoint_seq: int
    event_seq: int
    digest: str
    signature: str
    key_id: str
    ts: str

    def as_json(self) -> str:
        return json.dumps(
            {
                "ledger_id": self.ledger_id,
                "checkpoint_seq": self.checkpoint_seq,
                "event_seq": self.event_seq,
                "digest": self.digest,
                "signature": self.signature,
                "key_id": self.key_id,
                "ts": self.ts,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, line: str) -> AnchorRecord:
        data = json.loads(line)
        return cls(
            ledger_id=str(data["ledger_id"]),
            checkpoint_seq=int(data["checkpoint_seq"]),
            event_seq=int(data["event_seq"]),
            digest=str(data["digest"]),
            signature=str(data["signature"]),
            key_id=str(data["key_id"]),
            ts=str(data["ts"]),
        )


@runtime_checkable
class CheckpointShipper(Protocol):
    """Delivers a signed checkpoint off the machine and returns an acknowledgement string."""

    @property
    def destination(self) -> str: ...

    def ship(self, record: AnchorRecord) -> str: ...


class FileAnchorShipper:
    """Append-only anchor file, intended for a mount the proxy host cannot rewrite in place."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def destination(self) -> str:
        return f"file:{self._path}"

    def ship(self, record: AnchorRecord) -> str:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = record.as_json() + "\n"
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return hashlib.sha256(line.encode("utf-8")).hexdigest()


class HttpAnchorShipper:
    """POSTs the checkpoint to an anchoring service; the response body is the acknowledgement."""

    def __init__(self, url: str, *, timeout_s: float = 10.0, client: httpx.Client | None = None):
        self._url = url
        self._timeout = timeout_s
        self._client = client

    @property
    def destination(self) -> str:
        return self._url

    def ship(self, record: AnchorRecord) -> str:
        client = self._client or httpx.Client(timeout=self._timeout)
        try:
            response = client.post(
                self._url,
                content=record.as_json().encode("utf-8"),
                headers={"content-type": "application/json"},
            )
            response.raise_for_status()
            return response.text.strip()[:256] or "accepted"
        finally:
            if self._client is None:
                client.close()


def read_anchor_file(path: Path) -> list[AnchorRecord]:
    records: list[AnchorRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(AnchorRecord.from_json(line))
    return records


@dataclass(frozen=True, slots=True)
class AnchorVerification:
    ok: bool
    anchors: int
    newest_anchored_seq: int | None
    detail: str | None = None


def verify_anchor_signatures(
    anchors: Iterable[AnchorRecord], keys: Mapping[str, Ed25519PublicKey]
) -> AnchorVerification:
    """Every anchor must carry a signature valid under the key its key_id names."""
    count = 0
    newest: int | None = None
    for record in anchors:
        count += 1
        public = keys.get(record.key_id)
        if public is None:
            return AnchorVerification(False, count, newest, f"unknown key id {record.key_id}")
        try:
            import base64

            public.verify(
                base64.b64decode(record.signature),
                checkpoint_message(record.ledger_id, record.event_seq, record.digest),
            )
        except Exception:
            return AnchorVerification(
                False, count, newest, f"bad signature on anchor for seq {record.event_seq}"
            )
        newest = record.event_seq if newest is None or record.event_seq > newest else newest
    return AnchorVerification(True, count, newest)
