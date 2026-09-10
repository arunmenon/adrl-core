"""File keystore for per-session keys and the host HMAC secret. Primary: ADRL-MEM-010.

Secondary: ADRL-MEM-005, ADRL-MEM-001, ADRL-OPS-001. Private layout (mode 0700):
  master.key           host-local master key, wraps session keys
  hmac.key             host-local secret for keyed instruction hashes
  sessions/<hmac>.key  nonce || AES-GCM(master, session key); removed on shredding
  revoked/<hmac>.revoked  persistent denial marker, published before key mutation
  .keystore.lock      cooperating POSIX callers; nonblocking shared/exclusive lock
Session keys never enter the ledger. The session_keys table records create and shred actions
with the key id only, so an audit can see that a key existed and when it was destroyed.
"""

from __future__ import annotations

import errno
import fcntl
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag

from adrl.core.ids import SessionId
from adrl.ledger import crypto
from adrl.ledger.store import LedgerStore, utc_now_iso

MASTER_FILE = "master.key"
HMAC_FILE = "hmac.key"
SESSIONS_DIR = "sessions"
REVOKED_DIR = "revoked"
REVOCATION_VERSION = b"session-key-revocation-v1\n"


class KeyRevokedError(ValueError):
    """This session cannot receive or expose a key again."""


class KeyStoreBusyError(BlockingIOError):
    """A cooperating writer/read operation owns the keystore lock; no implicit retry."""


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("symlink_keystore_directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _write_private(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=f".key-write-{path.name}-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_pending(path: Path) -> bool:
    removed = False
    for pending in path.parent.glob(f".key-write-{path.name}-*"):
        info = pending.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsafe_pending_key_file")
        pending.unlink()
        removed = True
    if removed:
        _sync_directory(path.parent)
    return removed


class FileKeyStore:
    """KeyStore adapter over 0600 files; optional ledger for the create/shred audit rows."""

    def __init__(self, root: Path, *, store: LedgerStore | None = None) -> None:
        self._root = root
        self._store = store
        _private_directory(self._root)
        with self._lock():
            for directory in (SESSIONS_DIR, REVOKED_DIR):
                _private_directory(self._root / directory)
            for name in (MASTER_FILE, HMAC_FILE):
                _remove_pending(self._root / name)
                if not (self._root / name).exists():
                    _write_private(self._root / name, crypto.new_key())
            _sync_directory(self._root)

    @contextmanager
    def _lock(self, *, shared: bool = False) -> Iterator[None]:
        fd = os.open(
            self._root / ".keystore.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe_keystore_lock")
            os.fchmod(fd, 0o600)
            operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            try:
                fcntl.flock(fd, operation | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise KeyStoreBusyError("keystore_busy") from None
                raise
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @property
    def root(self) -> Path:
        return self._root

    def _master(self) -> bytes:
        return (self._root / MASTER_FILE).read_bytes()

    def _session_path(self, session: SessionId) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", str(session)):
            raise ValueError("invalid_session_key_identity")
        return self._root / SESSIONS_DIR / f"{session}.key"

    def _revocation_path(self, session: SessionId) -> Path:
        self._session_path(session)
        return self._root / REVOKED_DIR / f"{session}.revoked"

    def is_revoked(self, session: SessionId) -> bool:
        """Presence alone denies access, even for a partial or malformed marker."""
        marker = self._revocation_path(session)
        if os.path.lexists(marker):
            return True
        if self._store is None:
            return False
        return bool(
            self._store.read(
                "SELECT 1 FROM session_keys WHERE session_hmac=? AND action='shredded' "
                "UNION ALL SELECT 1 FROM lineage_events WHERE lineage_hmac=? "
                "AND event_type='erased' LIMIT 1",
                (str(session), str(session)),
            )
        )

    def _publish_revocation(self, session: SessionId) -> None:
        marker = self._revocation_path(session)
        try:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            fd = os.open(marker, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe_revocation_marker")
            os.fchmod(fd, 0o600)
            if info.st_size == 0 and os.write(fd, REVOCATION_VERSION) != len(REVOCATION_VERSION):
                raise OSError("short_revocation_write")
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync_directory(marker.parent)

    def _read_session_key(self, session: SessionId) -> bytes | None:
        path = self._session_path(session)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe_session_key_file")
            blob = handle.read(crypto.NONCE_BYTES + crypto.KEY_BYTES + 17)
        if len(blob) != crypto.NONCE_BYTES + crypto.KEY_BYTES + 16:
            raise ValueError("invalid_wrapped_key_size")
        return crypto.decrypt(
            self._master(),
            blob[: crypto.NONCE_BYTES],
            blob[crypto.NONCE_BYTES :],
            aad=str(session).encode(),
        )

    def _remove_session_key(self, session: SessionId) -> bool:
        path = self._session_path(session)
        removed_pending = _remove_pending(path)
        if not os.path.lexists(path):
            return removed_pending
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsafe_session_key_file")
        # Revocation is already durable. This replacement/unlink is logical removal,
        # not a claim about SSD blocks, old inodes, snapshots or cached plaintext.
        _write_private(path, os.urandom(crypto.NONCE_BYTES + crypto.KEY_BYTES + 16))
        path.unlink()
        _sync_directory(path.parent)
        return True

    def _audit(
        self, session: SessionId, action: str, key_identifier: str, reason: str | None
    ) -> None:
        if self._store is None:
            return

        def write(conn: sqlite3.Connection) -> None:
            conn.execute(
                "INSERT INTO session_keys (session_hmac, key_id, wrapped_key, action, reason, ts) "
                "VALUES (?,?,NULL,?,?,?)",
                (str(session), key_identifier, action, reason, utc_now_iso()),
            )

        self._store.submit(write).result(timeout=10)

    def create_session_key(self, session: SessionId) -> bytes:
        with self._lock():
            path = self._session_path(session)
            if self.is_revoked(session):
                raise KeyRevokedError("session_key_revoked")
            _remove_pending(path)
            existing = self._read_session_key(session)
            if existing is not None:
                return existing
            key = crypto.new_key()
            nonce, wrapped = crypto.encrypt(self._master(), key, aad=str(session).encode())
            _write_private(path, nonce + wrapped)
        # Never wait on a ledger writer while holding its required keystore lock.
        self._audit(session, "created", crypto.key_id(key), None)
        if self.is_revoked(session):
            raise KeyRevokedError("session_key_revoked")
        return key

    def get_session_key(self, session: SessionId) -> bytes | None:
        with self._lock(shared=True):
            if self.is_revoked(session):
                return None
            return self._read_session_key(session)

    def shred_session_key(self, session: SessionId, reason: str) -> bool:
        with self._lock():
            self._publish_revocation(session)
            try:
                key = self._read_session_key(session)
            except (ValueError, InvalidTag):
                key = None
            identifier = crypto.key_id(key) if key else "unknown"
            removed = self._remove_session_key(session)
        self._audit(session, "shredded", identifier, reason)
        return removed

    def has_session_key(self, session: SessionId) -> bool:
        return self.get_session_key(session) is not None

    def hmac_key(self) -> bytes:
        return (self._root / HMAC_FILE).read_bytes()

    def hmac_key_id(self) -> str:
        return crypto.key_id(self.hmac_key())

    def rotate_hmac_key(self) -> tuple[str, str]:
        """Replace the host HMAC secret; the caller records a projection rebuild (ADRL-MEM-007)."""
        with self._lock():
            old = self.hmac_key_id()
            _write_private(self._root / HMAC_FILE, crypto.new_key())
            return old, self.hmac_key_id()
