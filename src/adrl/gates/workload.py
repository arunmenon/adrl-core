"""Authenticated workload identity for the repository gate. Primary: ADRL-SAF-008.
Also implements: ADRL-TRU-001 (register additions of 2026-09-03).

The repository a session works in must be asserted by something the proxy trusts, never
inferred from prompt text (which the model, a tool result or a malicious file can shape). The
launcher helper ``adrl launch`` inventories the repository on the developer's machine, signs a
short-lived assertion under the host secret and hands it to the harness as a request header
(``ANTHROPIC_CUSTOM_HEADERS``) or, for harnesses that cannot add headers, as a file keyed by the
session id the launcher chose. The proxy verifies the signature and expiry; only then does the
manifest lookup happen, keyed on the asserted identity with exact matching.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from adrl.core.errors import GateFailure
from adrl.core.types import RequestContext

log = structlog.get_logger(__name__)

HEADER_WORKLOAD_ASSERTION = "x-adrl-workload-assertion"
HEADER_SESSION_ID = "x-claude-code-session-id"
ASSERTION_VERSION = 1
ASSERTION_PREFIX = "adrlwa1"
DEFAULT_TTL_S = 8 * 3600
CLOCK_SKEW_S = 120
FINGERPRINT_SAMPLE = 64
ASSERTIONS_DIR = "assertions"


class AssertionInvalid(GateFailure):
    """A presented assertion failed verification; the identity is treated as unknown."""


@dataclass(frozen=True, slots=True)
class RepoInventory:
    """What the launcher observed about a repository root."""

    root: str
    remote: str | None
    head: str | None
    fingerprint: str
    tracked_files: int

    def identities(self) -> tuple[str, ...]:
        """Exact-match keys for the manifest: normalised remote first, then the root path."""
        out: list[str] = []
        if self.remote:
            out.append(normalise_identity(self.remote))
        out.append(normalise_identity(self.root))
        return tuple(out)


@dataclass(frozen=True, slots=True)
class WorkloadAssertion:
    inventory: RepoInventory
    issued_at: float
    expires_at: float
    nonce: str
    key_id: str
    session_id: str | None

    @property
    def assertion_id(self) -> str:
        return hashlib.sha256(self.nonce.encode()).hexdigest()[:24]

    def identities(self) -> tuple[str, ...]:
        return self.inventory.identities()


def normalise_identity(identity: str) -> str:
    text = identity.strip()
    if text.endswith("/"):
        text = text[:-1]
    if text.endswith(".git"):
        text = text[:-4]
    if "://" in text or text.startswith("git@"):
        return text.lower()
    return text


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64url(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


# inventory ------------------------------------------------------------------------------------


def _git(root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _walk_files(root: Path, limit: int = 20000) -> list[str]:
    out: list[str] = []
    skip = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
            if len(out) >= limit:
                return out
    return out


def inventory_repo(path: Path) -> RepoInventory:
    """Inventory a repository root: remote, HEAD and a content fingerprint.

    The fingerprint covers every tracked file name plus the content hash of a deterministic
    sample, so two checkouts of the same repository agree and a directory merely named like
    a repository does not.
    """
    root = path.resolve()
    if not root.is_dir():
        raise GateFailure(f"repository root {root} is not a directory")
    tracked_text = _git(root, "ls-files", "-z")
    if tracked_text is not None:
        tracked = sorted(p for p in tracked_text.split("\0") if p)
    else:
        tracked = _walk_files(root)
    remote = _git(root, "config", "--get", "remote.origin.url")
    head = _git(root, "rev-parse", "HEAD")
    digest = hashlib.sha256()
    for rel in tracked:
        digest.update(rel.encode())
        digest.update(b"\0")
    step = max(1, len(tracked) // FINGERPRINT_SAMPLE) if tracked else 1
    for rel in tracked[::step][:FINGERPRINT_SAMPLE]:
        try:
            digest.update(hashlib.sha256((root / rel).read_bytes()).digest())
        except OSError:
            digest.update(b"unreadable")
    return RepoInventory(
        root=str(root),
        remote=remote,
        head=head,
        fingerprint=digest.hexdigest(),
        tracked_files=len(tracked),
    )


# signing --------------------------------------------------------------------------------------


def sign_assertion(
    inventory: RepoInventory,
    key: bytes,
    *,
    ttl_s: int = DEFAULT_TTL_S,
    now: float | None = None,
    session_id: str | None = None,
) -> str:
    issued = now if now is not None else time.time()
    payload: dict[str, Any] = {
        "v": ASSERTION_VERSION,
        "root": inventory.root,
        "remote": inventory.remote,
        "head": inventory.head,
        "fingerprint": inventory.fingerprint,
        "tracked_files": inventory.tracked_files,
        "iat": issued,
        "exp": issued + ttl_s,
        "nonce": uuid.uuid4().hex,
        "kid": _key_id(key),
        "sid": session_id,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(key, body, hashlib.sha256).hexdigest()
    return f"{ASSERTION_PREFIX}.{_b64url(body)}.{signature}"


def verify_assertion(token: str, key: bytes, *, now: float | None = None) -> WorkloadAssertion:
    """Verify signature, key id and validity window; raise AssertionInvalid otherwise."""
    current = now if now is not None else time.time()
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != ASSERTION_PREFIX:
        raise AssertionInvalid("malformed workload assertion")
    try:
        body = _unb64url(parts[1])
    except (ValueError, TypeError) as exc:
        raise AssertionInvalid("malformed workload assertion body") from exc
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts[2]):
        raise AssertionInvalid("workload assertion signature does not verify")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise AssertionInvalid("workload assertion payload is not JSON") from exc
    if not isinstance(payload, Mapping) or payload.get("v") != ASSERTION_VERSION:
        raise AssertionInvalid("unsupported workload assertion version")
    if payload.get("kid") != _key_id(key):
        raise AssertionInvalid("workload assertion signed under a different key")
    issued = float(payload.get("iat", 0))
    expires = float(payload.get("exp", 0))
    if issued > current + CLOCK_SKEW_S:
        raise AssertionInvalid("workload assertion issued in the future")
    if expires <= current:
        raise AssertionInvalid("workload assertion expired")
    root = payload.get("root")
    fingerprint = payload.get("fingerprint")
    if not isinstance(root, str) or not isinstance(fingerprint, str):
        raise AssertionInvalid("workload assertion lacks repository identity")
    inventory = RepoInventory(
        root=root,
        remote=payload.get("remote") if isinstance(payload.get("remote"), str) else None,
        head=payload.get("head") if isinstance(payload.get("head"), str) else None,
        fingerprint=fingerprint,
        tracked_files=int(payload.get("tracked_files", 0)),
    )
    session = payload.get("sid")
    return WorkloadAssertion(
        inventory=inventory,
        issued_at=issued,
        expires_at=expires,
        nonce=str(payload.get("nonce", "")),
        key_id=str(payload.get("kid")),
        session_id=session if isinstance(session, str) else None,
    )


# proxy-side resolution ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssertionResolution:
    assertion: WorkloadAssertion | None
    source: str
    reason: str | None = None


class AssertionVerifier:
    """Finds and verifies the assertion for a request: header first, then the session file."""

    def __init__(self, key: bytes, assertion_dir: Path | None = None) -> None:
        self._key = key
        self._dir = assertion_dir

    @property
    def key_id(self) -> str:
        return _key_id(self._key)

    def _from_file(self, session_id: str | None) -> str | None:
        if self._dir is None or not session_id:
            return None
        safe = "".join(ch for ch in session_id if ch.isalnum() or ch in "-_")
        if not safe:
            return None
        path = self._dir / f"{safe}.token"
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None

    def resolve(self, ctx: RequestContext, *, now: float | None = None) -> AssertionResolution:
        session_id = ctx.headers.get(HEADER_SESSION_ID)
        token = ctx.headers.get(HEADER_WORKLOAD_ASSERTION)
        source = "header"
        if token is None:
            token = self._from_file(session_id)
            source = "session_file"
        if token is None:
            return AssertionResolution(None, "absent", "no workload assertion presented")
        try:
            assertion = verify_assertion(token, self._key, now=now)
        except AssertionInvalid as exc:
            log.warning("workload_assertion_rejected", source=source, reason=exc.detail)
            return AssertionResolution(None, source, exc.detail)
        if assertion.session_id and session_id and assertion.session_id != session_id:
            log.warning("workload_assertion_session_mismatch", source=source)
            return AssertionResolution(None, source, "assertion bound to another session")
        return AssertionResolution(assertion, source)


# launcher -------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LaunchMaterial:
    token: str
    session_id: str
    token_path: Path | None
    inventory: RepoInventory

    def env_exports(self) -> dict[str, str]:
        return {
            "ANTHROPIC_CUSTOM_HEADERS": f"{HEADER_WORKLOAD_ASSERTION}: {self.token}",
        }


def mint_launch(
    repo: Path,
    key: bytes,
    *,
    assertion_dir: Path | None,
    ttl_s: int = DEFAULT_TTL_S,
    session_id: str | None = None,
) -> LaunchMaterial:
    """Inventory the repository, sign the assertion, and stage the session-file fallback."""
    inventory = inventory_repo(repo)
    chosen = session_id or str(uuid.uuid4())
    token = sign_assertion(inventory, key, ttl_s=ttl_s, session_id=chosen)
    token_path: Path | None = None
    if assertion_dir is not None:
        assertion_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(assertion_dir, 0o700)
        token_path = assertion_dir / f"{chosen}.token"
        descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as fh:
            fh.write(token)
    return LaunchMaterial(token, chosen, token_path, inventory)
