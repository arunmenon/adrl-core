"""OS-enforced sandbox for verification commands. Primary: ADRL-SAF-007.

Seatbelt (`sandbox-exec`) on macOS, bubblewrap on Linux. No network, writes limited to scratch,
selected credential paths denied at the kernel boundary. Seatbelt allows other filesystem reads;
neither backend certifies arbitrary untrusted repository code as safe. Where no
sandbox is available the runner reports unavailable and the caller labels the outcome
`unverifiable`. Commands come from a per-repository allow-list, never from the transcript.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from adrl.core.ports import SandboxResult

log = structlog.get_logger(__name__)

DENIED_READ_SUFFIXES: tuple[str, ...] = (".aws", ".ssh", ".claude", ".gnupg", ".netrc", ".npmrc")
DENIED_READ_GLOBS: tuple[str, ...] = (".env", ".env.")
TAIL_BYTES = 4000


class CommandNotAllowedError(ValueError):
    """The argv was not in the repository's allow-list."""


def _allowed(argv: Sequence[str], allow_list: Sequence[str]) -> bool:
    """An allow-list entry matches when the joined argv starts with it (exact or prefix)."""
    joined = " ".join(argv)
    return any(joined == entry or joined.startswith(entry + " ") for entry in allow_list)


def _tail(data: bytes) -> str:
    return data[-TAIL_BYTES:].decode("utf-8", errors="replace")


def _run(argv: Sequence[str], cwd: str, timeout_s: float, env: Mapping[str, str]) -> SandboxResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return SandboxResult(
            available=True,
            exit_code=None,
            stdout_tail=_tail(exc.stdout or b""),
            stderr_tail=_tail(exc.stderr or b"") + "\n[timeout]",
            duration_s=time.monotonic() - started,
        )
    return SandboxResult(
        available=True,
        exit_code=completed.returncode,
        stdout_tail=_tail(completed.stdout),
        stderr_tail=_tail(completed.stderr),
        duration_s=time.monotonic() - started,
    )


def _minimal_env(scratch: str) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": scratch,
        "TMPDIR": scratch,
        "LANG": "C.UTF-8",
        "ADRL_SANDBOX": "1",
    }


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    snapshot_dir: str
    scratch_dir: str
    denied_read: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def build(cls, snapshot_dir: str, scratch_dir: str) -> SandboxPolicy:
        home = Path.home()
        denied = [str(home / suffix) for suffix in DENIED_READ_SUFFIXES]
        return cls(snapshot_dir=snapshot_dir, scratch_dir=scratch_dir, denied_read=tuple(denied))


class SeatbeltRunner:
    """macOS `sandbox-exec` with a generated profile."""

    def __init__(self) -> None:
        self._binary = shutil.which("sandbox-exec")

    @property
    def platform_id(self) -> str:
        return "macos-seatbelt"

    @property
    def available(self) -> bool:
        return self._binary is not None and platform.system() == "Darwin"

    @staticmethod
    def profile(policy: SandboxPolicy) -> str:
        """Allow-default with kernel-enforced denies, the same shape as the harness's own sandbox.

        Later rules win in Seatbelt, so writes are denied everywhere and then re-allowed only
        under the scratch tree and the tty devices. Network is denied outright. Credential
        paths and .env files are denied for reading. Paths are real paths because Seatbelt
        matches the resolved path (/tmp is a symlink on macOS).
        """

        def lit(path: str) -> str:
            return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

        scratch = os.path.realpath(policy.scratch_dir)
        lines = [
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            "(deny file-write*)",
            "(allow file-write*",
            f"  (subpath {lit(scratch)})",
            '  (literal "/dev/null") (regex #"^/dev/tty") (regex #"^/dev/fd/"))',
        ]
        for denied in policy.denied_read:
            lines.append(f"(deny file-read* (subpath {lit(os.path.realpath(denied))}))")
        lines.append('(deny file-read* (regex #"(^|/)\\.env($|\\.)"))')
        return "\n".join(lines) + "\n"

    def run(
        self,
        argv: Sequence[str],
        snapshot_dir: str,
        allow_list: Sequence[str],
        *,
        timeout_s: float,
    ) -> SandboxResult:
        if not self.available:
            return SandboxResult(available=False, unavailable_reason="sandbox-exec not available")
        if not _allowed(argv, allow_list):
            raise CommandNotAllowedError(" ".join(argv))
        scratch = tempfile.mkdtemp(prefix="adrl-scratch-")
        policy = SandboxPolicy.build(snapshot_dir, scratch)
        profile_path = Path(scratch) / "profile.sb"
        profile_path.write_text(self.profile(policy), encoding="utf-8")
        wrapped = [str(self._binary), "-f", str(profile_path), *argv]
        try:
            return _run(wrapped, snapshot_dir, timeout_s, _minimal_env(scratch))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


class BubblewrapRunner:
    """Linux bubblewrap: unshared network, read-only snapshot bind, writable scratch."""

    def __init__(self) -> None:
        self._binary = shutil.which("bwrap")

    @property
    def platform_id(self) -> str:
        return "linux-bubblewrap"

    @property
    def available(self) -> bool:
        return self._binary is not None and platform.system() == "Linux"

    def run(
        self,
        argv: Sequence[str],
        snapshot_dir: str,
        allow_list: Sequence[str],
        *,
        timeout_s: float,
    ) -> SandboxResult:
        if not self.available:
            return SandboxResult(available=False, unavailable_reason="bwrap not available")
        if not _allowed(argv, allow_list):
            raise CommandNotAllowedError(" ".join(argv))
        scratch = tempfile.mkdtemp(prefix="adrl-scratch-")
        wrapped = [
            str(self._binary),
            "--unshare-net",
            "--unshare-pid",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--ro-bind-try",
            "/etc",
            "/etc",
            "--ro-bind-try",
            "/opt",
            "/opt",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",  # noqa: S108
            "--ro-bind",
            snapshot_dir,
            snapshot_dir,
            "--bind",
            scratch,
            scratch,
            "--chdir",
            snapshot_dir,
            *argv,
        ]
        try:
            return _run(wrapped, snapshot_dir, timeout_s, _minimal_env(scratch))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


class UnavailableRunner:
    """No sandbox on this host; every run is unavailable so callers label `unverifiable`."""

    def __init__(self, reason: str = "no OS sandbox on this platform") -> None:
        self._reason = reason

    @property
    def platform_id(self) -> str:
        return f"unavailable-{platform.system().lower()}"

    def run(
        self,
        argv: Sequence[str],
        snapshot_dir: str,
        allow_list: Sequence[str],
        *,
        timeout_s: float,
    ) -> SandboxResult:
        if not _allowed(argv, allow_list):
            raise CommandNotAllowedError(" ".join(argv))
        return SandboxResult(available=False, unavailable_reason=self._reason)


def detect_runner() -> SeatbeltRunner | BubblewrapRunner | UnavailableRunner:
    seatbelt = SeatbeltRunner()
    if seatbelt.available:
        return seatbelt
    bwrap = BubblewrapRunner()
    if bwrap.available:
        return bwrap
    return UnavailableRunner()


# snapshots and evidence --------------------------------------------------------------------


def git_worktree_snapshot(repo: Path, dest: Path, ref: str = "HEAD") -> Path:
    """Detached worktree of `ref`; tests that mutate files cannot mutate the measured tree."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "--detach", str(dest), ref],
        check=True,
        capture_output=True,
    )
    return dest


def remove_worktree_snapshot(repo: Path, dest: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "remove", "--force", str(dest)],
        check=False,
        capture_output=True,
    )


def tree_digest(root: Path, paths: Sequence[str]) -> dict[str, str | None]:
    """Content hashes of the given paths, None when absent. Evidence, not the control."""
    import hashlib

    result: dict[str, str | None] = {}
    for rel in paths:
        target = root / rel
        if target.is_file():
            result[rel] = hashlib.sha256(target.read_bytes()).hexdigest()
        else:
            result[rel] = None
    return result


def protected_path_diff(
    before: Mapping[str, str | None], after: Mapping[str, str | None]
) -> list[str]:
    """Paths whose digest changed between snapshots; recorded as evidence (ADRL-SAF-007)."""
    return sorted(p for p in before if before[p] != after.get(p))
