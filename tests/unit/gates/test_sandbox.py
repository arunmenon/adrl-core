"""OS sandbox (ADRL-SAF-007). Fault tests run for real where the platform binary exists."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from adrl.gates.sandbox import (
    BubblewrapRunner,
    CommandNotAllowedError,
    SeatbeltRunner,
    UnavailableRunner,
    detect_runner,
    git_worktree_snapshot,
    protected_path_diff,
    remove_worktree_snapshot,
    tree_digest,
)

ALLOW = ["/bin/sh -c", "/usr/bin/curl", "/bin/cat", "/bin/echo"]


def _runner() -> SeatbeltRunner | BubblewrapRunner:
    runner = detect_runner()
    if isinstance(runner, UnavailableRunner):
        pytest.skip("no OS sandbox on this host")
    return runner


def test_unavailable_runner_reports_unavailable(tmp_path: Path) -> None:
    result = UnavailableRunner().run(["/bin/echo", "hi"], str(tmp_path), ALLOW, timeout_s=5)
    assert not result.available and result.unavailable_reason


def test_command_not_in_allow_list_is_refused(tmp_path: Path) -> None:
    with pytest.raises(CommandNotAllowedError):
        detect_runner().run(["/bin/rm", "-rf", "x"], str(tmp_path), ALLOW, timeout_s=5)


def test_allowed_command_runs(tmp_path: Path) -> None:
    runner = _runner()
    result = runner.run(["/bin/echo", "hi"], str(tmp_path), ALLOW, timeout_s=10)
    assert result.available and result.exit_code == 0 and "hi" in result.stdout_tail


def test_network_egress_fails(tmp_path: Path) -> None:
    runner = _runner()
    result = runner.run(
        ["/usr/bin/curl", "-sS", "--max-time", "5", "https://example.com"],
        str(tmp_path),
        ALLOW,
        timeout_s=15,
    )
    assert result.available and result.exit_code not in (0, None)


def test_write_outside_scratch_fails(tmp_path: Path) -> None:
    runner = _runner()
    target = Path.home() / ".adrl-sandbox-write-test"
    result = runner.run(["/bin/sh", "-c", f"echo x > {target}"], str(tmp_path), ALLOW, timeout_s=10)
    try:
        assert result.exit_code not in (0, None)
        assert not target.exists()
    finally:
        if target.exists():
            target.unlink()


def test_denied_credential_read_fails(tmp_path: Path) -> None:
    runner = _runner()
    aws_dir = Path.home() / ".aws"
    created = False
    if not aws_dir.exists():
        aws_dir.mkdir()
        created = True
    probe = aws_dir / "adrl-sandbox-probe"
    probe.write_text("secret", encoding="utf-8")
    try:
        result = runner.run(["/bin/cat", str(probe)], str(tmp_path), ALLOW, timeout_s=10)
        assert result.exit_code not in (0, None)
        assert "secret" not in result.stdout_tail
    finally:
        probe.unlink()
        if created:
            os.rmdir(aws_dir)


def test_worktree_snapshot_and_diff(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", repo], check=True)
    subprocess.run(["git", "-C", repo, "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", repo, "config", "user.name", "t"], check=True)
    (repo / "a.txt").write_text("one", encoding="utf-8")
    subprocess.run(["git", "-C", repo, "add", "."], check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "init"], check=True)
    snapshot = git_worktree_snapshot(repo, tmp_path / "snap")
    before = tree_digest(snapshot, ["a.txt", "missing.txt"])
    (snapshot / "a.txt").write_text("two", encoding="utf-8")
    after = tree_digest(snapshot, ["a.txt", "missing.txt"])
    assert protected_path_diff(before, after) == ["a.txt"]
    assert (repo / "a.txt").read_text(encoding="utf-8") == "one"
    remove_worktree_snapshot(repo, snapshot)
