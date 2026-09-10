"""verify-finish refuses to run in the live workspace (ADRL-SAF-007, ADRL-MEM-003)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from adrl.cli.main import app
from adrl.ledger.store import LedgerStore


def test_verify_finish_requires_a_snapshot() -> None:
    result = CliRunner().invoke(app, ["ledger", "verify-finish", "--job-id", "job-1"])
    assert result.exit_code != 0
    assert "immutable snapshot" in (result.output + str(result.exception or ""))


def _git(repo: Path, *args: str) -> None:
    import subprocess

    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "HOME": str(repo),
        },
    )


def test_verify_begin_and_finish_run_in_separate_processes(tmp_path: Path) -> None:
    """The job material is sealed under the session key, so a second process can finish it
    (ADRL-MEM-003, ADRL-MEM-010)."""
    import json

    from tests.unit.ledger.conftest import write_decision

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "hello.txt").write_text("hello\n", encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "hello.txt")
    _git(repo, "commit", "-q", "-m", "init")

    ledger = tmp_path / "adrl.db"
    store = LedgerStore(ledger)
    store.open()
    try:
        route_id = write_decision(store)
    finally:
        store.close()

    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "plan_version": "targeted-tests-v1",
                "command_checks": [{"name": "list", "argv": ["/bin/ls"], "timeout_s": 30}],
                "require_changes": False,
                "allowed_commands": ["/bin/ls"],
            }
        ),
        encoding="utf-8",
    )
    env = {"ADRL_KEYSTORE_PATH": str(tmp_path / "keystore"), "ADRL_LEDGER_PATH": str(ledger)}

    begin = CliRunner().invoke(
        app,
        [
            "ledger",
            "verify-begin",
            "--route-id",
            str(route_id),
            "--workspace",
            str(repo),
            "--plan",
            str(plan),
            "--served-rung",
            "local",
            "--model",
            "local/test",
            "--ledger",
            str(ledger),
        ],
        env=env,
    )
    assert begin.exit_code == 0, begin.output + str(begin.exception)
    job_id = begin.output.strip().splitlines()[-1]

    finish = CliRunner().invoke(
        app,
        ["ledger", "verify-finish", "--job-id", job_id, "--auto-snapshot", "--ledger", str(ledger)],
        env=env,
    )
    assert finish.exit_code == 0, finish.output + str(finish.exception)
    report = json.loads(finish.output[finish.output.index("{") :])
    assert report["job_id"] == job_id
    assert report["route_id"] == str(route_id)
    assert report["result"] in {"pass", "fail", "indeterminate"}
