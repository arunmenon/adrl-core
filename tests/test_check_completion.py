"""Tests for tools/check_completion.py. Primary: ADRL-FND-005."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "check_completion.py"
CLAIM = "change router\n\nCompletion-Claim: W7.0b\nReview-Checkpoint: rv-test-2026-09-10\n"


def _git(root: pathlib.Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _make_runtime(tmp: pathlib.Path) -> pathlib.Path:
    root = tmp / "runtime"
    (root / "src" / "adrl" / "routing").mkdir(parents=True)
    (root / "tools").mkdir()
    (root / "tools" / "check_completion.py").write_text(TOOL.read_text())
    module = root / "src" / "adrl" / "routing" / "router.py"
    module.write_text('"""Router. Primary: ADRL-RTG-002."""\nX = 1\n')
    _git(root, "init", "-q", "-b", "main")
    _git(root, "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    _git(root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    return root


def _make_register(
    tmp: pathlib.Path,
    *,
    blocker_state: str,
    blocker_actor: str,
    cover: pathlib.Path | None,
    review_state: str = "reviewed",
) -> pathlib.Path:
    register = tmp / "register"
    folder = register / "reports" / "reviews" / "rv-test-2026-09-10"
    folder.mkdir(parents=True)
    finding = {
        "id": "RV-01",
        "global_id": "rv-test-2026-09-10:RV-01",
        "severity": "high",
        "blocking": True,
        "owning_adrs": ["ADRL-RTG-002"],
    }
    (folder / "findings.json").write_text(json.dumps({"findings": [finding]}))
    disposition = {"finding_id": "RV-01", "disposition": blocker_state, "actor": blocker_actor}
    (folder / "dispositions.jsonl").write_text(json.dumps(disposition) + "\n")
    (folder / "status.json").write_text(json.dumps({"state": review_state}))
    files = []
    if cover is not None:
        digest = hashlib.sha256(cover.read_bytes()).hexdigest()
        files.append(
            {"root": "runtime", "path": "src/adrl/routing/router.py", "disk_sha256": digest}
        )
    (folder / "inputs.json").write_text(json.dumps({"files": files}))
    return register


def _commit(root: pathlib.Path, message: str) -> None:
    _git(root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-am", message)


def _change_and_commit(root: pathlib.Path, message: str) -> None:
    module = root / "src" / "adrl" / "routing" / "router.py"
    module.write_text(module.read_text() + "Y = 2\n")
    _commit(root, message)


def _run(root: pathlib.Path, register: pathlib.Path) -> subprocess.CompletedProcess[str]:
    tool = str(root / "tools" / "check_completion.py")
    return subprocess.run(
        [sys.executable, tool, "--register", str(register)],
        cwd=root,
        capture_output=True,
        text=True,
    )


def test_no_claim_reports_blockers_and_passes(tmp_path: pathlib.Path) -> None:
    root = _make_runtime(tmp_path)
    register = _make_register(
        tmp_path, blocker_state="unresolved", blocker_actor="reviewer:x", cover=None
    )
    _change_and_commit(root, "change router")
    result = _run(root, register)
    assert result.returncode == 0
    assert "blocker touching changed owners: rv-test-2026-09-10:RV-01" in result.stdout


def test_claim_with_blocker_fails(tmp_path: pathlib.Path) -> None:
    root = _make_runtime(tmp_path)
    register = _make_register(
        tmp_path, blocker_state="unresolved", blocker_actor="reviewer:x", cover=None
    )
    _change_and_commit(root, CLAIM)
    result = _run(root, register)
    assert result.returncode == 1
    assert "blocking finding" in result.stdout


def test_claim_without_checkpoint_fails(tmp_path: pathlib.Path) -> None:
    root = _make_runtime(tmp_path)
    register = _make_register(
        tmp_path, blocker_state="verified-fixed", blocker_actor="reviewer:x", cover=None
    )
    _change_and_commit(root, "change router\n\nCompletion-Claim: W7.0b\n")
    result = _run(root, register)
    assert result.returncode == 1
    assert "without a Review-Checkpoint" in result.stdout


def test_implementer_cannot_clear_a_blocker(tmp_path: pathlib.Path) -> None:
    root = _make_runtime(tmp_path)
    register = _make_register(
        tmp_path, blocker_state="verified-fixed", blocker_actor="implementer:codex", cover=None
    )
    _change_and_commit(root, CLAIM)
    result = _run(root, register)
    assert result.returncode == 1
    assert "blocking finding" in result.stdout


def test_claim_with_uncovered_file_fails(tmp_path: pathlib.Path) -> None:
    root = _make_runtime(tmp_path)
    register = _make_register(
        tmp_path, blocker_state="verified-fixed", blocker_actor="reviewer:x", cover=None
    )
    _change_and_commit(root, CLAIM)
    result = _run(root, register)
    assert result.returncode == 1
    assert "not covered by checkpoint" in result.stdout


def test_claim_backed_by_checkpoint_passes(tmp_path: pathlib.Path) -> None:
    root = _make_runtime(tmp_path)
    module = root / "src" / "adrl" / "routing" / "router.py"
    module.write_text(module.read_text() + "Y = 2\n")
    register = _make_register(
        tmp_path, blocker_state="verified-fixed", blocker_actor="reviewer:x", cover=module
    )
    _commit(root, CLAIM)
    result = _run(root, register)
    assert result.returncode == 0, result.stdout
    assert "ok, claim" in result.stdout


@pytest.mark.parametrize("state", ["in-review", "changes-requested"])
def test_claim_against_unreviewed_checkpoint_fails(tmp_path: pathlib.Path, state: str) -> None:
    root = _make_runtime(tmp_path)
    module = root / "src" / "adrl" / "routing" / "router.py"
    module.write_text(module.read_text() + "Y = 2\n")
    register = _make_register(
        tmp_path,
        blocker_state="verified-fixed",
        blocker_actor="reviewer:x",
        cover=module,
        review_state=state,
    )
    _commit(root, CLAIM)
    result = _run(root, register)
    assert result.returncode == 1
    assert "not reviewed" in result.stdout
