"""Synthetic lab accounting and dispatch evidence. Primary: ADRL-EVL-005."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/run_routing_lab.py"
SUITE = ROOT / "artifacts/lab/routing-suite-v1.json"


def command(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    root = tmp_path_factory.mktemp("routing-lab")
    out = root / "run"
    # This invalid endpoint must never be used, nor may ambient paths receive writes.
    ambient = root / "must-not-exist"
    env = {
        **os.environ,
        "ADRL_CLASSIFIER_BASE_URL": "http://127.0.0.1:1",
        "ADRL_LEDGER_PATH": str(ambient),
        "ADRL_CONFIG_DIR": str(ambient),
        "ADRL_EGRESS_ANCHOR_URL": "http://127.0.0.1:1",
    }
    run = command("--suite", str(SUITE), "--out", str(out), env=env)
    assert run.returncode == 0, run.stdout + run.stderr
    assert not ambient.exists()
    return out, json.loads((out / "results.json").read_text())


def rows(report: dict[str, Any]) -> dict[str, Any]:
    return {row["case_id"]: row for row in report["rows"]}


def event(row: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [e["payload"] for e in row["events"] if e["event_type"] == kind]


def test_composed_choices_reach_endpoint_and_context_changes_choice(lab) -> None:
    _, report = lab
    data = rows(report)
    assert data["small-edit"]["decisions"][0]["decided_rung"] == "local"
    assert data["refactor"]["decisions"][0]["decided_rung"] == "frontier"
    assert data["long-context"]["decisions"][0]["decided_rung"] == "frontier"
    assert event(data["small-edit"], "request")[0]["target_rung"] == "local"
    assert data["small-edit"]["dispatched"][0]["model"] == "local-qwen-7b"
    assert data["refactor"]["dispatched"][0]["model"] == "claude-fable-5-1"
    assert report["eligible_for_learning"] is False
    assert report["task_success"] is None


def test_continuation_keeps_original_decision_and_records_escalation(lab) -> None:
    data = rows(lab[1])
    route_id = data["small-edit"]["decisions"][0]["route_id"]
    assert data["loop-escalated"]["decisions"][0]["route_id"] == route_id
    assert data["loop-escalated"]["decisions"][0]["decided_rung"] == "local"
    assert event(data["loop-escalated"], "request")[0]["target_rung"] == "cheap_cloud"
    assert data["loop-escalated"]["dispatched"][0]["model"] == "cheap-haiku-us"


def test_negative_cases_stay_in_denominator_and_receipt_is_honest(lab) -> None:
    _, report = lab
    data = rows(report)
    assert report["planned"] == 16 == sum(report["counts"].values())
    assert data["pinned-overflow"]["state"] == "blocked"
    assert not data["pinned-overflow"]["dispatched"]
    assert data["secret-pin"]["dispatched"][0]["model"] == "local-qwen-7b"
    assert data["pin-persists"]["dispatched"][0]["model"] == "local-qwen-7b"
    assert data["upstream-error"]["state"] == "upstream_error"
    assert data["upstream-error"]["http_status"] == 503
    assert data["responses-unqualified"]["state"] == "unsupported"
    assert event(data["missing-identity"], "served")[0]["served_source"] == "assumed_intended"


def test_existing_output_is_never_overwritten(lab) -> None:
    out, _ = lab
    before = (out / "events.jsonl").read_bytes()
    run = command("--suite", str(SUITE), "--out", str(out))
    assert run.returncode != 0
    assert (out / "events.jsonl").read_bytes() == before


def test_manifest_preserves_code_identity_and_readable_report(lab) -> None:
    out, report = lab
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["source"] == "synthetic"
    assert manifest["source_manifest"]["src/adrl/routing/router.py"]["sha256"]
    assert manifest["source_manifest"]["config/policy.yaml"]["sha256"]
    assert manifest["suite_sha256"]
    assert report["source_unchanged_during_run"] is True
    view = (out / "report.md").read_text()
    assert "loop-escalated | local | cheap_cloud" in view
    assert "no task" in view.lower() or "no harness or model" in view.lower()


def test_interrupted_journal_includes_unstarted_cases(tmp_path: Path) -> None:
    suite = json.loads(SUITE.read_text())
    (tmp_path / "manifest.json").write_text(
        json.dumps({"experiment_id": "interrupted", "suite": suite})
    )
    (tmp_path / "events.jsonl").write_text(
        json.dumps({"type": "started", "case_id": "small-edit"}) + '\n{"type":'
    )
    run = command("--inspect", str(tmp_path))
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["counts"] == {"indeterminate": 1, "not_started": 15}
    assert report["truncated_tail"] is True


def test_duplicate_case_rejected_before_any_run(tmp_path: Path) -> None:
    suite = json.loads(SUITE.read_text())
    suite["cases"].append(suite["cases"][0])
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(suite))
    out = tmp_path / "out"
    run = command("--suite", str(path), "--out", str(out))
    assert run.returncode != 0
    assert not out.exists()
