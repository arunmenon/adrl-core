"""Verification events with provenance, sandbox port, drift and late evidence (ADRL-MEM-003)."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from adrl.config.models import CloseRule
from adrl.core.enums import FailureType, OutcomeState, VerificationResult
from adrl.ledger.events import LATE_EVIDENCE_EVENT, VERIFICATION_EVENT, read_stored_events
from adrl.ledger.outcomes import Closer, current_label
from adrl.ledger.store import LedgerStore
from adrl.ledger.verification import (
    PROTECTED_PATH_POLICY_VERSION,
    VERIFIER_VERSION,
    VerificationJobs,
    VerificationPlan,
    snapshot_tree,
)
from tests.unit.ledger.conftest import FakeRunner, write_decision, write_outcome

PLAN = {
    "plan_version": "targeted-tests-v1",
    "command_checks": [{"name": "tests", "argv": ["pytest", "-q"], "timeout_s": 30}],
    "require_changes": True,
    "max_changed_files": 5,
}


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / ".git" / "refs" / "heads").mkdir(parents=True)
    (ws / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (ws / ".git" / "refs" / "heads" / "main").write_text("abc123\n")
    (ws / "src").mkdir()
    (ws / "src" / "a.py").write_text("print('a')\n")
    (ws / "src" / "b.py").write_text("print('b')\n")
    return ws


def _snapshot(ws: Path) -> Path:
    snap = ws.parent / f"{ws.name}-snapshot"
    if snap.exists():
        shutil.rmtree(snap)
    shutil.copytree(ws, snap)
    return snap


def test_plan_cannot_drop_git_protection() -> None:
    with pytest.raises(ValidationError):
        VerificationPlan.model_validate({**PLAN, "forbidden_path_globs": ["data/**"]})
    with pytest.raises(ValidationError):
        VerificationPlan.model_validate({**PLAN, "surprise": 1})
    plan = VerificationPlan.model_validate(PLAN)
    assert plan.effective_allow_list == ("pytest",)


def test_snapshot_tree_reads_head_and_excludes_touched(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    identity = snapshot_tree(ws, ["src/a.py"])
    assert identity.head_commit == "abc123"
    (ws / "src" / "a.py").write_text("changed\n")
    again = snapshot_tree(ws, ["src/a.py"])
    assert again.content_hash != identity.content_hash
    assert again.excluding_touched_hash == identity.excluding_touched_hash


async def test_pass_and_fail_carry_provenance(ledger_store: LedgerStore, tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    rid = write_decision(ledger_store)
    write_outcome(
        ledger_store,
        rid,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        tree_identity=snapshot_tree(ws, ["src/a.py"]).as_record(),
    )
    runner = FakeRunner()
    jobs = VerificationJobs(ledger_store, runner)
    job = jobs.begin(
        rid,
        ws,
        VerificationPlan.model_validate(PLAN),
        served_rung="local",
        model="m",
        harness="claude-code",
        touched_paths=["src/a.py"],
    )
    (ws / "src" / "a.py").write_text("edited by the turn\n")
    outcome = await jobs.finish(job, snapshot_dir=_snapshot(ws))
    assert outcome.result is VerificationResult.PASS and not outcome.tree_drift
    event = read_stored_events(ledger_store, rid, VERIFICATION_EVENT)[-1]
    assert event.payload["verifier_version"] == VERIFIER_VERSION
    assert event.payload["protected_path_policy_version"] == PROTECTED_PATH_POLICY_VERSION
    assert event.payload["argv"][0][0] == "tests"
    assert event.payload["argv"][0][1].startswith("hmac:"), "argv is stored as a keyed hash"
    assert "pytest" not in json.dumps(event.payload), "no command line in clear"
    assert event.payload["tree_identity"]["head_commit"] == "abc123"
    assert runner.calls == [("pytest", "-q")]
    assert current_label(ledger_store, rid).result == "success"

    failing = FakeRunner(exit_codes={"pytest": 1})
    job2 = VerificationJobs(ledger_store, failing).begin(
        rid,
        ws,
        VerificationPlan.model_validate(PLAN),
        served_rung="local",
        model="m",
        harness="claude-code",
        touched_paths=["src/a.py"],
    )
    (ws / "src" / "a.py").write_text("edited again\n")
    outcome2 = await VerificationJobs(ledger_store, failing).finish(
        job2, snapshot_dir=_snapshot(ws)
    )
    assert outcome2.result is VerificationResult.FAIL
    label = current_label(ledger_store, rid)
    assert label.result == "failure" and label.failure_type is FailureType.TASK_CAPABILITY


async def test_policy_block_and_unavailable_sandbox_are_indeterminate(
    ledger_store: LedgerStore, tmp_path: Path
) -> None:
    ws = _workspace(tmp_path)
    rid = write_decision(ledger_store)
    jobs = VerificationJobs(ledger_store, FakeRunner())
    job = jobs.begin(
        rid, ws, VerificationPlan.model_validate(PLAN), served_rung="local", model="m", harness="h"
    )
    (ws / ".git" / "refs" / "heads" / "main").write_text("deadbeef\n")
    (ws / "src" / "a.py").write_text("x\n")
    outcome = await jobs.finish(job, snapshot_dir=_snapshot(ws))
    assert outcome.result is VerificationResult.INDETERMINATE
    assert outcome.violations and outcome.violations[0].startswith("protected_path_changed")
    assert current_label(ledger_store, rid).failure_type is FailureType.UNVERIFIABLE

    absent = VerificationJobs(ledger_store, None)
    job2 = absent.begin(
        rid, ws, VerificationPlan.model_validate(PLAN), served_rung="local", model="m", harness="h"
    )
    (ws / "src" / "b.py").write_text("y\n")
    outcome2 = await absent.finish(job2, snapshot_dir=_snapshot(ws))
    assert outcome2.result is VerificationResult.INDETERMINATE
    assert outcome2.unverifiable_reason == "sandbox_runner_absent"

    unavailable = VerificationJobs(ledger_store, FakeRunner(available=False))
    job3 = unavailable.begin(
        rid, ws, VerificationPlan.model_validate(PLAN), served_rung="local", model="m", harness="h"
    )
    (ws / "src" / "b.py").write_text("z\n")
    assert (
        await unavailable.finish(job3, snapshot_dir=_snapshot(ws))
    ).unverifiable_reason == "sandbox_unavailable"


async def test_tree_drift_is_flagged_and_ignored_by_labels(
    ledger_store: LedgerStore, tmp_path: Path
) -> None:
    ws = _workspace(tmp_path)
    rid = write_decision(ledger_store)
    write_outcome(
        ledger_store,
        rid,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        tree_identity=snapshot_tree(ws, ["src/a.py"]).as_record(),
    )
    (ws / "src" / "b.py").write_text("someone else edited this after closed_turn\n")
    jobs = VerificationJobs(ledger_store, FakeRunner())
    job = jobs.begin(
        rid,
        ws,
        VerificationPlan.model_validate(PLAN),
        served_rung="local",
        model="m",
        harness="h",
        touched_paths=["src/a.py"],
    )
    (ws / "src" / "a.py").write_text("turn edit\n")
    outcome = await jobs.finish(job, snapshot_dir=_snapshot(ws))
    assert outcome.result is VerificationResult.PASS and outcome.tree_drift
    assert current_label(ledger_store, rid).failure_type is FailureType.UNVERIFIABLE


async def test_verification_after_closed_final_is_late_evidence(
    ledger_store: LedgerStore, tmp_path: Path
) -> None:
    ws = _workspace(tmp_path)
    rid = write_decision(ledger_store, session="sv")
    write_outcome(
        ledger_store,
        rid,
        OutcomeState.CLOSED_TURN,
        producer_seq=2,
        session="sv",
        harness_reported_success=True,
    )
    await Closer(ledger_store, CloseRule()).scan(now=datetime.now(UTC) + timedelta(hours=2))
    jobs = VerificationJobs(ledger_store, FakeRunner(exit_codes={"pytest": 2}))
    job = jobs.begin(
        rid,
        ws,
        VerificationPlan.model_validate(PLAN),
        served_rung="local",
        model="m",
        harness="h",
        touched_paths=["src/a.py"],
    )
    (ws / "src" / "a.py").write_text("late\n")
    outcome = await jobs.finish(job, snapshot_dir=_snapshot(ws))
    assert outcome.late_evidence
    assert read_stored_events(ledger_store, rid, LATE_EVIDENCE_EVENT)
    assert current_label(ledger_store, rid).result == "failure"


def test_begin_refuses_unknown_route(ledger_store: LedgerStore, tmp_path: Path) -> None:
    from adrl.core.ids import mint_route_id

    with pytest.raises(ValueError):
        VerificationJobs(ledger_store, FakeRunner()).begin(
            mint_route_id(),
            _workspace(tmp_path),
            VerificationPlan.model_validate(PLAN),
            served_rung="local",
            model="m",
            harness="h",
        )
