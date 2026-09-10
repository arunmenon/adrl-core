"""Independent comparison and archive failure cases. Primary: ADRL-EVL-006, ADRL-MEM-010."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from adrl.api.contracts import VersionRef
from adrl.cli.main import app
from adrl.core.ports import SandboxResult
from adrl.learning.improvement import (
    AssessmentCase,
    AssessmentSuite,
    Budget,
    VerifierProposal,
    evaluate,
    suite_digest,
)
from adrl.ledger.improvement import ExperimentArchive
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.session_verification import (
    Artifact,
    SessionCheck,
    SessionPlan,
    SnapshotLimits,
    snapshot_digest,
)
from adrl.ledger.store import LedgerStore


@pytest.fixture
def archive(tmp_path: Path) -> Iterator[ExperimentArchive]:
    store = LedgerStore(tmp_path / "archive.db")
    store.open()
    try:
        yield ExperimentArchive(store, FileKeyStore(tmp_path / "keys", store=store))
    finally:
        store.close()


@pytest.fixture
def inputs(tmp_path: Path) -> tuple[VerifierProposal, AssessmentSuite]:
    artifact = tmp_path / "checks.py"
    artifact.write_text("PINNED_OPERATOR_TEST")
    plans = []
    for arm in ("baseline", "candidate"):
        plans.append(
            SessionPlan(
                verifier=VersionRef(id="checks", version=arm),
                task_ref="fixture-task",
                artifacts={
                    "checks.py": Artifact(
                        path=artifact, sha256=hashlib.sha256(artifact.read_bytes()).hexdigest()
                    )
                },
                checks=(
                    SessionCheck(name="checks", argv=("/bin/echo", arm), failure_exit_codes=(1,)),
                ),
            )
        )
    cases = []
    for index, (contents, expected) in enumerate(
        [("good", "passed"), ("bad", "failed"), ("environment", "indeterminate")]
    ):
        workspace = tmp_path / f"case-{index}"
        workspace.mkdir()
        (workspace / "fixture").write_text(contents)
        cases.append(
            AssessmentCase.model_validate(
                dict(
                    case_id=f"case-{index}",
                    workspace=workspace,
                    snapshot_sha256=snapshot_digest(workspace, SnapshotLimits()),
                    expected=expected,
                )
            )
        )
    suite = AssessmentSuite(suite=VersionRef(id="fixtures", version="1"), cases=tuple(cases))
    proposal = VerifierProposal(
        proposal=VersionRef(id="proposal", version="1"),
        proposer=VersionRef(id="reviewed", version="1"),
        hypothesis="PRIVATE_HYPOTHESIS",
        affected_adrs=("ADRL-MEM-003",),
        suite_sha256=suite_digest(suite),
        baseline=plans[0],
        candidate=plans[1],
        repeats=2,
        budget=Budget(max_commands=12, max_declared_timeout_s=720),
    )
    return proposal, suite


class FixtureRunner:
    def __init__(self, mode: str = "normal") -> None:
        self.mode = mode
        self.calls: list[tuple[str, str]] = []

    @property
    def platform_id(self) -> str:
        return "test-fixture-runner"

    def run(
        self, argv: Sequence[str], snapshot_dir: str, allow_list: Sequence[str], *, timeout_s: float
    ) -> SandboxResult:
        root = Path(snapshot_dir)
        assert (root / ".adrl-verifier/checks.py").read_text() == "PINNED_OPERATOR_TEST"
        contents = (root / "fixture").read_text()
        arm = argv[1]
        self.calls.append((contents, arm))
        code = (
            2 if contents == "environment" else 1 if contents == "bad" and arm == "candidate" else 0
        )
        if self.mode == "all_pass":
            code = 0
        if self.mode == "regression" and arm == "candidate" and contents == "good":
            code = 1
        if (
            self.mode == "flaky"
            and arm == "candidate"
            and contents == "bad"
            and self.calls.count((contents, arm)) == 2
        ):
            code = 0
        if self.mode == "snapshot_drift":
            (root / "fixture").chmod(0o600)
            (root / "fixture").write_text("mutated")
        return SandboxResult(
            available=self.mode != "unavailable",
            exit_code=None if self.mode == "timeout" else code,
            duration_s=0.01,
            stdout_tail="PRIVATE_PROGRAM_OUTPUT",
        )


async def test_complete_comparison_records_every_trial_without_promoting(
    archive: ExperimentArchive, inputs: tuple[VerifierProposal, AssessmentSuite]
) -> None:
    proposal, suite = inputs
    runner = FixtureRunner()
    report = await evaluate(proposal, suite, archive, runner)
    assert report.recommendation == "candidate_supported"
    assert (report.baseline_correct, report.candidate_correct, report.distinct_cases) == (2, 3, 3)
    assert report.trials_recorded == report.commands_recorded == 12
    assert report.review_required and not report.eligible_for_learning
    assert runner.calls[:4] == [
        ("good", "baseline"),
        ("good", "candidate"),
        ("good", "candidate"),
        ("good", "baseline"),
    ]
    records = archive.read(report.experiment_id)
    assert len(records) == 14
    assert records[0]["event_type"] == "started" and records[-1]["event_type"] == "finished"
    assert records[0]["record"]["proposal"]["hypothesis"] == "PRIVATE_HYPOTHESIS"
    for table in ("decisions", "events", "product_sessions", "product_verifications"):
        assert not archive.store.read(f"SELECT * FROM {table}")
    for row in archive.store.read("SELECT * FROM improvement_records"):
        assert b"PRIVATE_HYPOTHESIS" not in row["ciphertext"]
        assert b"PRIVATE_PROGRAM_OUTPUT" not in row["ciphertext"]
    reconstructed = ExperimentArchive(archive.store, archive.keys)
    assert reconstructed.read(report.experiment_id) == records
    assert reconstructed.erase(report.experiment_id)
    assert all(row["payload_state"] == "erased" for row in reconstructed.read(report.experiment_id))
    with pytest.raises(ValueError, match="key is unavailable"):
        await reconstructed.append(report.experiment_id, "finished", report)
    assert len(reconstructed.read(report.experiment_id)) == 14


@pytest.mark.parametrize(
    ("mode", "recommendation"),
    [
        ("all_pass", "regression"),
        ("regression", "regression"),
        ("flaky", "indeterminate"),
        ("unavailable", "indeterminate"),
        ("timeout", "indeterminate"),
        ("snapshot_drift", "indeterminate"),
    ],
)
async def test_bad_or_uncertain_candidates_never_qualify(
    archive: ExperimentArchive,
    inputs: tuple[VerifierProposal, AssessmentSuite],
    mode: str,
    recommendation: str,
) -> None:
    proposal, suite = inputs
    report = await evaluate(proposal, suite, archive, FixtureRunner(mode))
    assert report.recommendation == recommendation
    assert not report.eligible_for_learning and report.review_required


async def test_no_improvement_is_a_valid_preserved_result(
    archive: ExperimentArchive, inputs: tuple[VerifierProposal, AssessmentSuite]
) -> None:
    proposal, suite = inputs
    proposal = VerifierProposal.model_validate(
        proposal.model_dump() | {"min_additional_correct": 2}
    )
    report = await evaluate(proposal, suite, archive, FixtureRunner())
    assert report.recommendation == "no_improvement"
    assert archive.read(report.experiment_id)[-1]["record"]["candidate_correct"] == 3


async def test_changed_case_stops_before_execution(
    archive: ExperimentArchive, inputs: tuple[VerifierProposal, AssessmentSuite]
) -> None:
    proposal, suite = inputs
    (suite.cases[0].workspace / "fixture").write_text("changed after freezing")
    runner = FixtureRunner()
    report = await evaluate(proposal, suite, archive, runner)
    assert report.recommendation == "indeterminate"
    assert report.trials_recorded == 0 and not runner.calls
    assert "input_changed" in report.blockers
    assert len(archive.read(report.experiment_id)) == 2


@pytest.mark.parametrize("invalid", ["suite", "command_budget", "timeout_budget"])
async def test_admission_refuses_changes_or_excess_budget_before_recording(
    archive: ExperimentArchive, inputs: tuple[VerifierProposal, AssessmentSuite], invalid: str
) -> None:
    proposal, suite = inputs
    update = (
        {"suite_sha256": "0" * 64}
        if invalid == "suite"
        else {
            "budget": {
                "max_commands": 1 if invalid == "command_budget" else 100,
                "max_declared_timeout_s": 1 if invalid == "timeout_budget" else 720,
            }
        }
    )
    proposal = VerifierProposal.model_validate(proposal.model_dump() | update)
    runner = FixtureRunner()
    with pytest.raises(ValueError):
        await evaluate(proposal, suite, archive, runner)
    assert not runner.calls and not archive.store.read("SELECT * FROM improvement_records")


def test_duplicate_snapshots_cannot_inflate_case_count(
    inputs: tuple[VerifierProposal, AssessmentSuite],
) -> None:
    _, suite = inputs
    with pytest.raises(ValidationError, match="not distinct cases"):
        AssessmentSuite.model_validate(
            suite.model_dump()
            | {"cases": (*suite.cases, suite.cases[0].model_copy(update={"case_id": "duplicate"}))}
        )


async def test_execution_identity_must_match_the_frozen_input(
    archive: ExperimentArchive,
    inputs: tuple[VerifierProposal, AssessmentSuite],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from adrl.learning import improvement

    real = improvement.snapshot_fingerprint

    def different_identity(*args: object) -> tuple[str, str]:
        digest, _ = real(*args)  # type: ignore[arg-type]
        return digest, "wrong-source-identity"

    monkeypatch.setattr(improvement, "snapshot_fingerprint", different_identity)
    report = await evaluate(*inputs, archive, FixtureRunner())
    assert report.recommendation == "indeterminate"
    assert "input_changed" in report.blockers


def test_invalid_session_verification_cli_is_not_reported_as_a_failed_test(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "product",
            "verify",
            "--connection",
            str(tmp_path / "missing"),
            "--workspace",
            str(tmp_path),
            "--plan",
            str(tmp_path / "missing-plan"),
        ],
        env={
            "ADRL_LEDGER_PATH": str(tmp_path / "missing.db"),
            "ADRL_KEYSTORE_PATH": str(tmp_path / "missing-keys"),
        },
    )
    assert result.exit_code == 2
    assert "setup is invalid or unavailable" in result.output


def test_show_does_not_recreate_missing_archive_keys(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / "keys").mkdir()
    (state / "experiments.db").touch()
    result = CliRunner().invoke(
        app, ["improve", "show", "--state", str(state), "--experiment-id", "missing"]
    )
    assert result.exit_code == 2
    assert not list((state / "keys").iterdir())


async def test_changed_evaluator_keeps_start_identity_and_blocks_recommendation(
    archive: ExperimentArchive,
    inputs: tuple[VerifierProposal, AssessmentSuite],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from adrl.learning import improvement

    original = improvement.implementation_refs()
    changed = (VersionRef(id=original[0].id, version="changed"), original[1])
    versions = iter((original, changed))
    monkeypatch.setattr(improvement, "implementation_refs", lambda: next(versions))
    report = await evaluate(*inputs, archive, FixtureRunner())
    assert report.recommendation == "indeterminate"
    assert "implementation_changed" in report.blockers
    assert (report.evaluator, report.snapshot_executor) == original
