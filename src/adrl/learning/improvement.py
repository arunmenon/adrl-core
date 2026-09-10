"""Compare reviewed verifier proposals offline. Primary: ADRL-EVL-006.

Secondary: ADRL-LRN-005, ADRL-LRN-007, ADRL-MEM-003, ADRL-EVL-005, ADRL-EVL-009.
This is a curated synthetic mechanism check, not a routing graduation report. It executes
frozen plans on fixed inputs, preserves every result and never deploys or produces labels.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from adrl.api.contracts import OpaqueId, SessionVerification, VersionRef
from adrl.config.loaders import canonical_json
from adrl.core.ports import SandboxRunner
from adrl.ledger import session_verification
from adrl.ledger.improvement import ExperimentArchive
from adrl.ledger.session_verification import (
    SessionPlan,
    SnapshotLimits,
    SnapshotVerifier,
    snapshot_digest,
    snapshot_fingerprint,
)

Sha256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
AdrId = Annotated[
    str, StringConstraints(pattern=r"^ADRL-(FND|SEM|SAF|RTG|CAS|MEM|LRN|TRU|EVL|OPS)-[0-9]{3}$")
]
Outcome = Literal["passed", "failed", "indeterminate"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AssessmentCase(Record):
    case_id: OpaqueId
    workspace: Path
    snapshot_sha256: Sha256
    expected: Outcome

    @model_validator(mode="after")
    def absolute_workspace(self) -> AssessmentCase:
        if not self.workspace.is_absolute():
            raise ValueError("Assessment working copies need absolute paths.")
        return self


class AssessmentSuite(Record):
    schema_version: Literal["verifier-assessment-v1"] = "verifier-assessment-v1"
    suite: VersionRef
    evidence_family: Literal["curated_synthetic"] = "curated_synthetic"
    limits: SnapshotLimits = SnapshotLimits()
    cases: tuple[AssessmentCase, ...] = Field(min_length=3, max_length=30)

    @model_validator(mode="after")
    def distinct_and_complete(self) -> AssessmentSuite:
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Case IDs must be unique.")
        if len({case.snapshot_sha256 for case in self.cases}) != len(self.cases):
            raise ValueError("Repeated copies of one snapshot are not distinct cases.")
        if {case.expected for case in self.cases} != {"passed", "failed", "indeterminate"}:
            raise ValueError("Include correct, incorrect and environment-failed examples.")
        return self


def suite_digest(suite: AssessmentSuite) -> str:
    return hashlib.sha256(canonical_json(suite.model_dump(mode="json"))).hexdigest()


class Budget(Record):
    max_commands: int = Field(ge=1, le=1000)
    max_declared_timeout_s: float = Field(gt=0, le=3600, allow_inf_nan=False)


class VerifierProposal(Record):
    schema_version: Literal["verifier-proposal-v1"] = "verifier-proposal-v1"
    proposal: VersionRef
    parent_ref: OpaqueId | None = None
    proposer: VersionRef
    hypothesis: str = Field(min_length=1, max_length=2000)
    affected_adrs: tuple[AdrId, ...] = Field(min_length=1)
    change_scope: Literal["verifier"] = "verifier"
    suite_sha256: Sha256
    baseline: SessionPlan
    candidate: SessionPlan
    repeats: int = Field(default=2, ge=1, le=5)
    min_additional_correct: int = Field(default=1, ge=1)
    budget: Budget

    @model_validator(mode="after")
    def comparable_plans(self) -> VerifierProposal:
        if self.baseline.verifier == self.candidate.verifier:
            raise ValueError("Baseline and candidate need distinct verifier versions.")
        if self.baseline.task_ref != self.candidate.task_ref:
            raise ValueError("Baseline and candidate must refer to the same task family.")
        return self

    def admit(self, suite: AssessmentSuite) -> None:
        if suite_digest(suite) != self.suite_sha256:
            raise ValueError("The assessment suite differs from the pinned suite.")
        plans = (self.baseline, self.candidate)
        commands = len(suite.cases) * self.repeats * sum(len(p.checks) for p in plans)
        timeout = (
            len(suite.cases)
            * self.repeats
            * sum(check.timeout_s for plan in plans for check in plan.checks)
        )
        if commands > self.budget.max_commands or timeout > self.budget.max_declared_timeout_s:
            raise ValueError("The declared experiment exceeds its command or timeout budget.")


class Trial(Record):
    case_id: OpaqueId
    repeat: int = Field(ge=0)
    arm: Literal["baseline", "candidate"]
    expected: Outcome
    verification: SessionVerification
    input_matches: bool


def implementation_refs() -> tuple[VersionRef, VersionRef]:
    def version(name: str, path: Path) -> VersionRef:
        return VersionRef(
            id=name, version="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        )

    return (
        version("verifier-comparison", Path(__file__)),
        version("snapshot-execution", Path(session_verification.__file__)),
    )


class ExperimentStart(Record):
    schema_version: Literal["verifier-experiment-start-v1"] = "verifier-experiment-start-v1"
    experiment_id: OpaqueId
    evaluator: VersionRef
    snapshot_executor: VersionRef
    started_at: datetime
    proposal: VerifierProposal
    suite: AssessmentSuite


class ExperimentReport(Record):
    schema_version: Literal["verifier-experiment-report-v1"] = "verifier-experiment-report-v1"
    experiment_id: OpaqueId
    proposal: VersionRef
    evaluator: VersionRef
    snapshot_executor: VersionRef
    suite: VersionRef
    evidence_family: Literal["curated_synthetic"] = "curated_synthetic"
    eligible_for_learning: Literal[False] = False
    review_required: Literal[True] = True
    recommendation: Literal["candidate_supported", "no_improvement", "regression", "indeterminate"]
    distinct_cases: int
    repeats: int
    trials_recorded: int
    commands_recorded: int
    baseline_correct: int
    candidate_correct: int
    candidate_false_passes: int
    candidate_false_failures: int
    blockers: tuple[OpaqueId, ...]
    check_duration_s: float
    started_at: datetime
    finished_at: datetime


def assess(
    experiment_id: str,
    proposal: VerifierProposal,
    suite: AssessmentSuite,
    trials: list[Trial],
    started_at: datetime,
    blockers: list[str],
    implementations: tuple[VersionRef, VersionRef],
) -> ExperimentReport:
    """Compare each distinct case conservatively; repetition does not multiply sample size."""
    groups = {
        (case.case_id, arm): [t for t in trials if t.case_id == case.case_id and t.arm == arm]
        for case in suite.cases
        for arm in ("baseline", "candidate")
    }
    if len(trials) != len(suite.cases) * 2 * proposal.repeats:
        blockers.append("incomplete_experiment")
    for members in groups.values():
        if len({t.verification.result for t in members}) > 1:
            blockers.append("repeat_disagreement")
        if any(not t.input_matches for t in members):
            blockers.append("input_changed")
    correct = {
        key: len(members) == proposal.repeats
        and all(t.verification.result == t.expected for t in members)
        for key, members in groups.items()
    }
    baseline = sum(correct[case.case_id, "baseline"] for case in suite.cases)
    candidate = sum(correct[case.case_id, "candidate"] for case in suite.cases)
    regressions = any(
        correct[case.case_id, "baseline"] and not correct[case.case_id, "candidate"]
        for case in suite.cases
    )
    false_passes = sum(
        any(t.verification.result == "passed" for t in groups[case.case_id, "candidate"])
        for case in suite.cases
        if case.expected != "passed"
    )
    false_failures = sum(
        any(t.verification.result == "failed" for t in groups[case.case_id, "candidate"])
        for case in suite.cases
        if case.expected == "passed"
    )
    recommendation = "no_improvement"
    if blockers:
        recommendation = "indeterminate"
    elif regressions or false_passes or false_failures:
        recommendation = "regression"
    elif candidate - baseline >= proposal.min_additional_correct:
        recommendation = "candidate_supported"
    return ExperimentReport.model_validate(
        dict(
            experiment_id=experiment_id,
            proposal=proposal.proposal,
            evaluator=implementations[0],
            snapshot_executor=implementations[1],
            suite=suite.suite,
            recommendation=recommendation,
            distinct_cases=len(suite.cases),
            repeats=proposal.repeats,
            trials_recorded=len(trials),
            commands_recorded=sum(len(t.verification.checks) for t in trials),
            baseline_correct=baseline,
            candidate_correct=candidate,
            candidate_false_passes=false_passes,
            candidate_false_failures=false_failures,
            blockers=tuple(sorted(set(blockers))),
            check_duration_s=sum(c.duration_s for t in trials for c in t.verification.checks),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
    )


async def evaluate(
    proposal: VerifierProposal,
    suite: AssessmentSuite,
    archive: ExperimentArchive,
    runner: SandboxRunner,
) -> ExperimentReport:
    proposal.admit(suite)
    implementations = implementation_refs()
    executor = SnapshotVerifier(archive.keys.hmac_key(), runner)
    experiment_id = archive.begin()
    started = datetime.now(UTC)
    await archive.append(
        experiment_id,
        "started",
        ExperimentStart(
            experiment_id=experiment_id,
            evaluator=implementations[0],
            snapshot_executor=implementations[1],
            started_at=started,
            proposal=proposal,
            suite=suite,
        ),
    )
    trials: list[Trial] = []
    blockers: list[str] = []
    try:
        for case_index, case in enumerate(suite.cases):
            for repetition in range(proposal.repeats):
                arms: tuple[Literal["baseline", "candidate"], ...] = ("baseline", "candidate")
                if (case_index + repetition) % 2:
                    arms = tuple(reversed(arms))
                for arm in arms:
                    digest, source_ref = await asyncio.to_thread(
                        snapshot_fingerprint, case.workspace, suite.limits, executor.secret
                    )
                    if digest != case.snapshot_sha256:
                        blockers.append("input_changed")
                        raise ValueError("Fixed experiment input changed.")
                    plan = proposal.baseline if arm == "baseline" else proposal.candidate
                    receipt = await executor.evaluate(case.workspace, plan, executor.start(plan))
                    after = await asyncio.to_thread(snapshot_digest, case.workspace, suite.limits)
                    trial = Trial(
                        case_id=case.case_id,
                        repeat=repetition,
                        arm=arm,
                        expected=case.expected,
                        verification=receipt,
                        input_matches=(
                            after == digest
                            and receipt.snapshot_unchanged is True
                            and receipt.source_snapshot_ref == source_ref
                        ),
                    )
                    await archive.append(experiment_id, "trial", trial)
                    trials.append(trial)
                    if receipt.reason not in {None, "check_indeterminate"}:
                        blockers.append("execution_integrity")
                    if any(
                        c.reason
                        in {"sandbox_unavailable", "execution_unavailable", "check_timeout"}
                        for c in receipt.checks
                    ):
                        blockers.append("execution_unavailable")
    except (OSError, ValueError):
        blockers.append("experiment_interrupted")
    try:
        if implementation_refs() != implementations:
            blockers.append("implementation_changed")
    except OSError:
        blockers.append("implementation_unavailable")
    report = assess(experiment_id, proposal, suite, trials, started, blockers, implementations)
    await archive.append(experiment_id, "finished", report)
    return report
