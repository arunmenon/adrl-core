"""Branched counterfactual pairs and their power budget. Primary: ADRL-LRN-002.
Also implements: ADRL-EVL-003 (register additions of 2026-09-03).

Secondary: ADRL-MEM-009 (explicit route_id binding), ADRL-LRN-001 (tier T5), ADRL-SAF-002
(pinned turns cannot produce a frontier arm).

A pair is a live branch from the same tree state and transcript prefix, never a replay.
Both arms run under identical rules. The pair budget is sized by McNemar power arithmetic.
"""

from __future__ import annotations

import math
import os
import shlex
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from statistics import NormalDist
from typing import Protocol

from adrl.core.enums import EvidenceTier, Rung, VerificationResult
from adrl.core.ids import RouteId

PAIR_CONTRACT_VERSION = "pair-contract-v1"

_RULE_FIELDS: tuple[str, ...] = (
    "transcript_prefix_hash",
    "tool_results_hash",
    "harness_dialect",
    "verifier_version",
    "sanitisation_version",
    "protected_path_policy_version",
    "tripwire_config_version",
    "pinned",
)


class PairContractError(ValueError):
    """The two arms do not share the state and rules the contract requires."""


class PinnedPairExcludedError(PairContractError):
    """A pinned turn cannot produce a frontier arm (ADRL-SAF-002)."""


@dataclass(frozen=True, slots=True)
class ArmSpec:
    rung: Rung
    model: str
    transcript_prefix_hash: str
    tool_results_hash: str
    harness_dialect: str
    verifier_version: str
    sanitisation_version: str
    protected_path_policy_version: str
    tripwire_config_version: str
    pinned: bool = False


@dataclass(frozen=True, slots=True)
class PairSpec:
    """Two arms branched from the same turn state, bound to an explicit route_id."""

    route_id: RouteId
    slice_id: str
    snapshot_commit: str
    arm_a: ArmSpec
    arm_b: ArmSpec
    contract_version: str = PAIR_CONTRACT_VERSION

    def validate(self) -> None:
        if not self.route_id:
            raise PairContractError("pair must bind to an explicit route_id (ADRL-MEM-009)")
        if self.arm_a.rung is self.arm_b.rung:
            raise PairContractError("arms must differ in rung")
        for name in _RULE_FIELDS:
            left = getattr(self.arm_a, name)
            right = getattr(self.arm_b, name)
            if left != right:
                raise PairContractError(f"arms differ in {name}: {left!r} vs {right!r}")
        if self.arm_a.pinned:
            raise PinnedPairExcludedError("pinned turn excluded from pairing (ADRL-SAF-002)")

    @property
    def treatment(self) -> ArmSpec:
        return self.arm_a if self.arm_a.rung > self.arm_b.rung else self.arm_b

    @property
    def control(self) -> ArmSpec:
        return self.arm_b if self.arm_a.rung > self.arm_b.rung else self.arm_a


@dataclass(frozen=True, slots=True)
class ArmResult:
    rung: Rung
    model: str
    verification: VerificationResult
    exit_code: int | None
    duration_s: float
    cost_usd: float | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class PairOutcome:
    pair_id: str
    route_id: RouteId
    slice_id: str
    treatment: ArmResult
    control: ArmResult
    tier: EvidenceTier = EvidenceTier.T5
    contract_version: str = PAIR_CONTRACT_VERSION

    @property
    def discordant(self) -> bool:
        return self.treatment.verification is not self.control.verification

    @property
    def treatment_better(self) -> bool | None:
        if not self.discordant:
            return None
        if VerificationResult.INDETERMINATE in (
            self.treatment.verification,
            self.control.verification,
        ):
            return None
        return self.treatment.verification is VerificationResult.PASS


# exclusion and power ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExclusionReport:
    candidates: int
    excluded_pinned: int
    rejected_contract: int

    @property
    def pinned_fraction(self) -> float:
        return self.excluded_pinned / self.candidates if self.candidates else 0.0


def screen_candidates(specs: Sequence[PairSpec]) -> tuple[list[PairSpec], ExclusionReport]:
    accepted: list[PairSpec] = []
    pinned = 0
    rejected = 0
    for spec in specs:
        try:
            spec.validate()
        except PinnedPairExcludedError:
            pinned += 1
            continue
        except PairContractError:
            rejected += 1
            continue
        accepted.append(spec)
    return accepted, ExclusionReport(len(specs), pinned, rejected)


def required_pairs_mcnemar(
    delta: float, discordance: float, *, alpha: float = 0.05, power: float = 0.80
) -> int:
    """Pairs per slice for McNemar's test at a detectable difference delta.

    n = (z_{alpha/2} sqrt(psi) + z_beta sqrt(psi - delta^2))^2 / delta^2 with psi the
    discordance rate. At delta 0.10 and psi in [0.15, 0.30] this gives roughly 116 to 234.
    """
    if not 0.0 < delta < 1.0:
        raise ValueError("delta must be within (0, 1)")
    if not delta**2 < discordance <= 1.0:
        raise ValueError("discordance must exceed delta squared and be at most 1")
    normal = NormalDist()
    z_alpha = normal.inv_cdf(1.0 - alpha / 2.0)
    z_beta = normal.inv_cdf(power)
    numerator = (z_alpha * discordance**0.5 + z_beta * (discordance - delta**2) ** 0.5) ** 2
    required: int = math.ceil(float(numerator) / float(delta**2))
    return required


@dataclass(frozen=True, slots=True)
class PairBudget:
    slice_id: str
    delta: float
    discordance: float
    required: int
    current: int

    @property
    def shortfall(self) -> int:
        return max(self.required - self.current, 0)


def pair_budget(
    slice_id: str, outcomes: Sequence[PairOutcome], *, delta: float, discordance: float
) -> PairBudget:
    current = sum(1 for o in outcomes if o.slice_id == slice_id)
    return PairBudget(
        slice_id, delta, discordance, required_pairs_mcnemar(delta, discordance), current
    )


def noise_floor(control_outcomes: Sequence[PairOutcome]) -> float:
    """Discordance rate among same-model control pairs; the floor any effect must clear."""
    if not control_outcomes:
        return 0.0
    return sum(1 for o in control_outcomes if o.discordant) / len(control_outcomes)


def observed_discordance(outcomes: Sequence[PairOutcome]) -> float:
    if not outcomes:
        return 0.0
    return sum(1 for o in outcomes if o.discordant) / len(outcomes)


def mcnemar_counts(outcomes: Sequence[PairOutcome]) -> tuple[int, int]:
    """(treatment better, control better) over discordant pairs with decided verifications."""
    better = sum(1 for o in outcomes if o.treatment_better is True)
    worse = sum(1 for o in outcomes if o.treatment_better is False)
    return better, worse


# live branch execution ---------------------------------------------------------------------


class BranchRunner(Protocol):
    """Runs one arm live from a snapshot; both arms of a pair use the same runner."""

    def run_arm(self, spec: PairSpec, arm: ArmSpec, *, timeout_s: float) -> ArmResult: ...


@dataclass(frozen=True, slots=True)
class SubprocessBranchRunner:
    """Executes each arm in its own detached git worktree of the snapshot commit.

    agent_argv runs the harness for the arm; verifier_argv runs the deterministic verifier.
    Both are argv templates; the arm's rung and model are passed through environment
    variables ADRL_ARM_RUNG and ADRL_ARM_MODEL, never interpolated into a shell string.
    """

    repository: Path
    worktree_root: Path
    agent_argv: tuple[str, ...]
    verifier_argv: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)

    def run_arm(self, spec: PairSpec, arm: ArmSpec, *, timeout_s: float) -> ArmResult:
        spec.validate()
        started = time.monotonic()
        worktree = self.worktree_root / f"{spec.route_id}-{arm.rung.value}"
        self._add_worktree(worktree, spec.snapshot_commit)
        env = {**os.environ, **self.env}
        env["ADRL_ARM_RUNG"] = arm.rung.value
        env["ADRL_ARM_MODEL"] = arm.model
        env["ADRL_ROUTE_ID"] = str(spec.route_id)
        exit_code: int | None
        try:
            agent = subprocess.run(
                list(self.agent_argv), cwd=worktree, env=env, timeout=timeout_s, check=False
            )
            exit_code = agent.returncode
            verifier = subprocess.run(
                list(self.verifier_argv), cwd=worktree, env=env, timeout=timeout_s, check=False
            )
            verification = (
                VerificationResult.PASS if verifier.returncode == 0 else VerificationResult.FAIL
            )
        except (subprocess.TimeoutExpired, OSError):
            exit_code = None
            verification = VerificationResult.INDETERMINATE
        finally:
            self._remove_worktree(worktree)
        return ArmResult(
            rung=arm.rung,
            model=arm.model,
            verification=verification,
            exit_code=exit_code,
            duration_s=time.monotonic() - started,
        )

    def _add_worktree(self, worktree: Path, commit: str) -> None:
        worktree.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(worktree), commit],
            cwd=self.repository,
            check=True,
            capture_output=True,
        )

    def _remove_worktree(self, worktree: Path) -> None:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=self.repository,
            check=False,
            capture_output=True,
        )

    def describe(self) -> str:
        return shlex.join(self.agent_argv) + " | " + shlex.join(self.verifier_argv)


def run_pair(spec: PairSpec, runner: BranchRunner, *, timeout_s: float = 1800.0) -> PairOutcome:
    """Run both arms live from the same snapshot and turn state (ADRL-LRN-002 clause 1)."""
    spec.validate()
    treatment = runner.run_arm(spec, spec.treatment, timeout_s=timeout_s)
    control = runner.run_arm(spec, spec.control, timeout_s=timeout_s)
    return PairOutcome(
        pair_id=f"pair-{spec.route_id}",
        route_id=spec.route_id,
        slice_id=spec.slice_id,
        treatment=treatment,
        control=control,
    )
