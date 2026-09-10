"""Local verifier experiments. Primary: ADRL-EVL-006. Secondary: ADRL-LRN-007, ADRL-MEM-010."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from adrl.gates.sandbox import detect_runner
from adrl.learning.improvement import AssessmentSuite, VerifierProposal, evaluate, suite_digest
from adrl.ledger.improvement import ExperimentArchive
from adrl.ledger.keystore import FileKeyStore
from adrl.ledger.session_verification import SnapshotLimits, _file_bytes, snapshot_digest
from adrl.ledger.store import LedgerStore

improve_app = typer.Typer(no_args_is_help=True, help="Offline verifier experiments; never deploys")


def _open(state: Path, *, create: bool = False) -> tuple[LedgerStore, ExperimentArchive]:
    if not create and (not (state / "experiments.db").is_file() or not (state / "keys").is_dir()):
        raise ValueError("An existing experiment archive is required.")
    if (state / "experiments.db").exists() or not create:
        if any(not (state / "keys" / name).is_file() for name in ("master.key", "hmac.key")):
            raise ValueError("Existing experiment keys must not be recreated.")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    store = LedgerStore(state / "experiments.db")
    store.open()
    return store, ExperimentArchive(store, FileKeyStore(state / "keys", store=store))


@improve_app.command("fingerprint")
def fingerprint(workspace: Path = typer.Option(...)) -> None:
    """Compute the fixed-input fingerprint with the default snapshot limits."""
    try:
        typer.echo(snapshot_digest(workspace, SnapshotLimits()))
    except (OSError, ValueError):
        typer.echo("Cannot capture a valid working-copy fingerprint.", err=True)
        raise typer.Exit(2) from None


@improve_app.command("suite-digest")
def digest(suite: Path = typer.Option(...)) -> None:
    """Compute the canonical assessment digest to pin in the proposal."""
    try:
        typer.echo(suite_digest(AssessmentSuite.model_validate_json(_file_bytes(suite, 2_000_000))))
    except (OSError, ValueError):
        typer.echo("Invalid assessment suite.", err=True)
        raise typer.Exit(2) from None


@improve_app.command("evaluate")
def run(
    proposal: Path = typer.Option(...),
    suite: Path = typer.Option(...),
    state: Path = typer.Option(..., help="Private local experiment state outside case workspaces"),
) -> None:
    """Execute reviewed pinned verifier plans, archive all trials, and recommend review only."""
    store = None
    try:
        specification = VerifierProposal.model_validate_json(_file_bytes(proposal, 2_000_000))
        assessment = AssessmentSuite.model_validate_json(_file_bytes(suite, 2_000_000))
        specification.admit(assessment)
        for case in assessment.cases:
            root = case.workspace.resolve(strict=True)
            if any(path.resolve().is_relative_to(root) for path in (state, proposal, suite)):
                raise ValueError("Control files and state must remain outside case workspaces.")
        store, archive = _open(state, create=True)
        report = asyncio.run(evaluate(specification, assessment, archive, detect_runner()))
        typer.echo(report.model_dump_json(indent=2))
        if report.recommendation == "indeterminate":
            raise typer.Exit(2)
    except (OSError, ValueError):
        typer.echo("Invalid or unavailable local verifier experiment.", err=True)
        raise typer.Exit(2) from None
    finally:
        if store is not None:
            store.close()


@improve_app.command("show")
def show(state: Path = typer.Option(...), experiment_id: str = typer.Option(...)) -> None:
    """Read experiment history. Exported copies have separate retention."""
    store = None
    try:
        store, archive = _open(state)
        records = archive.read(experiment_id)
        if not records:
            raise ValueError("Unknown experiment.")
        typer.echo(json.dumps(records, indent=2))
    except (OSError, ValueError):
        typer.echo("Experiment history is unavailable.", err=True)
        raise typer.Exit(2) from None
    finally:
        if store is not None:
            store.close()


@improve_app.command("erase")
def erase(state: Path = typer.Option(...), experiment_id: str = typer.Option(...)) -> None:
    """Shred this experiment's evidence key; keep its ledger skeleton and erasure audit."""
    store = None
    try:
        store, archive = _open(state)
        erased = archive.erase(experiment_id)
        typer.echo(json.dumps({"experiment_id": experiment_id, "key_removed": erased}))
    except (OSError, ValueError):
        typer.echo("Experiment erasure is unavailable.", err=True)
        raise typer.Exit(2) from None
    finally:
        if store is not None:
            store.close()
