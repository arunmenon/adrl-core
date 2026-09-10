"""Ledger operator commands: replay, close, readiness, retention, erasure, verification.

Primary: ADRL-MEM-001. Secondary: ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-004, ADRL-MEM-010.
Registered under `adrl ledger ...` so the top-level command names stay owned by their buckets.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import typer

from adrl.config.loaders import load_bundle
from adrl.config.settings import Settings
from adrl.core.ids import RouteId, SessionId
from adrl.core.ports import SandboxRunner
from adrl.ledger.store import LedgerStore


def _open_store(path: Path | None, settings: Settings) -> LedgerStore:
    store = LedgerStore(
        path or settings.ledger_path, busy_timeout_ms=settings.ledger_busy_timeout_ms
    )
    store.open()
    return store


def register(ledger_app: typer.Typer) -> None:
    @ledger_app.command("replay")
    def ledger_replay(
        ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
        embedder_version: str = typer.Option(
            "hashing-test-v1:64", help="Embedder version to index"
        ),
    ) -> None:
        """Rebuild outcome projections and the retrieval index from events (ADRL-MEM-001)."""
        from adrl.ledger.keystore import FileKeyStore
        from adrl.ledger.replay import replay

        settings = Settings()
        store = _open_store(ledger, settings)
        try:
            keystore = FileKeyStore(settings.keystore_path, store=store)
            report = asyncio.run(replay(store, keystore, embedder_version))
        finally:
            store.close()
        typer.echo(json.dumps(report.summary(), indent=2))

    @ledger_app.command("close")
    def ledger_close(ledger: Path | None = typer.Option(None, help="Path to adrl.db")) -> None:
        """Emit closed_final for every route whose close-v1 window elapsed (ADRL-MEM-002)."""
        from adrl.ledger.outcomes import Closer

        settings = Settings()
        bundle = load_bundle(settings)
        store = _open_store(ledger, settings)
        try:
            closed = asyncio.run(Closer(store, bundle.policy.close_rule).scan())
        finally:
            store.close()
        typer.echo(json.dumps([{"route_id": str(r), "trigger": t} for r, t in closed], indent=2))

    @ledger_app.command("readiness")
    def ledger_readiness(ledger: Path | None = typer.Option(None, help="Path to adrl.db")) -> None:
        """Censored, cause-clean label counts with blockers (ADRL-MEM-004, EVL-009)."""
        from adrl.ledger.readiness import learning_readiness

        settings = Settings()
        store = _open_store(ledger, settings)
        try:
            report = learning_readiness(store)
        finally:
            store.close()
        typer.echo(json.dumps(report.as_dict(), indent=2))

    @ledger_app.command("retention-sweep")
    def ledger_retention_sweep(
        ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
    ) -> None:
        """Shred expired prompt-class sessions; appends erased events only (ADRL-MEM-010)."""
        from adrl.ledger.keystore import FileKeyStore
        from adrl.ledger.retention import RetentionSweeper

        settings = Settings()
        bundle = load_bundle(settings)
        store = _open_store(ledger, settings)
        try:
            keystore = FileKeyStore(settings.keystore_path, store=store)
            report = asyncio.run(RetentionSweeper(store, keystore, bundle.policy).sweep())
        finally:
            store.close()
        typer.echo(
            json.dumps(
                {
                    "now": report.now,
                    "erased_sessions": len(report.erased),
                    "skeleton_expired_routes": report.skeleton_expired_routes,
                },
                indent=2,
            )
        )

    @ledger_app.command("erase")
    def ledger_erase(
        session: str = typer.Option(..., help="Session HMAC to crypto-shred"),
        reason: str = typer.Option("explicit_request", help="Recorded erasure reason"),
        ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
    ) -> None:
        """Crypto-shred one session's prompt-class artefacts (ADRL-MEM-010)."""
        from adrl.ledger.erasure import ErasureService
        from adrl.ledger.keystore import FileKeyStore

        settings = Settings()
        store = _open_store(ledger, settings)
        try:
            keystore = FileKeyStore(settings.keystore_path, store=store)
            receipt = asyncio.run(
                ErasureService(store, keystore).erase_session(SessionId(session), reason)
            )
        finally:
            store.close()
        typer.echo(
            json.dumps(
                {
                    "session": receipt.session_hmac,
                    "key_shredded": receipt.key_shredded,
                    "embedding_rows": receipt.embedding_rows,
                    "erased_seq": receipt.erased_seq,
                },
                indent=2,
            )
        )

    @ledger_app.command("verify-begin")
    def ledger_verify_begin(
        route_id: str = typer.Option(..., help="Explicit route_id from the decision event"),
        workspace: Path = typer.Option(..., help="Clean git workspace"),
        plan: Path = typer.Option(..., help="Verification plan JSON"),
        served_rung: str = typer.Option(...),
        model: str = typer.Option(...),
        harness: str = typer.Option("claude-code"),
        ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
    ) -> None:
        """Bind a verification job to a route and record the baseline tree (ADRL-MEM-003)."""
        from adrl.ledger.keystore import FileKeyStore
        from adrl.ledger.verification import VerificationJobs, VerificationPlan

        settings = Settings()
        store = _open_store(ledger, settings)
        try:
            keystore = FileKeyStore(settings.keystore_path, store=store)
            jobs = VerificationJobs(store, None, path_secret=keystore.hmac_key(), keystore=keystore)
            job_id = jobs.begin(
                RouteId(route_id),
                workspace,
                VerificationPlan.model_validate(json.loads(plan.read_text(encoding="utf-8"))),
                served_rung=served_rung,
                model=model,
                harness=harness,
            )
        finally:
            store.close()
        typer.echo(job_id)

    @ledger_app.command("verify-finish")
    def ledger_verify_finish(
        job_id: str = typer.Option(...),
        snapshot: Path | None = typer.Option(
            None, help="Immutable worktree snapshot to run the checks in (required)"
        ),
        auto_snapshot: bool = typer.Option(
            False,
            "--auto-snapshot",
            help="Create a detached git worktree of the workspace HEAD and run in it",
        ),
        ledger: Path | None = typer.Option(None, help="Path to adrl.db"),
    ) -> None:
        """Run the plan in the OS sandbox on an immutable snapshot (ADRL-MEM-003, ADRL-SAF-007).

        Checks never run in the live workspace: pass --snapshot or --auto-snapshot.
        """
        from adrl.ledger.keystore import FileKeyStore
        from adrl.ledger.verification import VerificationJobs

        if snapshot is None and not auto_snapshot:
            raise typer.BadParameter(
                "verification runs only on an immutable snapshot: pass --snapshot <dir> "
                "or --auto-snapshot (ADRL-SAF-007)"
            )
        settings = Settings()
        store = _open_store(ledger, settings)
        created: tuple[Path, Path] | None = None
        try:
            keystore = FileKeyStore(settings.keystore_path, store=store)
            runner = _sandbox_runner()
            jobs = VerificationJobs(
                store, runner, path_secret=keystore.hmac_key(), keystore=keystore
            )
            if snapshot is None:
                workspace = _job_workspace(jobs, job_id)
                snapshot = _make_snapshot(workspace, job_id)
                created = (workspace, snapshot)
            outcome = asyncio.run(jobs.finish(job_id, snapshot_dir=snapshot))
        finally:
            if created is not None:
                _remove_snapshot(*created)
            store.close()
        typer.echo(
            json.dumps(
                {
                    "job_id": outcome.job_id,
                    "route_id": str(outcome.route_id),
                    "result": outcome.result.value,
                    "tree_drift": outcome.tree_drift,
                    "violations": list(outcome.violations),
                    "unverifiable_reason": outcome.unverifiable_reason,
                    "late_evidence": outcome.late_evidence,
                },
                indent=2,
            )
        )


def _job_workspace(jobs: Any, job_id: str) -> Path:
    """Workspace recorded at verify-begin; the CLI needs it only to snapshot it."""
    try:
        return Path(jobs.workspace_of(job_id))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _make_snapshot(workspace: Path, job_id: str) -> Path:
    from adrl.gates.sandbox import git_worktree_snapshot

    dest = Path(tempfile.mkdtemp(prefix="adrl-verify-")) / job_id
    return git_worktree_snapshot(workspace, dest)


def _remove_snapshot(workspace: Path, snapshot: Path) -> None:
    from adrl.gates.sandbox import remove_worktree_snapshot

    remove_worktree_snapshot(workspace, snapshot)


def _sandbox_runner() -> SandboxRunner | None:
    """Pick the gates package's OS sandbox runner when present; None labels runs unverifiable."""
    try:
        from adrl.gates.sandbox import detect_runner
    except ImportError:
        return None
    return detect_runner()
