# ruff: noqa: B008
"""Operator commands owned by the gates package. Primary: ADRL-SAF-002.

Secondary: ADRL-SAF-003 (scan-measure), ADRL-SAF-007 (verify), ADRL-SAF-009 (audit).
Registered as a sub-app so the shared CLI module stays small.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from adrl.config.settings import Settings
from adrl.core.enums import ReleaseReason
from adrl.core.errors import AdrlError
from adrl.core.ids import LineageId, SessionId

gates_app = typer.Typer(no_args_is_help=True, help="Gate operator commands (SAF)")


def _open_stores(settings: Settings) -> tuple[object, object, object]:
    from adrl.ledger.anchoring import checkpoint_key_from_settings
    from adrl.ledger.egress import EgressLedger
    from adrl.ledger.facade import MemoryFacade, SqliteLedgerProvider
    from adrl.ledger.store import LedgerStore

    store = LedgerStore(settings.ledger_path, busy_timeout_ms=settings.ledger_busy_timeout_ms)
    store.open()
    facade = MemoryFacade(SqliteLedgerProvider(store))
    checkpoint_key = checkpoint_key_from_settings(settings)
    egress = EgressLedger(
        settings.egress_ledger_path,
        signing_key=checkpoint_key.private if checkpoint_key else None,
        key_id=checkpoint_key.key_id if checkpoint_key else None,
        checkpoint_every=settings.egress_checkpoint_every,
    )
    egress.open()
    return store, facade, egress


@gates_app.command("release")
def release(
    lineage: str = typer.Option(..., help="Lineage HMAC"),
    finding: str = typer.Option(..., help="Finding id shown in the block message"),
    reason: ReleaseReason = typer.Option(..., help="false_positive or test_fixture"),
    actor: str = typer.Option(..., help="Who is releasing; recorded in both ledgers"),
) -> None:
    """Audited, per-finding human pin release (ADRL-SAF-002 clause 3)."""
    from adrl.config.loaders import load_bundle
    from adrl.gates.pin import PinRegistry
    from adrl.gates.repo_class import RepoClassifier
    from adrl.ledger.egress import EgressLedger
    from adrl.ledger.facade import MemoryFacade
    from adrl.ledger.store import LedgerStore

    settings = Settings()
    bundle = load_bundle(settings)
    store, facade, egress = _open_stores(settings)
    assert isinstance(store, LedgerStore)
    assert isinstance(facade, MemoryFacade)
    assert isinstance(egress, EgressLedger)
    try:
        registry = PinRegistry(facade, egress, deployment_tag=settings.deployment_tag)
        classifier = RepoClassifier(bundle.repo_classification, facade)

        async def go() -> None:
            current = await classifier.current(LineageId(lineage))
            permitted = current.release_permitted if current else True
            record = await registry.release(
                LineageId(lineage),
                finding,
                reason,
                actor,
                release_permitted=permitted,
            )
            typer.echo(
                json.dumps(
                    {
                        "lineage": lineage,
                        "finding": record.finding_id,
                        "detector": record.detector_id,
                        "released": record.released,
                        "reason": reason.value,
                        "actor": actor,
                    }
                )
            )

        asyncio.run(go())
    except AdrlError as exc:
        typer.echo(f"REFUSED {exc.detail}")
        raise typer.Exit(code=1) from exc
    finally:
        egress.close()
        store.close()


@gates_app.command("scan-measure")
def scan_measure(
    corpus: Path = typer.Option(..., help="Directory of labelled JSONL samples"),
    out: Path | None = typer.Option(None, help="Write the JSON report here"),
) -> None:
    """Measure per-detector precision and recall on a labelled corpus (ADRL-SAF-003)."""
    from adrl.gates.detectors import load_detectors
    from adrl.gates.measure import measure
    from adrl.gates.secrets import TieredSecretScanner

    settings = Settings()
    config = load_detectors(settings.config_dir / "detectors.yaml")
    scanner = TieredSecretScanner(config, span_key=b"measure")
    report = measure(scanner, corpus).as_dict()
    text = json.dumps(report, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
    typer.echo(text)


@gates_app.command("verify")
def verify(
    snapshot: Path = typer.Option(..., help="Repository snapshot (worktree) to run in"),
    command: str = typer.Option(..., help="Allow-listed command, space separated"),
    allow: list[str] = typer.Option(..., help="Allow-list entries; repeat the flag"),
    timeout_s: float = typer.Option(300.0),
) -> None:
    """Run one allow-listed command inside the OS sandbox (ADRL-SAF-007)."""
    from adrl.gates.sandbox import CommandNotAllowedError, detect_runner

    runner = detect_runner()
    try:
        result = runner.run(command.split(), str(snapshot), allow, timeout_s=timeout_s)
    except CommandNotAllowedError as exc:
        typer.echo(f"REFUSED command not in allow-list: {exc}")
        raise typer.Exit(code=1) from exc
    typer.echo(
        json.dumps(
            {
                "platform": runner.platform_id,
                "available": result.available,
                "unavailable_reason": result.unavailable_reason,
                "exit_code": result.exit_code,
                "duration_s": round(result.duration_s, 3),
                "stdout_tail": result.stdout_tail[-500:],
                "stderr_tail": result.stderr_tail[-500:],
            }
        )
    )
    if not result.available:
        raise typer.Exit(code=3)


@gates_app.command("audit")
def audit(lineage: str = typer.Option(..., help="Lineage HMAC")) -> None:
    """Did this lineage's content ever leave the machine (ADRL-SAF-009)."""
    from adrl.gates.egress import audit_lineage
    from adrl.ledger.egress import EgressLedger

    settings = Settings()
    ledger = EgressLedger(settings.egress_ledger_path)
    ledger.open()
    try:
        typer.echo(json.dumps(audit_lineage(ledger, lineage), indent=2, default=str))
    finally:
        ledger.close()


@gates_app.command("promote-shadow")
def promote_shadow(
    lineage: str = typer.Option(..., help="Lineage HMAC"),
    finding: str = typer.Option(..., help="Shadow finding id"),
    actor: str = typer.Option(..., help="Who is promoting; recorded in both ledgers"),
    session: str | None = typer.Option(None, help="Session HMAC for suppression (optional)"),
) -> None:
    """Audited promotion of an observe-mode shadow finding into a pin (ADRL-SAF-002)."""
    from adrl.gates.pin import PinRegistry
    from adrl.ledger.egress import EgressLedger
    from adrl.ledger.erasure import ErasureService
    from adrl.ledger.facade import MemoryFacade
    from adrl.ledger.keystore import FileKeyStore
    from adrl.ledger.store import LedgerStore

    settings = Settings()
    store, facade, egress = _open_stores(settings)
    assert isinstance(store, LedgerStore)
    assert isinstance(facade, MemoryFacade)
    assert isinstance(egress, EgressLedger)
    try:
        keystore = FileKeyStore(settings.keystore_path, store=store)
        registry = PinRegistry(
            facade,
            egress,
            deployment_tag=settings.deployment_tag,
            suppression=ErasureService(store, keystore),
        )
        record = asyncio.run(
            registry.promote_shadow(
                LineageId(lineage),
                finding,
                actor,
                session=SessionId(session) if session else None,
            )
        )
        typer.echo(
            json.dumps(
                {
                    "lineage": lineage,
                    "finding": record.finding_id,
                    "detector": record.detector_id,
                    "pinned": not record.released,
                    "actor": actor,
                }
            )
        )
    except AdrlError as exc:
        typer.echo(f"REFUSED {exc.detail}")
        raise typer.Exit(code=1) from exc
    finally:
        egress.close()
        store.close()


def launch(
    repo: Path = typer.Option(..., help="Repository root the harness will work in"),
    ttl_s: int = typer.Option(8 * 3600, help="Assertion lifetime in seconds"),
    session_id: str | None = typer.Option(
        None, help="Session id to bind; generated when absent (pass it as claude --session-id)"
    ),
    shell: bool = typer.Option(True, help="Print shell export lines"),
) -> None:
    """Mint a signed workload assertion for a repository (ADRL-SAF-008).

    Prints the environment the harness needs (ANTHROPIC_CUSTOM_HEADERS) and writes the
    session-file fallback under the keystore so a harness that cannot add headers is still
    covered when launched with the printed session id.
    """
    from adrl.gates.workload import ASSERTIONS_DIR, mint_launch
    from adrl.ledger.keystore import FileKeyStore

    settings = Settings()
    keystore = FileKeyStore(settings.keystore_path)
    try:
        material = mint_launch(
            repo,
            keystore.hmac_key(),
            assertion_dir=settings.keystore_path / ASSERTIONS_DIR,
            ttl_s=ttl_s,
            session_id=session_id,
        )
    except AdrlError as exc:
        typer.echo(f"REFUSED {exc.detail}")
        raise typer.Exit(code=1) from exc
    if shell:
        for name, value in material.env_exports().items():
            typer.echo(f"export {name}='{value}'")
        typer.echo(f"export ADRL_LAUNCH_SESSION_ID='{material.session_id}'")
        typer.echo(f"# claude --session-id {material.session_id}")
    else:
        typer.echo(
            json.dumps(
                {
                    "session_id": material.session_id,
                    "token": material.token,
                    "token_path": str(material.token_path) if material.token_path else None,
                    "tracked_files": material.inventory.tracked_files,
                    "head": material.inventory.head,
                }
            )
        )
