"""Claude Code connection and evidence commands. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001."""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

import httpx
import typer

from adrl.api.auth import ApiError
from adrl.api.client import Connection, ToolOutbox, call, flush, validate_server, write_private
from adrl.api.contracts import IntegrationMode, SessionBinding, SessionRequest, VersionRef
from adrl.config.loaders import load_bundle
from adrl.config.settings import Settings
from adrl.core.errors import AdrlError
from adrl.gates.workload import (
    HEADER_SESSION_ID,
    HEADER_WORKLOAD_ASSERTION,
    mint_launch,
    normalise_identity,
)
from adrl.ledger.crypto import new_key
from adrl.ledger.keystore import FileKeyStore

connect_app = typer.Typer(help="Prepare isolated harness connections")
product_app = typer.Typer(help="Inspect local sessions and deliver observations")


def _connection(path: Path) -> Connection:
    return Connection.model_validate_json(path.read_bytes())


def _failure() -> None:
    typer.echo(
        "ADRL product operation failed; check the local service, binding and connection files.",
        err=True,
    )
    raise typer.Exit(1)


@connect_app.command("claude-code")
def connect_claude(
    repo: Path = typer.Option(..., help="Registered repository checkout"),
    output: Path = typer.Option(
        ..., help="New private connection directory outside the repository"
    ),
    server: str = typer.Option("http://127.0.0.1:8788"),
    mode: IntegrationMode = typer.Option(
        IntegrationMode.GATEWAY, help="Gateway or observations only"
    ),
) -> None:
    """Bind a new session and write environment/hook files. Does not start a model run."""
    try:
        server = validate_server(server)
        repo = repo.resolve()
        output = output.resolve()
        if output == repo or repo in output.parents:
            raise ValueError("Keep the credential directory outside the repository.")
        settings = Settings()
        bundle = load_bundle(settings)
        keys = FileKeyStore(settings.keystore_path)
        material = mint_launch(repo, keys.hmac_key(), assertion_dir=None)
        matches = {
            entry.repo_id
            for entry in bundle.repo_classification.repos
            if normalise_identity(entry.match) in material.inventory.identities()
        }
        if len(matches) != 1:
            raise ValueError("The checkout must match exactly one registered workload.")
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        token_path = output / "assertion.token"
        write_private(token_path, material.token.encode())
        connection = Connection(
            server=server,
            session_id=material.session_id,
            token_file=token_path,
            integration_mode=mode,
        )
        request = SessionRequest(
            adapter=VersionRef(id="claude-code", version="1"),
            profile=VersionRef(id="anthropic-messages-v1", version="1"),
            workload_ref=matches.pop(),
            integration_mode=mode,
        )
        binding = SessionBinding.model_validate(
            call(connection, "POST", "/adrl/v1/sessions", request.model_dump(mode="json"))
        )
        if (
            binding.session.session_id != material.session_id
            or binding.session.workload_ref != request.workload_ref
            or binding.session.profile != request.profile
            or binding.session.adapter != request.adapter
            or binding.session.integration_mode != mode
        ):
            raise ValueError("The service returned a different binding.")
        connection_path = output / "connection.json"
        write_private(connection_path, connection.model_dump_json(indent=2).encode())
        write_private(output / "outbox.key", new_key())
        environment = {"ADRL_LAUNCH_SESSION_ID": material.session_id}
        if mode == IntegrationMode.GATEWAY:
            custom = []
            for line in os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "").splitlines():
                name = line.partition(":")[0].strip().lower()
                if name not in {HEADER_WORKLOAD_ASSERTION, HEADER_SESSION_ID, "x-adrl-session-id"}:
                    custom.append(line)
            custom += [
                f"{HEADER_WORKLOAD_ASSERTION}: {material.token}",
                f"{HEADER_SESSION_ID}: {material.session_id}",
                f"x-adrl-session-id: {material.session_id}",
            ]
            environment.update(
                ANTHROPIC_BASE_URL=server, ANTHROPIC_CUSTOM_HEADERS="\n".join(custom)
            )
        write_private(
            output / "env.sh",
            (
                "\n".join(
                    f"export {name}={shlex.quote(value)}" for name, value in environment.items()
                )
                + "\n"
            ).encode(),
        )
        command = shlex.join(
            [
                sys.executable,
                "-m",
                "adrl.cli.main",
                "product",
                "claude-hook",
                "--connection",
                str(connection_path),
            ]
        )
        hooks = {
            name: [
                {"matcher": "", "hooks": [{"type": "command", "command": command, "timeout": 10}]}
            ]
            for name in ("PostToolUse", "PostToolUseFailure")
        }
        write_private(
            output / "claude-settings.json", json.dumps({"hooks": hooks}, indent=2).encode()
        )
        typer.echo(f"Prepared {connection_path}. No provider request was made.")
        if mode == IntegrationMode.OBSERVE:
            typer.echo(
                "Observation mode leaves native model authentication and destination unchanged. "
                "Check Claude /status and remove stale gateway overrides before launch. "
                "ADRL cannot inspect, block or account for model traffic in this mode."
            )
        typer.echo(
            f"Source {output / 'env.sh'}, then start Claude Code with --session-id "
            f"{material.session_id} --settings {shlex.quote(str(output / 'claude-settings.json'))}."
        )
    except (OSError, ValueError, httpx.HTTPError, AdrlError):
        _failure()


@product_app.command("claude-hook")
def claude_hook(connection: Path = typer.Option(...)) -> None:
    """Capture a supported tool observation; keep it queued if delivery fails."""
    outbox = None
    try:
        config = _connection(connection)
        # Bound memory use; raw tool input/output is discarded after typed extraction.
        raw = sys.stdin.buffer.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("Hook input exceeds the supported limit.")
        hook = json.loads(raw)
        if not isinstance(hook, dict):
            raise ValueError("Hook input must be an object.")
        outbox = ToolOutbox(connection.parent, config.session_id)
        outbox.capture(hook)
        flush(config, outbox, limit=1)
    except (OSError, ValueError, httpx.HTTPError):
        _failure()
    finally:
        if outbox is not None:
            outbox.close()


@product_app.command("flush")
def flush_events(connection: Path = typer.Option(...)) -> None:
    """Retry up to 50 pending observations with their original identities."""
    outbox = None
    try:
        config = _connection(connection)
        outbox = ToolOutbox(connection.parent, config.session_id)
        typer.echo(f"Acknowledged {flush(config, outbox)} observations.")
    except (OSError, ValueError, httpx.HTTPError):
        _failure()
    finally:
        if outbox is not None:
            outbox.close()


@product_app.command("status")
def session_status(connection: Path = typer.Option(...)) -> None:
    """Read the authenticated binding; coverage remains explicit, including unknowns."""
    try:
        config = _connection(connection)
        typer.echo(
            json.dumps(call(config, "GET", f"/adrl/v1/sessions/{config.session_id}"), indent=2)
        )
    except (OSError, ValueError, httpx.HTTPError):
        _failure()


@product_app.command("timeline")
def timeline(connection: Path = typer.Option(...), cursor: str | None = typer.Option(None)) -> None:
    """Read one page of decision and observation references."""
    try:
        config = _connection(connection)
        from urllib.parse import urlencode

        path = f"/adrl/v1/sessions/{config.session_id}/timeline"
        if cursor:
            path += "?" + urlencode({"cursor": cursor})
        typer.echo(json.dumps(call(config, "GET", path), indent=2))
    except (OSError, ValueError, httpx.HTTPError):
        _failure()


@product_app.command("verify")
def verify_session(
    connection: Path = typer.Option(..., help="Bound session connection file"),
    workspace: Path = typer.Option(..., help="Registered working copy to snapshot"),
    plan: Path = typer.Option(..., help="Operator plan outside the working copy"),
) -> None:
    """Run independent local checks and append receipts; does not create learning labels."""
    import asyncio

    from adrl.api.service import ProductService
    from adrl.core.ids import session_identity
    from adrl.gates.sandbox import detect_runner
    from adrl.ledger.session_verification import SessionPlan, SessionVerifier
    from adrl.ledger.store import LedgerStore

    store = None
    try:
        settings = Settings()
        if not settings.ledger_path.is_file() or not settings.keystore_path.is_dir():
            raise ValueError("The local session store must already exist.")
        workspace = workspace.resolve(strict=True)
        if plan.resolve(strict=True).is_relative_to(workspace) or plan.is_symlink():
            raise ValueError("The operator plan must be outside the working copy.")
        config = _connection(connection)
        bundle = load_bundle(settings)
        store = LedgerStore(settings.ledger_path)
        store.open()
        keys = FileKeyStore(settings.keystore_path, store=store)
        service = ProductService(store, keys, bundle)
        principal = service.principal(config.headers())
        service.status(config.headers(), config.session_id)
        if Path(principal.assertion.inventory.root).resolve() != workspace:
            raise ValueError("The workspace must match the signed session binding.")
        specification = SessionPlan.model_validate_json(plan.read_bytes())
        result = asyncio.run(
            SessionVerifier(service.data, detect_runner()).verify(
                session_identity(config.session_id, keys.hmac_key()), workspace, specification
            )
        )
        typer.echo(result.model_dump_json(indent=2))
        if result.result != "passed":
            raise typer.Exit(2 if result.result == "indeterminate" else 1)
    except (OSError, ValueError, httpx.HTTPError, AdrlError, ApiError):
        typer.echo("Local verification setup is invalid or unavailable.", err=True)
        raise typer.Exit(2) from None
    finally:
        if store is not None:
            store.close()
