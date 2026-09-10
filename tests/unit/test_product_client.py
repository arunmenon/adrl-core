"""Connection and outbox failure contracts. Primary: ADRL-SEM-007. Secondary: ADRL-MEM-001."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from adrl.api.client import Connection, ToolOutbox, flush, validate_server, write_private
from adrl.cli.main import app
from adrl.ledger.crypto import new_key
from adrl.wire.parse import forward_headers, redact_for_record
from tests.conftest import CONFIG_DIR


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1",
        "http://example.com",
        "http://localhost",
        "http://127.0.0.1@evil.test",
        "http://127.0.0.1/path",
        "http://127.0.0.1?token=x",
        "file:///tmp/socket",
    ],
)
def test_connection_rejects_unsupported_destinations(url: str) -> None:
    with pytest.raises(ValueError):
        validate_server(url)


def test_workload_credentials_never_forward_or_log() -> None:
    headers = {
        "X-ADRL-Workload-Assertion": "private",
        "X-ADRL-Session-ID": "session",
        "Authorization": "Bearer provider",
        "x-claude-code-session-id": "correlation",
    }
    forwarded = forward_headers(headers)
    assert "X-ADRL-Workload-Assertion" not in forwarded
    assert "X-ADRL-Session-ID" not in forwarded
    assert forwarded["Authorization"] == "Bearer provider"
    assert redact_for_record(headers)["X-ADRL-Workload-Assertion"] == "<redacted>"


def test_outbox_is_encrypted_and_survives_delivery_failure(tmp_path: Path) -> None:
    write_private(tmp_path / "outbox.key", new_key())
    write_private(tmp_path / "token", b"test-assertion")
    config = Connection(
        server="http://127.0.0.1:8788", session_id="test-session", token_file=tmp_path / "token"
    )
    hook = {
        "session_id": config.session_id,
        "hook_event_name": "PostToolUseFailure",
        "tool_use_id": "tool_123",
        "tool_input": {"secret": "PRIVATE_INPUT"},
        "error": "PRIVATE_OUTPUT",
        "transcript_path": "/PRIVATE_PATH",
    }
    outbox = ToolOutbox(tmp_path, config.session_id)
    try:
        assert outbox.capture(hook) == 0
        original = outbox.pending()[0][1]
        assert outbox.capture(hook) == 0
        assert len(outbox.pending()) == 1
        assert original.root.payload.model_dump()["outcome"] == "failed"
        raw = (tmp_path / "outbox.db").read_bytes()
        for secret in [
            b"PRIVATE_INPUT",
            b"PRIVATE_OUTPUT",
            b"PRIVATE_PATH",
            b"test-session",
            b"tool_123",
        ]:
            assert secret not in raw
        with respx.mock:
            respx.post("http://127.0.0.1:8788/adrl/v1/events").mock(
                return_value=httpx.Response(503)
            )
            with pytest.raises(ValueError):
                flush(config, outbox)
        assert outbox.pending()[0][1] == original
    finally:
        outbox.close()
    reopened = ToolOutbox(tmp_path, config.session_id)
    try:
        assert reopened.pending()[0][1] == original
        with respx.mock:
            route = respx.post("http://127.0.0.1:8788/adrl/v1/events").mock(
                return_value=httpx.Response(
                    200, json={"event_id": str(original.root.event_id), "status": "recorded"}
                )
            )
            assert flush(config, reopened) == 1
            assert json.loads(route.calls[0].request.content)["event_id"] == str(
                original.root.event_id
            )
        assert not reopened.pending()
        assert reopened.capture(hook) == 0
        assert not reopened.pending()
        assert os.stat(tmp_path / "outbox.db").st_mode & 0o777 == 0o600
    finally:
        reopened.close()


def test_outbox_rejects_foreign_and_uncovered_hooks(tmp_path: Path) -> None:
    write_private(tmp_path / "outbox.key", new_key())
    outbox = ToolOutbox(tmp_path, "session")
    try:
        for hook in [
            {"session_id": "other", "hook_event_name": "PostToolUse", "tool_use_id": "x"},
            {"session_id": "session", "hook_event_name": "PostCompact"},
        ]:
            with pytest.raises(ValueError):
                outbox.capture(hook)
        assert not outbox.pending()
    finally:
        outbox.close()


@pytest.mark.parametrize("mode", ["gateway", "observe"])
def test_connection_command_writes_private_isolated_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setenv("ADRL_CONFIG_DIR", str(CONFIG_DIR))
    monkeypatch.setenv("ADRL_KEYSTORE_PATH", str(tmp_path / "keys"))
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Org: existing")
    output = tmp_path / "connection with spaces"

    # The inventory and signed assertion are real; only local HTTP is stubbed.
    def bind_response(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "session": {
                    "session_id": request.headers["x-claude-code-session-id"],
                    "workload_ref": payload["workload_ref"],
                    "integration_mode": payload["integration_mode"],
                    "adapter": payload["adapter"],
                    "profile": payload["profile"],
                    "policy": {"id": "policy", "version": "1"},
                    "coverage": [],
                },
                "credential_ref": "assertion:test",
                "expires_at": "2026-09-07T23:00:00Z",
            },
        )

    with respx.mock:
        route = respx.post("http://127.0.0.1:8788/adrl/v1/sessions").mock(side_effect=bind_response)
        result = CliRunner().invoke(
            app,
            [
                "connect",
                "claude-code",
                "--repo",
                "/Users/arunmenon/projects/adrl-core",
                "--output",
                str(output),
                "--mode",
                mode,
            ],
        )
    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    token = (output / "assertion.token").read_text()
    assert token not in result.output
    environment = (output / "env.sh").read_text()
    if mode == "gateway":
        assert "X-Org: existing" in environment
        assert "ANTHROPIC_BASE_URL" in environment
    else:
        assert "ANTHROPIC" not in environment
        assert token not in environment
        assert "cannot inspect, block" in result.output
    hook_settings = json.loads((output / "claude-settings.json").read_text())
    assert set(hook_settings["hooks"]) == {"PostToolUse", "PostToolUseFailure"}
    for path in output.iterdir():
        assert os.stat(path).st_mode & 0o777 == 0o600
    config = Connection.model_validate_json((output / "connection.json").read_bytes())
    assert config.headers()["x-adrl-workload-assertion"] == token
    assert config.integration_mode == mode
    assert token not in (output / "claude-settings.json").read_text()
    assert os.stat(output).st_mode & 0o777 == 0o700


def test_private_file_creation_does_not_overwrite_existing(tmp_path: Path) -> None:
    path = tmp_path / "credential"
    write_private(path, b"first")
    with pytest.raises(FileExistsError):
        write_private(path, b"second")
    assert path.read_bytes() == b"first"
