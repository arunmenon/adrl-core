"""CLI smoke: the entry points a developer touches first must run (ADRL-OPS by gloss)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from adrl.cli.main import app
from tests.conftest import CONFIG_DIR

runner = CliRunner()


def test_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ("serve", "config", "ledger", "gates", "learning", "gateway-config"):
        assert name in result.output


def test_config_check_passes_on_dev_config() -> None:
    result = runner.invoke(app, ["config", "check", "--config-dir", str(CONFIG_DIR)])
    assert result.exit_code == 0, result.output


def test_gateway_config_generates_a_file(tmp_path: Path) -> None:
    out = tmp_path / "litellm.yaml"
    result = runner.invoke(
        app, ["gateway-config", "--config-dir", str(CONFIG_DIR), "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "adrl-local" in text and "adrl-frontier" in text
