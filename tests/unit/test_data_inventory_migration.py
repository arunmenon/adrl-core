"""Inventory catches columns introduced by migration. Primary: ADRL-MEM-001."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def test_undocumented_added_column_fails_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "inventory_check", root / "tools/check_data_inventory.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    document = tmp_path / "inventory.md"
    document.write_text(
        "\n".join(
            line
            for line in module.DOC.read_text().splitlines()
            if "product_sessions.integration_mode" not in line
        )
    )
    monkeypatch.setattr(module, "DOC", document)
    assert module.main([]) == 1
    assert "unlisted field: product_sessions.integration_mode" in capsys.readouterr().out
