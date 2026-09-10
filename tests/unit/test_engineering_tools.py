"""Engineering evidence must expose missing inputs and failed checks. ADRL-FND-005/EVL-009."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_all", ROOT / "tools/check_all.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_manifest_detects_changed_inputs_and_excludes_keys(tmp_path: Path) -> None:
    runner = load_runner()
    source = tmp_path / "src/example.py"
    source.parent.mkdir()
    source.write_text("first")
    keys = tmp_path / "config/keys"
    keys.mkdir(parents=True)
    (keys / "private.key").write_text("do not archive")
    before = runner.source_manifest(tmp_path)
    assert set(before) == {"src/example.py"}
    source.write_text("second")
    assert before != runner.source_manifest(tmp_path)
    source.unlink()
    source.symlink_to(keys / "private.key")
    with pytest.raises(ValueError, match="symlinked input"):
        runner.source_manifest(tmp_path)


@pytest.mark.parametrize("exit_code", [0, 7])
def test_check_records_real_exit_status(tmp_path: Path, exit_code: int) -> None:
    result = load_runner().run_check(
        "probe", [sys.executable, "-c", f"raise SystemExit({exit_code})"], tmp_path, tmp_path, 5
    )
    assert result["exit_code"] == exit_code
    assert result["status"] == ("passed" if exit_code == 0 else "failed")


def test_timeout_stops_child_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "escaped"
    child = f"import pathlib,time; time.sleep(2); pathlib.Path({str(marker)!r}).touch()"
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(20)"
    )
    result = load_runner().run_check("probe", [sys.executable, "-c", parent], tmp_path, tmp_path, 1)
    assert result["status"] == "timed_out"
    subprocess.run([sys.executable, "-c", "import time; time.sleep(2)"], check=True)
    assert not marker.exists()


def test_register_coverage_refuses_duplicate_rows(tmp_path: Path) -> None:
    register = tmp_path / "adr/FND"
    register.mkdir(parents=True)
    (register / "ADRL-FND-005.md").write_text("decision")
    row = "| [ADRL-FND-005](adr/FND/ADRL-FND-005.md) |\n"
    (tmp_path / "INDEX.md").write_text(row + row)
    result = load_runner().register_coverage(register.parent)
    assert result["status"] == "failed"
    assert result["duplicate_index_rows"] == ["ADRL-FND-005"]


def test_adr_map_handles_comments_and_rejects_stale_or_missing_inputs(tmp_path: Path) -> None:
    tools = tmp_path / "core/tools"
    tools.mkdir(parents=True)
    shutil.copyfile(ROOT / "tools/adr_module_map.py", tools / "adr_module_map.py")
    source = tmp_path / "core/src/adrl"
    source.mkdir(parents=True)
    module = source / "example.py"
    module.write_text('# comment\n"""Primary: ADRL-FND-005."""\n')
    (tmp_path / "core/docs").mkdir()
    register = tmp_path / "register/FND"
    register.mkdir(parents=True)
    (register / "ADRL-FND-005.md").write_text("decision")
    command = [sys.executable, str(tools / "adr_module_map.py"), "--register", str(register.parent)]
    assert subprocess.run(command, capture_output=True).returncode == 0
    assert subprocess.run([*command, "--check"], capture_output=True).returncode == 0
    saved = (tmp_path / "core/docs/adr-module-map.md").read_bytes()
    module.write_text('"""Primary: ADRL-FND-999."""\n')
    assert subprocess.run([*command, "--check"], capture_output=True).returncode == 1
    assert (tmp_path / "core/docs/adr-module-map.md").read_bytes() == saved
    assert subprocess.run(command, capture_output=True).returncode == 1
    shutil.rmtree(register)
    assert subprocess.run(command, capture_output=True).returncode == 2


def test_contract_check_never_rewrites_stale_artifact(tmp_path: Path) -> None:
    target = tmp_path / "contract.json"
    target.write_text(json.dumps({"stale": True}))
    command = [sys.executable, str(ROOT / "tools/export_api_contract.py"), "--out", str(target)]
    assert subprocess.run([*command, "--check"], capture_output=True).returncode == 1
    assert json.loads(target.read_text()) == {"stale": True}
    assert subprocess.run(command, capture_output=True).returncode == 0
    assert subprocess.run([*command, "--check"], capture_output=True).returncode == 0
