"""Record bounded local engineering checks. Primary: ADRL-FND-005.

Secondary: ADRL-EVL-009, ADRL-SEM-007. A passing run is evidence, never release authority.
Only named source directories are hashed. Private keys and runtime data are excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ("src", "tests", "tools", "config", "docs", "api", "artifacts")
SOURCE_FILES = ("pyproject.toml", "uv.lock", "README.md", "AGENTS.md", "CLAUDE.md", ".gitignore")
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}


def source_manifest(root: Path) -> dict[str, dict[str, str | int]]:
    """Hash declared inputs without reading private keys, caches or runtime payloads."""
    paths = [root / name for name in SOURCE_FILES if (root / name).exists()]
    for name in SOURCE_DIRS:
        directory = root / name
        if directory.is_symlink():
            raise ValueError(f"symlinked input directory: {name}")
        if directory.exists():
            paths.extend(directory.rglob("*"))
    result: dict[str, dict[str, str | int]] = {}
    for path in sorted(paths):
        relative = path.relative_to(root)
        if EXCLUDED_PARTS.intersection(relative.parts) or path.suffix == ".pyc":
            continue
        if path.name.startswith(".env") or path.suffix in {".key", ".pem"}:
            continue
        if path.is_symlink():
            raise ValueError(f"symlinked input: {relative}")
        if path.is_file():
            data = path.read_bytes()
            result[str(relative)] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "mode": path.stat().st_mode & 0o777,
            }
    return result


def stop_group(process: subprocess.Popen[bytes]) -> None:
    """Kill a timed-out check and its subprocess group on this POSIX runner."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_check(name: str, argv: list[str], root: Path, out: Path, timeout: int) -> dict[str, object]:
    started = time.monotonic()
    status = "failed"
    code: int | None = None
    with (out / f"{name}.log").open("wb") as log:
        try:
            process = subprocess.Popen(
                argv, cwd=root, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
            )
            try:
                code = process.wait(timeout=timeout)
                status = "passed" if code == 0 else "failed"
            except subprocess.TimeoutExpired:
                stop_group(process)
                status = "timed_out"
            except KeyboardInterrupt:
                stop_group(process)
                status = "cancelled"
        except OSError as exc:
            log.write(f"Cannot start check: {exc}\n".encode())
            status = "unavailable"
    return {
        "name": name,
        "argv": argv,
        "status": status,
        "exit_code": code,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": f"{name}.log",
    }


def register_coverage(register: Path) -> dict[str, object]:
    known = sorted(p.stem for p in register.glob("*/ADRL-*.md"))
    index = register.parent / "INDEX.md"
    rows = (
        re.findall(r"^\| \[(ADRL-[A-Z]{3}-\d{3})\]", index.read_text(), re.M)
        if index.is_file()
        else []
    )
    passed = bool(known) and len(rows) == len(set(rows)) and sorted(rows) == known
    return {
        "name": "register_index",
        "status": "passed" if passed else "failed",
        "decision_count": len(known),
        "missing_from_index": sorted(set(known) - set(rows)),
        "unknown_index_rows": sorted(set(rows) - set(known)),
        "duplicate_index_rows": sorted(row for row in set(rows) if rows.count(row) > 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, required=True, help="New private directory outside repo"
    )
    parser.add_argument("--timeout", type=int, default=600, help="Seconds per subprocess check")
    parser.add_argument("--register", type=Path, default=ROOT.parent / "adrl-world-class/adr")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 1800:
        parser.error("timeout must be between 1 and 1800 seconds")
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("output must be outside the source repository")
    os.umask(0o077)
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    report: dict[str, object] = {
        "schema_version": "adrl-engineering-checks-v1",
        "started_at": datetime.now(UTC).isoformat(),
        "status": "running",
        "source_root": str(ROOT),
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "installed_packages": sorted(
            f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions()
        ),
        "environment_scope": "Inherited environment; secret values and private keys not recorded",
        "source_scope": {"directories": SOURCE_DIRS, "root_files": SOURCE_FILES},
        "excluded_scope": "Private keys, .env files, caches, runtime data and Git internals",
        "per_check_timeout_seconds": args.timeout,
        "release_authority": False,
    }
    manifest = out / "manifest.json"

    def save() -> None:
        temporary = out / "manifest.pending"
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        temporary.replace(manifest)

    save()
    try:
        before = source_manifest(ROOT)
        report["source_before"] = before
        commands = [
            ("lint", ["-m", "ruff", "check", "src", "tests", "tools"]),
            ("format", ["-m", "ruff", "format", "--check", "src", "tests", "tools"]),
            ("types", ["-m", "mypy"]),
            ("tests", ["-m", "pytest", "-q"]),
            ("ledger", ["tools/check_ledger_discipline.py"]),
            ("config", ["-m", "adrl.cli.main", "config", "check"]),
            ("inventory", ["tools/check_data_inventory.py"]),
            ("learning", ["tools/check_learning_contract.py"]),
            (
                "api_contract",
                [
                    "tools/export_api_contract.py",
                    "--out",
                    "api/adrl-api-v1-preview.json",
                    "--check",
                ],
            ),
            (
                "adr_map",
                ["tools/adr_module_map.py", "--register", str(args.register), "--check"],
            ),
        ]
        checks: list[dict[str, object]] = []
        report["checks"] = checks
        for name, arguments in commands:
            report["active_check"] = name
            save()
            check = run_check(name, [sys.executable, *arguments], ROOT, out, args.timeout)
            checks.append(check)
            save()
            print(f"{name}: {check['status']}", flush=True)
            if check["status"] == "cancelled":
                break
        checks.append(register_coverage(args.register))
        after = source_manifest(ROOT)
        changed = sorted(
            name for name in before.keys() | after.keys() if before.get(name) != after.get(name)
        )
        report["source_after"] = after
        report["changed_inputs"] = changed
        report["status"] = (
            "passed"
            if not changed and len(checks) == 11 and all(c["status"] == "passed" for c in checks)
            else "failed"
        )
    except (OSError, ValueError) as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
    except KeyboardInterrupt:
        report["status"] = "cancelled"
    finally:
        report["active_check"] = None
        report["finished_at"] = datetime.now(UTC).isoformat()
        save()
    print(f"Engineering checks: {report['status']}; evidence: {manifest}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
