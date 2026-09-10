"""CI check: append-only SQL and no shadow imports into live routing. Primary: ADRL-MEM-001.

Secondary: ADRL-MEM-008. Fails if any UPDATE or DELETE SQL string appears under src/, or if
adrl.learning or a module whose name starts with shadow_ is imported by adrl.routing or adrl.proxy.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "adrl"
SQL_PATTERN = re.compile(r"(?<![A-Za-z_])(UPDATE|DELETE)\s", re.IGNORECASE)
LIVE_PACKAGES = ("adrl.routing", "adrl.proxy")


def find_mutating_sql() -> list[str]:
    hits: list[str] = []
    for path in list(SRC.rglob("*.py")) + list(SRC.rglob("*.sql")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("--"):
                continue
            if SQL_PATTERN.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{number}: {stripped}")
    return hits


def find_shadow_imports() -> list[str]:
    hits: list[str] = []
    for package in LIVE_PACKAGES:
        folder = SRC / package.split(".")[-1]
        if not folder.exists():
            continue
        for path in folder.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
                for name in names:
                    last = name.split(".")[-1]
                    if name.startswith("adrl.learning") or last.startswith("shadow_"):
                        hits.append(f"{path.relative_to(ROOT)}: imports {name}")
    return hits


def main() -> int:
    problems = find_mutating_sql() + find_shadow_imports()
    for problem in problems:
        print(problem)
    if problems:
        print(f"ledger discipline: {len(problems)} problem(s)")
        return 1
    print("ledger discipline: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
