"""Field-level data inventory check. Primary: ADRL-MEM-010. Secondary: ADRL-MEM-005.
Also implements: ADRL-OPS-004 (register additions of 2026-09-03).

Every column the two ledgers hold and every JSON payload key the producers listed below emit
must appear in docs/data-inventory.md with one of four classes. The check fails on an unlisted
field or on any field classed plaintext_prompt_class. Run with --list to print what the scan
finds, which is how the document is kept complete.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "data-inventory.md"
CLASSES = {"skeleton", "keyed_hash", "encrypted_prompt_class", "plaintext_prompt_class"}
PRODUCER_FILES = [
    "src/adrl/gates/repo_class.py",
    "src/adrl/gates/pin.py",
    "src/adrl/gates/pipeline.py",
    "src/adrl/gates/coverage.py",
    "src/adrl/gates/egress.py",
    "src/adrl/ledger/events.py",
    "src/adrl/ledger/verification.py",
    "src/adrl/ledger/erasure.py",
    "src/adrl/ledger/keystore.py",
    "src/adrl/ledger/embeddings.py",
]
PAYLOAD_FUNCTIONS = re.compile(
    r"(payload|event|_append_job|as_payload|as_record|_seal|record_|_write_durably|"
    r"record_shadow|promote_shadow|release|begin|finish|_run_checks|erase_session)"
)
PAYLOAD_NAMES = {"payload", "finished_payload", "material", "outputs", "results", "record"}
STRUCTURED_MODELS = {
    "src/adrl/core/resource_owner.py": {"ResourceEvent"},
    "src/adrl/core/container_control.py": {"ResourcePolicy"},
    "src/adrl/core/isolated_execution.py": {"LaunchEvent"},
    "src/adrl/core/execution_control.py": {"ExecutionPolicy"},
}
CREATE_TABLE = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)\s*\((.*?)\);", re.S)
ADDED_COLUMN = re.compile(
    r"ALTER TABLE (\w+)\s+ADD COLUMN (\w+)\s+(?:TEXT|INTEGER|REAL|BLOB)", re.I
)
COLUMN = re.compile(r"^\s*(\w+)\s+(?:TEXT|INTEGER|REAL|BLOB)", re.M)


def schema_fields() -> set[str]:
    found: set[str] = set()
    sources = list((ROOT / "src/adrl/ledger/migrations").glob("*.sql"))
    sources += [ROOT / "src/adrl/ledger/egress.py"]
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for table, column in ADDED_COLUMN.findall(text):
            found.add(f"{table}.{column}")
        for table, body in CREATE_TABLE.findall(text):
            for column in COLUMN.findall(body):
                found.add(f"{table}.{column}")
    return found


class _Collector(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.found: set[str] = set()
        self._stack: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]  # noqa: N815

    def _in_payload_function(self) -> bool:
        return any(PAYLOAD_FUNCTIONS.search(name) for name in self._stack)

    def visit_Dict(self, node: ast.Dict) -> None:
        if self._in_payload_function():
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    self.found.add(f"{self.module}:{key.value}")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        if targets & PAYLOAD_NAMES and isinstance(node.value, ast.Dict):
            for key in node.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    self.found.add(f"{self.module}:{key.value}")
        self.generic_visit(node)


def payload_fields() -> set[str]:
    found: set[str] = set()
    for rel in PRODUCER_FILES:
        path = ROOT / rel
        if not path.exists():
            continue
        module = path.stem
        collector = _Collector(module)
        collector.visit(ast.parse(path.read_text(encoding="utf-8")))
        found |= collector.found
    return found


def structured_fields() -> set[str]:
    """Inventory every annotated field of the persisted ownership and launch metadata models."""
    found: set[str] = set()
    for relative, names in STRUCTURED_MODELS.items():
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name in names:
                for field in node.body:
                    if isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name):
                        found.add(f"{node.name}:{field.target.id}")
    return found


def documented() -> dict[str, str]:
    out: dict[str, str] = {}
    if not DOC.exists():
        return out
    for line in DOC.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        name = cells[0].strip("`")
        cls = cells[1].strip("`")
        out[name] = cls
    return out


def main(argv: list[str]) -> int:
    fields = schema_fields() | payload_fields() | structured_fields()
    if "--list" in argv:
        for name in sorted(fields):
            print(name)
        return 0
    doc = documented()
    problems: list[str] = []
    for name in sorted(fields):
        cls = doc.get(name)
        if cls is None:
            problems.append(f"unlisted field: {name}")
        elif cls not in CLASSES:
            problems.append(f"unknown class {cls!r} for {name}")
        elif cls == "plaintext_prompt_class":
            problems.append(f"plaintext prompt-class field: {name}")
    for name, cls in doc.items():
        if cls == "plaintext_prompt_class":
            problems.append(f"plaintext prompt-class field documented: {name}")
    if problems:
        for problem in problems:
            print(problem)
        print(f"data inventory: {len(problems)} problem(s)")
        return 1
    print(f"data inventory: ok ({len(fields)} fields, {len(doc)} documented)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
