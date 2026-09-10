"""Generate docs/adr-module-map.md from module docstrings (ADRL-FND-005).

Only decisions that exist in the register count. IDs cited by a module but absent from the
register are reported as phantoms; register decisions with no citing module are listed so
presence can never be mistaken for coverage.
"""

from __future__ import annotations

import argparse
import ast
import collections
import os
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_REGISTER = ROOT.parent / "adrl-world-class" / "adr"
BUCKETS = "FND|SEM|SAF|RTG|CAS|MEM|LRN|TRU|EVL|OPS"
# A citation is ADRL-<BUCKET>-NNN optionally followed by /NNN continuations
# (ADRL-CAS-001/004/008 cites three decisions).
CITE_RE = re.compile(rf"ADRL-({BUCKETS})-(\d{{3}})((?:/\d{{3}})*)")


def cited_ids(doc: str) -> list[str]:
    ids: set[str] = set()
    for match in CITE_RE.finditer(doc):
        bucket, first, rest = match.groups()
        ids.add(f"ADRL-{bucket}-{first}")
        for number in rest.split("/"):
            if number:
                ids.add(f"ADRL-{bucket}-{number}")
    return sorted(ids)


def register_ids(register: pathlib.Path) -> set[str]:
    ids: set[str] = set()
    if not register.is_dir():
        return ids
    for path in register.rglob("ADRL-*.md"):
        match = re.match(rf"(ADRL-(?:{BUCKETS})-\d{{3}})\.md$", path.name)
        if match:
            ids.add(match.group(1))
    return ids


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--register",
        type=pathlib.Path,
        default=pathlib.Path(os.environ.get("ADRL_REGISTER", str(DEFAULT_REGISTER))),
        help="Path to the register's adr/ directory",
    )
    parser.add_argument("--check", action="store_true", help="Check without rewriting the map")
    args = parser.parse_args()
    known = register_ids(args.register)
    if not known:
        parser.error("register is absent or contains no ADR records")
    rows: list[tuple[str, list[str], str]] = []
    for path in sorted((ROOT / "src" / "adrl").rglob("*.py")):
        if path.name == "__init__.py":
            continue
        doc = (ast.get_docstring(ast.parse(path.read_text())) or "").strip()
        first = doc.splitlines()[0] if doc else ""
        rows.append((str(path.relative_to(ROOT / "src")), cited_ids(doc), first[:110]))
    by_id: dict[str, list[str]] = collections.defaultdict(list)
    for module, ids, _ in rows:
        for decision in ids:
            by_id[decision].append(module)
    mapped = sorted(d for d in by_id if d in known)
    phantoms = sorted(d for d in by_id if d not in known)
    unmapped = sorted(known - set(by_id))
    missing = [module for module, ids, _ in rows if not ids]

    lines = [
        "# ADR to module map",
        "",
        "Generated from module docstrings. Regenerate with `tools/adr_module_map.py`.",
        "",
        f"Register: ADR files ({len(known)} decisions). "
        f"Mapped: {len(mapped)} of {len(known)}. Phantom citations: {len(phantoms)}. "
        f"Register decisions with no module: {len(unmapped)}.",
        "",
        "## By module",
        "",
        "| Module | ADR IDs | Docstring |",
        "|---|---|---|",
    ]
    for module, ids, first in rows:
        lines.append(f"| `{module}` | {', '.join(ids) or 'none'} | {first.replace('|', '/')} |")
    lines += ["", "## By decision (register only)", "", "| ADR | Modules |", "|---|---|"]
    for decision in mapped:
        lines.append(f"| {decision} | {', '.join('`' + m + '`' for m in by_id[decision])} |")
    lines += ["", "## Register decisions with no implementing module", ""]
    lines += [f"- {decision}" for decision in unmapped] or ["- none"]
    lines += ["", "## Phantom citations (not in the register)", ""]
    lines += [
        f"- {decision}: {', '.join('`' + m + '`' for m in by_id[decision])}"
        for decision in phantoms
    ] or ["- none"]
    lines += ["", f"Modules without an ADR ID in their docstring: {len(missing)}", ""]
    lines += [f"- `{module}`" for module in missing]
    target = ROOT / "docs" / "adr-module-map.md"
    content = "\n".join(lines) + "\n"
    if args.check:
        if not target.exists() or target.read_text() != content:
            parser.exit(1, "ADR module map is stale; regenerate tools/adr_module_map.py\n")
    else:
        target.write_text(content)
    print(
        f"{len(rows)} modules; register {len(known)}; mapped {len(mapped)}; "
        f"unmapped {unmapped}; phantoms {phantoms}; no id {len(missing)}"
    )
    if phantoms or missing:
        parser.exit(1, "Modules have unknown or missing ADR citations\n")


if __name__ == "__main__":
    main()
