"""Numbered SQL migrations applied under PRAGMA user_version. Primary: ADRL-MEM-001."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str


def load_migrations() -> tuple[Migration, ...]:
    folder = Path(__file__).parent
    found: list[Migration] = []
    for path in sorted(folder.glob("*.sql")):
        match = _NAME.match(path.name)
        if not match:
            raise ValueError(f"migration file name {path.name} does not match NNNN_name.sql")
        found.append(Migration(int(match.group(1)), path.stem, path.read_text(encoding="utf-8")))
    versions = [m.version for m in found]
    if versions != list(range(1, len(versions) + 1)):
        raise ValueError(f"migration versions must be contiguous from 1, got {versions}")
    return tuple(found)
