"""Wire fixtures: scrubbed request shapes and the config bundle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.settings import Settings
from adrl.wire.parse import ParsedRequest, parse_request

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "wire"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))


def fixture_names() -> list[str]:
    """Only the wire goldens (files carrying an `expected` block); other packages share the dir."""
    names: list[str] = []
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "expected" in data and "body" in data:
            names.append(path.stem)
    return names


def parsed_fixture(name: str) -> ParsedRequest:
    data = load_fixture(name)
    body = json.dumps(data["body"]).encode("utf-8") if data["body"] is not None else b""
    return parse_request(data["method"], data["path"], data["headers"], body)


@pytest.fixture(scope="session")
def bundle() -> ConfigBundle:
    root = Path(__file__).resolve().parents[3]
    return load_bundle(Settings(config_dir=root / "config"))
