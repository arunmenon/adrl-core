"""Trust, residency and egress attacks (ADRL-SAF-008, ADRL-SAF-009, ADRL-FND-002).

The 2026-09-03 review showed that "local" was a label: a local group pointed at a remote host
passed every check and was audited as never leaving the machine. These tests keep that closed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from adrl.config.loaders import load_bundle
from adrl.config.models import EndpointInventory
from adrl.config.settings import Settings
from adrl.core.enums import Rung
from adrl.core.errors import ConfigError
from adrl.gates.deployments import DeploymentPolicy
from tests.conftest import CONFIG_DIR, REPO_ROOT

EXFIL = "https://exfil.example.com/v1"


def _copy_config(tmp_path: Path) -> Path:
    for path in CONFIG_DIR.iterdir():
        if path.is_file():
            (tmp_path / path.name).write_bytes(path.read_bytes())
    (tmp_path / "keys" / "dev").mkdir(parents=True)
    for key in (CONFIG_DIR / "keys" / "dev").iterdir():
        (tmp_path / "keys" / "dev" / key.name).write_bytes(key.read_bytes())
    return tmp_path


def _resign(config_dir: Path, name: str) -> None:
    import base64

    from cryptography.hazmat.primitives import serialization

    from adrl.config.loaders import canonical_json

    key = serialization.load_pem_private_key(
        (config_dir / "keys" / "dev" / "manifest-signing.key").read_bytes(), password=None
    )
    payload = canonical_json(json.loads((config_dir / f"{name}.json").read_bytes()))
    (config_dir / f"{name}.sig").write_text(
        base64.b64encode(key.sign(payload)).decode() + "\n"  # type: ignore[union-attr]
    )


def _tool(name: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tools" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_local_group_on_a_remote_host_fails_load_and_the_ci_tool(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    data = json.loads((config_dir / "endpoint-inventory-v1.json").read_text())
    data["deployments"][0]["api_base"] = EXFIL
    (config_dir / "endpoint-inventory-v1.json").write_text(json.dumps(data))
    _resign(config_dir, "endpoint-inventory-v1")
    with pytest.raises(ConfigError, match="not loopback"):
        load_bundle(Settings(config_dir=config_dir))
    assert _tool("check_config").main(["--config-dir", str(config_dir)]) == 1


def test_generator_refuses_a_local_deployment_off_the_host(bundle) -> None:  # type: ignore[no-untyped-def]
    gen = _tool("gen_litellm_config")
    data = json.loads((CONFIG_DIR / "endpoint-inventory-v1.json").read_text())
    data["deployments"][0]["api_base"] = EXFIL
    data["deployments"][0]["trust_zone"] = "public_cloud"
    inventory = EndpointInventory.model_validate(data)
    config = gen.generate(bundle, inventory)
    problems = gen.rung_closed(config, {g: r.value for g, r in bundle.rungs.group_to_rung.items()})
    assert any("not loopback" in p for p in problems)
    assert any("trust zone" in p for p in problems)


def test_pinned_lineage_never_reaches_a_non_local_host_deployment(bundle) -> None:  # type: ignore[no-untyped-def]
    data = json.loads((CONFIG_DIR / "endpoint-inventory-v1.json").read_text())
    data["deployments"].append(
        {
            "id": "local-exfil",
            "model_group": "adrl-local",
            "rung": "local",
            "provider": "openai_compatible",
            "model": "openai/anything",
            "api_base": EXFIL,
            "trust_zone": "public_cloud",
            "geo": "unknown",
            "attested_by": "nobody",
        }
    )
    policy = DeploymentPolicy(EndpointInventory.model_validate(data))
    for rungs in (frozenset(Rung), frozenset({Rung.LOCAL})):
        permitted = policy.permitted_for(permitted_rungs=rungs, pinned=True, residency=None)
        assert "local-exfil" not in permitted
        assert all(policy.catalog[i].is_local_host for i in permitted.ids)


def test_residency_class_in_use_without_in_geo_deployment_fails_load(tmp_path: Path) -> None:
    config_dir = _copy_config(tmp_path)
    data = json.loads((config_dir / "repo-classification-v1.json").read_text())
    data["repos"].append({"repo_id": "eu", "match": "/repos/eu-data", "class_id": "residency-eu"})
    (config_dir / "repo-classification-v1.json").write_text(json.dumps(data))
    _resign(config_dir, "repo-classification-v1")
    with pytest.raises(ConfigError, match="no deployment there"):
        load_bundle(Settings(config_dir=config_dir))
    lenient = load_bundle(Settings(config_dir=config_dir, residency_unreachable_is_error=False))
    assert lenient.repo_classification.class_by_id("residency-eu").residency == "eu"
