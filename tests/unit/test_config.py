"""Config loading and load-time checks."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from adrl.config.checks import all_checks
from adrl.config.loaders import load_bundle
from adrl.config.settings import Settings
from adrl.core.enums import RoutingMode, Rung
from adrl.core.errors import ConfigError
from tests.conftest import CONFIG_DIR


def _copy_config(tmp_path: Path) -> Path:
    target = tmp_path / "config"
    shutil.copytree(CONFIG_DIR, target)
    return target


def test_default_bundle_loads_and_checks_pass(settings: Settings) -> None:
    bundle = load_bundle(settings)
    assert bundle.rungs.version == "rung-membership-v1"
    assert bundle.manifest_signature_verified
    assert all(c.ok for c in all_checks(bundle, settings))
    assert bundle.rungs.group_to_rung["adrl-local-large"] is Rung.LOCAL
    assert (
        bundle.provider_pairs.rule_for("anthropic", "anthropic", True).action
        == "keep_latest_thinking"
    )
    assert (
        bundle.provider_pairs.rule_for("mystery", "anthropic", True).action == "strip_and_disable"
    )


def test_cross_rung_fallback_group_fails(tmp_path: Path) -> None:
    cfg = _copy_config(tmp_path)
    data = yaml.safe_load((cfg / "rungs.yaml").read_text())
    data["fallback_groups"].append({"primary": "adrl-local", "fallbacks": ["adrl-frontier"]})
    (cfg / "rungs.yaml").write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match="spans rungs"):
        load_bundle(Settings(config_dir=cfg))


def test_compaction_deadlock_fails(tmp_path: Path) -> None:
    cfg = _copy_config(tmp_path)
    data = yaml.safe_load((cfg / "rungs.yaml").read_text())
    data["rungs"]["local"]["boundary"]["context_ceiling"] = 32768
    (cfg / "rungs.yaml").write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match="pinned lineages will deadlock"):
        load_bundle(Settings(config_dir=cfg))


def test_live_mode_requires_evidence(tmp_path: Path) -> None:
    cfg = _copy_config(tmp_path)
    with pytest.raises(ConfigError, match="without an evidence_ref"):
        load_bundle(Settings(config_dir=cfg, routing_mode=RoutingMode.LIVE))


def test_tampered_manifest_fails_signature(tmp_path: Path) -> None:
    cfg = _copy_config(tmp_path)
    manifest = json.loads((cfg / "repo-classification-v1.json").read_text())
    manifest["default_class_id"] = "open"
    (cfg / "repo-classification-v1.json").write_text(json.dumps(manifest))
    with pytest.raises(ConfigError, match="signature is invalid"):
        load_bundle(Settings(config_dir=cfg))


def test_unsigned_manifest_allowed_only_when_not_required(tmp_path: Path) -> None:
    cfg = _copy_config(tmp_path)
    (cfg / "repo-classification-v1.sig").unlink()
    with pytest.raises(ConfigError, match="must be signed"):
        load_bundle(Settings(config_dir=cfg))
    bundle = load_bundle(Settings(config_dir=cfg, require_signed_manifest=False))
    assert not bundle.manifest_signature_verified


def test_exploration_epsilon_bounded(tmp_path: Path) -> None:
    cfg = _copy_config(tmp_path)
    data = yaml.safe_load((cfg / "policy.yaml").read_text())
    data["exploration_epsilon_by_rung"] = {"local": 0.5}
    (cfg / "policy.yaml").write_text(yaml.safe_dump(data))
    with pytest.raises(ConfigError, match="epsilon"):
        load_bundle(Settings(config_dir=cfg))
