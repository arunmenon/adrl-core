"""FND-002 config generator and CI checker."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.models import FallbackGroup, RungsConfig
from adrl.config.settings import Settings
from adrl.core.errors import ConfigError
from tests.conftest import CONFIG_DIR, REPO_ROOT

TOOLS = REPO_ROOT / "tools"


def _load(name: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_generator_produces_rung_closed_groups(bundle: ConfigBundle) -> None:
    gen = _load("gen_litellm_config")
    config = gen.generate(bundle, bundle.endpoint_inventory)
    assert (
        gen.rung_closed(config, {g: r.value for g, r in bundle.rungs.group_to_rung.items()}) == []
    )
    names = {m["model_name"] for m in config["model_list"]}
    assert {"adrl-local", "adrl-cheap-cloud", "adrl-frontier", "adrl-pinned-local"} <= names
    # every attested deployment is addressable by id and answers with that id as its receipt
    assert {"local-qwen-7b", "local-qwen-32b", "cheap-haiku-us", "frontier-fable-us"} <= names
    by_id = {
        m["model_info"]["id"] for m in config["model_list"] if m["model_name"] == "cheap-haiku-us"
    }
    assert by_id == {"cheap-haiku-us"}
    local_fallbacks = [f for f in config["router_settings"]["fallbacks"] if "local-qwen-7b" in f]
    assert local_fallbacks == [{"local-qwen-7b": ["local-qwen-32b"]}]
    assert "claude-fable-5-1" in names
    assert config["router_settings"]["context_window_fallbacks"] == []
    pinned = next(f for f in config["router_settings"]["fallbacks"] if "adrl-pinned-local" in f)
    assert pinned["adrl-pinned-local"] == ["adrl-local-large"]
    assert (
        config["router_settings"]["num_retries"]
        == bundle.policy.gateway_retry_budget.max_attempts_per_turn - 1
    )


def test_checker_rejects_cross_rung_fallback(bundle: ConfigBundle, tmp_path: Path) -> None:
    gen = _load("gen_litellm_config")
    config = gen.generate(bundle, bundle.endpoint_inventory)
    config["router_settings"]["fallbacks"].append({"adrl-local": ["adrl-cheap-cloud"]})
    problems = gen.rung_closed(config, {g: r.value for g, r in bundle.rungs.group_to_rung.items()})
    assert problems and "crosses rung" in problems[0]
    # and the load-time check refuses the same thing in rungs.yaml
    for path in CONFIG_DIR.iterdir():
        if path.is_file():
            (tmp_path / path.name).write_bytes(path.read_bytes())
    (tmp_path / "keys" / "dev").mkdir(parents=True)
    for key in (CONFIG_DIR / "keys" / "dev").iterdir():
        (tmp_path / "keys" / "dev" / key.name).write_bytes(key.read_bytes())
    rungs = yaml.safe_load((tmp_path / "rungs.yaml").read_text())
    rungs["fallback_groups"].append({"primary": "adrl-local", "fallbacks": ["adrl-cheap-cloud"]})
    (tmp_path / "rungs.yaml").write_text(yaml.safe_dump(rungs))
    with pytest.raises(ConfigError, match="spans rungs"):
        load_bundle(Settings(config_dir=tmp_path))


def test_check_config_tool_runs_clean() -> None:
    checker = _load("check_config")
    assert checker.main(["--config-dir", str(CONFIG_DIR)]) == 0


def test_rungs_model_rejects_duplicate_membership(bundle: ConfigBundle) -> None:
    from dataclasses import replace

    from adrl.config.checks import check_rung_closed_membership

    data = yaml.safe_load((CONFIG_DIR / "rungs.yaml").read_text())
    data["rungs"]["cheap_cloud"]["members"] = ["adrl-local"]
    patched = replace(bundle, rungs=RungsConfig.model_validate(data))
    assert not check_rung_closed_membership(patched).ok
    assert FallbackGroup(primary="a", fallbacks=("b",)).primary == "a"
