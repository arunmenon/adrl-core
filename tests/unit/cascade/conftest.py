from __future__ import annotations

import pytest

from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.settings import Settings
from adrl.routing.registry import RungRegistry
from tests.conftest import CONFIG_DIR


@pytest.fixture(scope="session")
def bundle() -> ConfigBundle:
    return load_bundle(Settings(config_dir=CONFIG_DIR))


@pytest.fixture
def registry(bundle: ConfigBundle) -> RungRegistry:
    return RungRegistry(bundle.rungs)
