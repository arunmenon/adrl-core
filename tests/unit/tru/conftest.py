from __future__ import annotations

import pytest

from adrl.config.loaders import ConfigBundle, load_bundle
from adrl.config.settings import Settings
from tests.conftest import CONFIG_DIR


@pytest.fixture
def bundle() -> ConfigBundle:
    return load_bundle(Settings(config_dir=CONFIG_DIR))
