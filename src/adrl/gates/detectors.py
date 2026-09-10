"""Versioned detector tier table. Primary: ADRL-SAF-003.

Loaded from `config/detectors.yaml`. Tier membership follows measured precision; the file records
whether the figures are provisional or measured, and `adrl scan-measure` publishes new ones.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from adrl.core.enums import DetectorTier
from adrl.core.errors import ConfigError


class DetectorEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    detector_id: str
    tier: DetectorTier
    provisional_precision: float = Field(ge=0.0, le=1.0)
    measured_precision: float | None = Field(default=None, ge=0.0, le=1.0)
    enabled: bool = True


class DetectorsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["detectors-v1"]
    measured_on: str | None = None
    generic_min_length: int = 16
    generic_min_entropy_bits: float = 3.5
    base64_min_length: int = 24
    detectors: tuple[DetectorEntry, ...]

    def tier_for(self, detector_id: str) -> DetectorTier | None:
        for entry in self.detectors:
            if entry.detector_id == detector_id:
                return entry.tier if entry.enabled else None
        return None

    @property
    def enabled_ids(self) -> frozenset[str]:
        return frozenset(e.detector_id for e in self.detectors if e.enabled)


def load_detectors(path: Path) -> DetectorsConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"missing detectors config {path}") from exc
    try:
        return DetectorsConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"detectors config invalid: {exc}") from exc
