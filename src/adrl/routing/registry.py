"""Rung registry with measured boundaries. Primary: ADRL-RTG-001. Secondary: ADRL-RTG-008.

Rungs are defined by a versioned boundary, never by a model name. Reasoning effort and
thinking budget are dispatch parameters inside a rung and never a rung input.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from adrl.config.models import RungBoundary, RungsConfig
from adrl.core.enums import Rung

CONSERVATIVE_TASK_CLASSES: tuple[str, ...] = ("mechanical_edit", "small_diff", "small_context")
ANY_TASK_CLASS = "any"

EFFORT_PARAMETERS: tuple[str, ...] = ("thinking", "output_config", "reasoning_effort", "effort")


@dataclass(frozen=True, slots=True)
class RungEntry:
    rung: Rung
    members: tuple[str, ...]
    alias: str
    boundary: RungBoundary
    tokenizer_ratio: float
    enabled: bool
    family: str
    intra_rung_escalation_order: tuple[str, ...]

    @property
    def has_organic_evidence(self) -> bool:
        return self.boundary.evidence_ref is not None

    @property
    def permitted_task_classes(self) -> tuple[str, ...]:
        """Published scope; a rung without organic evidence gets the conservative subset."""
        if self.has_organic_evidence or self.rung is Rung.FRONTIER:
            return self.boundary.permitted_task_classes
        return tuple(
            c for c in self.boundary.permitted_task_classes if c in CONSERVATIVE_TASK_CLASSES
        )

    def permits_task_class(self, task_class: str) -> bool:
        classes = self.permitted_task_classes
        return ANY_TASK_CLASS in classes or task_class in classes


def default_family(rung: Rung) -> str:
    return "local" if rung is Rung.LOCAL else "anthropic"


class RungRegistry:
    """Read-only view over rungs.yaml (rung-membership-v1)."""

    def __init__(self, config: RungsConfig) -> None:
        self._config = config
        self._entries: dict[Rung, RungEntry] = {}
        for rung, spec in config.rungs.items():
            self._entries[rung] = RungEntry(
                rung=rung,
                members=spec.members,
                alias=spec.members[0],
                boundary=spec.boundary,
                tokenizer_ratio=spec.tokenizer_ratio,
                enabled=spec.enabled,
                family=spec.family or default_family(rung),
                intra_rung_escalation_order=spec.intra_rung_escalation_order,
            )
        self._group_to_rung = config.group_to_rung
        self._frontier_names = frozenset(config.frontier_model_names)

    @property
    def version(self) -> str:
        return self._config.version

    @property
    def cheap_cloud_admission_criterion(self) -> str:
        return self._config.cheap_cloud_admission_criterion

    def entry(self, rung: Rung) -> RungEntry:
        return self._entries[rung]

    def entries(self) -> tuple[RungEntry, ...]:
        return tuple(self._entries[r] for r in Rung.ordered() if r in self._entries)

    def enabled_rungs(self) -> tuple[Rung, ...]:
        return tuple(e.rung for e in self.entries() if e.enabled)

    def alias_for(self, rung: Rung) -> str:
        return self._entries[rung].alias

    def family_for(self, rung: Rung) -> str:
        return self._entries[rung].family

    def context_ceiling(self, rung: Rung) -> int:
        return self._entries[rung].boundary.context_ceiling

    def rung_for_group(self, group: str) -> Rung | None:
        return self._group_to_rung.get(group)

    def rung_for_model_name(self, model: str) -> Rung | None:
        """Map a harness-requested model name or a group alias to its rung."""
        if model in self._group_to_rung:
            return self._group_to_rung[model]
        if model in self._frontier_names:
            return Rung.FRONTIER
        return None

    def has_evidence(self, rung: Rung) -> bool:
        return self._entries[rung].has_organic_evidence

    def next_higher(self, rung: Rung, permitted: Any) -> Rung | None:
        """The lowest permitted rung strictly above `rung`, or None."""
        for candidate in Rung.ordered():
            if candidate > rung and candidate in permitted and candidate in self._entries:
                return candidate
        return None


def effort_parameters(body: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the within-rung dispatch parameters (thinking budget, effort).

    These are recorded for dispatch and never fed to rung selection or sticky state.
    """
    return {key: body[key] for key in EFFORT_PARAMETERS if key in body}


def strip_effort_parameters(body: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in body.items() if key not in EFFORT_PARAMETERS}
