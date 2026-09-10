"""Session-marginal, cache-aware cost accounting. Primary: ADRL-RTG-009.

Secondary: ADRL-RTG-002, ADRL-RTG-005. Cost of a candidate rung is the expected cost of the
remaining episode on that rung given its cache state, plus the cache-rebuild cost of a
switch, plus the expected cascade cost on failure. No figure is ever list price alone; every
figure carries its label.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from adrl.config.models import PolicyConfig, PricesConfig
from adrl.core.enums import Rung
from adrl.core.ports import StickyState
from adrl.core.types import PermittedSet
from adrl.routing.registry import RungRegistry

CostLabel = Literal["after_cache_effects", "list_price"]
MILLION = 1_000_000.0


class EpisodeLengthEstimator(Protocol):
    """Expected number of remaining requests in the episode (ADRL-RTG-009 clause 3)."""

    def remaining_requests(self, request_kind: str, band_id: str | None) -> float: ...

    @property
    def version(self) -> str: ...


class ConstantEpisodeLength:
    """episode-constant-v1: one versioned constant until a shadow corpus exists."""

    def __init__(self, constant: int, version: str = "episode-constant-v1") -> None:
        self._constant = float(constant)
        self._version = version

    def remaining_requests(self, request_kind: str, band_id: str | None) -> float:
        return self._constant

    @property
    def version(self) -> str:
        return self._version


@dataclass(frozen=True, slots=True)
class CostEstimate:
    rung: Rung
    after_cache_usd: float
    list_price_usd: float
    switch_cost_usd: float
    cascade_cost_usd: float
    cache_warm: bool
    remaining_requests: float
    episode_estimator_version: str
    prices_version: str
    label: CostLabel = "after_cache_effects"

    def as_record(self) -> dict[str, float | str | bool]:
        return {
            "rung": self.rung.value,
            "after_cache_usd": round(self.after_cache_usd, 6),
            "list_price_usd": round(self.list_price_usd, 6),
            "switch_cost_usd": round(self.switch_cost_usd, 6),
            "cascade_cost_usd": round(self.cascade_cost_usd, 6),
            "cache_warm": self.cache_warm,
            "remaining_requests": self.remaining_requests,
            "episode_estimator_version": self.episode_estimator_version,
            "prices_version": self.prices_version,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class CostInputs:
    context_tokens: int
    expected_output_tokens: int
    request_kind: str
    band_id: str | None
    now: datetime
    sticky: StickyState | None
    served_model: str | None = None


class CostModel:
    """Computes CostEstimate per rung. Trip-wire escalation is exempt from the switch charge."""

    def __init__(
        self,
        prices: PricesConfig,
        policy: PolicyConfig,
        registry: RungRegistry,
        episode_estimator: EpisodeLengthEstimator | None = None,
    ) -> None:
        self._prices = prices
        self._policy = policy
        self._registry = registry
        self._episodes = episode_estimator or ConstantEpisodeLength(
            policy.episode_length_constant, "episode-" + policy.episode_length_estimator
        )

    @property
    def episode_estimator_version(self) -> str:
        return self._episodes.version

    def cache_is_warm(self, rung: Rung, inputs: CostInputs) -> bool:
        sticky = inputs.sticky
        if sticky is None or sticky.rung is not rung or sticky.last_served_at is None:
            return False
        if inputs.served_model is not None and sticky.served_model not in (
            None,
            inputs.served_model,
        ):
            return False
        ttl = self._prices.by_rung[rung].cache_ttl_s
        if ttl <= 0:
            return False
        age = (inputs.now - sticky.last_served_at).total_seconds()
        return 0 <= age <= ttl

    def _episode_cost(
        self, rung: Rung, inputs: CostInputs, *, warm: bool
    ) -> tuple[float, float, float]:
        """Return (after_cache, list_price, switch_cost) for the remaining episode on `rung`."""
        price = self._prices.by_rung[rung]
        remaining = max(1.0, self._episodes.remaining_requests(inputs.request_kind, inputs.band_id))
        ctx = inputs.context_tokens
        out = inputs.expected_output_tokens
        input_price = price.input / MILLION
        output_price = price.output / MILLION
        list_price = remaining * (ctx * input_price + out * output_price)
        first_request = (
            ctx
            * input_price
            * (price.cache_read_multiplier if warm else price.cache_write_multiplier)
        )
        later_requests = (remaining - 1.0) * ctx * input_price * price.cache_read_multiplier
        outputs = remaining * out * output_price
        after_cache = first_request + later_requests + outputs
        switch_cost = (
            0.0
            if warm
            else ctx * input_price * (price.cache_write_multiplier - price.cache_read_multiplier)
        )
        return after_cache, list_price, max(0.0, switch_cost)

    def estimate(
        self,
        rung: Rung,
        inputs: CostInputs,
        *,
        p_complete: float,
        permitted: PermittedSet,
        escalation_exempt: bool = False,
    ) -> CostEstimate:
        warm = self.cache_is_warm(rung, inputs)
        after_cache, list_price, switch_cost = self._episode_cost(
            rung, inputs, warm=warm or escalation_exempt
        )
        if escalation_exempt:
            switch_cost = 0.0
        cascade_cost = 0.0
        next_rung = self._registry.next_higher(rung, permitted)
        if next_rung is not None and p_complete < 1.0:
            next_after, _, _ = self._episode_cost(next_rung, inputs, warm=False)
            cascade_cost = (1.0 - p_complete) * next_after
        return CostEstimate(
            rung=rung,
            after_cache_usd=after_cache + cascade_cost,
            list_price_usd=list_price,
            switch_cost_usd=switch_cost,
            cascade_cost_usd=cascade_cost,
            cache_warm=warm,
            remaining_requests=self._episodes.remaining_requests(
                inputs.request_kind, inputs.band_id
            ),
            episode_estimator_version=self._episodes.version,
            prices_version=self._prices.version,
            label=self._prices.label,
        )

    def estimate_all(
        self,
        inputs: CostInputs,
        probabilities: Mapping[Rung, float],
        permitted: PermittedSet,
        *,
        escalation_exempt: bool = False,
    ) -> dict[Rung, CostEstimate]:
        return {
            rung: self.estimate(
                rung,
                inputs,
                p_complete=probabilities.get(rung, 0.0),
                permitted=permitted,
                escalation_exempt=escalation_exempt,
            )
            for rung in permitted
        }
