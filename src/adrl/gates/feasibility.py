"""Feasibility filter: unhealthy or context-infeasible rungs are removed. Primary: ADRL-SAF-006.

Secondary: ADRL-SAF-005 (pinned overflow block), ADRL-SEM-001 (local count_tokens estimate).
Rule per rung: input_est * ratio + max_tokens + thinking_budget <= window - margin. The ratio errs
long. Health is read from the gateway's own view, never probed. Feasibility is evaluated per
request and is not part of the monotone lineage state: a healthy rung that was unhealthy an hour
ago is feasible again, but the request that cannot be served now is what triggers escalation
(unpinned) or a block (pinned).
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx
import structlog

from adrl.config.models import RungsConfig
from adrl.core.enums import Rung
from adrl.core.ports import Tokenizer
from adrl.core.types import PermittedSet
from adrl.gates.content import total_text

log = structlog.get_logger(__name__)

CHARS_PER_TOKEN_FALLBACK = 4


class CharRatioTokenizer:
    """Fallback estimate when no tokenizer.json is configured. Clearly labelled as such."""

    def __init__(self, chars_per_token: int = CHARS_PER_TOKEN_FALLBACK) -> None:
        self._cpt = chars_per_token

    @property
    def tokenizer_id(self) -> str:
        return f"chars-per-token-{self._cpt}"

    def count(self, text: str) -> int:
        return max(1, len(text) // self._cpt) if text else 0


class HfTokenizer:
    """HF `tokenizers` adapter over a tokenizer.json file (the local model's tokenizer)."""

    def __init__(self, path: Path, tokenizer_id: str | None = None) -> None:
        from tokenizers import Tokenizer as _Tokenizer

        self._impl = _Tokenizer.from_file(str(path))
        self._id = tokenizer_id or path.stem

    @property
    def tokenizer_id(self) -> str:
        return self._id

    def count(self, text: str) -> int:
        if not text:
            return 0
        return len(self._impl.encode(text, add_special_tokens=False).ids)


def tokenizer_for_rung(spec_tokenizer_id: str | None, tokenizer_path: Path | None) -> Tokenizer:
    if tokenizer_path is not None and tokenizer_path.exists():
        return HfTokenizer(tokenizer_path, spec_tokenizer_id)
    return CharRatioTokenizer()


@runtime_checkable
class GatewayHealth(Protocol):
    """Gateway-owned health view (ADRL-FND-002). None means unknown."""

    async def is_healthy(self, model_group: str) -> bool | None: ...


class StaticHealth:
    def __init__(self, healthy: Mapping[str, bool] | None = None) -> None:
        self._healthy = dict(healthy or {})

    def set(self, model_group: str, healthy: bool) -> None:
        self._healthy[model_group] = healthy

    async def is_healthy(self, model_group: str) -> bool | None:
        return self._healthy.get(model_group)


class LiteLLMHealth:
    """Reads LiteLLM `/health` (healthy_endpoints / unhealthy_endpoints) with a short cache."""

    def __init__(self, client: httpx.AsyncClient, *, ttl_s: float = 5.0) -> None:
        self._client = client
        self._ttl = ttl_s
        self._cache: dict[str, bool] = {}
        self._fetched_at = 0.0

    async def _refresh(self) -> None:
        if time.monotonic() - self._fetched_at < self._ttl:
            return
        try:
            response = await self._client.get("/health", timeout=2.0)
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("gateway_health_unavailable", error=type(exc).__name__)
            self._fetched_at = time.monotonic()
            return
        healthy: dict[str, bool] = {}
        for entry in data.get("healthy_endpoints", []):
            for key in ("model", "model_name", "litellm_model_name"):
                name = entry.get(key) if isinstance(entry, Mapping) else None
                if isinstance(name, str):
                    healthy[name] = True
        for entry in data.get("unhealthy_endpoints", []):
            for key in ("model", "model_name", "litellm_model_name"):
                name = entry.get(key) if isinstance(entry, Mapping) else None
                if isinstance(name, str):
                    healthy[name] = False
        self._cache = healthy
        self._fetched_at = time.monotonic()

    async def is_healthy(self, model_group: str) -> bool | None:
        await self._refresh()
        return self._cache.get(model_group)


@dataclass(frozen=True, slots=True)
class FeasibilityVerdict:
    permitted_after: PermittedSet
    removed: Mapping[Rung, str]
    input_estimate: int
    estimates_by_rung: Mapping[Rung, int]
    thinking_budget: int
    max_tokens: int


class FeasibilityFilter:
    def __init__(
        self,
        rungs: RungsConfig,
        tokenizers: Mapping[Rung, Tokenizer],
        health: GatewayHealth,
        *,
        safety_margin_tokens: int = 4_000,
    ) -> None:
        self._rungs = rungs
        self._tokenizers = tokenizers
        self._health = health
        self._margin = safety_margin_tokens

    def tokenizer(self, rung: Rung) -> Tokenizer:
        return self._tokenizers.get(rung) or CharRatioTokenizer()

    @staticmethod
    def thinking_budget(body: Mapping[str, Any]) -> int:
        thinking = body.get("thinking")
        if isinstance(thinking, Mapping):
            budget = thinking.get("budget_tokens")
            if isinstance(budget, int):
                return budget
        return 0

    def estimate_for(self, rung: Rung, text: str) -> int:
        spec = self._rungs.rungs[rung]
        return int(self.tokenizer(rung).count(text) * spec.tokenizer_ratio + 0.999)

    def fits(self, rung: Rung, input_estimate: int, max_tokens: int, thinking: int) -> bool:
        spec = self._rungs.rungs[rung]
        return (
            input_estimate + max_tokens + thinking <= spec.boundary.context_ceiling - self._margin
        )

    async def rung_healthy(self, rung: Rung) -> bool:
        """A rung is healthy when the gateway reports any member healthy, or reports nothing."""
        spec = self._rungs.rungs[rung]
        seen_any = False
        for member in spec.members:
            state = await self._health.is_healthy(member)
            if state is True:
                return True
            if state is False:
                seen_any = True
        return not seen_any

    async def evaluate(
        self, body: Mapping[str, Any], permitted: PermittedSet
    ) -> FeasibilityVerdict:
        text = total_text(body)
        raw_max = body.get("max_tokens")
        max_tokens = int(raw_max) if isinstance(raw_max, int) else 0
        thinking = self.thinking_budget(body)
        removed: dict[Rung, str] = {}
        estimates: dict[Rung, int] = {}
        keep: list[Rung] = []
        for rung in permitted:
            spec = self._rungs.rungs.get(rung)
            if spec is None or not spec.enabled:
                removed[rung] = "disabled"
                continue
            estimate = self.estimate_for(rung, text)
            estimates[rung] = estimate
            if not self.fits(rung, estimate, max_tokens, thinking):
                removed[rung] = "context_infeasible"
                continue
            if not await self.rung_healthy(rung):
                removed[rung] = "unhealthy"
                continue
            keep.append(rung)
        base_estimate = estimates.get(Rung.LOCAL) or (estimates and min(estimates.values())) or 0
        return FeasibilityVerdict(
            permitted_after=permitted.tighten(keep),
            removed=removed,
            input_estimate=int(base_estimate),
            estimates_by_rung=estimates,
            thinking_budget=thinking,
            max_tokens=max_tokens,
        )

    async def infeasible_now(self, rung: Rung) -> bool:
        """Health-only view for a sticky route; never used to re-decide a healthy route."""
        return not await self.rung_healthy(rung)

    def estimate_count_tokens(self, body: Mapping[str, Any]) -> dict[str, int]:
        """Local estimate in the Anthropic count_tokens response shape (pinned passthrough)."""
        text = total_text(body)
        return {"input_tokens": self.estimate_for(Rung.LOCAL, text)}
