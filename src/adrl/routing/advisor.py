"""Advisory LLM classifier and the exploration port. Primary: ADRL-RTG-006.

Secondary: ADRL-LRN-008 (Explorer port, implemented by the learning package and injected by
the composition root; this package never imports adrl.learning). The classifier runs only on
ambiguous-band turns, after the gates, never widens the permitted set, and on a pinned
lineage runs locally or is skipped.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from adrl.core.enums import Rung
from adrl.core.types import PermittedSet, RequestContext

CLASSIFIER_LABELS: tuple[str, ...] = tuple(r.value for r in Rung.ordered())
CLASSIFIER_TIMEOUT_OUTCOME = "classifier_timeout"

PROMPT_TEMPLATE = (
    "You are a routing advisor for a coding agent. Given a compact description of one developer "
    'turn, answer with a single JSON object {"rung": <one of local|cheap_cloud|frontier>, '
    '"confidence": <0..1>}. local = a small local model can complete it; cheap_cloud = a small '
    "cloud model; frontier = the strongest model is needed.\n"
    "Turn features: {features}\n"
    "Permitted rungs: {permitted}\n"
    "Answer with JSON only."
)


@dataclass(frozen=True, slots=True)
class ClassifierResult:
    label: Rung | None
    confidence: float
    raw: str
    model_id: str
    prompt_version: str
    prompt_hash: str
    timed_out: bool
    malformed: bool
    tokens_used: int
    latency_s: float

    def as_provenance(self) -> dict[str, Any]:
        return {
            "classifier_model_id": self.model_id,
            "prompt_version": self.prompt_version,
            "prompt_hash": self.prompt_hash,
            "raw_label": self.label.value if self.label else None,
            "confidence": self.confidence,
            "timed_out": self.timed_out,
            "malformed": self.malformed,
            "tokens_used": self.tokens_used,
            "latency_s": round(self.latency_s, 4),
            "outcome": CLASSIFIER_TIMEOUT_OUTCOME if (self.timed_out or self.malformed) else "ok",
        }


class AdvisoryClassifier(Protocol):
    async def classify(
        self, ctx: RequestContext, features: Mapping[str, Any], permitted: PermittedSet
    ) -> ClassifierResult: ...

    @property
    def model_id(self) -> str: ...

    @property
    def is_local(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class ExplorationChoice:
    rung: Rung
    propensity: float
    explore_version: str


class Explorer(Protocol):
    """Logged exploration in the ambiguous band (ADRL-LRN-008); implemented by adrl.learning."""

    def explore(
        self,
        ctx: RequestContext,
        features: Mapping[str, Any],
        band_id: str,
        permitted: PermittedSet,
        default: Rung,
    ) -> ExplorationChoice | None: ...

    @property
    def version(self) -> str: ...


def _features_for_prompt(features: Mapping[str, Any]) -> str:
    keys = (
        "verb_class",
        "scope_hint",
        "context_tokens_estimate",
        "files_mentioned",
        "recent_edit_failures",
        "recent_error_results",
        "prev_turn_interrupted",
        "task_classes",
        "expected_first_action_side_effect",
        "n_tools",
    )
    return json.dumps({k: features.get(k) for k in keys}, sort_keys=True)


def _parse(raw: str, permitted: PermittedSet) -> tuple[Rung | None, float, bool]:
    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        return None, 0.0, True
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None, 0.0, True
    label = data.get("rung")
    if label not in CLASSIFIER_LABELS:
        return None, 0.0, True
    rung = Rung(label)
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    if rung not in permitted:
        return rung, confidence, True
    return rung, confidence, False


class LocalHttpClassifier:
    """Calls an OpenAI-compatible chat endpoint under a versioned timeout and token cap."""

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout_s: float,
        token_cap: int,
        prompt_version: str,
        is_local: bool = True,
        client: httpx.AsyncClient | None = None,
        max_output_tokens: int = 64,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s
        self._token_cap = token_cap
        self._prompt_version = prompt_version
        self._is_local = is_local
        self._client = client
        self._max_output_tokens = max_output_tokens

    @property
    def model_id(self) -> str:
        return self._model

    @property
    def is_local(self) -> bool:
        return self._is_local

    def build_prompt(self, features: Mapping[str, Any], permitted: PermittedSet) -> str:
        return PROMPT_TEMPLATE.replace("{features}", _features_for_prompt(features)).replace(
            "{permitted}", ",".join(permitted.as_list())
        )

    async def classify(
        self, ctx: RequestContext, features: Mapping[str, Any], permitted: PermittedSet
    ) -> ClassifierResult:
        prompt = self.build_prompt(features, permitted)
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        prompt_tokens = len(prompt) // 4
        started = time.monotonic()
        if prompt_tokens + self._max_output_tokens > self._token_cap:
            return ClassifierResult(
                None,
                0.0,
                "",
                self._model,
                self._prompt_version,
                prompt_hash,
                True,
                False,
                prompt_tokens,
                0.0,
            )
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self._max_output_tokens,
            "temperature": 0,
        }
        raw = ""
        tokens_used = prompt_tokens
        timed_out = False
        try:
            client = self._client or httpx.AsyncClient(timeout=self._timeout_s)
            try:
                response = await client.post(
                    self._base_url + "/v1/chat/completions", json=payload, timeout=self._timeout_s
                )
                data = response.json()
                raw = str(data["choices"][0]["message"]["content"])
                usage = data.get("usage") or {}
                tokens_used = int(usage.get("total_tokens") or prompt_tokens)
            finally:
                if self._client is None:
                    await client.aclose()
        except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError):
            timed_out = True
        latency = time.monotonic() - started
        if timed_out or latency > self._timeout_s:
            return ClassifierResult(
                None,
                0.0,
                raw,
                self._model,
                self._prompt_version,
                prompt_hash,
                True,
                False,
                tokens_used,
                latency,
            )
        label, confidence, malformed = _parse(raw, permitted)
        return ClassifierResult(
            label,
            confidence,
            raw,
            self._model,
            self._prompt_version,
            prompt_hash,
            False,
            malformed,
            tokens_used,
            latency,
        )
