"""Pydantic models for every versioned config file. Primary: ADRL-FND-002.

Secondary: ADRL-RTG-001/002/003/004/005/009, ADRL-CAS-001/004, ADRL-SAF-008, ADRL-LRN-004/005,
ADRL-SEM-004, ADRL-MEM-002/010.
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from adrl.core.enums import Rung


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# rungs.yaml (rung-membership-v1) ---------------------------------------------------------


class RungBoundary(StrictModel):
    context_ceiling: int = Field(gt=0)
    permitted_task_classes: tuple[str, ...]
    evidence_ref: str | None = None
    evidence_date: date | None = None


class RungSpec(StrictModel):
    members: tuple[str, ...] = Field(min_length=1, description="LiteLLM model group names")
    boundary: RungBoundary
    tokenizer_ratio: float = Field(default=1.0, gt=0)
    tokenizer_id: str | None = None
    enabled: bool = True
    intra_rung_escalation_order: tuple[str, ...] = ()
    family: str | None = Field(
        default=None,
        description="Provider family for CAS-004 pair rules; defaults to local or anthropic",
    )


class FallbackGroup(StrictModel):
    primary: str
    fallbacks: tuple[str, ...]


class RungsConfig(StrictModel):
    version: Literal["rung-membership-v1"]
    rungs: dict[Rung, RungSpec]
    fallback_groups: tuple[FallbackGroup, ...] = ()
    frontier_model_names: tuple[str, ...] = Field(
        default=(), description="Harness model names that the gateway maps into the frontier rung"
    )
    cheap_cloud_admission_criterion: str
    compaction_window_tokens: int = 100_000
    compaction_overhead_tokens: int = 8_000
    gateway_served_model_header: str = "x-litellm-model-id"

    @property
    def group_to_rung(self) -> dict[str, Rung]:
        mapping: dict[str, Rung] = {}
        for rung, spec in self.rungs.items():
            for member in spec.members:
                mapping[member] = rung
        return mapping

    def alias_for(self, rung: Rung) -> str:
        return self.rungs[rung].members[0]


# policy.yaml ----------------------------------------------------------------------------


class Band(StrictModel):
    band_id: str
    rung: Rung | None = Field(default=None, description="None means the ambiguous band")
    rule_ids: tuple[str, ...] = ()
    description: str = ""


class ObjectiveWeights(StrictModel):
    verified_quality: float
    retry_risk: float
    latency: float
    session_cost: float


class CloseRule(StrictModel):
    rule_id: Literal["close-v1"] = "close-v1"
    subsequent_turns: int = 3
    idle_minutes: int = 30


class AttemptBudget(StrictModel):
    unit: Literal["tool_calls", "wall_clock_s", "tokens"] = "tool_calls"
    limit: int = 12
    wall_clock_cap_s: int = 600


class RetryBudget(StrictModel):
    max_attempts_per_turn: int = 2
    wall_clock_cap_s: int = 30


class PolicyConfig(StrictModel):
    version: str
    tau_by_rung: dict[Rung, float]
    bands: tuple[Band, ...]
    rule_precision_threshold: float = 0.85
    ambiguous_fallback_rung: Rung = Rung.FRONTIER
    classifier_timeout_s: float = 2.0
    classifier_token_cap: int = 2_000
    objective_version: str
    objective_weights: ObjectiveWeights
    close_rule: CloseRule = CloseRule()
    local_attempt_budget: AttemptBudget = AttemptBudget()
    cascade_safety_margin_tokens: int = 4_000
    gateway_retry_budget: RetryBudget = RetryBudget()
    retention_prompt_class_days: int = 90
    retention_skeleton_days: int = 730
    exploration_epsilon_by_rung: dict[Rung, float] = Field(default_factory=dict)
    exploration_version: str | None = None
    latency_weight_by_mode: dict[str, float] = Field(
        default_factory=lambda: {"interactive": 1.0, "background_subagent": 0.05, "utility": 0.2}
    )
    episode_length_estimator: str = "constant-v1"
    episode_length_constant: int = 12
    rule_thresholds: dict[str, float] = Field(
        default_factory=lambda: {
            "large_context_tokens": 20_000.0,
            "small_context_tokens": 8_000.0,
            "small_diff_max_files": 2.0,
            "multi_file_min_files": 4.0,
        },
        description="Thresholds the band rules read (ADRL-RTG-003); versioned with the policy",
    )
    estimator_params: dict[str, float] = Field(
        default_factory=lambda: {
            "frontier_base": 0.95,
            "frontier_slope": 0.10,
            "cheap_cloud_base": 0.90,
            "cheap_cloud_slope": 0.60,
            "local_base": 0.85,
            "local_slope": 0.90,
            "clear_band_floor": 0.85,
            "clear_frontier_local_cap": 0.30,
            "clear_frontier_cheap_cap": 0.50,
            "classifier_confidence_floor": 0.60,
        },
        description="Coefficients of the band-heuristic-v1 estimator (ADRL-RTG-002)",
    )
    classifier_prompt_version: str = "classifier-prompt-v1"
    expected_output_tokens_by_mode: dict[str, int] = Field(
        default_factory=lambda: {"interactive": 2_000, "background_subagent": 2_000, "utility": 64}
    )

    @model_validator(mode="after")
    def _epsilon_bounds(self) -> PolicyConfig:
        for rung, eps in self.exploration_epsilon_by_rung.items():
            if not 0.0 <= eps <= 0.10:
                raise ValueError(f"exploration epsilon for {rung.value} must be within [0, 0.10]")
        return self


# prices.yaml ----------------------------------------------------------------------------


class PriceVector(StrictModel):
    """USD per million tokens; local carries a non-zero latency-equivalent cost (ADRL-RTG-009)."""

    input: float = Field(ge=0)
    output: float = Field(ge=0)
    cache_write_multiplier: float = Field(default=1.25, ge=0)
    cache_read_multiplier: float = Field(default=0.10, ge=0)
    cache_ttl_s: int = Field(default=300, ge=0)


class PricesConfig(StrictModel):
    version: str
    by_rung: dict[Rung, PriceVector]
    label: Literal["after_cache_effects", "list_price"] = "after_cache_effects"


# provider-pairs.yaml --------------------------------------------------------------------


class ProviderPairRule(StrictModel):
    source_family: str
    target_family: str
    thinking_enabled: bool
    action: Literal["keep_latest_thinking", "strip_and_disable", "disable_thinking_for_handoff"]
    map_tool_ids: bool = False
    note: str = ""
    source_has_thinking: bool | None = None
    """None matches any source turn; False matches a source turn with no thinking blocks."""


class ProviderPairsConfig(StrictModel):
    version: str
    litellm_version_pin: str
    rules: tuple[ProviderPairRule, ...]
    default_action: Literal["strip_and_disable"] = "strip_and_disable"

    def rule_for(
        self,
        source_family: str,
        target_family: str,
        thinking_enabled: bool,
        *,
        source_has_thinking: bool | None = None,
    ) -> ProviderPairRule:
        """Exact match on source_has_thinking wins over a rule that matches any source."""
        general: ProviderPairRule | None = None
        for rule in self.rules:
            if not (
                rule.source_family == source_family
                and rule.target_family == target_family
                and rule.thinking_enabled == thinking_enabled
            ):
                continue
            if rule.source_has_thinking is None:
                general = general or rule
            elif (
                source_has_thinking is not None and rule.source_has_thinking == source_has_thinking
            ):
                return rule
        if general is not None:
            return general
        return ProviderPairRule(
            source_family=source_family,
            target_family=target_family,
            thinking_enabled=thinking_enabled,
            action=self.default_action,
            note="unknown pair; default",
        )


# tripwires.yaml -------------------------------------------------------------------------


class WireThresholds(StrictModel):
    repeated_tool_calls: int = 3
    invalid_tool_calls: int = 2
    tool_error_repeats: int = 3
    attempt_budget_exhausted: bool = True
    verifier_failure: bool = True
    long_running_allowance: int = 2


class TripwiresConfig(StrictModel):
    version: str
    tuning_run_id: str | None = None
    by_rung: dict[Rung, WireThresholds]


# repo-classification-v1.json ------------------------------------------------------------


class RepoClass(StrictModel):
    class_id: str
    allowed_rungs: tuple[Rung, ...] = Field(
        default=(Rung.LOCAL, Rung.CHEAP_CLOUD, Rung.FRONTIER),
        description="Rung ceiling; a residency class may omit it and constrain by geo instead",
    )
    residency: str | None = None
    release_permitted: bool = True
    restricted: bool = False


class RepoEntry(StrictModel):
    repo_id: str
    match: str = Field(description="git remote URL prefix or absolute path prefix")
    class_id: str
    restricted_path_prefixes: tuple[str, ...] = ()


class RepoClassificationManifest(StrictModel):
    version: Literal["repo-classification-v1"]
    default_class_id: str
    classes: tuple[RepoClass, ...]
    repos: tuple[RepoEntry, ...]
    owner: str
    unknown_identity_policy: Literal["local_only", "default_class"] = Field(
        default="local_only",
        description="What a lineage without a verified workload assertion may use: "
        "local_only (ADRL-SAF-008 as amended) or the default class (dev opt-out)",
    )

    def class_by_id(self, class_id: str) -> RepoClass:
        for cls in self.classes:
            if cls.class_id == class_id:
                return cls
        raise KeyError(class_id)


# learning-contract-v1.json --------------------------------------------------------------


class FeatureSpec(StrictModel):
    name: str
    dtype: Literal["int", "float", "bool", "str", "vector"]
    source: str


class LearningContract(StrictModel):
    version: str
    feature_schema_version: str
    features: tuple[FeatureSpec, ...]
    deny_list: tuple[str, ...]
    forbidden_targets: tuple[str, ...]
    failure_types_version: str
    tier_rules: dict[str, str]
    verifier_precision_threshold: float = 0.9
    target_risk: float = 0.05


# utility-fingerprints.yaml --------------------------------------------------------------


class UtilityFingerprint(StrictModel):
    fingerprint_id: str
    kind: Literal["cosmetic", "context_bearing"]
    system_prefix_contains: tuple[str, ...] = ()
    user_prefix_contains: tuple[str, ...] = ()
    max_tokens_at_most: int | None = None
    requires_no_tools: bool = True


class UtilityFingerprintsConfig(StrictModel):
    version: str
    fingerprints: tuple[UtilityFingerprint, ...]
    pre_warm_max_tokens: int = 1
    subagent_system_contains: tuple[str, ...] = Field(
        default=(),
        description="Body-fingerprint fallback for subagent lineage; empty until measured",
    )


# endpoint-inventory-v1.json (ADRL-SAF-008 residency, ADRL-FND-002, ADRL-RTG-008) -------------

TrustZone = Literal["local_host", "private_cloud", "public_cloud"]
TRUST_ZONE_ORDER: dict[str, int] = {"local_host": 0, "private_cloud": 1, "public_cloud": 2}


class Deployment(StrictModel):
    """One attested gateway deployment. ADRL policy constrains these, never bare rung labels."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    model_group: str = Field(description="LiteLLM model group (rung member in rungs.yaml)")
    rung: Rung
    provider: str
    model: str = Field(description="provider/model as LiteLLM names it")
    api_base: str | None = None
    api_key_env: str | None = None
    trust_zone: TrustZone
    geo: str
    data_use_profile: str = "no_training_no_retention"
    attested_by: str
    max_input_tokens: int | None = None

    @property
    def api_base_host(self) -> str | None:
        if self.api_base is None:
            return None
        from urllib.parse import urlsplit

        parts = urlsplit(self.api_base)
        if parts.scheme in ("unix", "http+unix"):
            return "unix"
        if parts.hostname is None:
            return None
        return f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname

    @property
    def is_loopback(self) -> bool:
        if self.api_base is None:
            return False
        from urllib.parse import urlsplit

        parts = urlsplit(self.api_base)
        if parts.scheme in ("unix", "http+unix"):
            return True
        host = parts.hostname
        if host is None:
            return False
        import ipaddress

        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False


class EndpointInventory(StrictModel):
    version: Literal["endpoint-inventory-v1"]
    owner: str
    deployments: tuple[Deployment, ...] = Field(min_length=1)
    frontier_aliases_to: str | None = None
    pinned_alias: str | None = None

    @model_validator(mode="after")
    def _unique_ids(self) -> EndpointInventory:
        ids = [d.id for d in self.deployments]
        if len(ids) != len(set(ids)):
            raise ValueError("deployment ids must be unique")
        return self

    def by_id(self, deployment_id: str) -> Deployment:
        for d in self.deployments:
            if d.id == deployment_id:
                return d
        raise KeyError(deployment_id)

    def for_rung(self, rung: Rung) -> tuple[Deployment, ...]:
        return tuple(d for d in self.deployments if d.rung is rung)

    def for_group(self, group: str) -> tuple[Deployment, ...]:
        return tuple(d for d in self.deployments if d.model_group == group)

    def by_host(self, host: str) -> Deployment | None:
        for d in self.deployments:
            if d.api_base_host is not None and d.api_base_host == host:
                return d
        return None

    def geos(self) -> frozenset[str]:
        return frozenset(d.geo for d in self.deployments)
