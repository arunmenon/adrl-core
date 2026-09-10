"""Process settings from environment. Primary: ADRL-OPS-001 (referenced by gloss)."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from adrl.core.enums import GateMode, RoutingMode


class Settings(BaseSettings):
    """Runtime settings; environment variables carry the ADRL_ prefix."""

    model_config = SettingsConfigDict(env_prefix="ADRL_", env_file=None, extra="ignore")

    listen_host: str = "127.0.0.1"
    listen_port: int = 8788
    gateway_base_url: str = "http://127.0.0.1:4000"
    gateway_timeout_s: float = 600.0

    config_dir: Path = Path("config")
    data_dir: Path = Path("data")
    ledger_path: Path = Path("data/adrl.db")
    egress_ledger_path: Path = Path("data/egress.db")
    keystore_path: Path = Path("data/keystore")

    gate_mode: GateMode = GateMode.ENFORCE
    routing_mode: RoutingMode = RoutingMode.SHADOW
    fallback_mode: RoutingMode = RoutingMode.SHADOW

    deployment_tag: str = "dev-local"
    deployment_geo: str = "local"
    hmac_key_id: str = Field(default="dev", description="Identifier of the active HMAC key")
    require_signed_manifest: bool = True
    require_signed_inventory: bool = True
    residency_unreachable_is_error: bool = Field(
        default=True,
        description="Fail config load when a residency class in use has no in-geo deployment; "
        "when false the runtime backstop (local or block) applies (ADRL-SAF-008)",
    )
    egress_checkpoint_every: int = 500
    egress_checkpoint_interval_s: float = Field(
        default=300.0, description="Time-based checkpoint cadence for the egress ledger"
    )
    checkpoint_signing_key_path: Path | None = Field(
        default=None,
        description="Ed25519 private key that signs egress checkpoints (ADRL-SAF-009); "
        "distinct from the manifest-signing key",
    )
    checkpoint_public_key_path: Path | None = Field(
        default=None, description="Public half of the checkpoint key, for verifiers"
    )
    dev_keys_allowed: bool = Field(
        default=False,
        description="Permit keys under a 'dev' path; never set outside a developer machine",
    )
    egress_anchor_path: Path | None = Field(
        default=None, description="Append-only anchor file on an off-device mount"
    )
    egress_anchor_url: str | None = Field(
        default=None, description="HTTP anchoring endpoint that acknowledges checkpoints"
    )
    ledger_busy_timeout_ms: int = 5000

    fail_open_alert_threshold: float = 0.05

    classifier_base_url: str | None = Field(
        default=None, description="OpenAI-compatible endpoint for the advisory classifier"
    )
    classifier_model: str = "qwen2.5:3b-instruct"
    classifier_is_local: bool = True

    gateway_health_enabled: bool = Field(
        default=True, description="Read rung health from the gateway /health view (ADRL-SAF-006)"
    )
    local_tokenizer_path: Path | None = Field(
        default=None, description="tokenizer.json of the local rung; chars/4 fallback when absent"
    )
    gate_p99_budget_s: float = Field(
        default=0.05, description="Gate latency budget on continuations (ADRL-SAF-003)"
    )
    exploration_artifact_path: Path | None = Field(
        default=None,
        description="manifest.json of a graduated exploration artifact (ADRL-LRN-008); "
        "absent means no exploration",
    )

    def resolved_config_path(self, name: str) -> Path:
        return self.config_dir / name
