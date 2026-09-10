"""Config file loaders and the signed-manifest check. Primary: ADRL-FND-002.

Secondary: ADRL-SAF-008.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from adrl.config.models import (
    EndpointInventory,
    LearningContract,
    PolicyConfig,
    PricesConfig,
    ProviderPairsConfig,
    RepoClassificationManifest,
    RungsConfig,
    TripwiresConfig,
    UtilityFingerprintsConfig,
)
from adrl.config.settings import Settings
from adrl.core.errors import ConfigError

MANIFEST_SIGNATURE_FILE = "repo-classification-v1.sig"
MANIFEST_PUBLIC_KEY_FILE = "keys/dev/manifest-signing.pub"
INVENTORY_FILE = "endpoint-inventory-v1.json"
INVENTORY_SIGNATURE_FILE = "endpoint-inventory-v1.sig"


@dataclass(frozen=True, slots=True)
class ConfigBundle:
    rungs: RungsConfig
    policy: PolicyConfig
    prices: PricesConfig
    provider_pairs: ProviderPairsConfig
    tripwires: TripwiresConfig
    repo_classification: RepoClassificationManifest
    learning_contract: LearningContract
    utility_fingerprints: UtilityFingerprintsConfig
    manifest_signature_verified: bool
    endpoint_inventory: EndpointInventory
    inventory_signature_verified: bool = False

    @property
    def versions(self) -> dict[str, str]:
        return {
            "rungs": self.rungs.version,
            "policy": self.policy.version,
            "prices": self.prices.version,
            "provider_pairs": self.provider_pairs.version,
            "tripwires": self.tripwires.version,
            "repo_classification": self.repo_classification.version,
            "learning_contract": self.learning_contract.version,
            "utility_fingerprints": self.utility_fingerprints.version,
            "endpoint_inventory": self.endpoint_inventory.version,
        }


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"missing config file {path}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at top level")
    return data


def _read_json_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise ConfigError(f"missing config file {path}") from exc


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_manifest_signature(
    manifest_bytes: bytes, signature_b64: str, public_key_pem: bytes, *, what: str = "manifest"
) -> None:
    public_key = _load_public_key(public_key_pem)
    payload = canonical_json(json.loads(manifest_bytes))
    try:
        public_key.verify(base64.b64decode(signature_b64), payload)
    except InvalidSignature as exc:
        raise ConfigError(f"{what} signature is invalid") from exc


def _verify_signed_file(
    base: Path, content: bytes, signature_file: str, *, required: bool, what: str
) -> bool:
    signature_path = base / signature_file
    key_path = base / MANIFEST_PUBLIC_KEY_FILE
    if signature_path.exists() and key_path.exists():
        verify_manifest_signature(
            content,
            signature_path.read_text(encoding="utf-8").strip(),
            key_path.read_bytes(),
            what=what,
        )
        return True
    if required:
        raise ConfigError(f"{what} must be signed; missing signature or public key")
    return False


def _load_public_key(pem: bytes) -> Ed25519PublicKey:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError("manifest signing key must be Ed25519")
    return key


def load_bundle(settings: Settings) -> ConfigBundle:
    base = settings.config_dir
    try:
        rungs = RungsConfig.model_validate(_read_yaml(base / "rungs.yaml"))
        policy = PolicyConfig.model_validate(_read_yaml(base / "policy.yaml"))
        prices = PricesConfig.model_validate(_read_yaml(base / "prices.yaml"))
        pairs = ProviderPairsConfig.model_validate(_read_yaml(base / "provider-pairs.yaml"))
        tripwires = TripwiresConfig.model_validate(_read_yaml(base / "tripwires.yaml"))
        fingerprints = UtilityFingerprintsConfig.model_validate(
            _read_yaml(base / "utility-fingerprints.yaml")
        )
        manifest_bytes = _read_json_bytes(base / "repo-classification-v1.json")
        manifest = RepoClassificationManifest.model_validate(json.loads(manifest_bytes))
        contract = LearningContract.model_validate(
            json.loads(_read_json_bytes(base / "learning-contract-v1.json"))
        )
        inventory_bytes = _read_json_bytes(base / INVENTORY_FILE)
        inventory = EndpointInventory.model_validate(json.loads(inventory_bytes))
    except ValidationError as exc:
        raise ConfigError(f"config validation failed: {exc}") from exc

    verified = _verify_signed_file(
        base,
        manifest_bytes,
        MANIFEST_SIGNATURE_FILE,
        required=settings.require_signed_manifest,
        what="repo classification manifest",
    )
    inventory_verified = _verify_signed_file(
        base,
        inventory_bytes,
        INVENTORY_SIGNATURE_FILE,
        required=settings.require_signed_inventory,
        what="endpoint inventory",
    )

    from adrl.config.checks import run_checks

    bundle = ConfigBundle(
        rungs=rungs,
        policy=policy,
        prices=prices,
        provider_pairs=pairs,
        tripwires=tripwires,
        repo_classification=manifest,
        learning_contract=contract,
        utility_fingerprints=fingerprints,
        manifest_signature_verified=verified,
        endpoint_inventory=inventory,
        inventory_signature_verified=inventory_verified,
    )
    run_checks(bundle, settings)
    return bundle
