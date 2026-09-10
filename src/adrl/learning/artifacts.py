"""Artifact manifests, graduation records and fail-closed loading. Primary: ADRL-LRN-005.
Also implements: ADRL-EVL-006, ADRL-EVL-007 (register additions of 2026-09-03).

Secondary: ADRL-LRN-007 (no autonomous promotion), ADRL-LRN-001 (tier mix), ADRL-LRN-004
(deny-list version), ADRL-MEM-004 (failure-type enum version), EVL-006/007 (graduation).

An artifact is loadable only when its manifest carries a graduation record whose signature
verifies and whose policy-compatibility set matches the running configuration. Any mismatch
fails closed to the deterministic policy and is counted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pickle
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from prometheus_client import Counter
from pydantic import BaseModel, ConfigDict, Field

from adrl.config.loaders import ConfigBundle, canonical_json
from adrl.core.enums import FAILURE_TYPES_VERSION
from adrl.telemetry.metrics import REGISTRY

MANIFEST_VERSION = "artifact-manifest-v2"
log = structlog.get_logger("adrl.learning.artifacts")

ARTIFACT_REFUSED_TOTAL = Counter(
    "adrl_artifact_refused_total",
    "Learned artifacts refused at load time by reason",
    ["reason"],
    registry=REGISTRY,
)


class ArtifactRefusedError(RuntimeError):
    """The artifact may not be loaded; the deterministic policy stays in charge."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class PolicyCompatibility(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str
    version: str


class GraduationRecord(BaseModel):
    """Signed by EVL-007; absence means the artifact is a proposal, not a deployment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evaluation_report_hash: str
    approved_by: str
    approved_at: str
    key_id: str
    signature_b64: str


class ArtifactManifest(BaseModel):
    """Manifest v2 (ADRL-LRN-005 follow-up)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_version: str = MANIFEST_VERSION
    artifact_id: str
    artifact_kind: str = Field(description="estimator | abstention | exploration")
    artifact_version: str
    feature_schema_version: str
    data_snapshot: str = Field(description="content hash or ledger snapshot id")
    objective: str
    calibration: Mapping[str, Any]
    thresholds: Mapping[str, float]
    policy_compatibility: tuple[PolicyCompatibility, ...]
    training_code_commit: str
    seed: int
    embedding_model_version: str | None
    ledger_high_water_mark: int
    tier_mix: Mapping[str, int]
    deny_list_version: str
    failure_types_version: str = FAILURE_TYPES_VERSION
    target_columns: tuple[str, ...] = ()
    model_file: str | None = None
    model_sha256: str | None = None
    graduation: GraduationRecord | None = None

    def signing_payload(self) -> bytes:
        data = self.model_dump(mode="json")
        data.pop("graduation", None)
        return canonical_json(data)


def compatibility_from_bundle(bundle: ConfigBundle) -> tuple[PolicyCompatibility, ...]:
    pairs = [
        PolicyCompatibility(policy_id=k, version=v) for k, v in sorted(bundle.versions.items())
    ]
    pairs.append(PolicyCompatibility(policy_id="failure_types", version=FAILURE_TYPES_VERSION))
    return tuple(pairs)


def sign_graduation(
    manifest: ArtifactManifest,
    private_key: Ed25519PrivateKey,
    *,
    evaluation_report_hash: str,
    approved_by: str,
    approved_at: str,
    key_id: str,
) -> ArtifactManifest:
    """Attach a graduation record. This is a human action (EVL-007), never automated."""
    payload = manifest.signing_payload() + evaluation_report_hash.encode()
    signature = base64.b64encode(private_key.sign(payload)).decode()
    record = GraduationRecord(
        evaluation_report_hash=evaluation_report_hash,
        approved_by=approved_by,
        approved_at=approved_at,
        key_id=key_id,
        signature_b64=signature,
    )
    return manifest.model_copy(update={"graduation": record})


def verify_graduation(manifest: ArtifactManifest, public_key: Ed25519PublicKey) -> None:
    if manifest.graduation is None:
        raise ArtifactRefusedError("no_graduation_record", manifest.artifact_id)
    record = manifest.graduation
    payload = manifest.signing_payload() + record.evaluation_report_hash.encode()
    try:
        public_key.verify(base64.b64decode(record.signature_b64), payload)
    except (InvalidSignature, ValueError) as exc:
        raise ArtifactRefusedError("graduation_signature_invalid", manifest.artifact_id) from exc


def check_policy_compatibility(manifest: ArtifactManifest, bundle: ConfigBundle) -> None:
    expected = {p.policy_id: p.version for p in compatibility_from_bundle(bundle)}
    declared = {p.policy_id: p.version for p in manifest.policy_compatibility}
    mismatched = sorted(
        pid for pid, version in declared.items() if expected.get(pid) not in (None, version)
    )
    missing = sorted(pid for pid in expected if pid not in declared)
    if mismatched or missing:
        raise ArtifactRefusedError(
            "policy_incompatible",
            f"{manifest.artifact_id}: mismatched={mismatched} missing={missing}",
        )
    if manifest.feature_schema_version != bundle.learning_contract.feature_schema_version:
        raise ArtifactRefusedError("feature_schema_mismatch", manifest.artifact_id)
    if manifest.failure_types_version != FAILURE_TYPES_VERSION:
        raise ArtifactRefusedError("failure_types_mismatch", manifest.artifact_id)
    forbidden = [
        c for c in manifest.target_columns if c in bundle.learning_contract.forbidden_targets
    ]
    if forbidden:
        raise ArtifactRefusedError("forbidden_target", ",".join(forbidden))


def write_manifest(manifest: ArtifactManifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True))


def read_manifest(path: Path) -> ArtifactManifest:
    return ArtifactManifest.model_validate(json.loads(path.read_text()))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_model(obj: Any, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL))
    return sha256_file(path)


@dataclass(frozen=True, slots=True)
class LoadedArtifact:
    manifest: ArtifactManifest
    model: Any | None


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ArtifactRefusedError("graduation_key_invalid", "graduation key must be Ed25519")
    return key


def load_graduated(
    manifest_path: Path, bundle: ConfigBundle, public_key_pem: bytes
) -> LoadedArtifact:
    """Load only a graduated, compatible artifact; refuse everything else (ADRL-LRN-007)."""
    try:
        manifest = read_manifest(manifest_path)
        verify_graduation(manifest, load_public_key(public_key_pem))
        check_policy_compatibility(manifest, bundle)
        model: Any | None = None
        if manifest.model_file is not None:
            model_path = manifest_path.parent / manifest.model_file
            if manifest.model_sha256 is None or sha256_file(model_path) != manifest.model_sha256:
                raise ArtifactRefusedError("model_hash_mismatch", manifest.artifact_id)
            model = pickle.loads(model_path.read_bytes())  # noqa: S301  hash verified above
    except ArtifactRefusedError as exc:
        ARTIFACT_REFUSED_TOTAL.labels(reason=exc.reason).inc()
        log.warning("artifact_refused", reason=exc.reason, detail=exc.detail)
        raise
    log.info("artifact_loaded", artifact_id=manifest.artifact_id, version=manifest.artifact_version)
    return LoadedArtifact(manifest, model)


def manifests_under(root: Path) -> Sequence[Path]:
    return sorted(root.rglob("manifest.json")) if root.exists() else []
