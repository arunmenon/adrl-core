"""ADRL-LRN-005 and ADRL-LRN-007 manifests, graduation and fail-closed loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adrl.learning.artifacts import (
    ArtifactManifest,
    ArtifactRefusedError,
    PolicyCompatibility,
    compatibility_from_bundle,
    load_graduated,
    save_model,
    sign_graduation,
    write_manifest,
)


def _manifest(bundle, **overrides: object) -> ArtifactManifest:  # type: ignore[no-untyped-def]
    base = dict(
        artifact_id="cate",
        artifact_kind="estimator",
        artifact_version="v1",
        feature_schema_version=bundle.learning_contract.feature_schema_version,
        data_snapshot="snap",
        objective="cate:verified_outcome",
        calibration={"method": "isotonic"},
        thresholds={"target_risk": 0.05},
        policy_compatibility=compatibility_from_bundle(bundle),
        training_code_commit="abc",
        seed=0,
        embedding_model_version=None,
        ledger_high_water_mark=0,
        tier_mix={"T1": 10},
        deny_list_version=bundle.learning_contract.version,
    )
    base.update(overrides)
    return ArtifactManifest(**base)  # type: ignore[arg-type]


@pytest.fixture
def keys() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, pem


def test_artifact_without_graduation_is_refused(bundle, keys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "manifest.json"
    write_manifest(_manifest(bundle), path)
    with pytest.raises(ArtifactRefusedError, match="no_graduation_record"):
        load_graduated(path, bundle, keys[1])


def test_graduated_compatible_artifact_loads(bundle, keys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    sha = save_model({"weights": [1, 2, 3]}, tmp_path / "model.pkl")
    manifest = sign_graduation(
        _manifest(bundle, model_file="model.pkl", model_sha256=sha),
        keys[0],
        evaluation_report_hash="deadbeef",
        approved_by="evl-owner",
        approved_at="2026-09-02T00:00:00Z",
        key_id="test",
    )
    path = tmp_path / "manifest.json"
    write_manifest(manifest, path)
    loaded = load_graduated(path, bundle, keys[1])
    assert loaded.model == {"weights": [1, 2, 3]}


def test_policy_mismatch_fails_closed(bundle, keys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    stale = tuple(
        PolicyCompatibility(policy_id=p.policy_id, version="stale-v0")
        if p.policy_id == "policy"
        else p
        for p in compatibility_from_bundle(bundle)
    )
    manifest = sign_graduation(
        _manifest(bundle, policy_compatibility=stale),
        keys[0],
        evaluation_report_hash="x",
        approved_by="a",
        approved_at="t",
        key_id="k",
    )
    path = tmp_path / "manifest.json"
    write_manifest(manifest, path)
    with pytest.raises(ArtifactRefusedError, match="policy_incompatible"):
        load_graduated(path, bundle, keys[1])


def test_tampered_manifest_or_wrong_key_is_refused(bundle, keys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    manifest = sign_graduation(
        _manifest(bundle),
        keys[0],
        evaluation_report_hash="x",
        approved_by="a",
        approved_at="t",
        key_id="k",
    )
    tampered = manifest.model_copy(update={"thresholds": {"target_risk": 0.5}})
    path = tmp_path / "manifest.json"
    write_manifest(tampered, path)
    with pytest.raises(ArtifactRefusedError, match="graduation_signature_invalid"):
        load_graduated(path, bundle, keys[1])
    write_manifest(manifest, path)
    other = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(ArtifactRefusedError, match="graduation_signature_invalid"):
        load_graduated(path, bundle, other)


def test_forbidden_target_in_manifest_is_refused(bundle, keys, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    manifest = sign_graduation(
        _manifest(bundle, target_columns=("served_rung",)),
        keys[0],
        evaluation_report_hash="x",
        approved_by="a",
        approved_at="t",
        key_id="k",
    )
    path = tmp_path / "manifest.json"
    write_manifest(manifest, path)
    with pytest.raises(ArtifactRefusedError, match="forbidden_target"):
        load_graduated(path, bundle, keys[1])
