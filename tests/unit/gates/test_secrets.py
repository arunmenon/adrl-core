"""Tiered secret scanner (ADRL-SAF-003)."""

from __future__ import annotations

import base64

from adrl.core.enums import DetectorTier
from adrl.core.ports import ContentBlock
from adrl.gates.secrets import TieredSecretScanner, shannon_entropy
from tests.unit.gates.conftest import AWS_KEY, FAKE_GITHUB


def _block(text: str, path: str | None = None, ctype: str = "tool_result") -> ContentBlock:
    return ContentBlock("b1", ctype, text, path)


def test_aws_key_is_high_confidence_and_pins(scanner: TieredSecretScanner) -> None:
    findings = scanner.scan([_block(f"config: {AWS_KEY}")])
    ids = {f.detector_id for f in findings if f.pins}
    assert "aws_access_key" in ids
    finding = next(f for f in findings if f.detector_id == "aws_access_key")
    assert finding.tier is DetectorTier.HIGH_CONFIDENCE
    assert AWS_KEY not in finding.span_hash and len(finding.span_hash) == 64


def test_private_key_header_pins(scanner: TieredSecretScanner) -> None:
    findings = scanner.scan([_block("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")])
    assert any(f.detector_id == "private_key_block" and f.pins for f in findings)


def test_github_token_pins(scanner: TieredSecretScanner) -> None:
    findings = scanner.scan([_block(f"token = {FAKE_GITHUB}")])
    assert any(f.detector_id == "github_token" and f.pins for f in findings)


def test_uncorroborated_high_entropy_is_shadow_only(scanner: TieredSecretScanner) -> None:
    value = "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4YWJjZGVm"
    findings = scanner.scan([_block(f"blob: {value}", path="/repo/README.md")])
    assert findings, "generic detector should still log a shadow finding"
    assert all(not f.pins for f in findings)


def test_generic_hit_with_sensitive_path_pins(scanner: TieredSecretScanner) -> None:
    findings = scanner.scan(
        [_block("DB_PASSWORD=Qz9v8b7N6m5L4k3J2h1G0fXyWvUt", path="/srv/app/.env")]
    )
    pinning = [f for f in findings if f.pins]
    assert pinning
    assert any(f.corroboration in {"sensitive_path", "credential_variable_name"} for f in pinning)


def test_placeholder_connection_string_is_ignored(scanner: TieredSecretScanner) -> None:
    findings = scanner.scan([_block("postgres://user:pass@localhost/db")])
    assert not any(f.detector_id == "connection_string_cred" for f in findings)


def test_base64_encoded_key_is_detected(scanner: TieredSecretScanner) -> None:
    encoded = base64.b64encode(f"aws key {AWS_KEY} here".encode()).decode()
    findings = scanner.scan([_block(f"payload: {encoded}")])
    assert any(f.detector_id == "base64:aws_access_key" and f.pins for f in findings)


def test_entropy_helper() -> None:
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcdefgh") > 2.9


def test_dedup_same_span_same_detector(scanner: TieredSecretScanner) -> None:
    findings = scanner.scan([_block(f"{AWS_KEY} and again {AWS_KEY}")])
    aws = [f for f in findings if f.detector_id == "aws_access_key"]
    assert len(aws) == 1
