"""Tiered secret detection on new content. Primary: ADRL-SAF-003.

Two detector families feed one tier table: first-party high-confidence formats (the ones the
prior corpus scan relied on) and detect-secrets plugins. A generic-tier hit pins only when a
second signal corroborates it (sensitive path, credential-shaped variable name, or a second
detector on the same block); otherwise it is a shadow finding. Findings are content-free: the
matched value is reduced to a keyed span hash before it leaves this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

import structlog
from detect_secrets.core import scan as ds_scan
from detect_secrets.settings import transient_settings

from adrl.core.enums import DetectorTier
from adrl.core.ports import ContentBlock
from adrl.core.types import Finding
from adrl.gates.detectors import DetectorsConfig

log = structlog.get_logger(__name__)

_ENV_KEY = (
    r"[A-Z][A-Z0-9]*_?(?:API_?KEY|SECRET(?:_?KEY)?|PASSWORD|PASSWD|ACCESS_?KEY|AUTH_?TOKEN|"
    r"PRIVATE_?KEY|CLIENT_?SECRET|TOKEN)[A-Z0-9_]*"
)

FIRST_PARTY_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "anthropic_api_key": re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}"),
    "openai_api_key": re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9]{32,}"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    "slack_token": re.compile(r"\bxox[abp]-[a-zA-Z0-9-]{20,}"),
    "stripe_live_key": re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "connection_string_cred": re.compile(
        r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s/:@]+:"
        r"(?P<val>[^\s@]+)@(?P<host>[^\s/:]+)"
    ),
    "env_assignment": re.compile(
        r"\b(?P<name>" + _ENV_KEY + r")\s*[=:]\s*['\"]?(?P<val>[A-Za-z0-9+/=_.-]{16,})['\"]?"
    ),
}
GENERIC_FIRST_PARTY = frozenset({"jwt", "connection_string_cred", "env_assignment"})

PLACEHOLDER_CREDS = frozenset(
    {
        "pass",
        "password",
        "passwd",
        "changeme",
        "secret",
        "example",
        "test",
        "user",
        "username",
        "foo",
        "bar",
        "xxx",
        "your_password",
        "placeholder",
        "admin",
        "root",
        "123456",
        "postgres",
        "mysql",
        "redis",
    }
)
PLACEHOLDER_HOSTS = frozenset({"localhost", "127.0.0.1", "example.com", "host", "db", "database"})

SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.env[^/]*|credentials[^/]*|secrets?[^/]*|id_(?:rsa|ed25519|ecdsa)[^/]*|"
    r"[^/]*\.(?:pem|key|p12|pfx|jks|keystore)|\.netrc|\.npmrc|\.pypirc|"
    r"(?:config|settings)\.(?:json|ya?ml|toml|ini))$",
    re.IGNORECASE,
)
CREDENTIAL_NAME = re.compile(r"\b" + _ENV_KEY + r"\b|\b(?:password|passwd|secret|token)\b", re.I)
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_ASSIGNMENT_TAIL = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*[=:]\s*[\"\']?\s*$")
MAX_LINE_CHUNK = 8_000
LINE_CHUNK_OVERLAP = 256

DS_PLUGINS: tuple[dict[str, object], ...] = (
    {"name": "AWSKeyDetector"},
    {"name": "PrivateKeyDetector"},
    {"name": "GitHubTokenDetector"},
    {"name": "GitLabTokenDetector"},
    {"name": "SlackDetector"},
    {"name": "StripeDetector"},
    {"name": "OpenAIDetector"},
    {"name": "SendGridDetector"},
    {"name": "TwilioKeyDetector"},
    {"name": "NpmDetector"},
    {"name": "PypiTokenDetector"},
    {"name": "AzureStorageKeyDetector"},
    {"name": "JwtTokenDetector"},
    {"name": "KeywordDetector"},
    {"name": "BasicAuthDetector"},
    {"name": "Base64HighEntropyString", "limit": 4.5},
    {"name": "HexHighEntropyString", "limit": 3.0},
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass(frozen=True, slots=True)
class RawHit:
    detector_id: str
    value: str
    block_id: str
    content_type: str
    path_hint: str | None
    variable_name: str | None = None


class TieredSecretScanner:
    """SecretScanner port over first-party patterns plus detect-secrets plugins."""

    def __init__(self, config: DetectorsConfig, span_key: bytes) -> None:
        self._config = config
        self._span_key = span_key
        self._plugins = [dict(p) for p in DS_PLUGINS]

    @property
    def ruleset_version(self) -> str:
        return self._config.version

    @property
    def config(self) -> DetectorsConfig:
        return self._config

    # public ----------------------------------------------------------------------------

    def scan(self, blocks: Sequence[ContentBlock]) -> Sequence[Finding]:
        hits: list[RawHit] = []
        for block in blocks:
            if not block.text:
                continue
            hits.extend(self._first_party(block))
            hits.extend(self._detect_secrets(block))
            hits.extend(self._base64_pass(block))
        return self._to_findings(hits)

    # detectors -------------------------------------------------------------------------

    def _first_party(self, block: ContentBlock) -> Iterable[RawHit]:
        enabled = self._config.enabled_ids
        for detector_id, pattern in FIRST_PARTY_PATTERNS.items():
            if detector_id not in enabled:
                continue
            for match in pattern.finditer(block.text):
                value = match.group("val") if "val" in pattern.groupindex else match.group(0)
                name = match.group("name") if "name" in pattern.groupindex else None
                if detector_id == "connection_string_cred":
                    if (
                        value.lower() in PLACEHOLDER_CREDS
                        or match.group("host").lower() in PLACEHOLDER_HOSTS
                    ):
                        continue
                if detector_id in GENERIC_FIRST_PARTY and not self._entropy_ok(value):
                    continue
                yield RawHit(
                    detector_id, value, block.block_id, block.content_type, block.path_hint, name
                )

    def _detect_secrets(self, block: ContentBlock) -> Iterable[RawHit]:
        enabled = self._config.enabled_ids
        with transient_settings({"plugins_used": self._plugins}):
            for line in _chunked_lines(block.text):
                if not line.strip():
                    continue
                try:
                    secrets = list(ds_scan.scan_line(line))
                except Exception as exc:  # detect-secrets raises on odd encodings
                    log.warning("detect_secrets_line_failed", error=type(exc).__name__)
                    continue
                for secret in secrets:
                    plugin = _plugin_class_name(secret.type)
                    detector_id = f"ds:{plugin}"
                    if detector_id not in enabled or not secret.secret_value:
                        continue
                    if self._config.tier_for(detector_id) is DetectorTier.GENERIC:
                        if not self._entropy_ok(str(secret.secret_value)):
                            continue
                    yield RawHit(
                        detector_id,
                        str(secret.secret_value),
                        block.block_id,
                        block.content_type,
                        block.path_hint,
                        _variable_name(line, str(secret.secret_value)),
                    )

    def _base64_pass(self, block: ContentBlock) -> Iterable[RawHit]:
        for run in BASE64_RUN.finditer(block.text):
            candidate = run.group(0)
            if len(candidate) < self._config.base64_min_length:
                continue
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                decoded = base64.b64decode(padded, validate=True).decode("ascii")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if not decoded.isprintable():
                continue
            for detector_id, pattern in FIRST_PARTY_PATTERNS.items():
                if detector_id in GENERIC_FIRST_PARTY:
                    continue
                if pattern.search(decoded):
                    yield RawHit(
                        f"base64:{detector_id}",
                        candidate,
                        block.block_id,
                        block.content_type,
                        block.path_hint,
                    )

    def _entropy_ok(self, value: str) -> bool:
        return (
            len(value) >= self._config.generic_min_length
            and shannon_entropy(value) >= self._config.generic_min_entropy_bits
        )

    # tiering ---------------------------------------------------------------------------

    def _tier(self, detector_id: str) -> DetectorTier | None:
        if detector_id.startswith("base64:"):
            return DetectorTier.HIGH_CONFIDENCE
        return self._config.tier_for(detector_id)

    def _to_findings(self, hits: Sequence[RawHit]) -> list[Finding]:
        by_block: dict[str, list[RawHit]] = {}
        for hit in hits:
            by_block.setdefault(hit.block_id, []).append(hit)
        findings: dict[tuple[str, str], Finding] = {}
        for block_id, block_hits in by_block.items():
            distinct_detectors = {h.detector_id for h in block_hits}
            for hit in block_hits:
                tier = self._tier(hit.detector_id)
                if tier is None:
                    continue
                span_hash = self._span_hash(hit.value)
                corroboration = self._corroboration(hit, distinct_detectors)
                shadow = tier is DetectorTier.GENERIC and corroboration is None
                key = (hit.detector_id, span_hash)
                if key in findings:
                    continue
                findings[key] = Finding(
                    detector_id=hit.detector_id,
                    tier=tier,
                    span_hash=span_hash,
                    finding_id=_finding_id(block_id, hit.detector_id, span_hash),
                    content_type=hit.content_type,
                    corroboration=corroboration,
                    shadow=shadow,
                )
        return list(findings.values())

    @staticmethod
    def _corroboration(hit: RawHit, detectors_on_block: set[str]) -> str | None:
        if hit.path_hint and SENSITIVE_PATH.search(hit.path_hint):
            return "sensitive_path"
        if hit.variable_name and CREDENTIAL_NAME.search(hit.variable_name):
            return "credential_variable_name"
        others = detectors_on_block - {hit.detector_id}
        if others:
            return "second_detector:" + sorted(others)[0]
        return None

    def _span_hash(self, value: str) -> str:
        return hmac.new(self._span_key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _chunked_lines(text: str) -> Iterable[str]:
    """Lines, with any line longer than MAX_LINE_CHUNK split into overlapping pieces."""
    for line in text.splitlines():
        if len(line) <= MAX_LINE_CHUNK:
            yield line
            continue
        start = 0
        while start < len(line):
            yield line[start : start + MAX_LINE_CHUNK]
            start += MAX_LINE_CHUNK - LINE_CHUNK_OVERLAP


def _plugin_class_name(secret_type: str) -> str:
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    mapping: dict[str, type[Any]] = get_mapping_from_secret_type_to_class()
    cls = mapping.get(secret_type)
    return cls.__name__ if cls is not None else secret_type.replace(" ", "")


def _variable_name(line: str, value: str | None = None) -> str | None:
    """Identifier immediately before the assignment that carries `value`.

    Only the 120 characters before the value are examined and the pattern is bounded, so a very
    long line cannot make this quadratic.
    """
    end = len(line)
    if value:
        idx = line.find(value)
        if idx >= 0:
            end = idx
    window = line[max(0, end - 120) : end]
    match = _ASSIGNMENT_TAIL.search(window)
    return match.group(1) if match else None


def _finding_id(block_id: str, detector_id: str, span_hash: str) -> str:
    seed = f"{block_id}|{detector_id}|{span_hash}"
    return "fnd_" + uuid.uuid5(uuid.NAMESPACE_URL, seed).hex[:20]
