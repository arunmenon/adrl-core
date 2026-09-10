"""Per-detector precision and recall on a labelled corpus. Primary: ADRL-SAF-003.

The corpus is a directory of JSONL files. Each line is one sample:
{"text": "...", "path_hint": "...", "secrets": ["aws_access_key", ...]}
where `secrets` lists the detector ids that SHOULD fire (empty for a clean sample). Output is a
JSON document with precision, recall, counts and the ruleset version, ready to publish and to
feed back into `config/detectors.yaml` tiers.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adrl.core.ports import ContentBlock
from adrl.gates.secrets import TieredSecretScanner

EQUIVALENT: dict[str, set[str]] = {
    "aws_access_key": {"ds:AWSKeyDetector"},
    "private_key_block": {"ds:PrivateKeyDetector"},
    "github_token": {"ds:GitHubTokenDetector"},
    "slack_token": {"ds:SlackDetector"},
    "stripe_live_key": {"ds:StripeDetector"},
    "openai_api_key": {"ds:OpenAIDetector"},
    "jwt": {"ds:JwtTokenDetector"},
}


@dataclass
class DetectorTally:
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    shadow_hits: int = 0

    @property
    def precision(self) -> float | None:
        total = self.true_positive + self.false_positive
        return self.true_positive / total if total else None

    @property
    def recall(self) -> float | None:
        total = self.true_positive + self.false_negative
        return self.true_positive / total if total else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "shadow_hits": self.shadow_hits,
            "precision": self.precision,
            "recall": self.recall,
        }


@dataclass
class MeasurementReport:
    ruleset_version: str
    samples: int = 0
    by_detector: dict[str, DetectorTally] = field(
        default_factory=lambda: defaultdict(DetectorTally)
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleset_version": self.ruleset_version,
            "samples": self.samples,
            "by_detector": {k: v.as_dict() for k, v in sorted(self.by_detector.items())},
        }


def _base(detector_id: str) -> str:
    return detector_id.split(":", 1)[1] if detector_id.startswith("base64:") else detector_id


def _matches(expected: str, fired: str) -> bool:
    fired = _base(fired)
    return fired == expected or fired in EQUIVALENT.get(expected, set())


def iter_samples(corpus_dir: Path) -> Iterable[dict[str, Any]]:
    for path in sorted(corpus_dir.glob("*.jsonl")):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)


def measure(scanner: TieredSecretScanner, corpus_dir: Path) -> MeasurementReport:
    report = MeasurementReport(ruleset_version=scanner.ruleset_version)
    for index, sample in enumerate(iter_samples(corpus_dir)):
        report.samples += 1
        expected = set(sample.get("secrets", []))
        block = ContentBlock(
            block_id=f"sample:{index}",
            content_type=str(sample.get("content_type", "text")),
            text=str(sample.get("text", "")),
            path_hint=sample.get("path_hint"),
        )
        findings = scanner.scan([block])
        fired_pinning = {f.detector_id for f in findings if f.pins}
        for finding in findings:
            if finding.shadow:
                report.by_detector[finding.detector_id].shadow_hits += 1
        for detector in fired_pinning:
            if any(_matches(exp, detector) for exp in expected):
                report.by_detector[detector].true_positive += 1
            else:
                report.by_detector[detector].false_positive += 1
        for exp in expected:
            if not any(_matches(exp, fired) for fired in fired_pinning):
                report.by_detector[exp].false_negative += 1
    return report
