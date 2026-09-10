"""CI check for the learning contract. Primary: ADRL-LRN-004. Secondary: ADRL-LRN-003,
ADRL-LRN-001.

Fails when the deny-list is missing from the contract, when any manifest under artifacts/
names a forbidden target, or when a manifest's tier mix pools counterfactual or exploration
evidence with organic tiers in its objective.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "config" / "learning-contract-v1.json"
ARTIFACTS = ROOT / "artifacts"

REQUIRED_DENY = ("served_rung", "escalated", "outcome_state", "verified_result")
REQUIRED_FORBIDDEN_TARGETS = ("served_rung", "decision")


def main() -> int:
    problems: list[str] = []
    contract = json.loads(CONTRACT.read_text())
    deny = set(contract.get("deny_list", ()))
    for name in REQUIRED_DENY:
        if name not in deny:
            problems.append(f"deny_list missing {name}")
    feature_names = {f["name"] for f in contract.get("features", ())}
    leaked = sorted(feature_names & deny)
    if leaked:
        problems.append("feature schema contains deny-listed names: " + ",".join(leaked))
    forbidden = set(contract.get("forbidden_targets", ()))
    for name in REQUIRED_FORBIDDEN_TARGETS:
        if name not in forbidden:
            problems.append(f"forbidden_targets missing {name}")

    manifests = sorted(ARTIFACTS.rglob("manifest.json")) if ARTIFACTS.exists() else []
    for path in manifests:
        try:
            manifest = json.loads(path.read_text())
        except ValueError:
            problems.append(f"{path}: unreadable manifest")
            continue
        targets = set(manifest.get("target_columns", ()))
        bad = sorted(targets & forbidden)
        if bad:
            problems.append(f"{path}: forbidden target {','.join(bad)}")
        mix = manifest.get("tier_mix", {})
        organic = any(mix.get(t, 0) for t in ("T1", "T2", "T3"))
        pooled = [t for t in ("T5", "explore") if mix.get(t, 0)]
        if organic and pooled and manifest.get("artifact_kind") == "estimator":
            problems.append(f"{path}: pools organic tiers with {','.join(pooled)}")
        if manifest.get("deny_list_version") != contract.get("version"):
            problems.append(f"{path}: deny_list_version does not match the contract")

    if problems:
        for problem in problems:
            print("FAIL " + problem)
        return 1
    print(f"learning contract: ok ({len(manifests)} manifests checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
