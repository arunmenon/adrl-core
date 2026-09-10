"""Completion check against the register review ledger. Primary: ADRL-FND-005.

Secondary owner: ADRL-EVL-009.

A commit may carry unresolved review findings. A commit that CLAIMS completion may not. A completion
claim is a `Completion-Claim:` trailer in the commit message (or `--claim` locally). When a claim is
present this check requires: a `Review-Checkpoint:` trailer naming a schema-v1 review folder in the
register; that folder's inputs.json covering every changed runtime source file at its current hash;
and no blocking finding, in any review, whose owning ADRs intersect the owners of the changed
modules.
Without a claim the check only reports blockers touching the changed owners and exits 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ADR_RE = re.compile(r"ADRL-(?:FND|SEM|SAF|TRU|RTG|CAS|MEM|LRN|EVL|OPS)-\d{3}")
CLEARED = {"verified-fixed"}
REVIEWED_STATES = {"reviewed", "reviewed-with-open-items"}


def run_git(root: pathlib.Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    return result.stdout


def changed_files(root: pathlib.Path, base: str | None, staged: bool) -> list[str]:
    if staged:
        out = run_git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    elif base:
        out = run_git(root, "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD")
    else:
        out = run_git(root, "diff", "--name-only", "--diff-filter=ACMR", "HEAD~1", "HEAD")
    return [
        line for line in out.splitlines() if line.startswith("src/adrl/") and line.endswith(".py")
    ]


def owners_of(root: pathlib.Path, files: list[str]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for rel in files:
        path = root / rel
        if not path.exists():
            continue
        head = path.read_text(errors="ignore")[:600]
        ids = set(ADR_RE.findall(head))
        for match in re.findall(r"ADRL-([A-Z]{3})-(\d{3})((?:/\d{3})+)", head):
            bucket, first, rest = match
            for number in [first, *rest.strip("/").split("/")]:
                ids.add(f"ADRL-{bucket}-{number}")
        result[rel] = ids
    return result


def sha256_of(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def commit_trailers(root: pathlib.Path) -> dict[str, str]:
    message = run_git(root, "log", "-1", "--format=%B")
    trailers: dict[str, str] = {}
    for line in message.splitlines():
        match = re.match(r"^([A-Za-z-]+):\s*(.+)$", line.strip())
        if match:
            trailers[match.group(1)] = match.group(2).strip()
    return trailers


def latest_dispositions(folder: pathlib.Path) -> dict[str, dict[str, object]]:
    latest: dict[str, dict[str, object]] = {}
    path = folder / "dispositions.jsonl"
    if not path.exists():
        return latest
    for line in path.read_text().splitlines():
        if line.strip():
            record = json.loads(line)
            latest[str(record.get("finding_id"))] = record
    return latest


def blocking_findings(register: pathlib.Path) -> list[dict[str, object]]:
    reviews = register / "reports" / "reviews"
    result: list[dict[str, object]] = []
    for folder in sorted(p for p in reviews.iterdir() if p.is_dir()):
        findings_path = folder / "findings.json"
        if not findings_path.exists():
            continue
        latest = latest_dispositions(folder)
        for finding in json.loads(findings_path.read_text()).get("findings", []):
            if not finding.get("blocking"):
                continue
            record = latest.get(str(finding["id"]), {})
            actor = str(record.get("actor", ""))
            state = str(record.get("disposition", "unresolved"))
            if state in CLEARED and actor.startswith("reviewer:"):
                continue
            result.append(
                {
                    "global_id": finding.get("global_id"),
                    "severity": finding.get("severity"),
                    "owning_adrs": set(finding.get("owning_adrs", [])),
                    "state": state,
                    "review": folder.name,
                }
            )
    return result


def checkpoint_covers(
    register: pathlib.Path, review_id: str, root: pathlib.Path, files: list[str]
) -> tuple[bool, list[str]]:
    folder = register / "reports" / "reviews" / review_id
    inputs_path = folder / "inputs.json"
    status_path = folder / "status.json"
    if not inputs_path.exists() or not status_path.exists():
        return False, [f"checkpoint {review_id} missing inputs.json or status.json"]
    state = json.loads(status_path.read_text()).get("state")
    problems: list[str] = []
    if state not in REVIEWED_STATES:
        problems.append(f"checkpoint {review_id} state is {state}, not reviewed")
    hashes = {
        entry["path"]: entry.get("disk_sha256") or entry.get("sha256")
        for entry in json.loads(inputs_path.read_text()).get("files", [])
        if entry.get("root") in ("runtime", "C", "adrl-core")
    }
    for rel in files:
        current = sha256_of(root / rel) if (root / rel).exists() else None
        if hashes.get(rel) != current:
            problems.append(f"{rel} at its current hash is not covered by checkpoint {review_id}")
    return not problems, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_register = pathlib.Path(__file__).resolve().parents[1].parent / "adrl-world-class"
    parser.add_argument("--register", type=pathlib.Path, default=default_register)
    parser.add_argument("--base", default=None, help="base ref for the change set (CI)")
    parser.add_argument("--staged", action="store_true", help="use the staged index")
    parser.add_argument("--claim", default=None, help="local completion claim")
    parser.add_argument("--checkpoint", default=None, help="local review checkpoint id")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    register = args.register.resolve()
    if not (register / "reports" / "reviews").is_dir():
        print(f"completion check: register not found at {register}")
        return 2
    files = changed_files(root, args.base, args.staged)
    owners = owners_of(root, files)
    touched = set().union(*owners.values()) if owners else set()
    blockers = [b for b in blocking_findings(register) if b["owning_adrs"] & touched]
    trailers = {} if args.staged else commit_trailers(root)
    claim = args.claim or trailers.get("Completion-Claim")
    checkpoint = args.checkpoint or trailers.get("Review-Checkpoint")
    owner_text = ", ".join(sorted(touched)) or "none"
    print(f"completion check: {len(files)} changed runtime source files, owners {owner_text}")
    for blocker in blockers:
        print(
            f"  blocker touching changed owners: {blocker['global_id']} "
            f"({blocker['severity']}, {blocker['state']})"
        )
    if not claim:
        print("completion check: no completion claim; unresolved findings may be committed")
        return 0
    problems: list[str] = []
    if blockers:
        problems.append(
            f"completion claim '{claim}' with {len(blockers)} blocking finding(s) on changed owners"
        )
    if not checkpoint:
        problems.append("completion claim without a Review-Checkpoint trailer")
    else:
        _, coverage_problems = checkpoint_covers(register, checkpoint, root, files)
        problems.extend(coverage_problems)
    for problem in problems:
        print(f"completion check: FAIL {problem}")
    if problems:
        return 1
    print(f"completion check: ok, claim '{claim}' backed by checkpoint {checkpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
