# Offline verifier experiments

ADRL can compare an operator-reviewed candidate verifier against a baseline on fixed
curated code examples. It records the proposal, both plans, input fingerprints, every
trial and the final assessment. This is an offline library and local CLI, with no
remote API, proposal-generation agent, deployment operation or learning admission.

Use reviewed code and an explicit private state directory separate from live state.
The existing OS sandbox denies network and limits writes to scratch, but does not
provide general read isolation. This workflow is not qualified for hostile code or
secret holdouts. The same local operator owns fixtures, expected answers and plans.

## Prepare and execute

1. Create separate working copies for correct implementations, known defects and a
   broken environment. Record why each should pass, fail or be indeterminate before
   running the comparison. Distinct content fingerprints are required, but do not
   prove statistical independence or semantic diversity.
2. Prepare two `session-verifier-plan-v1` plans with different verifier versions and
   the same task reference. Commands use absolute executables; operator test files
   live outside case workspaces and are pinned by SHA-256. Define assertion failures
   as exit 1 and setup errors as exit 2; declare only 1 in `failure_exit_codes`.
3. Build a `verifier-assessment-v1` JSON suite, then a `verifier-proposal-v1` JSON
   proposal pinning its canonical digest. Set the hypothesis, proposer version,
   affected ADRs, optional parent reference, repeats and budget before executing.
4. Run and read the complete history. Review any recommendation before changing a
   verifier used for real tasks. This command cannot apply that change.

```bash
.venv/bin/adrl improve fingerprint --workspace /absolute/path/to/case
.venv/bin/adrl improve suite-digest --suite /absolute/path/to/suite.json
.venv/bin/adrl improve evaluate --proposal /absolute/path/to/proposal.json \
  --suite /absolute/path/to/suite.json --state /absolute/path/to/private-experiment-state
.venv/bin/adrl improve show --state /absolute/path/to/private-experiment-state \
  --experiment-id ID_FROM_REPORT
```

The Python contracts in `adrl.learning.improvement` expose `model_json_schema()` for
exact fields. The dated experiment in the sibling register archives a complete suite,
proposal and verifier artifacts; its reproduction tool rebuilds temporary local paths.
Fingerprinting includes files, executable flags and directory entries. Git metadata,
virtual environments, caches and bytecode are excluded. Symlinks, special files and
`.adrl-verifier` in the source tree are rejected. Default fingerprint limits match the
suite defaults; custom limits require the Python helper with those same limits.

## How the result is decided

Baseline and candidate run on separate captures of the same pinned code example.
Their order alternates across cases and repeats. Each distinct case is counted once;
all its repetitions must match the expected outcome to count as correct. The report
records command executions separately from case counts.

`candidate_supported` requires the predeclared minimum additional correct cases, no
lost baseline-correct case, no candidate false pass or false failure, and no blockers.
`regression` reports a per-case regression or a candidate false pass/failure;
`no_improvement` means no sufficient demonstrated gain. `indeterminate` covers drift,
incomplete trials, repeat disagreement or execution/integrity failures. It cannot be
averaged away by a higher score. A test environment error can be an expected
indeterminate outcome; a missing sandbox, timeout or unavailable executor is a blocker.

All results remain `curated_synthetic`, `eligible_for_learning=false` and
`review_required=true`. This is not the complete EVL-006 routing evaluation protocol,
an EVL-007 graduation decision or a claim about organic task accuracy. Expected answers
are operator assertions. Hashes bind reviewed content; they do not establish its truth.

The budget bounds admitted command count and the sum of declared timeout ceilings.
It is not an overall elapsed-time, CPU or memory limit. Dependencies and OS state are
not frozen. The records pin evaluator and snapshot-executor source, sandbox source,
executable and operator artifacts; these hashes are not a hermetic build attestation.

`evaluate` exits 0 for completed comparisons, including regression/no improvement;
inspect `recommendation`. Invalid or indeterminate execution exits 2. The separate
`product verify` command returns 0 for passed, 1 for failed checks, and 2 for invalid
setup or indeterminate verification.

## Evidence lifecycle and limits

Migration 0006 adds append-only encrypted `improvement_records`. Experiments reuse the
keystore through a separate identity namespace; they fabricate no product session,
routing decision, outcome or label. The start record contains full versioned inputs,
trial records contain individual receipts, and the final record contains the assessment.
Missing master/HMAC keys are never recreated for an existing CLI archive.

```bash
.venv/bin/adrl improve erase --state /absolute/path/to/private-experiment-state \
  --experiment-id ID_TO_ERASE
```

Erasure shreds the experiment key and appends the existing key-erasure audit. Ledger
skeletons remain; later writes cannot resurrect that key. Exported CLI output, backups,
case copies and plans require separate removal. Losing the host HMAC key prevents
mapping experiment IDs back to their records. Store the private directory accordingly.

A process interruption can leave a started record or partial trial history. There is no
resume or idempotent retry API; rerunning starts a new experiment, and interrupted runs
must be disclosed during review. A key may be created before a started append fails.
The local operator can alter underlying storage; this is not remote attestation.

Next steps are fresh independently reviewed examples, exact task-close output binding,
and another harness using the same verification contracts. Automatic proposal creation,
protected held-out evaluation and any recursive improvement of the proposer come later.
