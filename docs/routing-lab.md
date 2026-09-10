# Routing lab

Primary owner: ADRL-EVL-005. Supporting owners: RTG-002, MEM-001, SEM-007.

This workbench makes the real router's choices and actual dispatched requests visible
under repeatable synthetic conditions. It is the first part of Lab A, not a model
benchmark, general experiment service or qualified real-harness runner.

From the repository root, run:

```sh
.venv/bin/python tools/run_routing_lab.py \
  --suite artifacts/lab/routing-suite-v1.json \
  --out /tmp/adrl-routing-lab-first
```

Choose a new output directory for every run. Open its `report.md`: each row links
the initial decision with the tier actually dispatched, the model alias received
by the controlled endpoint, receipt provenance and request state. A continuation
retains the original decision; an escalation can change its dispatch. `results.json`
contains the full decision feature snapshots, versions and request/served events.

The suite includes small edits, repairs, tests, refactors, mixed intent and long
context/recovery. Two prompts retain previously identified mixed-intent weaknesses;
this slice does not change the router to resolve them. Privacy, blocked overflow,
upstream failure, missing identity and an unsupported Responses cell remain visible.

## What is real and what is simulated

Real composition: GatePipeline, Router, CascadeController, SQLite state/ledgers,
Messages parsing, body transformations and response observation. Both HTTP clients
use in-process ASGI transports with no network provider. Endpoint health is static.
Streaming fixtures test SSE interpretation after in-process buffering; they do not
qualify network timing, backpressure or interrupted socket streaming.

The client and endpoint are synthetic. No Claude Code binary, actual model,
repository editing, verification, paid tokens or task outcome runs. Model names
come from development configuration and do not establish provider availability.
The synthetic workload assertion names the configured development repository;
it is not a captured task repository. Harness/model/repository versions are absent
where nothing actually executed. A changed config can change results or block cases.

The bundle loads under shadow checks and is injected into live-mode stages only
inside this fixed in-process simulator, using the existing integration-test pattern.
No live configuration admission, network endpoint option or permission is added.
Environment settings cannot redirect this tool to a real ledger/classifier/anchor.

## Evidence and interruption

The immutable manifest freezes the suite, source/config hashes and planned cells
before execution. The append-only journal records started/finished attempts with
flushed writes. All planned cells remain in the denominator, including unsupported,
blocked, failed and unfinished ones. Inspect an interrupted run with:

```sh
.venv/bin/python tools/run_routing_lab.py --inspect /tmp/adrl-routing-lab-first
```

A started attempt without a complete terminal record is indeterminate. A truncated
last journal line is reported; earlier corruption is rejected. No retry or resume
API exists; rerunning uses a new experiment ID and output directory. This is not a
tamper-proof external archive or a filesystem power-loss qualification.

SQLite stores and generated keys exist in a disposable temporary directory; only
synthetic diagnostic exports persist. They must not receive real developer inputs
or be imported into production ledgers. No outcome labels or training records are
created. Exports explicitly say simulation, synthetic T4 and ineligible for learning;
zero usage in a fixture is not a measured model cost. The existing encrypted verifier
experiment archive remains separate; this tool does not extend that archive's API.

Next work: routing correction, followed by qualified real-harness task execution.
K0 knowledge, learned policy evaluation and RSI retain their roadmap gates.
