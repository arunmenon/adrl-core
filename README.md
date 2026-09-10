# adrl-core

W3.2b2d1 current context: [stopped resource ownership](docs/stopped-resource-ownership.md)
adds internal create/bind/inspect/non-force-remove for an explicitly selected local Docker
engine and synthetic image. Durable identity allows cleanup after session-key erasure; lost
create acknowledgements stay unresolved. There is no launch, kill, adoption or workspace release
operation. Schema 11 adds authenticated metadata; public API preview 4 and routing are unchanged.
Full writer containment, active plaintext erasure and exact task-close capture remain open.

W3.2b2b2 current context: [attempt stop coordination](docs/attempt-coordination.md) commits a
workspace block before a synthetic supervised launch and observes erasure, expiry and journal
closure to request cleanup. Terminal events and restart cannot release that block. The group-only
backend still cannot qualify safe reuse, exact-close capture or real task execution.

W3.2b2b1 fixes [key-revocation failure ordering](docs/key-revocation.md): a persistent marker
precedes key mutation and prevents restored-key reads or same-session recreation after a
failed audit. Product access honors that denial. Process/erasure coordination and workspace
release remain open; database schema 9 and API preview 4 are unchanged.

W3.2b2a adds [reserved terminal capacity](docs/attempt-lifecycle.md) for new v2 journal attempts.
The start and quota grant commit together; close requests cannot spend the reserved terminal
slot or bytes. Old v1 records retain their contract. Erasure/process coordination and exact
task-close attribution remain open. Database schema is 9; public API remains preview 4.

W3.2b1 adds an internal [owned process-group runner](docs/process-ownership.md) for bounded
synthetic commands. It tests exit, timeout, cancellation and owner-death cleanup. Detached
and unrelated writers remain outside its scope; every result is ineligible for exact task
closure or learning. Writer containment and journal/capture association remain open.

W3.2a adds an [internal attempt journal](docs/attempt-lifecycle.md): encrypted starts, close
requests and interruption history with transactional workspace reservations. It does not launch
processes or establish that writers stopped. Process supervision and capture association remain
W3.2b work; the public API is still preview 4.

W3.1 adds [retained operator captures](docs/operator-captures.md) as an internal, fixture-tested
API. Encrypted output A can be recovered after the workspace changes to B. Exact task-close
attribution, active-copy erasure coordination and verifier/CLI integration remain later W3 work;
real task capture is not enabled by this slice.

Offline verifier experiments now compare reviewed proposals against a baseline on fixed
curated examples, preserve encrypted evidence and recommend review without deployment.
See the [experiment guide](docs/verifier-experiments.md). The public API remains preview 4.

W0 execution began on 7 September 2026. Use the [engineering check runner](docs/engineering-checks.md)
for a repeatable local evidence record and the sibling register's
[implementation journey](../adrl-world-class/reports/adrl-implementation-journey.md) for progress,
limitations and the next packet.

Product API preview 4 adds independent session verification: a local operator runs pinned checks
on a separate code snapshot and the authenticated timeline shows started/finished receipts.
This works for observation sessions with no routing decisions. Receipts are encrypted,
erasable and excluded from learning. See [product services and setup](docs/product-services.md).

Claude Code observation mode keeps model traffic on its native subscription connection.
One live pilot captured 18 tool events; the same repaired task is the first session-verifier
fixture. Second-harness integration, routing benefits and full privacy enforcement remain
unvalidated. See the dated evidence in the sibling ADRL register for exact denominators.

A Python implementation of ADRL, the Adaptive Routing Layer: a transparent proxy that sits between a coding harness (Claude Code, speaking the Anthropic Messages API) and a model gateway (LiteLLM). ADRL chooses a capability rung per user turn, `local`, `cheap_cloud` or `frontier`, while the gateway chooses the concrete endpoint. It enforces a one-way privacy pin, deterministic escalation trip-wires, an append-only evidence ledger and a hash-chained egress ledger, and it collects the evidence a learned router would need without ever authorising one.

The architecture is the ADR register reviewed on 2026-09-02, held in the sibling repository `adrl-world-class`. Every module names the decision it implements in its docstring; `docs/adr-module-map.md` is the generated cross-reference. The stack rationale is in `adrl-world-class/design/implementation-stack.md`.

## Layout

```
config/            versioned policy: rungs, policy, prices, provider pairs, trip-wires,
                   detectors, repo classification (signed), endpoint inventory (signed),
                   learning contract, fingerprints
src/adrl/
  api/             authenticated local sessions, observations, evidence reads and preview schemas
  core/            shared vocabulary: enums, ids, types, ports, errors
  config/          settings, config models, loaders, load-time checks
  wire/      SEM   request parsing, request classes, session and lineage identity, SSE observer, body rewrite
  gates/     SAF   gate pipeline, repo classification, secret scanner, pin, feasibility, block contract,
                   sandbox runners, egress writer
  routing/   RTG   rung registry, features, band policy, cache-aware cost, advisor ports, router
  cascade/   CAS   action boundary, trip-wires, sticky state, provider-pair handoff, controller
  ledger/    MEM   event store, migrations, outcomes, labels, verification, keystore, erasure,
                   retention, embeddings, projections, shadow retrieval, counterfactual, replay
  learning/  LRN   evidence tiers, dataset, branched pairs, CATE estimators, abstention,
                   artifact manifests, exploration, readiness
  proxy/           ASGI app, pipeline, upstream client, fail-open resolution
  app.py           composition root
  cli/             the adrl command
tests/             unit, integration, adversarial, e2e; scrubbed wire fixtures under tests/fixtures/wire
tools/             local engineering checks and generators; no hosted CI workflow yet
```

## Setup

```bash
uv venv -p 3.12 .venv
uv sync --all-extras
.venv/bin/adrl config check
```

Python 3.12, pure wheels only. Extras: `retrieval` (model2vec), `learning` (scikit-learn), `otel`.

## Run

```bash
.venv/bin/adrl gateway-config --out litellm.yaml    # rung-closed LiteLLM config from rungs.yaml and the signed inventory
.venv/bin/adrl serve                                # listens per ADRL_* settings; point ANTHROPIC_BASE_URL at it
```

Subsystem modes are independent: `ADRL_GATE_MODE` (`enforce` or `observe`), `ADRL_ROUTING_MODE` (`off`, `shadow`, `live`), `ADRL_FALLBACK_MODE`. The intended first deployment is gates enforced and routing in shadow, which computes and records every decision but forwards to the model the harness asked for. Live routing refuses to load unless every enabled rung carries an evidence reference.

## Operate

```bash
.venv/bin/adrl gates audit --lineage <hmac>         # did this lineage's content ever leave the machine
.venv/bin/adrl launch --repo <path>                  # signed workload assertion; eval its output before starting the harness
.venv/bin/adrl gates release --finding <id> --reason false_positive --actor <name>
.venv/bin/adrl gates promote-shadow --lineage <hmac> --finding <id> --actor <name>
.venv/bin/adrl gates scan-measure <corpus-dir>      # per-detector precision and recall
.venv/bin/adrl ledger close | replay | readiness | retention-sweep | erase --session <hmac>
.venv/bin/adrl ledger verify-begin | verify-finish  # sandboxed deterministic verification
.venv/bin/adrl learning build-dataset | train | evaluate | explore-check
.venv/bin/adrl readiness
```

## Checks

```bash
.venv/bin/python -m ruff check src tests tools
.venv/bin/python -m mypy
.venv/bin/python -m pytest -q
.venv/bin/python tools/check_ledger_discipline.py   # no UPDATE or DELETE, no shadow imports into live routing
.venv/bin/python tools/check_config.py              # rung-closed groups, evidence refs, compaction feasibility
.venv/bin/python tools/check_learning_contract.py   # deny-list, no served_rung target, no tier pooling
.venv/bin/python tools/check_data_inventory.py      # every persisted field classified; no plaintext prompt-class data
.venv/bin/python tools/adr_module_map.py
```

## Invariants the code enforces

- The frontier and passthrough path forwards the original request bytes and relays response bytes untouched (FND-001). The removal test asserts byte identity. One carve-out: after an escalation whose source turn had no thinking blocks, the thinking parameter is stripped from frontier-bound requests until the next user turn (CAS-004), recorded as thinking_suppressed.
- Every supported Messages request is gated; routing happens once per user turn and continuations inherit (FND-003, SAF-001, SEM-003).
- The pin is one-way, durable across restart, inherited by descendants, and released only by an audited, reason-coded human action (SAF-002).
- Repository identity is a signed workload assertion minted by `adrl launch`, never prompt text. A harness without one is an unknown workload and stays local-only (SAF-008). Manifest lookup is an exact match.
- Gate observe mode is observational: findings land in a shadow namespace, nothing pins or shreds, and only an audited `adrl gates promote-shadow` turns one into a pin (SAF-001, SAF-002).
- No path, command line, remote URL or program output reaches either ledger in clear; such material is a keyed hash or sealed under a per-session key that erasure shreds. `docs/data-inventory.md` lists every field and `tools/check_data_inventory.py` enforces it (MEM-005, MEM-010).
- The permitted rung set can only shrink within a lineage; a fallback path can never widen it (SAF-001, FND-004).
- The object constrained is a set of attested deployments from the signed endpoint inventory, not a rung label. A pinned lineage may only reach a `local_host` deployment, a residency-tagged lineage only in-geo deployments plus the local host, and a local deployment must be on loopback or a unix socket or the config refuses to load (SAF-008, FND-002).
- Every dispatch addresses a deployment by id and records the gateway's destination receipt; the egress audit answers from recorded trust zones and says when a destination is unconfirmed (SAF-009, RTG-008).
- The egress ledger is written before a request leaves the machine; an append failure on a pinned lineage blocks (SAF-009).
- The evidence ledger has no UPDATE or DELETE; erasure is key deletion plus an `erased` event (MEM-001, MEM-010).
- ADRL makes exactly one attempt per request and never re-issues after streamed tool content (CAS-003, CAS-007).
- Learned artifacts load only with a signed graduation record and matching policy compatibility (LRN-005, LRN-007).

## Status

This build has scoped D1/D2 implementation evidence. Gateway control has been tested with local
fixtures and a fake gateway; the separate native Claude Code observation pilot recorded one
task, without ADRL model routing. That pilot does not establish organic routing qualification.
Maturity belongs to the exact behavior and population recorded in the register and does not
transfer from the prior implementation. The 2026-09-03 external review and its dated fixes
remain in the register. Later verification and experiments have their own source manifests.
The local runner includes all tests, including `tests/adversarial`, and a failure fails its
engineering result. No hosted CI/release pipeline is installed or claimed. Residual gaps and
current-scope corrections are listed in [known gaps](docs/known-gaps.md).

## Product integration boundary

The first extraction toward a multi-harness product is implemented: `MessagesProfile` owns the
pipeline's protocol interpretation and `ClaudeCodeAdapter` supplies identity correlation signals.
Decision records include both component versions. This does not yet add a second harness or make
the gates and cascade independent of Messages semantics.

`GET /adrl/v1/capabilities` reports shipped profiles, adapters and implementation limits. Local
session binding, durable observation intake and scoped evidence reads are implemented in API
preview 4. Operator verification adds encrypted receipts; hook intake cannot claim verification
authority. The product namespace is never forwarded to the model gateway. Explicitly bound
model sessions reject unsupported endpoints; callers omitting all session signals retain the
legacy forwarding gap. Capabilities describe shipped code, not an attestation of enforcement.

Read `docs/protocol-boundary.md` for the current boundary, contract export command and next work,
and `docs/responses-admission.md` for the selected Responses spike scope and remaining admission
requirements. The single observation pilot does not establish Messages gateway compatibility,
a second harness, Responses admission or routing benefit.
