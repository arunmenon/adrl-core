# ADR to module map

Generated from module docstrings. Regenerate with `tools/adr_module_map.py`.

Register: ADR files (77 decisions). Mapped: 74 of 77. Phantom citations: 0. Register decisions with no module: 3.

## By module

| Module | ADR IDs | Docstring |
|---|---|---|
| `adrl/api/auth.py` | ADRL-SEM-002, ADRL-TRU-001 | Local session authority. Primary: ADRL-TRU-001. Secondary: ADRL-SEM-002. |
| `adrl/api/client.py` | ADRL-MEM-001, ADRL-MEM-005, ADRL-SEM-007 | Local integration client and observation outbox. Primary: ADRL-SEM-007. |
| `adrl/api/contracts.py` | ADRL-MEM-001, ADRL-SEM-007, ADRL-TRU-001 | Versioned product records. Primary: ADRL-SEM-007. Secondary: ADRL-MEM-001, ADRL-TRU-001. |
| `adrl/api/http.py` | ADRL-SEM-007, ADRL-TRU-001 | Local product HTTP boundary. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001. |
| `adrl/api/schema.py` | ADRL-FND-001, ADRL-SEM-007 | Export the product API preview. Primary: ADRL-SEM-007. Secondary: ADRL-FND-001. |
| `adrl/api/service.py` | ADRL-MEM-001, ADRL-SEM-007, ADRL-TRU-001 | Local product service. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001, ADRL-MEM-001. |
| `adrl/api/store.py` | ADRL-MEM-001, ADRL-MEM-010 | Durable product intake. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-010. |
| `adrl/app.py` | ADRL-FND-001, ADRL-FND-002, ADRL-LRN-007 | Composition root. Primary: ADRL-FND-002. |
| `adrl/cascade/boundary.py` | ADRL-CAS-003 | Action boundary on the wire. Primary: ADRL-CAS-003. |
| `adrl/cascade/controller.py` | ADRL-CAS-001, ADRL-CAS-003, ADRL-CAS-004, ADRL-CAS-005, ADRL-CAS-006, ADRL-CAS-007, ADRL-CAS-008, ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-004, ADRL-SEM-006 | ADRL-CAS-003: plan dispatch, observe responses, escalate at boundaries. |
| `adrl/cascade/handoff.py` | ADRL-CAS-003, ADRL-CAS-004 | Cross-model handoff transform. Primary: ADRL-CAS-004. Secondary: ADRL-CAS-003. |
| `adrl/cascade/sticky.py` | ADRL-CAS-005, ADRL-CAS-006, ADRL-OPS-006, ADRL-SEM-005 | Sticky state within an episode. Primary: ADRL-CAS-005. Secondary: ADRL-CAS-006, ADRL-SEM-005. |
| `adrl/cascade/tripwires.py` | ADRL-CAS-001, ADRL-CAS-002 | Deterministic post-call trip-wires. Primary: ADRL-CAS-001. Secondary: ADRL-CAS-002. |
| `adrl/cli/improvement.py` | ADRL-EVL-006, ADRL-LRN-007, ADRL-MEM-010 | Local verifier experiments. Primary: ADRL-EVL-006. Secondary: ADRL-LRN-007, ADRL-MEM-010. |
| `adrl/cli/ledger_commands.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-004, ADRL-MEM-010 | Ledger operator commands: replay, close, readiness, retention, erasure, verification. |
| `adrl/cli/main.py` | ADRL-OPS-001, ADRL-SAF-009 | adrl command line. Primary: ADRL-OPS-001 (referenced by gloss). Secondary: ADRL-SAF-009. |
| `adrl/cli/product.py` | ADRL-SEM-007, ADRL-TRU-001 | Claude Code connection and evidence commands. Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001. |
| `adrl/config/checks.py` | ADRL-CAS-002, ADRL-FND-002, ADRL-LRN-004, ADRL-OPS-003, ADRL-RTG-001, ADRL-SAF-005 | Load-time configuration checks. Primary: ADRL-FND-002. |
| `adrl/config/loaders.py` | ADRL-FND-002, ADRL-SAF-008 | Config file loaders and the signed-manifest check. Primary: ADRL-FND-002. |
| `adrl/config/models.py` | ADRL-CAS-001, ADRL-CAS-004, ADRL-FND-002, ADRL-LRN-004, ADRL-LRN-005, ADRL-MEM-002, ADRL-MEM-010, ADRL-RTG-001, ADRL-RTG-002, ADRL-RTG-003, ADRL-RTG-004, ADRL-RTG-005, ADRL-RTG-009, ADRL-SAF-008, ADRL-SEM-004 | Pydantic models for every versioned config file. Primary: ADRL-FND-002. |
| `adrl/config/settings.py` | ADRL-OPS-001 | Process settings from environment. Primary: ADRL-OPS-001 (referenced by gloss). |
| `adrl/core/attempt_coordinator.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-005, ADRL-MEM-010, ADRL-OPS-001, ADRL-SAF-007, ADRL-TRU-001 | Stop coordination with permanent workspace fences. Primary: ADRL-OPS-001. |
| `adrl/core/container_control.py` | ADRL-MEM-005, ADRL-OPS-001, ADRL-SAF-007, ADRL-TRU-001 | Create-only local container transport. Primary: ADRL-OPS-001. |
| `adrl/core/enums.py` | ADRL-CAS-002, ADRL-MEM-001, ADRL-MEM-004 | Versioned enums and state sets shared across buckets. Primary: ADRL-CAS-002. |
| `adrl/core/errors.py` | ADRL-CAS-007, ADRL-SAF-004, ADRL-SAF-005 | Error hierarchy and the published error-code table. Primary: ADRL-CAS-007. |
| `adrl/core/execution_control.py` | ADRL-MEM-005, ADRL-OPS-001, ADRL-SAF-007, ADRL-TRU-001 | Pinned synthetic execution transport. Primary: ADRL-OPS-001. |
| `adrl/core/ids.py` | ADRL-MEM-001, ADRL-SEM-002 | Identity minting and hashing. Primary: ADRL-MEM-001. Secondary: ADRL-SEM-002. |
| `adrl/core/isolated_execution.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-005, ADRL-MEM-010, ADRL-OPS-001, ADRL-SAF-007, ADRL-TRU-001 | One-shot isolated fixture execution. Primary: ADRL-OPS-001. |
| `adrl/core/launch_markers.py` | ADRL-MEM-001, ADRL-MEM-005, ADRL-MEM-010, ADRL-OPS-001, ADRL-TRU-001 | Permanent one-shot denial markers. Primary: ADRL-OPS-001. |
| `adrl/core/ports.py` | ADRL-FND-002, ADRL-MEM-005, ADRL-MEM-006, ADRL-MEM-010, ADRL-SAF-003, ADRL-SAF-006, ADRL-SAF-007 | Port interfaces every adapter implements. Primary: ADRL-MEM-006. |
| `adrl/core/process_anchor.py` | ADRL-OPS-001, ADRL-SAF-007, ADRL-SEM-006, ADRL-TRU-001 | Private process-group launcher. Primary: ADRL-OPS-001. |
| `adrl/core/process_owner.py` | ADRL-MEM-003, ADRL-OPS-001, ADRL-SAF-007, ADRL-SEM-006, ADRL-TRU-001 | Owned process-group execution and cleanup. Primary: ADRL-OPS-001. |
| `adrl/core/resource_owner.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-005, ADRL-MEM-010, ADRL-OPS-001, ADRL-SAF-007, ADRL-TRU-001 | Durable ownership of stopped resources. Primary: ADRL-OPS-001. |
| `adrl/core/types.py` | ADRL-CAS-004, ADRL-CAS-006, ADRL-RTG-002, ADRL-RTG-009, ADRL-SAF-001, ADRL-SEM-001, ADRL-TRU-002 | Value objects shared across packages. Primary: ADRL-SEM-001. |
| `adrl/gates/block.py` | ADRL-SAF-004, ADRL-SAF-005, ADRL-SEM-004 | Fail-loud and block contract. Primary: ADRL-SAF-004. Secondary: ADRL-SAF-005, ADRL-SEM-004. |
| `adrl/gates/cli.py` | ADRL-SAF-002, ADRL-SAF-003, ADRL-SAF-007, ADRL-SAF-009 | Operator commands owned by the gates package. Primary: ADRL-SAF-002. |
| `adrl/gates/content.py` | ADRL-SAF-003, ADRL-SAF-006, ADRL-SAF-008 | Content extraction for gates: every scannable block with its position. Primary: ADRL-SAF-003. |
| `adrl/gates/coverage.py` | ADRL-SAF-003 | Per-lineage scan coverage so only new content is scanned. Primary: ADRL-SAF-003. |
| `adrl/gates/deployments.py` | ADRL-FND-002, ADRL-RTG-008, ADRL-SAF-001, ADRL-SAF-008, ADRL-SAF-009, ADRL-TRU-002 | Permitted deployment sets and destination receipts. Primary: ADRL-SAF-008. |
| `adrl/gates/detectors.py` | ADRL-SAF-003 | Versioned detector tier table. Primary: ADRL-SAF-003. |
| `adrl/gates/egress.py` | ADRL-SAF-009 | Write-ahead egress recording for the gate stage. Primary: ADRL-SAF-009. |
| `adrl/gates/feasibility.py` | ADRL-SAF-005, ADRL-SAF-006, ADRL-SEM-001 | Feasibility filter: unhealthy or context-infeasible rungs are removed. Primary: ADRL-SAF-006. |
| `adrl/gates/measure.py` | ADRL-SAF-003 | Per-detector precision and recall on a labelled corpus. Primary: ADRL-SAF-003. |
| `adrl/gates/pin.py` | ADRL-OPS-005, ADRL-SAF-002 | Durable, one-way, lineage-scoped privacy pin. Primary: ADRL-SAF-002. |
| `adrl/gates/pipeline.py` | ADRL-FND-004, ADRL-OPS-005, ADRL-SAF-001, ADRL-SAF-002, ADRL-SAF-003, ADRL-SAF-005, ADRL-SAF-006, ADRL-SAF-008, ADRL-SAF-009 | Ordered hard gates on every request. Primary: ADRL-SAF-001. |
| `adrl/gates/repo_class.py` | ADRL-MEM-005, ADRL-SAF-008, ADRL-TRU-001 | Static repository and data-class gate. Primary: ADRL-SAF-008. |
| `adrl/gates/sandbox.py` | ADRL-SAF-007 | OS-enforced sandbox for verification commands. Primary: ADRL-SAF-007. |
| `adrl/gates/secrets.py` | ADRL-SAF-003 | Tiered secret detection on new content. Primary: ADRL-SAF-003. |
| `adrl/gates/suppression.py` | ADRL-MEM-005, ADRL-SAF-003 | Retroactive suppression hook for pinned lineages. Primary: ADRL-SAF-003. Secondary: ADRL-MEM-005. |
| `adrl/gates/workload.py` | ADRL-SAF-008, ADRL-TRU-001 | Authenticated workload identity for the repository gate. Primary: ADRL-SAF-008. |
| `adrl/learning/abstention.py` | ADRL-LRN-004, ADRL-LRN-006, ADRL-MEM-005, ADRL-MEM-006 | Selective prediction and out-of-distribution abstention. Primary: ADRL-LRN-006. |
| `adrl/learning/artifacts.py` | ADRL-EVL-006, ADRL-EVL-007, ADRL-LRN-001, ADRL-LRN-004, ADRL-LRN-005, ADRL-LRN-007, ADRL-MEM-004 | Artifact manifests, graduation records and fail-closed loading. Primary: ADRL-LRN-005. |
| `adrl/learning/dataset.py` | ADRL-EVL-002, ADRL-LRN-001, ADRL-LRN-004, ADRL-MEM-007 | Pre-decision features, enforced by construction. Primary: ADRL-LRN-004. |
| `adrl/learning/estimator.py` | ADRL-LRN-001, ADRL-LRN-003, ADRL-LRN-004 | CATE estimator for the marginal effect of a higher rung. Primary: ADRL-LRN-003. |
| `adrl/learning/explore.py` | ADRL-CAS-005, ADRL-LRN-002, ADRL-LRN-005, ADRL-LRN-008, ADRL-SAF-001, ADRL-SAF-002 | Logged exploration in the ambiguous band and off-policy estimation. Primary: ADRL-LRN-008. |
| `adrl/learning/improvement.py` | ADRL-EVL-005, ADRL-EVL-006, ADRL-EVL-009, ADRL-LRN-005, ADRL-LRN-007, ADRL-MEM-003 | Compare reviewed verifier proposals offline. Primary: ADRL-EVL-006. |
| `adrl/learning/pairs.py` | ADRL-EVL-003, ADRL-LRN-001, ADRL-LRN-002, ADRL-MEM-009, ADRL-SAF-002 | Branched counterfactual pairs and their power budget. Primary: ADRL-LRN-002. |
| `adrl/learning/readiness.py` | ADRL-EVL-004, ADRL-EVL-009, ADRL-FND-005, ADRL-LRN-001, ADRL-LRN-002, ADRL-LRN-006 | Learning readiness report. Primary: ADRL-LRN-001. Secondary: ADRL-FND-005, ADRL-EVL-004, |
| `adrl/learning/tiers.py` | ADRL-EVL-005, ADRL-LRN-001, ADRL-LRN-002, ADRL-LRN-008, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-004 | Evidence tiers and pooling rules. Primary: ADRL-LRN-001. |
| `adrl/ledger/anchoring.py` | ADRL-OPS-002, ADRL-OPS-007, ADRL-SAF-009, ADRL-TRU-003 | Checkpoint key custody, off-device anchoring and anchor verification. Primary: ADRL-SAF-009. |
| `adrl/ledger/attempts.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-005, ADRL-MEM-010, ADRL-OPS-001, ADRL-SEM-002, ADRL-SEM-007, ADRL-TRU-001 | Append-only operator attempt lifecycle. Primary: ADRL-MEM-002. |
| `adrl/ledger/capture.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-005, ADRL-MEM-010, ADRL-SAF-007, ADRL-SEM-002, ADRL-SEM-007, ADRL-TRU-001 | Retained operator-time snapshots. Primary: ADRL-MEM-003. |
| `adrl/ledger/counterfactual.py` | ADRL-LRN-001, ADRL-MEM-009 | Counterfactual evidence bound to an explicit route_id. Primary: ADRL-MEM-009. |
| `adrl/ledger/crypto.py` | ADRL-MEM-005, ADRL-MEM-010 | AES-GCM and keyed hashing primitives for prompt-class data. Primary: ADRL-MEM-010. |
| `adrl/ledger/egress.py` | ADRL-SAF-009, ADRL-TRU-003 | Tamper-evident, content-free egress ledger. Primary: ADRL-SAF-009. |
| `adrl/ledger/embeddings.py` | ADRL-MEM-005, ADRL-MEM-010, ADRL-SAF-002 | Embeddings and keyed instruction hashes as prompt-class data. Primary: ADRL-MEM-005. |
| `adrl/ledger/erasure.py` | ADRL-MEM-005, ADRL-MEM-007, ADRL-MEM-010, ADRL-OPS-004, ADRL-SAF-002 | Crypto-shredding by session and pin-triggered suppression. Primary: ADRL-MEM-010. |
| `adrl/ledger/events.py` | ADRL-MEM-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-004, ADRL-MEM-009, ADRL-MEM-010 | Typed event constructors and producer sequencing. Primary: ADRL-MEM-001. |
| `adrl/ledger/facade.py` | ADRL-MEM-001, ADRL-MEM-006, ADRL-SAF-002 | Fail-safe memory facade. Primary: ADRL-MEM-006. Secondary: ADRL-MEM-001, ADRL-SAF-002. |
| `adrl/ledger/improvement.py` | ADRL-LRN-005, ADRL-MEM-001, ADRL-MEM-005, ADRL-MEM-010 | Encrypted offline experiment history. Primary: ADRL-MEM-001. |
| `adrl/ledger/keystore.py` | ADRL-MEM-001, ADRL-MEM-005, ADRL-MEM-010, ADRL-OPS-001 | File keystore for per-session keys and the host HMAC secret. Primary: ADRL-MEM-010. |
| `adrl/ledger/labels.py` | ADRL-LRN-001, ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-004 | Cause-typed labels on failure-types-v2. Primary: ADRL-MEM-004. |
| `adrl/ledger/outcomes.py` | ADRL-CAS-005, ADRL-MEM-002, ADRL-MEM-004 | Outcome lifecycle: pending, closed_turn, closed_final. Primary: ADRL-MEM-002. |
| `adrl/ledger/projections.py` | ADRL-LRN-004, ADRL-MEM-007, ADRL-MEM-010 | Rebuildable, stamped NumPy retrieval projection. Primary: ADRL-MEM-007. |
| `adrl/ledger/readiness.py` | ADRL-EVL-004, ADRL-EVL-009, ADRL-FND-005, ADRL-MEM-002, ADRL-MEM-004, ADRL-MEM-006 | Learning readiness counts on censored, cause-clean labels. Primary: ADRL-MEM-004. |
| `adrl/ledger/replay.py` | ADRL-MEM-001, ADRL-MEM-007 | Rebuild every projection from events. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-007. |
| `adrl/ledger/retention.py` | ADRL-MEM-010 | Retention sweep over two storage classes. Primary: ADRL-MEM-010. |
| `adrl/ledger/session_verification.py` | ADRL-LRN-001, ADRL-MEM-001, ADRL-MEM-003, ADRL-MEM-010, ADRL-SAF-007, ADRL-SEM-007 | Snapshot execution and bound-session operator checks. Primary: ADRL-MEM-003. |
| `adrl/ledger/shadow_retrieval.py` | ADRL-MEM-005, ADRL-MEM-007, ADRL-MEM-008 | Advisory retrieval that writes only to the ledger. Primary: ADRL-MEM-008. |
| `adrl/ledger/state.py` | ADRL-CAS-006, ADRL-MEM-006, ADRL-SAF-002 | Provider-backed routing state. Primary: ADRL-MEM-006. Secondary: ADRL-SAF-002, ADRL-CAS-006. |
| `adrl/ledger/store.py` | ADRL-MEM-001, ADRL-MEM-006, ADRL-MEM-007 | SQLite event store with one writer thread. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-006. |
| `adrl/ledger/upcast.py` | ADRL-MEM-001, ADRL-MEM-004 | Schema upcasters for old event payloads. Primary: ADRL-MEM-001. Secondary: ADRL-MEM-004. |
| `adrl/ledger/verification.py` | ADRL-MEM-002, ADRL-MEM-003, ADRL-MEM-005, ADRL-MEM-009, ADRL-MEM-010, ADRL-SAF-007 | Verification events with provenance, and the begin/finish job flow. Primary: ADRL-MEM-003. |
| `adrl/proxy/asgi.py` | ADRL-FND-001 | Starlette application exposing the proxy. Primary: ADRL-FND-001. |
| `adrl/proxy/errors.py` | ADRL-CAS-007, ADRL-SEM-007 | Compatibility exports for Messages responses. Primary: ADRL-CAS-007. Secondary: ADRL-SEM-007. |
| `adrl/proxy/fallback.py` | ADRL-FND-004, ADRL-OPS-008, ADRL-SAF-001, ADRL-SAF-009 | Fail to last-known-safe. Primary: ADRL-FND-004. Secondary: ADRL-SAF-001, ADRL-SAF-009. |
| `adrl/proxy/observe_only.py` | ADRL-FND-001, ADRL-MEM-006, ADRL-SEM-006 | Observe-only stage implementations. Primary: ADRL-FND-001. Secondary: ADRL-SEM-006, ADRL-MEM-006. |
| `adrl/proxy/pipeline.py` | ADRL-CAS-006, ADRL-FND-001, ADRL-FND-003, ADRL-FND-004, ADRL-MEM-001, ADRL-MEM-002, ADRL-SAF-001, ADRL-SAF-009, ADRL-SEM-003, ADRL-SEM-004, ADRL-SEM-006, ADRL-TRU-002 | The per-request pipeline. Primary: ADRL-FND-003. |
| `adrl/proxy/stages.py` | ADRL-CAS-005, ADRL-FND-002, ADRL-RTG-002, ADRL-SAF-001 | Stage protocols the pipeline composes. Primary: ADRL-FND-002. |
| `adrl/proxy/upstream.py` | ADRL-CAS-007, ADRL-FND-001 | Gateway client: one attempt, verbatim relay. Primary: ADRL-CAS-007. Secondary: ADRL-FND-001. |
| `adrl/routing/advisor.py` | ADRL-LRN-008, ADRL-RTG-006 | Advisory LLM classifier and the exploration port. Primary: ADRL-RTG-006. |
| `adrl/routing/cascade_feasibility.py` | ADRL-RTG-004 | Local-first only with a bounded, clean cascade. Primary: ADRL-RTG-004. |
| `adrl/routing/cost.py` | ADRL-RTG-002, ADRL-RTG-005, ADRL-RTG-009 | Session-marginal, cache-aware cost accounting. Primary: ADRL-RTG-009. |
| `adrl/routing/features.py` | ADRL-LRN-004, ADRL-RTG-003 | Pre-decision feature snapshot features-v2. Primary: ADRL-LRN-004. Secondary: ADRL-RTG-003. |
| `adrl/routing/policy.py` | ADRL-RTG-002, ADRL-RTG-003 | Bands, the band-heuristic-v1 estimator and threshold selection. Primary: ADRL-RTG-002. |
| `adrl/routing/registry.py` | ADRL-RTG-001, ADRL-RTG-008 | Rung registry with measured boundaries. Primary: ADRL-RTG-001. Secondary: ADRL-RTG-008. |
| `adrl/routing/router.py` | ADRL-LRN-008, ADRL-RTG-002, ADRL-RTG-003, ADRL-RTG-004, ADRL-RTG-006, ADRL-RTG-009 | Router: composes features, bands, estimator, cost, advisor and cascade feasibility. |
| `adrl/routing/rule_health.py` | ADRL-RTG-003 | Per-band rule precision on verified outcomes. Primary: ADRL-RTG-003. |
| `adrl/routing/side_effects.py` | ADRL-CAS-003, ADRL-CAS-009, ADRL-RTG-004 | Mechanical side-effect classification of tool calls. Primary: ADRL-CAS-003. |
| `adrl/telemetry/logging.py` | ADRL-OPS-001 | structlog JSON logging with contextvars. Primary: ADRL-OPS-001 (referenced by gloss). |
| `adrl/telemetry/metrics.py` | ADRL-FND-004, ADRL-MEM-006, ADRL-SAF-001, ADRL-SAF-005, ADRL-SAF-009, ADRL-SEM-001 | Prometheus SLIs named in the decisions. Primary: ADRL-FND-004. |
| `adrl/telemetry/semconv.py` | ADRL-RTG-008 | OpenTelemetry GenAI semantic-convention attribute names. Primary: ADRL-RTG-008. |
| `adrl/wire/adapters.py` | ADRL-SEM-002, ADRL-SEM-007 | Harness identity evidence adapters. Primary: ADRL-SEM-002. Secondary: ADRL-SEM-007. |
| `adrl/wire/classify.py` | ADRL-FND-003, ADRL-SEM-001, ADRL-SEM-004 | Mechanical request classification. Primary: ADRL-SEM-001. Secondary: ADRL-SEM-004, ADRL-FND-003. |
| `adrl/wire/identity.py` | ADRL-SEM-002, ADRL-SEM-006 | Session key and lineage identity. Primary: ADRL-SEM-002. Secondary: ADRL-SEM-006. |
| `adrl/wire/observe.py` | ADRL-CAS-003, ADRL-CAS-006, ADRL-FND-001, ADRL-OPS-006, ADRL-RTG-009, ADRL-TRU-002 | Response observation on the relayed byte stream. Primary: ADRL-CAS-006. |
| `adrl/wire/parse.py` | ADRL-FND-001, ADRL-SEM-001 | Read-only view of an inbound request. Primary: ADRL-SEM-001. Secondary: ADRL-FND-001. |
| `adrl/wire/profiles/base.py` | ADRL-FND-001, ADRL-SEM-007 | Protocol interpretation ports. Primary: ADRL-SEM-007. Secondary: ADRL-FND-001. |
| `adrl/wire/profiles/messages.py` | ADRL-FND-001, ADRL-SEM-007 | Messages protocol interpretation. Primary: ADRL-SEM-007. Secondary: ADRL-FND-001. |
| `adrl/wire/profiles/messages_responses.py` | ADRL-CAS-007, ADRL-SAF-004, ADRL-SAF-005, ADRL-SEM-004, ADRL-SEM-007 | Messages errors and synthetic responses. Primary: ADRL-CAS-007. Secondary: ADRL-SEM-007. |
| `adrl/wire/rewrite.py` | ADRL-FND-001, ADRL-FND-002 | Body rewrite for non-Claude rungs. Primary: ADRL-FND-001. Secondary: ADRL-FND-002. |

## By decision (register only)

| ADR | Modules |
|---|---|
| ADRL-CAS-001 | `adrl/cascade/controller.py`, `adrl/cascade/tripwires.py`, `adrl/config/models.py` |
| ADRL-CAS-002 | `adrl/cascade/tripwires.py`, `adrl/config/checks.py`, `adrl/core/enums.py` |
| ADRL-CAS-003 | `adrl/cascade/boundary.py`, `adrl/cascade/controller.py`, `adrl/cascade/handoff.py`, `adrl/routing/side_effects.py`, `adrl/wire/observe.py` |
| ADRL-CAS-004 | `adrl/cascade/controller.py`, `adrl/cascade/handoff.py`, `adrl/config/models.py`, `adrl/core/types.py` |
| ADRL-CAS-005 | `adrl/cascade/controller.py`, `adrl/cascade/sticky.py`, `adrl/learning/explore.py`, `adrl/ledger/outcomes.py`, `adrl/proxy/stages.py` |
| ADRL-CAS-006 | `adrl/cascade/controller.py`, `adrl/cascade/sticky.py`, `adrl/core/types.py`, `adrl/ledger/state.py`, `adrl/proxy/pipeline.py`, `adrl/wire/observe.py` |
| ADRL-CAS-007 | `adrl/cascade/controller.py`, `adrl/core/errors.py`, `adrl/proxy/errors.py`, `adrl/proxy/upstream.py`, `adrl/wire/profiles/messages_responses.py` |
| ADRL-CAS-008 | `adrl/cascade/controller.py` |
| ADRL-CAS-009 | `adrl/routing/side_effects.py` |
| ADRL-EVL-002 | `adrl/learning/dataset.py` |
| ADRL-EVL-003 | `adrl/learning/pairs.py` |
| ADRL-EVL-004 | `adrl/learning/readiness.py`, `adrl/ledger/readiness.py` |
| ADRL-EVL-005 | `adrl/learning/improvement.py`, `adrl/learning/tiers.py` |
| ADRL-EVL-006 | `adrl/cli/improvement.py`, `adrl/learning/artifacts.py`, `adrl/learning/improvement.py` |
| ADRL-EVL-007 | `adrl/learning/artifacts.py` |
| ADRL-EVL-009 | `adrl/learning/improvement.py`, `adrl/learning/readiness.py`, `adrl/ledger/readiness.py` |
| ADRL-FND-001 | `adrl/api/schema.py`, `adrl/app.py`, `adrl/proxy/asgi.py`, `adrl/proxy/observe_only.py`, `adrl/proxy/pipeline.py`, `adrl/proxy/upstream.py`, `adrl/wire/observe.py`, `adrl/wire/parse.py`, `adrl/wire/profiles/base.py`, `adrl/wire/profiles/messages.py`, `adrl/wire/rewrite.py` |
| ADRL-FND-002 | `adrl/app.py`, `adrl/config/checks.py`, `adrl/config/loaders.py`, `adrl/config/models.py`, `adrl/core/ports.py`, `adrl/gates/deployments.py`, `adrl/proxy/stages.py`, `adrl/wire/rewrite.py` |
| ADRL-FND-003 | `adrl/proxy/pipeline.py`, `adrl/wire/classify.py` |
| ADRL-FND-004 | `adrl/gates/pipeline.py`, `adrl/proxy/fallback.py`, `adrl/proxy/pipeline.py`, `adrl/telemetry/metrics.py` |
| ADRL-FND-005 | `adrl/learning/readiness.py`, `adrl/ledger/readiness.py` |
| ADRL-LRN-001 | `adrl/learning/artifacts.py`, `adrl/learning/dataset.py`, `adrl/learning/estimator.py`, `adrl/learning/pairs.py`, `adrl/learning/readiness.py`, `adrl/learning/tiers.py`, `adrl/ledger/counterfactual.py`, `adrl/ledger/labels.py`, `adrl/ledger/session_verification.py` |
| ADRL-LRN-002 | `adrl/learning/explore.py`, `adrl/learning/pairs.py`, `adrl/learning/readiness.py`, `adrl/learning/tiers.py` |
| ADRL-LRN-003 | `adrl/learning/estimator.py` |
| ADRL-LRN-004 | `adrl/config/checks.py`, `adrl/config/models.py`, `adrl/learning/abstention.py`, `adrl/learning/artifacts.py`, `adrl/learning/dataset.py`, `adrl/learning/estimator.py`, `adrl/ledger/projections.py`, `adrl/routing/features.py` |
| ADRL-LRN-005 | `adrl/config/models.py`, `adrl/learning/artifacts.py`, `adrl/learning/explore.py`, `adrl/learning/improvement.py`, `adrl/ledger/improvement.py` |
| ADRL-LRN-006 | `adrl/learning/abstention.py`, `adrl/learning/readiness.py` |
| ADRL-LRN-007 | `adrl/app.py`, `adrl/cli/improvement.py`, `adrl/learning/artifacts.py`, `adrl/learning/improvement.py` |
| ADRL-LRN-008 | `adrl/learning/explore.py`, `adrl/learning/tiers.py`, `adrl/routing/advisor.py`, `adrl/routing/router.py` |
| ADRL-MEM-001 | `adrl/api/client.py`, `adrl/api/contracts.py`, `adrl/api/service.py`, `adrl/api/store.py`, `adrl/cascade/controller.py`, `adrl/cli/ledger_commands.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/enums.py`, `adrl/core/ids.py`, `adrl/core/isolated_execution.py`, `adrl/core/launch_markers.py`, `adrl/core/resource_owner.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/ledger/events.py`, `adrl/ledger/facade.py`, `adrl/ledger/improvement.py`, `adrl/ledger/keystore.py`, `adrl/ledger/replay.py`, `adrl/ledger/session_verification.py`, `adrl/ledger/store.py`, `adrl/ledger/upcast.py`, `adrl/proxy/pipeline.py` |
| ADRL-MEM-002 | `adrl/cascade/controller.py`, `adrl/cli/ledger_commands.py`, `adrl/config/models.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/isolated_execution.py`, `adrl/core/resource_owner.py`, `adrl/learning/tiers.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/ledger/events.py`, `adrl/ledger/labels.py`, `adrl/ledger/outcomes.py`, `adrl/ledger/readiness.py`, `adrl/ledger/verification.py`, `adrl/proxy/pipeline.py` |
| ADRL-MEM-003 | `adrl/cli/ledger_commands.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/isolated_execution.py`, `adrl/core/process_owner.py`, `adrl/learning/improvement.py`, `adrl/learning/tiers.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/ledger/events.py`, `adrl/ledger/labels.py`, `adrl/ledger/session_verification.py`, `adrl/ledger/verification.py` |
| ADRL-MEM-004 | `adrl/cascade/controller.py`, `adrl/cli/ledger_commands.py`, `adrl/core/enums.py`, `adrl/learning/artifacts.py`, `adrl/learning/tiers.py`, `adrl/ledger/events.py`, `adrl/ledger/labels.py`, `adrl/ledger/outcomes.py`, `adrl/ledger/readiness.py`, `adrl/ledger/upcast.py` |
| ADRL-MEM-005 | `adrl/api/client.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/container_control.py`, `adrl/core/execution_control.py`, `adrl/core/isolated_execution.py`, `adrl/core/launch_markers.py`, `adrl/core/ports.py`, `adrl/core/resource_owner.py`, `adrl/gates/repo_class.py`, `adrl/gates/suppression.py`, `adrl/learning/abstention.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/ledger/crypto.py`, `adrl/ledger/embeddings.py`, `adrl/ledger/erasure.py`, `adrl/ledger/improvement.py`, `adrl/ledger/keystore.py`, `adrl/ledger/shadow_retrieval.py`, `adrl/ledger/verification.py` |
| ADRL-MEM-006 | `adrl/core/ports.py`, `adrl/learning/abstention.py`, `adrl/ledger/facade.py`, `adrl/ledger/readiness.py`, `adrl/ledger/state.py`, `adrl/ledger/store.py`, `adrl/proxy/observe_only.py`, `adrl/telemetry/metrics.py` |
| ADRL-MEM-007 | `adrl/learning/dataset.py`, `adrl/ledger/erasure.py`, `adrl/ledger/projections.py`, `adrl/ledger/replay.py`, `adrl/ledger/shadow_retrieval.py`, `adrl/ledger/store.py` |
| ADRL-MEM-008 | `adrl/ledger/shadow_retrieval.py` |
| ADRL-MEM-009 | `adrl/learning/pairs.py`, `adrl/ledger/counterfactual.py`, `adrl/ledger/events.py`, `adrl/ledger/verification.py` |
| ADRL-MEM-010 | `adrl/api/store.py`, `adrl/cli/improvement.py`, `adrl/cli/ledger_commands.py`, `adrl/config/models.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/isolated_execution.py`, `adrl/core/launch_markers.py`, `adrl/core/ports.py`, `adrl/core/resource_owner.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/ledger/crypto.py`, `adrl/ledger/embeddings.py`, `adrl/ledger/erasure.py`, `adrl/ledger/events.py`, `adrl/ledger/improvement.py`, `adrl/ledger/keystore.py`, `adrl/ledger/projections.py`, `adrl/ledger/retention.py`, `adrl/ledger/session_verification.py`, `adrl/ledger/verification.py` |
| ADRL-OPS-001 | `adrl/cli/main.py`, `adrl/config/settings.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/container_control.py`, `adrl/core/execution_control.py`, `adrl/core/isolated_execution.py`, `adrl/core/launch_markers.py`, `adrl/core/process_anchor.py`, `adrl/core/process_owner.py`, `adrl/core/resource_owner.py`, `adrl/ledger/attempts.py`, `adrl/ledger/keystore.py`, `adrl/telemetry/logging.py` |
| ADRL-OPS-002 | `adrl/ledger/anchoring.py` |
| ADRL-OPS-003 | `adrl/config/checks.py` |
| ADRL-OPS-004 | `adrl/ledger/erasure.py` |
| ADRL-OPS-005 | `adrl/gates/pin.py`, `adrl/gates/pipeline.py` |
| ADRL-OPS-006 | `adrl/cascade/sticky.py`, `adrl/wire/observe.py` |
| ADRL-OPS-007 | `adrl/ledger/anchoring.py` |
| ADRL-OPS-008 | `adrl/proxy/fallback.py` |
| ADRL-RTG-001 | `adrl/config/checks.py`, `adrl/config/models.py`, `adrl/routing/registry.py` |
| ADRL-RTG-002 | `adrl/config/models.py`, `adrl/core/types.py`, `adrl/proxy/stages.py`, `adrl/routing/cost.py`, `adrl/routing/policy.py`, `adrl/routing/router.py` |
| ADRL-RTG-003 | `adrl/config/models.py`, `adrl/routing/features.py`, `adrl/routing/policy.py`, `adrl/routing/router.py`, `adrl/routing/rule_health.py` |
| ADRL-RTG-004 | `adrl/config/models.py`, `adrl/routing/cascade_feasibility.py`, `adrl/routing/router.py`, `adrl/routing/side_effects.py` |
| ADRL-RTG-005 | `adrl/config/models.py`, `adrl/routing/cost.py` |
| ADRL-RTG-006 | `adrl/routing/advisor.py`, `adrl/routing/router.py` |
| ADRL-RTG-008 | `adrl/gates/deployments.py`, `adrl/routing/registry.py`, `adrl/telemetry/semconv.py` |
| ADRL-RTG-009 | `adrl/config/models.py`, `adrl/core/types.py`, `adrl/routing/cost.py`, `adrl/routing/router.py`, `adrl/wire/observe.py` |
| ADRL-SAF-001 | `adrl/core/types.py`, `adrl/gates/deployments.py`, `adrl/gates/pipeline.py`, `adrl/learning/explore.py`, `adrl/proxy/fallback.py`, `adrl/proxy/pipeline.py`, `adrl/proxy/stages.py`, `adrl/telemetry/metrics.py` |
| ADRL-SAF-002 | `adrl/gates/cli.py`, `adrl/gates/pin.py`, `adrl/gates/pipeline.py`, `adrl/learning/explore.py`, `adrl/learning/pairs.py`, `adrl/ledger/embeddings.py`, `adrl/ledger/erasure.py`, `adrl/ledger/facade.py`, `adrl/ledger/state.py` |
| ADRL-SAF-003 | `adrl/core/ports.py`, `adrl/gates/cli.py`, `adrl/gates/content.py`, `adrl/gates/coverage.py`, `adrl/gates/detectors.py`, `adrl/gates/measure.py`, `adrl/gates/pipeline.py`, `adrl/gates/secrets.py`, `adrl/gates/suppression.py` |
| ADRL-SAF-004 | `adrl/core/errors.py`, `adrl/gates/block.py`, `adrl/wire/profiles/messages_responses.py` |
| ADRL-SAF-005 | `adrl/config/checks.py`, `adrl/core/errors.py`, `adrl/gates/block.py`, `adrl/gates/feasibility.py`, `adrl/gates/pipeline.py`, `adrl/telemetry/metrics.py`, `adrl/wire/profiles/messages_responses.py` |
| ADRL-SAF-006 | `adrl/core/ports.py`, `adrl/gates/content.py`, `adrl/gates/feasibility.py`, `adrl/gates/pipeline.py` |
| ADRL-SAF-007 | `adrl/core/attempt_coordinator.py`, `adrl/core/container_control.py`, `adrl/core/execution_control.py`, `adrl/core/isolated_execution.py`, `adrl/core/ports.py`, `adrl/core/process_anchor.py`, `adrl/core/process_owner.py`, `adrl/core/resource_owner.py`, `adrl/gates/cli.py`, `adrl/gates/sandbox.py`, `adrl/ledger/capture.py`, `adrl/ledger/session_verification.py`, `adrl/ledger/verification.py` |
| ADRL-SAF-008 | `adrl/config/loaders.py`, `adrl/config/models.py`, `adrl/gates/content.py`, `adrl/gates/deployments.py`, `adrl/gates/pipeline.py`, `adrl/gates/repo_class.py`, `adrl/gates/workload.py` |
| ADRL-SAF-009 | `adrl/cli/main.py`, `adrl/gates/cli.py`, `adrl/gates/deployments.py`, `adrl/gates/egress.py`, `adrl/gates/pipeline.py`, `adrl/ledger/anchoring.py`, `adrl/ledger/egress.py`, `adrl/proxy/fallback.py`, `adrl/proxy/pipeline.py`, `adrl/telemetry/metrics.py` |
| ADRL-SEM-001 | `adrl/core/types.py`, `adrl/gates/feasibility.py`, `adrl/telemetry/metrics.py`, `adrl/wire/classify.py`, `adrl/wire/parse.py` |
| ADRL-SEM-002 | `adrl/api/auth.py`, `adrl/core/ids.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/wire/adapters.py`, `adrl/wire/identity.py` |
| ADRL-SEM-003 | `adrl/proxy/pipeline.py` |
| ADRL-SEM-004 | `adrl/config/models.py`, `adrl/gates/block.py`, `adrl/proxy/pipeline.py`, `adrl/wire/classify.py`, `adrl/wire/profiles/messages_responses.py` |
| ADRL-SEM-005 | `adrl/cascade/sticky.py` |
| ADRL-SEM-006 | `adrl/cascade/controller.py`, `adrl/core/process_anchor.py`, `adrl/core/process_owner.py`, `adrl/proxy/observe_only.py`, `adrl/proxy/pipeline.py`, `adrl/wire/identity.py` |
| ADRL-SEM-007 | `adrl/api/client.py`, `adrl/api/contracts.py`, `adrl/api/http.py`, `adrl/api/schema.py`, `adrl/api/service.py`, `adrl/cli/product.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py`, `adrl/ledger/session_verification.py`, `adrl/proxy/errors.py`, `adrl/wire/adapters.py`, `adrl/wire/profiles/base.py`, `adrl/wire/profiles/messages.py`, `adrl/wire/profiles/messages_responses.py` |
| ADRL-TRU-001 | `adrl/api/auth.py`, `adrl/api/contracts.py`, `adrl/api/http.py`, `adrl/api/service.py`, `adrl/cli/product.py`, `adrl/core/attempt_coordinator.py`, `adrl/core/container_control.py`, `adrl/core/execution_control.py`, `adrl/core/isolated_execution.py`, `adrl/core/launch_markers.py`, `adrl/core/process_anchor.py`, `adrl/core/process_owner.py`, `adrl/core/resource_owner.py`, `adrl/gates/repo_class.py`, `adrl/gates/workload.py`, `adrl/ledger/attempts.py`, `adrl/ledger/capture.py` |
| ADRL-TRU-002 | `adrl/core/types.py`, `adrl/gates/deployments.py`, `adrl/proxy/pipeline.py`, `adrl/wire/observe.py` |
| ADRL-TRU-003 | `adrl/ledger/anchoring.py`, `adrl/ledger/egress.py` |

## Register decisions with no implementing module

- ADRL-EVL-001
- ADRL-EVL-008
- ADRL-RTG-007

## Phantom citations (not in the register)

- none

Modules without an ADR ID in their docstring: 0

