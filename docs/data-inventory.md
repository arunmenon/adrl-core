# Data inventory

Field-level classification of everything ADRL persists (ADRL-MEM-005, ADRL-MEM-010). Checked by
`tools/check_data_inventory.py`, which fails on any field missing here or classed
`plaintext_prompt_class`. Regenerate the candidate list with `--list`.

Classes:

- `skeleton`: identifiers, timestamps, enum values, counts, versions, digests. Retained for the
  evidence horizon; never derived from prompt text.
- `keyed_hash`: HMAC under a host-local secret of a path, command line, session key or content
  span. Unlinkable across hosts; not reversible; retained with the skeleton.
- `encrypted_prompt_class`: prompt-class material sealed with AES-GCM under a per-session key
  from the keystore. Crypto-shredding the session key (`adrl ledger erase`, retention sweep,
  late pin) makes it unreadable in place.
- `plaintext_prompt_class`: prompt content, paths, command lines or program output in clear.
  Target is zero; the check fails if any appears.

Naming: `table.column` for ledger and egress-ledger columns; `module:key` for JSON payload keys
emitted by that producer module (`events` is `adrl.ledger.events`, `verification` is
`adrl.ledger.verification`, and so on). Keys that only ever occur inside a sealed blob are
listed as `encrypted_prompt_class` because that is the only form in which they reach disk.

Logs: structlog lines carry identifiers, hashes, detector ids, counts and exception class names.
No handler receives request bodies, tool inputs or program output.

| Field | Class | Note |
|---|---|---|
| `checkpoint_shipments.checkpoint_seq` | `skeleton` |  |
| `checkpoint_shipments.destination` | `skeleton` |  |
| `checkpoint_shipments.seq` | `skeleton` |  |
| `checkpoint_shipments.ts` | `skeleton` |  |
| `checkpoints.digest` | `skeleton` |  |
| `checkpoints.event_seq` | `skeleton` |  |
| `checkpoints.key_id` | `skeleton` |  |
| `checkpoints.seq` | `skeleton` |  |
| `checkpoints.signature` | `skeleton` |  |
| `checkpoints.ts` | `skeleton` |  |
| `decisions.cascade_feasible` | `skeleton` |  |
| `decisions.cascade_reason` | `skeleton` |  |
| `decisions.classifier_provenance_json` | `skeleton` | model id, prompt hash, label, confidence |
| `decisions.content_bearing` | `skeleton` |  |
| `decisions.context_json` | `skeleton` | identifiers, verdict records, config versions, protocol/adapter IDs and versions, supported-operation flag |
| `decisions.decided_rung` | `skeleton` |  |
| `decisions.estimator` | `skeleton` |  |
| `decisions.estimator_version` | `skeleton` |  |
| `decisions.explore_version` | `skeleton` |  |
| `decisions.features_json` | `skeleton` | counts, scores and enum values computed at decision time; no text |
| `decisions.features_version` | `skeleton` |  |
| `decisions.lineage_hmac` | `keyed_hash` |  |
| `decisions.no_rung_met_threshold` | `skeleton` |  |
| `decisions.objective_version` | `skeleton` |  |
| `decisions.permitted_set` | `skeleton` |  |
| `decisions.policy_version` | `skeleton` |  |
| `decisions.propensity` | `skeleton` |  |
| `decisions.request_class` | `skeleton` |  |
| `decisions.route_id` | `skeleton` |  |
| `decisions.schema_version` | `skeleton` |  |
| `decisions.session_hmac` | `keyed_hash` |  |
| `decisions.ts` | `skeleton` |  |
| `egress:block` | `skeleton` | error code only |
| `egress:failure_class` | `skeleton` |  |
| `egress:pinned` | `skeleton` |  |
| `egress:unscanned` | `skeleton` |  |
| `egress_events.actor` | `skeleton` |  |
| `egress_events.bytes_out` | `skeleton` |  |
| `egress_events.content_bearing` | `skeleton` |  |
| `egress_events.deployment_tag` | `skeleton` |  |
| `egress_events.destination_rung` | `skeleton` |  |
| `egress_events.detector_tier` | `skeleton` |  |
| `egress_events.digest` | `skeleton` |  |
| `egress_events.event_kind` | `skeleton` |  |
| `egress_events.gate_verdicts_json` | `skeleton` |  |
| `egress_events.lineage_hmac` | `keyed_hash` |  |
| `egress_events.prev_digest` | `skeleton` |  |
| `egress_events.reason` | `skeleton` |  |
| `egress_events.request_class` | `skeleton` |  |
| `egress_events.schema_version` | `skeleton` |  |
| `egress_events.seq` | `skeleton` |  |
| `egress_events.span_hashes_json` | `keyed_hash` |  |
| `egress_events.ts` | `skeleton` |  |
| `embeddings.ciphertext` | `encrypted_prompt_class` |  |
| `embeddings.dimension` | `skeleton` |  |
| `embeddings.embedder_version` | `skeleton` |  |
| `embeddings.nonce` | `encrypted_prompt_class` |  |
| `embeddings.route_id` | `skeleton` |  |
| `embeddings.seq` | `skeleton` |  |
| `embeddings.session_hmac` | `keyed_hash` |  |
| `embeddings.ts` | `skeleton` |  |
| `erasure:embedding_rows` | `skeleton` |  |
| `erasure:key_shredded` | `skeleton` |  |
| `erasure:reason` | `skeleton` |  |
| `erasure:schema_version` | `skeleton` |  |
| `erasure:session_hmac` | `keyed_hash` |  |
| `events.event_type` | `skeleton` |  |
| `events.payload_json` | `skeleton` |  |
| `events.producer` | `skeleton` |  |
| `events.producer_seq` | `skeleton` |  |
| `events.route_id` | `skeleton` |  |
| `events.schema_version` | `skeleton` |  |
| `events.seq` | `skeleton` |  |
| `events.ts` | `skeleton` |  |
| `events:argv` | `keyed_hash` | check name plus hmac of the command line |
| `events:causes` | `skeleton` |  |
| `events:checks` | `skeleton` | status, exit code, byte lengths and keyed hashes per check |
| `events:detail` | `skeleton` | late-evidence detail: ids and results |
| `events:escalated_to_route_id` | `skeleton` |  |
| `events:failure_types_version` | `skeleton` |  |
| `events:finished_at` | `skeleton` |  |
| `events:harness_reported_success` | `skeleton` |  |
| `events:job_id` | `skeleton` |  |
| `events:lineage_hmac` | `keyed_hash` |  |
| `events:operation` | `skeleton` |  |
| `events:pair_id` | `skeleton` |  |
| `events:protected_path_policy_version` | `skeleton` |  |
| `events:reason` | `skeleton` |  |
| `events:result` | `skeleton` |  |
| `events:served_model` | `skeleton` |  |
| `events:served_rung` | `skeleton` |  |
| `events:session_hmac` | `keyed_hash` |  |
| `events:source` | `skeleton` |  |
| `events:started_at` | `skeleton` |  |
| `events:tier` | `skeleton` |  |
| `events:touched_paths` | `keyed_hash` | keyed path hashes written by the cascade |
| `events:tree_drift` | `skeleton` |  |
| `events:tree_identity` | `keyed_hash` | content hashes and keyed path pseudonyms |
| `events:turn_index` | `skeleton` |  |
| `events:unverifiable_reason` | `skeleton` |  |
| `events:verifier_version` | `skeleton` |  |
| `instruction_hashes.ciphertext` | `encrypted_prompt_class` |  |
| `instruction_hashes.hmac_key_id` | `keyed_hash` |  |
| `instruction_hashes.nonce` | `encrypted_prompt_class` |  |
| `instruction_hashes.route_id` | `skeleton` |  |
| `instruction_hashes.seq` | `skeleton` |  |
| `instruction_hashes.session_hmac` | `keyed_hash` |  |
| `instruction_hashes.ts` | `skeleton` |  |
| `lineage_events.event_type` | `skeleton` |  |
| `lineage_events.lineage_hmac` | `keyed_hash` |  |
| `lineage_events.payload_json` | `skeleton` |  |
| `lineage_events.seq` | `skeleton` |  |
| `lineage_events.ts` | `skeleton` |  |
| `meta.key` | `skeleton` |  |
| `meta.value` | `skeleton` |  |
| `pin:actor` | `skeleton` |  |
| `pin:content_type` | `skeleton` |  |
| `pin:corroboration` | `skeleton` |  |
| `pin:detector_id` | `skeleton` |  |
| `pin:finding_id` | `skeleton` |  |
| `pin:gate` | `skeleton` |  |
| `pin:pinned` | `skeleton` |  |
| `pin:promoted` | `skeleton` |  |
| `pin:reason` | `skeleton` |  |
| `pin:request_class` | `skeleton` |  |
| `pin:session_hmac` | `keyed_hash` |  |
| `pin:source` | `skeleton` |  |
| `pin:span_hash` | `keyed_hash` |  |
| `pin:tier` | `skeleton` |  |
| `pin:would_pin` | `skeleton` |  |
| `pipeline:action` | `skeleton` |  |
| `pipeline:exception` | `skeleton` | exception class name only |
| `pipeline:failure_class` | `skeleton` |  |
| `pipeline:gate` | `skeleton` |  |
| `pipeline:mode` | `skeleton` |  |
| `pipeline:pinned` | `skeleton` |  |
| `pipeline:request_class` | `skeleton` |  |
| `pipeline:unscanned` | `skeleton` |  |
| `projections.code_version` | `skeleton` |  |
| `projections.embedder_version` | `skeleton` |  |
| `projections.high_water_seq` | `skeleton` |  |
| `projections.name` | `skeleton` |  |
| `projections.seq` | `skeleton` |  |
| `projections.state` | `skeleton` |  |
| `projections.ts` | `skeleton` |  |
| `repo_class:allowed_rungs` | `skeleton` |  |
| `repo_class:assertion_id` | `skeleton` |  |
| `repo_class:class_id` | `skeleton` |  |
| `repo_class:corroborated` | `skeleton` |  |
| `repo_class:evidence_hashes` | `keyed_hash` |  |
| `repo_class:release_permitted` | `skeleton` |  |
| `repo_class:repo_id` | `skeleton` | manifest identifier chosen by security, not prompt content |
| `repo_class:residency` | `skeleton` |  |
| `repo_class:restricted` | `skeleton` |  |
| `repo_class:restricted_prefix_hit` | `skeleton` |  |
| `repo_class:source` | `skeleton` |  |
| `session_keys.action` | `skeleton` |  |
| `session_keys.key_id` | `skeleton` |  |
| `session_keys.reason` | `skeleton` |  |
| `session_keys.seq` | `skeleton` |  |
| `session_keys.session_hmac` | `keyed_hash` |  |
| `session_keys.ts` | `skeleton` |  |
| `session_keys.wrapped_key` | `skeleton` | always NULL; keys live only in the 0600 keystore |
| `verification:argv_hash` | `keyed_hash` |  |
| `verification:argv_hashes` | `keyed_hash` |  |
| `verification:baseline` | `skeleton` |  |
| `verification:baseline_files` | `keyed_hash` |  |
| `verification:check_names` | `skeleton` |  |
| `verification:ciphertext` | `encrypted_prompt_class` |  |
| `verification:closed_turn_identity` | `skeleton` |  |
| `verification:content_hash` | `keyed_hash` |  |
| `verification:duration_s` | `skeleton` |  |
| `verification:excluding_touched_hash` | `keyed_hash` |  |
| `verification:exit_code` | `skeleton` |  |
| `verification:file_count` | `skeleton` |  |
| `verification:harness` | `skeleton` |  |
| `verification:head_commit` | `skeleton` |  |
| `verification:job_id` | `skeleton` |  |
| `verification:key_id` | `keyed_hash` |  |
| `verification:model` | `skeleton` |  |
| `verification:name` | `skeleton` |  |
| `verification:nonce` | `encrypted_prompt_class` |  |
| `verification:plan` | `encrypted_prompt_class` | inside the sealed job material only (argv); plaintext keeps names and keyed hashes |
| `verification:plan_sha256` | `keyed_hash` |  |
| `verification:plan_version` | `skeleton` |  |
| `verification:protected_files` | `keyed_hash` |  |
| `verification:reason` | `skeleton` |  |
| `verification:required` | `skeleton` |  |
| `verification:result` | `skeleton` |  |
| `verification:route_id` | `skeleton` |  |
| `verification:schema_version` | `skeleton` |  |
| `verification:sealed` | `encrypted_prompt_class` |  |
| `verification:sealed_reason` | `skeleton` |  |
| `verification:served_rung` | `skeleton` |  |
| `verification:session_hmac` | `keyed_hash` |  |
| `verification:status` | `skeleton` |  |
| `verification:stderr_bytes` | `skeleton` |  |
| `verification:stderr_hash` | `keyed_hash` |  |
| `verification:stderr_tail` | `encrypted_prompt_class` | inside the sealed output blob only (last 400 chars) |
| `verification:stdout_bytes` | `skeleton` |  |
| `verification:stdout_hash` | `keyed_hash` |  |
| `verification:stdout_tail` | `encrypted_prompt_class` | inside the sealed output blob only (last 400 chars) |
| `verification:touched_path_hashes` | `keyed_hash` |  |
| `verification:touched_paths` | `encrypted_prompt_class` | inside the sealed job material only |
| `verification:tree_drift` | `skeleton` |  |
| `verification:verifier_version` | `skeleton` |  |
| `verification:violations` | `skeleton` |  |
| `verification:workspace` | `encrypted_prompt_class` | inside the sealed job material only; AES-GCM under the session key |
| `verification:workspace_hash` | `keyed_hash` |  |
| `verification_jobs.job_id` | `skeleton` |  |
| `verification_jobs.payload_json` | `skeleton` |  |
| `verification_jobs.route_id` | `skeleton` |  |
| `verification_jobs.seq` | `skeleton` |  |
| `verification_jobs.status` | `skeleton` |  |
| `verification_jobs.ts` | `skeleton` |  |

## Product service fields (2026-09-07)

| Field | Class | Treatment |
|---|---|---|
| `product_events.ciphertext` | `encrypted_prompt_class` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.event_key` | `keyed_hash` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.event_type` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.nonce` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.producer_id` | `keyed_hash` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.producer_seq` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.route_id` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.seq` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.sequence_status` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.session_hmac` | `keyed_hash` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_events.ts` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.adapter_id` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.adapter_version` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.config_digest` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.policy_version` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.profile_id` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.profile_version` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.session_hmac` | `keyed_hash` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.ts` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_sessions.workload_ref` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_timeline.route_id` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_timeline.seq` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_timeline.session_hmac` | `keyed_hash` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_timeline.source` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_timeline.source_seq` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |
| `product_timeline.ts` | `skeleton` | Product service migration 0003; caller envelopes encrypted under the session key |

The local Claude connection directory is a separate client copy. Its assertion credential,
outbox key and encrypted outbox are not erased by the server erasure operation. See
`docs/product-services.md` for its lifecycle and the explicit pilot limitation.

| `product_sessions.integration_mode` | `skeleton` | Migration 0004; immutable gateway/observe coverage mode, legacy bindings default to gateway |

## Session verification receipts (preview 4)

The typed receipt, including task, snapshot, command and output references, is entirely
inside session-key encryption. Erasure denies both decryption and new receipts. The
local operator plan and temporary test workspace have separate retention lifecycles.

| Field | Class | Note |
|---|---|---|
| `product_verifications.seq` | `skeleton` | Append order |
| `product_verifications.session_hmac` | `keyed_hash` | Existing bound session |
| `product_verifications.job_key` | `keyed_hash` | Session-key HMAC of job ID; not a route |
| `product_verifications.phase` | `skeleton` | started or finished |
| `product_verifications.nonce` | `skeleton` | AEAD nonce |
| `product_verifications.ciphertext` | `encrypted_prompt_class` | Typed session verification receipt |
| `product_verifications.ts` | `skeleton` | Record time |

## Offline verifier experiments

Migration 0006 stores the proposal, suite, every trial and final comparison encrypted
under an experiment-specific key. Its identity uses a separate HMAC namespace and
creates no product session. The existing key-shredding audit is reused. Exported
history, plans, fixtures, backups and verifier artifacts have separate retention.

| Field | Class | Note |
|---|---|---|
| `improvement_records.seq` | `skeleton` | Append order |
| `improvement_records.experiment_hmac` | `keyed_hash` | HMAC of namespaced experiment ID |
| `improvement_records.event_type` | `skeleton` | started, trial or finished |
| `improvement_records.record_key` | `keyed_hash` | Unique HMAC of record identity |
| `improvement_records.nonce` | `skeleton` | AEAD nonce |
| `improvement_records.ciphertext` | `encrypted_prompt_class` | Full versioned evidence envelope |
| `improvement_records.ts` | `skeleton` | Record time |

## Retained operator captures (internal, migration 0007)

Every request field, raw attempt/task identity, workspace reference, source hash, policy,
capture time, relative path, mode and file byte is inside the encrypted envelope. Captures reuse
the existing bound session key; this code never creates a key. No route or learning label is
created. The new table contains complete captures only, with atomic append and identity checks.

| Field | Class | Note |
|---|---|---|
| `product_captures.seq` | `skeleton` | Append order, not a task-close clock |
| `product_captures.session_hmac` | `keyed_hash` | Existing bound product session |
| `product_captures.capture_key` | `keyed_hash` | Session-key HMAC of the capture UUID |
| `product_captures.attempt_key` | `keyed_hash` | Session-key HMAC of the attempt UUID |
| `product_captures.nonce` | `skeleton` | AEAD nonce |
| `product_captures.ciphertext` | `encrypted_prompt_class` | Entire retained-operator-capture-v1 envelope |
| `product_captures.ts` | `skeleton` | Durable append time |

Key shredding denies future access, including after restoring an old key when its erasure audit
remains intact. Already returned objects and leased plaintext copies have their own lifetime.
Materialization cleans its private temporary directory on ordinary exit, exceptions and Python
cancellation. Process death, backups, swap, filesystem remnants and copies made by an operator
are not physically erased by this mechanism. Startup reconciliation and active-lease erasure
coordination remain required before real task capture. Only synthetic fixtures use this internal
slice. Erased ciphertext still consumes the archive quota; no automatic data rewrite or quota
reclamation is implemented. See [capture boundary](operator-captures.md).

## Operator attempt history (internal, migration 0008)

The entire operator command, raw task/attempt/capture IDs, initial manifest, source reference,
reason and policy are inside the session-key envelope. Initial manifests contain paths and
hashes, not file bytes. No keys, routes, learning labels or plaintext materializations are created.

| Field | Class | Note |
|---|---|---|
| `product_attempt_events.seq` | `skeleton` | Append order |
| `product_attempt_events.session_hmac` | `keyed_hash` | Existing bound session |
| `product_attempt_events.attempt_key` | `keyed_hash` | Session-key HMAC of attempt UUID |
| `product_attempt_events.event_key` | `keyed_hash` | Session-key HMAC of command UUID |
| `product_attempt_events.workspace_key` | `keyed_hash` | Host-key HMAC of canonical workspace |
| `product_attempt_events.event_type` | `skeleton` | started, close_requested, cancelled, incomplete |
| `product_attempt_events.attempt_seq` | `skeleton` | Per-attempt sequence, authenticated with payload |
| `product_attempt_events.nonce` | `skeleton` | AEAD nonce |
| `product_attempt_events.ciphertext` | `encrypted_prompt_class` | Complete operator-attempt-event-v1 |
| `product_attempt_events.ts` | `skeleton` | Append time checked against encrypted event |

Erasure denies reads/appends and does not reclaim ciphertext quota or release an unfinished
workspace reservation. Active in-memory copies and external backups retain separate lifetimes.
Only synthetic fixtures are used. See [journal boundary](attempt-lifecycle.md) for its quota,
pending-history and recovery limits; this addition does not settle the wider DQ6 copy policy.

## Reserved attempt capacity (W3.2b2a, 2026-09-08)

Schema 9 adds six accounting fields. The grant is appended atomically with a v2 start and
never rewritten; its consumption is inferred from the terminal event. These fields reuse
existing keyed identities and expose only quota/version metadata, not raw task content.
Erasing a pending session leaves the commitment charged; no new key or plaintext copy exists.
The metadata remains after key shredding, as do the existing journal skeleton and ciphertext.

| Field | Class | Note |
|---|---|---|
| `product_attempt_events.capacity_version` | `skeleton` | Zero for legacy; v2 binds version one into AEAD associated data |
| `product_attempt_capacity.session_hmac` | `keyed_hash` | Existing bound-session key |
| `product_attempt_capacity.attempt_key` | `keyed_hash` | Existing session-key HMAC of attempt UUID |
| `product_attempt_capacity.start_event_key` | `keyed_hash` | Existing session-key HMAC of start command UUID |
| `product_attempt_capacity.reserved_bytes` | `skeleton` | Logical encrypted terminal allowance, not allocated disk blocks |
| `product_attempt_capacity.history_limit` | `skeleton` | Versioned admission ceiling checked against encrypted start policy |

The complete v2 policy is inside the existing encrypted event, not a new plaintext payload.
Active reservation, erasure/release and physical storage failure remain distinct concerns.
See the [journal contract](attempt-lifecycle.md) for v1 compatibility and the remaining gates.

## Keystore revocation filesystem metadata (W3.2b2b1, 2026-09-08)

The schema/payload field scan remains 279 fields. These three additional metadata entries
describe the keystore filesystem surface, outside the SQL/payload scan. They add no raw
task material or session keys to the ledger. Production filenames reuse the existing keyed
session identity; the lower-level library also accepts safe opaque fixture identities.

| Field | Class | Note |
|---|---|---|
| `keystore.revocation.identity` | `keyed_hash` | Existing session identity in revoked/<identity>.revoked; permanently retires that identity |
| `keystore.revocation.version` | `skeleton` | Fixed session-key-revocation-v1 bytes; even incomplete marker presence denies access |
| `keystore.coordination_lock` | `skeleton` | Empty private .keystore.lock; no key, PID or task payload; do not delete while callers are active |

Revocation markers survive session key removal and audit failure. They contain no reason,
raw path, key bytes or captured output. They are not erased with the key because their role
is to prevent that identity being reused. A keystore restore must preserve newer revocations;
restoring both old markers/audit and old wrapped keys remains an unresolved backup-recovery
boundary, not an approved way to resume an erased session.

**Key material remains a separate filesystem secret, never ledger payload.** Atomic writes
temporarily hold the same bytes as their destination: raw host master/HMAC secret or wrapped
session key. Files use 0600 under private directories and the owned name
`.key-write-<target-name>-<random>`. Normal failure removes the temporary; process death can
leave it. Session creation/shredding cleans only that session's pending files, and keystore
initialization cleans host-secret pending writes. These key files are not classified as
anonymized metadata or as encrypted task payload. No physical-block, snapshot, backup or
cached-key erasure guarantee follows from unlinking them. See [key revocation](key-revocation.md).

## W3.2b2b2 permanent execution-fence metadata

These rows block workspace reuse even after session key revocation. No release or deletion path
is implemented. Policy JSON contains only versions, numeric bounds and the nested ProcessPolicy;
no process request or report is stored here. See [coordination limits](attempt-coordination.md).

| Field | Class | Note |
|---|---|---|
| `product_execution_fences.workspace_key` | `keyed_hash` | Host-key HMAC of canonical workspace, no raw path |
| `product_execution_fences.session_hmac` | `keyed_hash` | Existing bound session pseudonym |
| `product_execution_fences.attempt_key` | `keyed_hash` | Session-key HMAC of attempt ID |
| `product_execution_fences.start_event_key` | `keyed_hash` | Session-key HMAC of original start event ID |
| `product_execution_fences.host_key_id` | `skeleton` | Detects host HMAC key rotation; refuses new admission |
| `product_execution_fences.policy_json` | `skeleton` | Validated bounded versioned coordination and process policy |
| `product_execution_fences.ts` | `skeleton` | Admission timestamp, not process start or completion time |

## W3.2b2d1 stopped resource metadata (2026-09-08)

The internal stopped-resource owner adds an append-only five-phase, host-authenticated history.
The fence policy JSON may now hold `stopped-resource-policy-v1`; it still has no command,
workspace path, task material or credential. The inventory checker enumerates every field of
ResourceEvent and its nested ResourcePolicy as well as the SQL columns.

Cleanup metadata deliberately survives session-key revocation. Keyed references are pseudonyms,
not a claim of anonymity or complete erasure. Resource/image identifiers, timestamps and limits
remain operational metadata. Host key loss prevents cleanup authentication. See the
[ownership contract](stopped-resource-ownership.md) for retention and recovery limitations.

| Field | Class | Note |
|---|---|---|
| `product_resource_events.operation_key` | `keyed_hash` | Host-keyed operation UUID |
| `product_resource_events.workspace_key` | `keyed_hash` | Existing canonical workspace HMAC; permanent fence foreign key |
| `product_resource_events.event_seq` | `skeleton` | Bounded sequence 0 through 4 |
| `product_resource_events.event_type` | `skeleton` | Intent, issued, bound or removal phase |
| `product_resource_events.payload_json` | `skeleton` | Validated operational metadata envelope; nested fields inventoried below |
| `product_resource_events.prev_mac` | `keyed_hash` | Previous authenticated event MAC |
| `product_resource_events.mac` | `keyed_hash` | Host-keyed chain authenticator, not a content key |
| `ResourceEvent:schema_version` | `skeleton` | Versioned operational limit or contract discriminator |
| `ResourceEvent:operation_key` | `keyed_hash` | Host HMAC of opaque operation UUID |
| `ResourceEvent:workspace_key` | `keyed_hash` | Existing host HMAC of canonical workspace |
| `ResourceEvent:session_hmac` | `keyed_hash` | Existing bound session pseudonym |
| `ResourceEvent:attempt_key` | `keyed_hash` | Existing session-key HMAC of attempt UUID |
| `ResourceEvent:start_event_key` | `keyed_hash` | Existing session-key HMAC of initial event UUID |
| `ResourceEvent:host_key_id` | `skeleton` | Detects host HMAC key change |
| `ResourceEvent:engine_ref` | `keyed_hash` | Host HMAC of local endpoint, engine ID and API version |
| `ResourceEvent:request_ref` | `keyed_hash` | Host HMAC of requested image/argv, policy, profile pin and engine reference |
| `ResourceEvent:image_id` | `skeleton` | Immutable local fixture image SHA-256 ID |
| `ResourceEvent:seccomp_sha256` | `skeleton` | Digest of supplied public seccomp profile bytes |
| `ResourceEvent:policy` | `skeleton` | Nested versioned bounds; every policy field is enumerated below |
| `ResourceEvent:sequence` | `skeleton` | Versioned operational limit or contract discriminator |
| `ResourceEvent:phase` | `skeleton` | Versioned operational limit or contract discriminator |
| `ResourceEvent:recorded_at` | `skeleton` | Ledger observation time, not task completion time |
| `ResourceEvent:resource_id` | `skeleton` | Exact full Engine resource ID, never a saved host PID |
| `ResourceEvent:resource_created` | `skeleton` | Exact engine creation timestamp, including fractional precision |
| `ResourceEvent:configuration_ref` | `keyed_hash` | Host HMAC of complete inspected Config/HostConfig/mount/command identity |
| `ResourceEvent:workspace_state` | `skeleton` | Always blocked; no release is implemented |
| `ResourceEvent:exact_close_eligible` | `skeleton` | Always false |
| `ResourceEvent:eligible_for_learning` | `skeleton` | Always false |
| `ResourcePolicy:schema_version` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:api_version` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:max_resources` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:max_event_bytes` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:request_seconds` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:response_bytes` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:command_bytes` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:memory_bytes` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:pids_limit` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:nano_cpus` | `skeleton` | Versioned preparation bound; no task payload or credential |
| `ResourcePolicy:user` | `skeleton` | Versioned preparation bound; no task payload or credential |

The engine receives argv, a fixed environment and profile JSON in memory. A stopped container
still stores its configuration and writable layer in daemon-managed storage. Synthetic fixtures
only: no host repository/credential/socket mounts, payload execution or model calls are enabled.
Non-force removal and absence reconciliation do not prove physical block, snapshot or backup
erasure. No new retention disposition for real data is implied.


## W3.2b2d2 one-shot fixture execution, schema 12

These operational records do not contain task payloads. Keyed references and resource/timestamp
metadata remain linkable after content-key erasure; they are not anonymous. At most 32 histories,
eight 4096-byte events each, and 32 permanent <=64-byte denial markers form a logical metadata
ceiling independent of encrypted attempt-content grants, not preallocated disk capacity.
Raw inspection, engine/socket profile and image-layer evidence are used in memory and hashed.
The complete event and policy model fields are checked by the inventory scanner.

| Field | Class | Meaning |
|---|---|---|
| `product_launch_events.operation_key` | `keyed_hash` | Existing authenticated resource operation reference |
| `product_launch_events.event_seq` | `skeleton` | Sequence 0 through 7 |
| `product_launch_events.event_type` | `skeleton` | Claim, acknowledgement, seal, stopped or discard phase |
| `product_launch_events.payload_json` | `skeleton` | Validated metadata envelope; nested fields below |
| `product_launch_events.prev_mac` | `keyed_hash` | Prior launch or original bound-event MAC |
| `product_launch_events.mac` | `keyed_hash` | Host-keyed launch chain authenticator |
| `LaunchEvent:schema_version` | `skeleton` | Versioned record discriminator |
| `LaunchEvent:operation_key` | `keyed_hash` | Existing opaque operation UUID HMAC |
| `LaunchEvent:workspace_key` | `keyed_hash` | Existing canonical workspace HMAC and permanent fence |
| `LaunchEvent:host_key_id` | `skeleton` | Detects host HMAC key replacement |
| `LaunchEvent:resource_id` | `skeleton` | Original exact full Engine ID; no saved host PID |
| `LaunchEvent:resource_created` | `skeleton` | Exact original daemon creation timestamp |
| `LaunchEvent:resource_mac` | `keyed_hash` | Original authenticated stopped binding MAC |
| `LaunchEvent:engine_ref` | `keyed_hash` | HMAC of engine identity, endpoint and capability/version profile |
| `LaunchEvent:configuration_ref` | `keyed_hash` | HMAC of complete execution projection including Id/Created |
| `LaunchEvent:fixture_ref` | `keyed_hash` | HMAC of admitted image/layer/binary/argv evidence |
| `LaunchEvent:policy` | `skeleton` | Nested versioned bounds and pinned public fixture/profile constants |
| `LaunchEvent:sequence` | `skeleton` | Bounded event sequence |
| `LaunchEvent:phase` | `skeleton` | Validated launch lifecycle phase |
| `LaunchEvent:recorded_at` | `skeleton` | Observation time, not task completion |
| `LaunchEvent:started_at` | `skeleton` | Exact acknowledged first start timestamp; null before acknowledgement |
| `LaunchEvent:workspace_state` | `skeleton` | Always blocked |
| `LaunchEvent:exact_close_eligible` | `skeleton` | Always false |
| `LaunchEvent:eligible_for_learning` | `skeleton` | Always false |
| `ExecutionPolicy:schema_version` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:active_request_seconds` | `skeleton` | V2 active HTTP phase/elapsed-response bound; default two seconds. V1 histories retain the fixed two-second admission ceiling and original coupled transport |
| `ExecutionPolicy:max_histories` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:max_events` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:max_event_bytes` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:max_marker_bytes` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:marker_directory` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:marker_contents` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:poll_seconds` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:max_run_seconds` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:stop_seconds` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:ledger_seconds` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:fixture_lifetime_seconds` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:engine_version` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:api_version` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:kernel_version` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:cgroup_driver` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:seccomp_sha256` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:archive_sha256` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:executable_sha256` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `ExecutionPolicy:fixture_argv` | `skeleton` | Versioned operational bound or pinned public engine/fixture constant; no task payload |
| `launch_denial:filename` | `keyed_hash` | Existing resource operation HMAC with fixed .denied suffix; permanent denial only |
| `launch_denial:contents` | `skeleton` | Fixed adrl-launch-denial-v1 line, <=64 bytes; never task content |
| `launch_denial:directory` | `skeleton` | Fixed launch-denials-v1 subdirectory under private keystore root |
| `launch_denial:lock` | `skeleton` | Fixed .launch-denial.lock; local nonblocking advisory lock, no payload |
| `launch_denial:filesystem_metadata` | `skeleton` | Filesystem UID, permissions, link count, size and timestamps; locally linkable |
| `ExecutionPolicy:recovery_directory` | `skeleton` | Fixed private launch-recovery-locks-v1 directory; separate from marker publication lock |
| `launch_recovery:filename` | `keyed_hash` | Authenticated operation key with .lock suffix; only existing admitted histories create files |
| `launch_recovery:metadata` | `skeleton` | Private empty mode-0600 lock and filesystem metadata, bounded by the 32 authenticated histories |
