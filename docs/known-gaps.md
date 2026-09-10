# Known gaps (reconciled 2026-09-08)

W3.2b2d1 current context: [stopped resource ownership](stopped-resource-ownership.md)
adds internal create/bind/inspect/non-force-remove for an explicitly selected local Docker
engine and synthetic image. Durable identity allows cleanup after session-key erasure; lost
create acknowledgements stay unresolved. There is no launch, kill, adoption or workspace release
operation. Schema 11 adds authenticated metadata; public API preview 4 and routing are unchanged.
Full writer containment, active plaintext erasure and exact task-close capture remain open.

W3.2b2b2 current context: [attempt stop coordination](attempt-coordination.md) now connects
the journal and process owner for disposable synthetic fixtures. A permanent prelaunch fence
blocks reuse through cancellation, erasure, terminal-write failure and restart. A dedicated
monitor requests stopping on lost authority. This is eventual observation, not atomic launch
exclusion or an erasure-completion guarantee. Complete writer containment, safe release, active
plaintext leases, crash-copy cleanup and exact-close capture binding remain open. Earlier
entries below preserve their dated scope; coordination is now partly implemented.

W3.2b2b1 current context: [persistent key revocation](key-revocation.md) closes the tested
key-removal-before-audit resurrection path. Marker publication precedes mutation; restored
files and same-session recreation are denied after audit/removal failure or a tested process
death. This does not withdraw cached keys/plaintext, certify physical deletion, anchor backup
rollback or release pending attempts. Process/erasure/release coordination remains next.

W3.2b2a current context: new [v2 attempt starts](attempt-lifecycle.md) reserve one terminal
event slot and byte allowance. This prevents later journal work from consuming those logical
quota commitments. V1 histories retain their original limits; physical disk/database failure,
expired credentials and erasure can still prevent an append. Erased pending grants remain
charged and blocked. Coordinated erasure/process/reservation release and complete writer
containment remain required before real supervised execution.

W3.2b1 current context: the [owned process-group runner](process-ownership.md) has bounded
synthetic exit/cancellation/owner-loss cleanup mechanics. A detached fixture survives by
design, so no result qualifies for exact-close attribution. It is not integrated with the
journal, captures or verifier. Complete writer containment, terminal-capacity reservation,
erasure/release coordination and restart qualification remain W3.2b2/b3 work.

W3.2a current context: the [attempt journal](attempt-lifecycle.md) records durable intent and
interruption but has no process supervisor. Reservations are journal state only. Quota exhaustion
or erasing a pending attempt can leave a reservation blocked; terminal-capacity reservation and
coordinated release are required before real execution. Capture association also remains open.

W3.1 current context: [retained operator capture](operator-captures.md) is implemented internally
for synthetic fixtures. Trusted task closure, active-copy erasure coordination, crash-leftover
cleanup and verifier/CLI binding still block real task capture. The older entries below keep
their existing policy scope; this addition changes no routing behavior.

W0 reconciliation: the health reader returns unknown for an unlisted group, but the feasibility
policy still permits a rung when it sees no reported member state. Hook failures are now ingested
as product observations; this does not make them trusted cascade inputs. The earlier closed
table retains its date and original counts. New work and owners are tracked in the sibling
register's [W0 packet](../../adrl-world-class/reports/waves/w0-baseline.md).

Each entry names the decision, what the code does today, and what closes the gap. None of these is hidden behind a passing test; they are places where the register asks for more than the current build delivers. Closed items are kept in the second table so the history of the 2026-09-03 review stays visible.

| ADR | Today | Closes the gap |
|---|---|---|
| SAF-006 | `LiteLLMHealth` returns `None` for unlisted groups; `Feasibility.rung_healthy` retains a rung if none of its members has a reported state. | DQ3/W6: disposition unknown-health eligibility and freshness; make the agreed behavior explicit and test it. |
| SEM-004 | A pinned cosmetic utility call is forwarded to the local rung when local is healthy; the empty-but-valid answer fires only when local is unavailable. Both readings satisfy the text. | Decide whether cosmetic calls on a pinned lineage should always be answered empty (cheaper, no local load) and make it a policy field. |
| RTG-006 | With no classifier configured, the ambiguous band always takes the configured fallback rung (frontier by default). | Configure `ADRL_CLASSIFIER_BASE_URL` to a local model, then measure the ambiguous-band share before tuning the fallback. |
| LRN-008 | Exploration epsilon is read from the manifest's `thresholds.epsilon_by_rung`, a convention chosen here; no exploration manifest exists. | Record the convention in the learning contract when the first exploration artifact is proposed. |
| FND-001 / CAS-004 | The local-rung rewrite drops `cache_control` from `system` blocks. CAS-004's "handoff never modifies system" holds for the handoff step; the wire rewrite for a non-Claude rung does touch `system`. | Documented; the frontier path is untouched, which is the property the removal test asserts. |
| SAF-007 | The Seatbelt profile is allow-default with kernel denies (network, writes outside scratch, credential paths). Reads are not limited to the snapshot. | A deny-default profile once the harness's own profile shape is confirmed on the target macOS version. |
| SAF-003 | Detector tiers in `config/detectors.yaml` carry provisional precision figures. | Run `adrl gates scan-measure` on a representative labelled corpus and re-tier from the results. |
| RTG-009 | Remaining-episode length is the constant estimator `episode-constant-v1`. | Replace with the empirical continuation distribution once a shadow corpus exists; the version is recorded on every decision row. |
| CAS-001 | `PostToolUseFailure` is ingested as an authenticated product observation. The cascade still relies on its existing wire/internal evidence; product observations do not have trusted failure authority. | Define and test a lineage-bound authoritative event bridge before using hook observations to trigger escalation. |
| SAF-003 | The split-secret tail (last 64 characters of the previous scanned block) is carried across requests on a lineage, so a request that follows a pinning finding can re-pin on a generic detector even after an audited release of the first finding. | Decide whether the tail should reset on a release event; today a release is per finding and a re-pin is the conservative reading of SAF-002. |
| CAS-003 | The gateway-side clause "never re-issue after first streamed tool content" is not expressible in LiteLLM configuration and is untested on the gateway. ADRL's own side (one attempt, no re-issue) is tested. | A gateway contract test once the gateway team exposes retry hooks. |
| SEM-006 | Agent parent links are persisted as `agent_parent` lineage events on the session root and primed on the first request of a session per process. A grandchild whose parent link was never seen by any process (the parent's own request was lost) still shortens its chain. | Carry the full chain in the harness headers if Anthropic adds it; until then the rescan under the new lineage is the backstop. |
| FND-001 / CAS-004 | After an escalation whose source turn had no thinking blocks, frontier-bound continuations are re-serialised to strip `thinking` until the next user turn. This is a deliberate carve-out from the byte-exact rule and is not covered by the removal test. | Add the carve-out to the register (FND-001 amendment or CAS-004 clause) and a removal-test variant that asserts identity for every field except `thinking`. |
| CAS-001 (e) | `controller._verifier_consumed` is process-local; after a restart each historical `verifier_failed` event counts as fresh once and re-arms one escalation. | Persist consumption as a lineage event (`verifier_consumed` with the job id) and read it back on start. |
| SAF-002 | `PinRegistry` invalidates its cache on every `PRAGMA data_version` change, which this process's own writer bumps on nearly every request, so pins are re-read on almost every request. Correct but not a cache. | Track the writer's own last data_version and invalidate only on changes made by other connections. |
| SAF-009 | Checkpoints are signed with a separate checkpoint key, written every N rows and T seconds, shipped to a file or HTTP anchor with append-only acknowledgements, and `adrl ledger verify-egress` verifies signatures against a key set and the anchor file. The HTTP anchor is a plain POST with the response body as acknowledgement; there is no server-side counter-signature or inclusion proof yet. | An anchoring service that counter-signs or publishes a Merkle inclusion proof, so an attacker who controls both the host and the anchor endpoint cannot forge acknowledgements. |
| SAF-009 | Rows appended after the newest anchored checkpoint are covered only by the local chain until the next checkpoint (at most N rows or T seconds). | Tune `ADRL_EGRESS_CHECKPOINT_EVERY` and the interval to the tolerated exposure window; alert on anchor age. |
| SAF-008 | Repository identity now comes only from a signed workload assertion (`adrl launch`, header or session file). A harness started without the launcher is an unknown workload and stays local-only. The launcher runs on the developer's host under the same HMAC key as the proxy; a compromised host can mint assertions for any path it can read. | An SCM-backed inventory service or a launcher key held outside the developer's account, so an assertion proves membership in the organisation's repository inventory rather than local readability. |
| SAF-008 | The `unknown_identity_policy: default_class` manifest value exists as a dev opt-out and is not set in the shipped manifest. | Keep it out of production manifests; the config check should refuse it outside a dev deployment tag. |
| SAF-001 | Observe mode records shadow findings and never pins; an authoritative pin taken earlier under enforce still narrows in observe mode because a pin is a decision already made, not an observation. | Document in OPS whether an operator may flip to observe on a lineage with live pins. |
| SAF-008 | The default dev inventory has no EU deployment, so `residency-eu` lineages are local-or-block; `check_residency_reachable` fails at load when a residency class is assigned to a repo and no in-geo deployment exists. `ADRL_RESIDENCY_UNREACHABLE_IS_ERROR=false` downgrades that to the runtime backstop. | Add an attested in-geo deployment before assigning a residency class. |
| RTG-008 / SAF-009 | A receipt is trusted when the gateway returns `x-litellm-model-id` equal to a deployment id (the generator sets `model_info.id`) or an `x-litellm-model-api-base` whose host matches the inventory. A gateway that returns neither leaves every egress row `assumed_intended`, which the audit reports as unconfirmed rather than as proof. | Require `return_response_headers` on the gateway and alert on the unconfirmed fraction. |
| FND-001 / SAF-008 | In shadow routing mode the rung ceiling of the repository class is advisory on the frontier passthrough (the harness's own model is forwarded); the pin and residency still bind at the deployment level. | Decide whether shadow mode should enforce the class ceiling; if so the removal test needs a per-class fixture. |
| CAS-003 / CAS-009 | The trusted-tool-server allow-list ships empty, so every MCP hint is ignored and every unknown MCP tool is destructive until a platform team lists its servers. Built-ins are trusted by name only. | Populate `config/trusted-tool-servers.yaml` from the attested server inventory; the composition root loads it into the router and the cascade controller. |
| RTG-007 | No pre-build gate code exists for the marginal-utility estimator; the decision stays unmapped in `docs/adr-module-map.md` on purpose. | Implement the gate once EVL-001 baselines and LRN-002 pair counts exist to feed it. |

## Closed on 2026-09-03

| ADR | Was | Closed by |
|---|---|---|
| SAF-008 / SAF-009 | "Local" and residency were labels: nothing read `residency`, a local group pointed at a remote host passed every check, and the egress audit inferred "never left" from the rung name. | Closed: signed `endpoint-inventory-v1.json` with trust zone, geo and attested api_base; the permitted set is now a `DeploymentSet` (pin keeps `local_host` only, residency keeps in-geo plus local host); dispatch addresses deployments by id and records the gateway receipt; `lineage_left_machine` answers from the recorded trust zone and reports unconfirmed rows. Tests: `tests/adversarial/test_tru_suite.py`, `tests/unit/tru/`, `tests/integration/e2e/test_tru.py`. |
| SAF-008 | Repository identity was a regex over prompt text; a spoofed system prompt could claim a permissive repository. | Signed workload assertion from `adrl launch` (`gates/workload.py`); unknown identity is local-only; exact manifest matching. |
| SAF-009 | Checkpoints were manual, unverified by the CLI, and signed with the manifest dev key loaded unconditionally. | Separate checkpoint key, dev keys refused without `dev_keys_allowed`, automatic checkpoints with file or HTTP anchoring, `adrl ledger verify-egress` checks signatures and anchors (`ledger/anchoring.py`). |
| MEM-005 / MEM-010 | Working directories, remotes, touched paths, argv and 400 characters of verifier output were stored in clear. | Field-level inventory (`docs/data-inventory.md`, `tools/check_data_inventory.py`): 215 fields, zero plaintext prompt-class; job material sealed per session and shredded with the session key. |
| SAF-001 | Observe mode wrote durable pins and triggered suppression before the enforce switch was consulted. | Shadow findings live in their own namespace; promotion is an audited operator action (`adrl gates promote-shadow`). |
| CAS-003 | MCP hints were trusted unconditionally and shell commands were prefix-matched, so `echo $TOKEN > /tmp/leak` was read-only. | `side-effects-v2`: hints honoured only from allow-listed servers, compound commands parsed, unknown is destructive, read-only calls enumerated in the handoff record. |
| RTG-003 | The file-mention regex captured extensions, so ten files counted as one. | Non-capturing group; ten paths count as ten. |
| SAF-007 | `verify-finish` could run checks in the live workspace. | The CLI requires `--snapshot` or `--auto-snapshot`; the verification CLI seals job material with the keystore so begin and finish may run in different processes. |
| CAS-001 (e) | Verifier outcomes never reached the trip-wire evaluator. | `verifier_failed` lineage events are consumed at the next boundary. |
