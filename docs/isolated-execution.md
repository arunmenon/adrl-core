# Internal one-shot fixture execution

W3.2b2d2, 8 September 2026. Primary OPS-001; secondary MEM-001/002/003/005/010, SAF-007 and
TRU-001. This backend is internal, synthetic-only and absent from public API exports. The
shared API remains preview 4. It creates no successful task outcome or learning label.

`IsolatedExecution` takes an existing authenticated stopped resource from `StoppedResourceOwner`.
The latter keeps its original raw configuration binding, non-force removal and no-start API.
The execution transport needs an explicitly selected local socket, pinned seccomp and an HTTP
I/O budget of at most two seconds. Execution policy v2 records `active_request_seconds` and
uses an independent tighter client for profile, inspection, start, kill, discard and recovery.
The stopped owner keeps its existing preparation policy (ten-second default, fifteen-second
maximum); execution no longer requires reducing that budget before creation. The active bound
is an HTTP phase timeout plus elapsed-response rejection, not a hard deadline over all requests.
V1 histories keep their original profile hash and coupled <=2-second admission rule; recovery
uses the authenticated event's version even when opened by a v2 coordinator. No rows are rewritten.
A strict expected-status check requires 204 on start/kill/
discard. This is separate from arbitrary Docker CLI arguments, pull, exec or restart support.

Admission requires a readable started attempt with intact grant, the exact never-started bound
resource and a supported engine/capability profile. The fixture command is only `/probe forced_stop`.
The image's single RootFS diff-ID must equal the retained self-authored tar digest. Policy pins
that archive, its executable and the explicit seccomp bytes. Supplying an arbitrary image ID
with a claimed binary hash cannot satisfy the layer check. The current profile is intentionally
specific to the tested Docker 27.3.1/API 1.47/Linux arm64/kernel/cgroup configuration.

Before starting, the original full configuration binding is checked. The new execution projection
covers every original Config/HostConfig/mount/image/name/command field plus Id/Created, accepting
only the observed unsupported OomKillDisable false/null change. Canonical JSON preserves strict
boolean/numeric distinction in the configuration. Engine/profile and projected configuration are
host-HMAC references linked to the authenticated original bound-event MAC. Raw commands, socket
addresses, engine profiles and inspections stay outside the ledger. Changing lifecycle state is
checked separately, including exact StartedAt, typed PID/restart count and a valid exited state.

## One launch, then seal

A private mode-0700 `launch-denials-v1` directory under the keystore holds a mode-0600 permanent
`<operation-key>.denied` file. Its fixed version line contains no task content. A nonblocking
local lock serializes marker capacity and exclusive creation. File and directory fsync precede
ledger claim and dispatch; the lock is released before any ledger wait. Any existing marker,
including an empty, malformed or symlink marker, denies new launch. There is no removal/release API.

Only the caller that created the marker and committed a unique launch claim sends start once.
A lost claim acknowledgement cannot resume dispatch. The append-only schema-12 history permits
claim -> acknowledged/sealed; acknowledged -> sealed; sealed -> stopped/discard_issued;
stopped -> discard_issued; discard_issued -> discarded. Identical phase retries read state but
never grant a second launch. Fields, original binding and chain MACs are checked on every read.
A maximum 32 histories/markers and eight 4096-byte events per history bound logical metadata,
independently of encrypted attempt-content quota; this is not preallocated disk space.

After the first start acknowledgement and observed launch timestamp, future admission is sealed.
The sole worker runs outside the caller event loop, checks identity/authority and observes stop,
revocation/expiry/closure or deadline. Cancellation repeatedly shields and drains that worker.
Known startup plus sealing and a matching observed exit can retain the container layer as
`stopped`; this is not yet an exact task-close or capture receipt. The authority check and daemon
mutation are not atomic, and erasure may race the final check. Real plaintext remains prohibited.

## Uncertainty and cleanup

A lost or rejected create response can leave a created object without binding authority.
Creation is never retried or adopted by name. Bounded transport causes distinguish read/connect/
write/pool timeout, HTTP transport failure and socket failure in transient errors and private
synthetic-fixture diagnostics. Raw exception text is suppressed; no diagnostic field is added
to the product ledger. Cancellation still drains the original worker and may retain its genuine
returned and validated binding. A response that never arrives retains uncertainty and its fence.
The September 8 historical failed create has no retained underlying cause: a reproduced timeout
mechanism does not establish that it caused the earlier failure. V2 remains offline tested until
a separately bounded real-engine acceptance completes.

`recover(operation_id)` is a trusted local operator operation. It never starts, restarts, adopts
by name or signals saved PIDs. An authenticated existing launch history permits sealing and
force-discarding only its original exact owned fixture, followed by exact-ID absence confirmation.
A marker without a launch history grants no new cleanup authority; the stopped owner may still
assess a never-started bound object separately.

If an audit append fails, authenticated emergency cleanup can proceed, while `audit_failed`
remains visible. `resource_state` describes observed stopped/absent/uncertain state and
`execution_failed` preserves a failed run even if cleanup succeeds. No missing durable phase is
invented. A separate nonblocking operation lock serializes recovery across callers. An already-issued
discard can only reconcile exact absence; if the resource remains present, it stays uncertain
without another DELETE. The recovery lock may span ledger/daemon work; ledger callbacks never
acquire it, and it is separate from the short marker-publication lock. If auditing fails before
a durable discard claim, the authenticated emergency-cleanup exception still applies; it makes
no exactly-once network-delivery promise. Lost discard replies can reconcile exact-ID absence
without repeating deletion.
An engine/profile/configuration or known StartedAt mismatch refuses cleanup. A 404 from engine
info/version is never a resource-absence receipt; the stopped-only path has the same correction.

Every result leaves the original permanent workspace fence and false exact-close/learning flags.
The fixture has its own seven-second timer, which applies only to that exact program and remains
subject to OS scheduling. A dead owner does not stop a daemon-owned task: recovery later seals
and discards its authenticated resource. Bounded I/O and polling are not hard real-time guarantees.

## Compatibility and remaining qualification

Existing schema/data, content keys, attempt grants and stopped histories are preserved. Metadata
remains linkable after content-key erasure. Removal does not prove physical blocks, snapshots,
backups, caches or arbitrary active copies erased. Markers prevent a repeated launch after
ledger-only prefix rollback when the newer marker survives; restoring both data and marker/key
state, replacing roots or hostile host/daemon administration remains outside qualification.
No startup process-owner lock or multi-worker production qualification follows from these tests.

The new unit fault cases and opt-in engine cases are in the launch test modules; exact run results
and hashes belong to the register evidence. Active plaintext leases, safe output extraction,
stop/capture association, verifier/CLI integration, independent review and a real-harness profile
remain later gates. Full W3.2 and W3 are open. See the [data inventory](data-inventory.md).

The bundled test seccomp fixture is the pinned public Moby v27.3.1
[default profile](https://raw.githubusercontent.com/moby/moby/v27.3.1/profiles/seccomp/default.json).
