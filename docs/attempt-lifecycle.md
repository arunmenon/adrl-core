# Internal attempt journal: W3.2a

Current extension, 8 September 2026: W3.2b2a uses `operator-attempt-policy-v2` for new starts
and reserves terminal capacity in schema 9. V1 records retain their original contract.
The lifecycle still records intent and interruption only; process/capture integration is pending.

Primary: ADRL-MEM-002. Secondary: ADRL-MEM-001/003/005/010, ADRL-SEM-002/007,
ADRL-TRU-001, ADRL-OPS-001.

`AttemptJournal` records operator intent and interruption independently of a routing decision.
It is an internal library tested with synthetic fixtures. There is no new CLI, HTTP endpoint,
harness hook mapping or process launch. API preview 4 remains unchanged.

The supported history is:

```text
started -> close_requested -> cancelled or incomplete
started --------------------> cancelled or incomplete
```

No successful-close, quiesced-writer, capture-associated or verified-result state exists here.
Every event reports attribution as `unestablished` and learning eligibility as false. A close
request is only a request. The existing capture library remains independent; it does not enforce
this journal's reservations or associate its manual captures with close requests. W3.2b must
implement that association with an actual writer barrier before claiming exact task output.

## Identity, evidence and recovery

A start reserves an attempt UUID and a future capture UUID within the bound session, names an
opaque task reference and optional terminal parent attempt, and records its initial included-tree
manifest, fingerprint, canonical workspace reference and policy. The manifest retains names,
permissions and content hashes, without the file bytes. The capture scanner establishes the same
included-tree scope and rejects its existing unsafe-input/drift cases. This is operator-time
initial state, not proof that a harness had yet to write anything.

Migration 0008 stores encrypted append-only events. It reuses the bound session key and creates
no new key. Raw UUIDs, task identity, source/workspace references, names/hashes, reasons and policy
remain encrypted. Session, attempt, event and workspace pseudonyms plus phase, sequence and append
time form a plaintext skeleton. The workspace pseudonym is host-keyed so different sessions on
the same ledger refer to one canonical workspace. Headers are authenticated with the ciphertext.
Erasure changes no existing row and denies fresh access or append, including when an old wrapped
key is restored while the erasure audit remains intact.

The caller supplies a previously authenticated local principal. Binding, workload, session,
workspace, expiry and erasure checks retain the existing same-OS-user boundary. This is not a
remote verifier identity service or an authorization mechanism for arbitrary same-user code.

An identical event UUID and command returns the original record, even after later phases are
appended. A start retry keeps the original initial manifest when files have since changed.
Changed commands, policies or workspaces under that UUID conflict. A different UUID cannot
repeat an already pending close or append after a terminal event. Existing attempt and capture
IDs cannot be reassigned, and a capture cannot retrospectively establish its attempt's start.
Parent validation requires the same task, session and workspace plus a terminal parent.

One active journal attempt per canonical workspace is admitted transactionally across sessions
on the same ledger. This is a data reservation, not an operating-system/file lock. Terminal
journal state does not prove a process stopped. On reopen, a pending attempt remains pending and
retains its reservation; there is no expiry-based abandonment or automatic process resumption.
An authorized operator can append an explicit incomplete reason when the key and quota permit.

Read validation detects altered identities/headers/ciphertext, missing starts, sequence gaps and
invalid transitions. It does not anchor history against an attacker removing a suffix or rolling
back the entire database. These states cannot produce a successful-close projection. A future
supervisor must reconcile actual process ownership and liveness before reuse; persisted PIDs
alone cannot grant signal/kill authority after restart.

## Current v2 admission and reserved terminal capacity

`AttemptPolicy` now means `operator-attempt-policy-v2`. It retains the upper limits of three
attempts per session, eight events per attempt, 8,000,000 plaintext bytes per event and
32,000,000 ciphertext-plus-nonce history bytes. It requires at least two event slots and
reserves one for cancellation or explicit incomplete. `terminal_reserve_bytes` defaults to
1,024 and may be between 1,024 and 4,096. Before admission, all permitted terminal variants
must fit the recorded plaintext and reserved-byte bounds. The existing capture scan limits
are unchanged.

The initial event and its capacity grant commit in one serialized transaction. Pending
grants count against history quota along with stored ciphertext and nonces. Every append,
including a v1 continuation, respects all pending grants. A close request cannot spend a
reserved terminal slot or bytes. The terminal event consumes only its own reservation;
the append-only grant remains in storage and consumption is inferred from terminal history.
Retries do not create another grant or consume it twice. Failed transactions leave neither
partial admission nor partial consumption.

Each active grant's recorded history ceiling constrains later admissions. A different caller
cannot offer a larger limit to spend that commitment. A newly lowered caller limit applies
to new/nonterminal work but cannot revoke an existing v2 terminal grant. That terminal still
uses its original bounded policy and respects all other commitments. Once a grant is consumed,
its active ceiling ends, while its stored history remains charged. This is the v2 admission
contract, not an exception to the absolute maximum or a rewrite of v1 behavior.

Schema 9 adds `capacity_version` to event headers (zero for legacy, one for v2); v2 binds it
into AEAD associated data. The small `product_attempt_capacity` table stores existing keyed
session/attempt/start-event references, reserved bytes and the admission ceiling. Reads and
transitions check a grant against its owning encrypted policy. Missing required grants and
structural mismatches deny admission. Clear accounting metadata is not an externally anchored
tamper log; whole-database rollback and a hostile direct database writer remain outside this
guarantee. See the [field inventory](data-inventory.md).

`LegacyAttemptPolicy` permits read, matching-policy retries and continuations of historical
v1 records. A new v1 start is refused. Migration preserves old ciphertext/nonces and does not
retroactively grant capacity; legacy event exhaustion can still block termination. Public API
preview 4, phase names, attribution and learning eligibility are unchanged. No successful close,
capture binding, new process launch or materialization is added.

Logical quota is not physical disk reservation. Database/disk failure, key erasure, expired
credentials or corrupt history may still prevent a terminal append. Erasure does not remove a
pending grant or free a journal workspace reservation. Do not restore keys or treat blocked
records as safe workspace release. W3.2b2b must coordinate process cleanup, erasure and release;
writer containment, capture association and active-copy/crash recovery remain separate gates.

Evidence: [W3.2b2a report](../../adrl-world-class/reports/adrl-w3-2b2a-terminal-capacity-2026-09-08.md)
and [capacity fixtures](../tests/unit/test_attempt_capacity.py).

## Historical v1 bounds and unresolved recovery

The following preserves W3.2a's original v1 contract. New starts now use the v2 rules above.

The starting `AttemptPolicy` limits attempts per session (upper/default 3), events per attempt
(8), encoded plaintext bytes per event (8,000,000), and ciphertext-plus-nonce bytes across the
attempt table (32,000,000). Limits may be lower. Its embedded capture policy supplies initial
scan bounds; no capture archive row is created by the scan. Later transitions retain the
attempt's original policy, with a newly lowered journal-wide byte bound also respected.

Quota checks occur in the serialized write transaction; failed writes add no partial event and
lost acknowledgements can be recovered through the same ID. Erased history still occupies quota.
SQLite/WAL overhead is outside the logical count. Quota exhaustion can leave an attempt pending,
and erasing an unfinished attempt can leave its reservation blocked because its key is no longer
available. Neither condition silently releases a possibly active workspace. A supervisor admission
and recovery design must reserve terminal-record capacity and coordinate erasure/release before
real execution is enabled. The small-policy fault cases intentionally exercise this conservative
blocked state; it is not a completed operations/recovery feature.

No new plaintext materialization is introduced, and fixture state is removed afterward. W3.1's
active-copy erasure and process-death leftover gates remain open. The next slice must test owned
writers, descendants, cancellation, restart and capture association. Full W3 still needs those
gates, retained verification/CLI/timeline integration and a bounded native Claude demonstration.
