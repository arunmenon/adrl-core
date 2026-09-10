# Attempt stop coordination

W3.2b2b2, 8 September 2026. Internal local API for disposable synthetic fixtures only.
Owning ADRs: OPS-001, MEM-001/002/003/005/010, SAF-007 and TRU-001.

`AttemptCoordinator(AttemptJournal(data), CoordinationPolicy(...)).run(principal, attempt_id,
spec)` connects an existing v2 attempt to the owned process-group runner. It first commits a
permanent workspace fence in schema 10. Only then can it try one launch. A second coordinator
or a new journal attempt cannot use the fenced canonical workspace, even after cancellation,
an incomplete journal entry, erasure, lost acknowledgement or restart. A matching journal-start
retry still retrieves its original record; it does not authorize another launch.

```text
Readable v2 start + terminal grant + bound workspace
                       |
              Commit workspace fence
                       |
              Try one owned launch
                       |
   Monitor revocation, expiry and journal state
                       |
        Exit / timeout / loss of authority / cancel
                       |
         Drain owned process-group cleanup
                       |
   Try incomplete record, or preserve existing terminal
                       |
             Workspace remains blocked
```

This backend has no release operation. That includes failures before any workload launch once
the fence has committed. A process group cannot contain detached or unrelated writers, so no
group result, caller assertion, terminal event or revocation marker proves safe workspace reuse.
Use a different disposable fixture directory for the next admitted run. Do not delete fences,
rotate host keys or recreate databases to bypass this boundary for real work. There is no CLI,
HTTP endpoint, successful task close, captured output association or learning authority.

## Admission and identity

The original attempt must be readable, unexpired, still `started`, version 2, and have an intact
terminal grant. Process cwd must resolve to the authenticated workspace and its journal identity.
These checks and the fence insert serialize in one ledger transaction. Cancellation before
admission is rejected. A lost acknowledgement can leave a committed fence without a process;
it never permits automatic replay. Actual executable validation remains in ProcessOwner, after
fence admission; a bad executable pin therefore leaves a block but no new process report.

Fence metadata is limited to keyed workspace/session/attempt/start-event identifiers, host HMAC
key ID, timestamp and the validated policy JSON. Policy defaults: 0.05-second observation interval
(0.01 to 1), at most 128 permanent workspace fences per ledger (configurable downward), and the
existing versioned ProcessPolicy limits. No raw path, command, environment, output, task label,
PID or plaintext file bytes are persisted. The policy is at most 1,024 encoded characters.
Fences using a different host HMAC key ID block all new journal/execution admission, preventing
key rotation from silently bypassing existing workspace identities.

This is bounded local operational metadata under the existing inventory/retention contract;
keyed hashes are not a claim of anonymity or regulatory qualification. Old schema-9 histories
migrate unchanged and acquire no invented execution fence. Mixed old/new running binaries are
not qualified. The database and host keys remain trusted; malicious mutation, truncation or
whole-state rollback is outside this evidence. Canonical path identity does not contain rename,
replacement, mount alias or writes through other paths. It is not an OS filesystem lock.

## Stop, erasure and partial failure

A monitor thread checks revocation before expiry and readable journal state. Another service's
erasure, direct keystore shredding, missing keys, damaged history or an observation error causes
a stop request to the actual in-memory owner. `request_close`, `cancel` and `mark_incomplete`
also request stopping. Checks observe state eventually: a revocation can race a launch, and
disk, database or OS scheduling can delay observation. No atomic erasure/launch exclusion or
hard real-time deadline is claimed. Erasure receipt semantics remain unchanged; the service
does not wait for this observer or certify process/active-plaintext cleanup.

The existing nonblocking keystore lock can report busy before an erasure publishes its marker;
that erasure has failed and must not be reported complete. Conversely, a monitor encountering
an exclusive key operation can request stop with `authority_unavailable` before it observes
confirmed revocation. The report preserves that uncertainty. No automatic erasure retry is added.

The protected executor worker covers admission, process cleanup and terminal writing. Repeated
coroutine cancellation sets its stop event and drains the worker before propagating. The process
owner retains any unresolved owned handle and refuses reuse after its existing cleanup failures;
no persisted PID grants signal authority. Actual owner death relies on the runner's existing
control-pipe/watchdog mechanics for its group. Restart recovers the fence, not a process outcome.

After cleanup, the coordinator tries `incomplete/quiescence_unavailable` using the journal's
original terminal capacity. An existing terminal is preserved. If erasure, expiry, disk failure
or corruption prevents writing/readback, `terminal_record=unavailable` means completion was not
confirmed, including possible lost acknowledgements. No fresh event-ID retry occurs. An honest
terminal can consume its reserved quota while the separate workspace fence remains blocked.
An unreadable pending journal retains its grant. Neither result reverses key revocation.

`CoordinationReport` and its optional process observation remain in memory and on return. They
always say `workspace_state=blocked`, `exact_close_eligible=false` and
`eligible_for_learning=false`. Reports do not retain raw exceptions. A rejected new launch never
borrows the prior launch's report. No durable process completion receipt is added in this slice.

## Qualification still needed

Real supervised work still needs a complete writer boundary, a defensible release/recovery
contract, active plaintext lease erasure and process-death copy cleanup. Exact-close capture
association follows those gates. These tests use real local fixture processes, not model services
or actual user task payloads; they do not graduate W3 or certify sandboxing, privacy deletion,
production readiness, another harness or better routing.
