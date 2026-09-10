# Local product services, preview 4

Primary: ADRL-SEM-007. Secondary: ADRL-TRU-001, ADRL-MEM-001/005/010, ADRL-FND-001.

This package connects the existing model path to authenticated session and observation APIs.
It supports a root Claude Code session using the Messages profile. One real Claude Code observation pilot has been recorded in the sibling ADRL register.
This does not establish a second harness, Responses compatibility, remote tenancy or savings.

## Implemented contract

| Operation | Behavior |
|---|---|
| `GET /adrl/v1/capabilities` | Public description of shipped code; not runtime enforcement evidence |
| `POST /adrl/v1/sessions` | Verify launcher signature, expiry, explicit session and exact registered workload; append an immutable binding |
| `GET /adrl/v1/sessions/{session_id}` | Read the caller's binding and explicitly scoped coverage |
| `POST /adrl/v1/events` | Append encrypted observations; acknowledge only after commit; reject conflicting event IDs or producer sequences |
| `GET /adrl/v1/sessions/{session_id}/timeline` | Paginated decisions, observations and local verification receipts; decrypt available envelopes |
| `GET /adrl/v1/decisions/{route_id}` | Explain the caller's recorded decision, known dispatch evidence and missing evidence |

All private operations require `x-adrl-workload-assertion` from the trusted local launcher.
The `credential_ref` in a binding response identifies that assertion; it is not a newly issued
bearer token. Provider authentication remains separate. The preview accepts loopback clients only.
The launcher and service share the existing host keystore. Code running as the same operating-system
user is within that trust boundary; this is not tenant isolation or a hardware-backed identity proof.

An assertion must match exactly one repository in the verified manifest. Session headers must
agree with its explicit session ID. An identical binding is repeatable; renewal with a new assertion
for the same session does not create a new identity, route history or privacy state. Rebinding a
session to a different workload or configuration is rejected. Configuration changes require an
operator migration/reconciliation; the service does not silently reset a restricted session.
Separate child-session binding and a remote verifier credential role remain unsupported.

Bound model requests require the matching native session header and valid assertion. They may
use only the admitted Messages endpoints; unsupported methods/paths are rejected with native
error objects. Unbound legacy traffic retains its previous forwarding behavior. A caller stripping
all session signals can reach that legacy path: a fully enforcing listener remains a release blocker.
ADRL assertion and product-session headers are removed before gateway dispatch and redacted in
recorded header views. Provider credentials and unchanged model request bytes are preserved.

## Observations and evidence

Authenticated harness producers can submit tool outcomes, reported task closure and compaction
observations. A verification-shaped event receives 403 with a harness credential. Existing internal
verifier evidence is referenced in the timeline; public ingestion does not create trusted labels or
automatically close an internal outcome. Opaque references are recorded, never dereferenced by intake.

Identity is stable per bound session. Public idempotency is `(authenticated producer, event UUID)`;
internal outcome-event idempotency is unchanged. Identical retries return the original acknowledgement,
including timestamp and sequence status. A reused event UUID with changed content, or a reused producer
sequence with another UUID, returns 409. Sequences start at zero; gaps and late arrivals are marked
without inventing missing events. Producer sequence and occurrence time are observations, not proof
of execution order. Failed requests and validation errors do not echo input content.

Migration 0003 adds bindings, encrypted intake and a reference-only timeline projection. Caller
envelopes, including their raw session and tool references, are encrypted using the existing session
key. Erasure removes access; timeline entries then show `erased`, and intake/rebinding cannot recreate
that evidence key. Immutable skeleton identifiers remain subject to the register's retention design.
No old decision or event row is rewritten. The writer now uses SQLite `synchronous=FULL`; cancellation
after a transaction starts cannot cancel its writer future or stop later writes.

Timeline sequence denotes append order in its reference index. Late evidence can appear after a
previously read page. Signed cursors bind to one session; limits are 1-100. Dispatch references are
observed proxy records, not an inventory of hidden gateway retry attempts. Missing served deployment
identity remains absent. Historical records without adapter/profile metadata report `unknown`.

## Observation-only setup

Use `adrl connect claude-code --mode observe` with the same repository, output and server
arguments below to bind a session for hooks while Claude uses its native model connection.
The emitted environment file exports only ADRL_LAUNCH_SESSION_ID. No provider base URL,
provider credential or ADRL assertion is installed in Claude's model environment. The hooks
read the separate local connection credential. Existing native environment/settings remain
the caller's responsibility: inspect Claude /status and remove stale gateway overrides.
This command prepares files; it does not start Claude or authorize usage-credit/API spend.

Session responses now include immutable `integration_mode` (`gateway` by default or `observe`).
Observation sessions explicitly report request interception, content inspection, dispatch
enforcement and served destination as unavailable. Identity binding is enforced for local API
access; other dimensions remain unknown until independently evidenced. An observation session
cannot be rebound as a gateway session, and model requests carrying its identity are rejected.
This does not close the separately documented unbound legacy forwarding path.

Migration 0004 adds the mode column. Existing bindings retain their original gateway semantics;
no event history is rewritten. Preview-4 session requests replace earlier preview requests, so
connection clients must be upgraded together. Existing preview-2 and preview-3 event envelopes
remain readable and deliverable from pending outboxes without changing their idempotency
payloads. New event envelopes use preview 4. Reconnect/restart/resume limitations below still apply.

The Messages profile on an observation session identifies the declared harness profile, not
proof that the service saw or validated native model traffic. Observations do not prove privacy
pins, complete egress accounting, trusted outcomes, local model compatibility or routing savings.

## Independent session verification

W3.1 adds a separate [internal retained-capture API](operator-captures.md). The command below
still takes its own temporary snapshot; it does not yet consume the retained capture or establish
exact task-close attribution. Public API preview 4 and historical receipts remain unchanged.

`adrl product verify` is a local operator command. It uses the configured ledger and keystore,
validates the connection against its signed workload and snapshots that exact working copy.
It needs no running HTTP service or model call. Start the service using the same configuration
and data paths to read the receipt through the authenticated timeline. This is not a public
verification-submit API: harness credentials still cannot claim verifier authority.

Keep a reviewed plan and its verifier artifacts outside the working copy. Pin each artifact by
SHA-256 and use an opaque task reference and explicit verifier version. An example plan is:

```json
{
  "schema_version": "session-verifier-plan-v1",
  "verifier": {"id": "project-tests", "version": "1"},
  "task_ref": "pilot-task-001",
  "artifacts": {
    "check.py": {"path": "/absolute/operator/check.py", "sha256": "<64 lowercase hex digits>"}
  },
  "checks": [{
    "name": "acceptance",
    "argv": ["/absolute/python", "-B", ".adrl-verifier/check.py"],
    "timeout_s": 60,
    "failure_exit_codes": [1]
  }]
}
```

Replace example paths and hash with the actual trusted files. The check script must import the
application from the snapshot working directory and load its pinned tests from `.adrl-verifier`.
It should return 0 only for passed checks, 1 for asserted failure, and a different status for
setup errors. Exit semantics are operator policy: declaring a tool's generic exit 1 as failure
also classifies that tool's setup errors as failure. Review the script before using this mapping.

With `ADRL_CONFIG_DIR`, `ADRL_LEDGER_PATH` and `ADRL_KEYSTORE_PATH` pointing to the bound
session's existing local state:

```bash
.venv/bin/python -m adrl.cli.main product verify \
  --connection "$ADRL_CONNECTION/connection.json" \
  --workspace "$ADRL_PILOT_REPO" --plan "$ADRL_VERIFIER_PLAN"
.venv/bin/python -m adrl.cli.main product timeline \
  --connection "$ADRL_CONNECTION/connection.json"
```

The CLI exits 0 for passed, 1 for a declared failed check, and 2 for indeterminate or invalid
setup. A valid run appends `verification.started` and `verification.finished` with the same job
ID. The receipt includes plan, source and executed-snapshot references, verifier version,
command and executable references, sandbox backend and implementation-source digest, individual
results and timestamps. The sandbox digest versions the Python driver and its policy code; it does
not identify the kernel or all external dependencies. Output tails are keyed
references, not raw logs. The plan itself remains operator-owned; archive it with reviewed test
artifacts to interpret those references later. An interrupted run can retain only its started
receipt. Re-running creates a new job; there is no automatic resume or result replacement.

Snapshot capture retains regular files, executable flags and directories. It excludes `.git`,
`.venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache` and `.pyc` files; these are
not part of the claimed snapshot. Symlinks and a workload-owned `.adrl-verifier` are rejected.
Limits count snapshot files/directories and bytes, including injected artifacts. Changed source
or snapshot content, unavailable execution, timeouts and unclassified exits are indeterminate.
Only complete checks on an unchanged snapshot can pass or fail conclusively.

The existing OS sandbox denies network and limits writes to scratch. macOS Seatbelt permits
other filesystem reads except selected credential paths; it is not a VM or a read-confined
workspace. Use reviewed pilot repositories only. Interpreter dependencies and the host OS are
not frozen by the snapshot or executable reference. Trust in the operator's plan, its exit
mapping and the same-OS-user boundary remains explicit; this is not remote attestation.

Migration 0005 adds encrypted append-only session verification records. The session key protects
the entire receipt. Erasure hides receipts and blocks further writes without recreating a key;
local plan files, CLI output and external evidence copies have separate retention lifecycles.
Receipts use `session-verification-v1`, have `origin=pilot` and `eligible_for_learning=false`,
and create no route, internal outcome or learning label. Session-level outcome coverage remains
unknown: a receipt proves the recorded checks ran, not complete task acceptance or verifier
accuracy across a task population. Calibration, correction workflows, CI identities and a
separate remote verifier role remain future work.

## Gateway setup

Prepare the approved repository classification, signed inventory, gateway and provider credentials
first. Use isolated pilot ledger/keystore paths and the same configuration in the service and launcher.
No model or budget is selected by this helper. Known health and shadow-mode ceiling gaps must be
resolved or explicitly constrained before real pilot traffic; see `docs/known-gaps.md`.

With ADRL running on loopback and the pilot environment already configured:

```bash
.venv/bin/python -m adrl.cli.main connect claude-code \
  --repo "$ADRL_PILOT_REPO" \
  --output "$ADRL_CONNECTION" \
  --server http://127.0.0.1:8788
.venv/bin/python -m adrl.cli.main product status \
  --connection "$ADRL_CONNECTION/connection.json"
```

`ADRL_CONNECTION` must name a new private directory outside the repository. The helper binds a new
session, writes 0600 credential/environment/hook files, and makes no model request. It preserves
other custom headers present in the launcher's environment. It does not edit global or project
Claude settings, select provider credentials, override other settings sources or start Claude.
After provider/budget admission, from the selected repository and pilot terminal:

```bash
source "$ADRL_CONNECTION/env.sh"
claude --session-id "$ADRL_LAUNCH_SESSION_ID" \
  --settings "$ADRL_CONNECTION/claude-settings.json"
```

Confirm the actual base URL and credential source with Claude Code's `/status`. Native session
headers and existing settings precedence still need measurement on the supported harness version.
The generated hooks cover `PostToolUse` and `PostToolUseFailure` only. Validation rejections,
permission denials, compaction, child relationships and task acceptance are not automatically
covered. A successful tool hook does not mean that the engineering task is correct.

The hook discards raw tool inputs, outputs, errors, transcript paths and working directories. It
records a pseudonymous tool reference and typed outcome in an encrypted local outbox, attempts one
pending delivery, and retains unacknowledged events on failure. Hook errors are observational;
they do not retroactively block the tool. Retry pending observations and inspect the timeline with:

```bash
.venv/bin/python -m adrl.cli.main product flush \
  --connection "$ADRL_CONNECTION/connection.json"
.venv/bin/python -m adrl.cli.main product timeline \
  --connection "$ADRL_CONNECTION/connection.json"
```

The local connection directory has its own outbox key and credential lifecycle. Server-side erasure
does not erase that client copy. Stop the session and dispose of its private connection directory
under the pilot's retention procedure; validate this separately before an erasure guarantee. A
connection is for one new session. Automatic token refresh, CLI resume/rebind and outbox sequence
coordination across multiple connection directories are pending; do not create a second connection
directory for the same session to bypass expiry or sequence conflicts.

Official integration references checked on 2026-09-07:
[gateway connection and custom headers](https://code.claude.com/docs/en/llm-gateway-connect),
[hook input and failure coverage](https://code.claude.com/docs/en/hooks).
