# Stopped resource ownership

W3.2b2d1, 8 September 2026. Primary ADRL-OPS-001; secondary ADRL-MEM-001/002/005/010,
ADRL-SAF-007 and ADRL-TRU-001. Internal synthetic preparation, not a public harness contract.

`StoppedResourceOwner` connects a readable v2 attempt to one never-started local container.
It creates a container, records its identity, inspects a matching retry, and removes a bound
container without force. It cannot start, exec, restart, kill, adopt, capture or release a
workspace. The optional Docker-specific transport sits behind the product's shared attempt
contracts; native observation mode remains available and no Docker dependency is imposed on
every harness. This slice does not qualify a second harness or real supervised execution.

## Why the order matters

1. Validate the bound workspace, current session key/assertion, readable v2 start and intact
   terminal-capacity grant. Atomically append a permanent execution fence and resource intent.
   Existing group-backend fences still block admission.
2. Inspect the pinned local image and prepare the bounded container configuration. Recheck
   session authority, started attempt and grant in the transaction claiming `create_issued`.
3. Only the caller that commits this claim may make one create request. Bind the full returned
   ID only after inspecting the intended engine, creation time, complete configuration and
   never-started state. Names and labels alone cannot establish ownership.
4. A matching bound retry revalidates the existing object. An issued-but-unbound create stays
   uncertain: no create retry, lookup by name, adoption or guessed cleanup is available.
5. For removal, authenticate and re-inspect the bound identity, append `remove_issued`, then
   issue DELETE with `force=false&v=false`. Confirm the exact ID is absent before recording
   `removed`. If a removal reply is lost, a retry may reconcile absence of this previously
   bound ID. A running, exited, restarted, renamed or otherwise changed object is refused.

The five append-only events are `intent`, `create_issued`, `bound`, `remove_issued`, `removed`.
Every event says workspace blocked, exact-close ineligible and learning ineligible. Removal
does not close the attempt or return capacity. There is no fence release. An external removal
before `remove_issued` leaves a conservative unresolved bound state in this version.

Cancellation sets a stop flag and drains the protected worker, including repeated cancellation.
An already issued create can finish binding or stay unresolved. Session revocation is checked
before admission/claim; revocation and daemon creation are not one atomic transaction. A race
after the check may create a stopped synthetic object, with no workload or payload execution.

## Identity, data and recovery

`product_resource_events` is added by schema migration 11. Host-keyed chain MACs authenticate
the event sequence and its permanent fence association. Store reopen can recover a bound
object without process-local PID authority. Interior gaps, changed rows, invalid MACs, changed
fence fields or host-key rotation refuse this authority. An independently anchored high-water
mark is not implemented: rollback to an intact earlier prefix or rollback of the complete
database/key state is outside this qualification and can evade suffix-loss detection.

The raw operation UUID, workspace path, command, environment and profile JSON are not persisted
in the new history. Engine, request and full observed configuration are host-keyed digests;
resource/image IDs and timestamps remain operational metadata. These are pseudonymous/linkable
records, not a guarantee of anonymization. The [inventory](data-inventory.md) lists every SQL,
event and nested policy field. A session erase does not erase the host cleanup evidence.

The trusted local operator needs the original operation UUID, ledger and intact host HMAC key
for cleanup after session-key erasure. This is not an unauthenticated remote cleanup endpoint.
If create returned an ID but the receipt or durable binding was lost, this implementation
cannot safely recover it by scanning names or labels. A stopped orphan and a blocked workspace
may remain for later reviewed recovery. Tests retain original receipts separately so their
own deliberately uncertain fixtures can be accounted for and removed without adoption.

## Versioned preparation limits

`stopped-resource-policy-v1` admits at most 32 permanent histories per ledger, five events of
at most 4,096 bytes each. This is a logical space bound, not preallocated durable disk capacity.
Storage failure still blocks an append. The policy is immutable on an admitted history.

The transport uses Engine API 1.47 over an explicitly supplied local Unix socket and verifies
Linux/arm64/cgroup-v2 identity. It uses no ambient Docker context, proxy, registry authentication,
redirects or image pulls. The HTTP I/O timeout defaults to 10 seconds and is capped at 15;
elapsed checks between raw response chunks reject continued progress beyond that limit.
Responses are capped at 131,072 bytes, encoded responses are refused, and request bodies are
capped at 65,536 bytes. These checks are not a hard real-time watchdog for a wedged OS or a
daemon that dribbles response headers. Killing a client does not prove daemon work stopped.

Only an already-present immutable Linux/arm64 image is accepted. Inherited environment,
entrypoint, volumes, healthchecks and OnBuild controls are refused. The created object uses:

- UID/GID 65532, all capabilities dropped, no-new-privileges and explicitly pinned seccomp.
- No network, host mounts, published ports, automatic removal or restart.
- Private cgroup/IPC/PID namespaces and runc; no daemon settings are changed.
- At most 32 processes, 96 MiB memory with equal memory/swap limit, and 0.5 CPU.
- A synthetic writable layer, `/work` working directory, fixed environment and no execution.

An inspected configuration match proves what the daemon reported. With no start operation,
this slice does not demonstrate runtime enforcement of these controls or containment against
a hostile daemon/host administrator. Non-force removal plus absence does not prove physical
block, snapshot, backup or plaintext erasure.

## Evidence and remaining work

[Unit tests](../tests/unit/test_resource_owner.py) exercise real local Unix-socket HTTP fixtures,
concurrency, changed identity, admission failures, revocation, corruption, atomic write failures,
cancellation and schema-10 migration. [Opt-in engine tests](../tests/integration/test_resource_engine.py)
use the supplied local synthetic image and profile. Their fixture logs original create receipts
and confirms absence; they never start a container. Explicit environment variables are required,
including a private accounting file and a cumulative 16-container limit. Ordinary runs skip
these four engine cases when the fixture is absent.

The next contract must address one-shot launch, lost launch acknowledgements, closing admission
to new writers, complete stopping, owner death and erasure while active. Safe output extraction,
durable task-close/capture association and real-harness network/image/credential/retention
choices follow. None of those gates is satisfied by this preparation primitive. See the
[running journey](../../adrl-world-class/reports/adrl-implementation-journey.md).
