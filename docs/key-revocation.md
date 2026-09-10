# Session-key revocation and failure ordering

W3.2b2b1, 8 September 2026. Primary ADRL-MEM-010; related MEM-005, MEM-001, OPS-001
and TRU-001. This corrects the keystore beneath the existing capture/journal/product APIs.
Database schema 9, public API preview 4 and the key-wrapping format are unchanged.

## Why revocation precedes removal

The previous keystore removed a wrapped key and then wrote its shred audit. A synthetic
audit failure left no durable revocation record. Restoring the old wrapped file made it
readable, or a caller could create a replacement key for that same session. The pre-change
probe demonstrated both behaviors using disposable data.

The keystore now creates `revoked/<session>.revoked` first, flushes the marker and its
directory, then removes the session's owned pending-write files and wrapped key. The marker
contains only `session-key-revocation-v1`; its filename reuses the existing session identity
(normally a keyed pseudonym). Presence alone denies key access, even for an incomplete or
malformed marker. There is no API to remove revocation or give that session a new key.

`get_session_key` returns unavailable and `has_session_key` returns false for a revoked
session, even when a wrapped file remains or is restored. `create_session_key` raises
`KeyRevokedError`. An attached legacy ledger's erased/shredded audit also denies restored
keys when no filesystem marker exists. A standalone keystore without that ledger can only
honor its filesystem markers; restoring both older keys and older revocation state is not
protected by an external anchor here.

After removal, the existing append-only audit is written outside the file lock. An audit
failure is still an error; no successful erasure-service receipt is returned. A retry can
remove remaining copies and append the missing audit while leaving the marker intact.
The removal boolean is true if a current wrapped file or its owned pending copy was removed,
and false if none was present. Even erasing a missing key persists revocation. Repeated
shred calls may append another audit; any historical shred remains a permanent denial.

Product erasure status also honors the marker. Its timeline reports an unavailable payload
as `erased`, and rebinding/event submission remain forbidden after an audit failure. This
is access denial, not proof that physical cleanup or the audit finished successfully.
Pending journal state and terminal-capacity grants are neither changed nor released.

## Cooperating filesystem operations

One private `.keystore.lock` coordinates current POSIX implementations sharing a local root.
Key reads take a shared lock; initialization, creation, shredding and host-HMAC rotation
take an exclusive lock. Acquisition is nonblocking: contention raises `KeyStoreBusyError`,
with no hidden retry or waiting loop. File operations and audit waits can still be delayed
by the operating system; no hard real-time deadline or full runtime multi-worker support
is claimed. The file lock is released before submitting/waiting on a ledger audit, so the
ledger writer can read a key without deadlocking behind the same audit.

Writes use private temporary files named `.key-write-<target-name>-<random>` in the target
directory, flush their bytes, atomically replace the destination and flush the directory.
The same wrapping and master/HMAC formats are preserved. Failed normal writes clean their
temporary file. A process crash can leave one: a later session create/shred cleans owned
pending session files under the exclusive lock; initialization cleans pending host-secret
writes. Unrelated session files are preserved. Unsafe symlink, hardlink or special pending
files are rejected. This is targeted cleanup, not a complete keystore backup/recovery service.

Directories are private (0700), marker/lock/key files are private (0600). Session identities
must be safe basenames. Lock and session-file opens reject symlinks and special files;
nonblocking opens prevent a FIFO from hanging before validation. These controls coordinate
cooperating software on a trusted local account. They do not defend against an attacker
replacing parent directories, deleting the lock or rolling back the whole keystore/ledger,
nor qualify older binaries or network filesystems.

## Failure observations and remaining work

If marker creation fails before it exists, destructive key mutation does not run and the
error is visible. If a partial marker exists or marker flushing fails, future reads are
denied; retry must flush it before removal. A failure or process death after publication
can leave a wrapped file, but current APIs continue denying it after reopen. Corrupt key
bytes can be logically removed after revocation; unsafe file aliases are left untouched
and failure is surfaced.

Replacing/unlinking a file does not establish secure removal from SSD blocks, old inodes,
snapshots or backups. Keys/plaintext already returned to callers cannot be withdrawn by
this marker. Physical power-loss recovery and independent security review are not tested.
The file and SQLite audit are still separate resources: the monotone marker prevents
resurrection across the tested failures, not an atomic transaction across both stores.

W3.2b2b2 must coordinate active processes and erasure, retain blocked/uncertain reservations,
and qualify any safe release. Complete writer containment, active plaintext leases, crash
copies and durable task-close/capture association still gate real task payload capture.
This slice does not signal processes, grant capture/learning authority or change privacy pins.

The implementation uses Python's documented [file-lock operations](https://docs.python.org/3.12/library/fcntl.html#fcntl.flock)
and [file synchronization](https://docs.python.org/3.12/library/os.html#os.fsync). The actual
evidence is the local fault suite, not a claim of storage-platform certification from those docs.

See the [report](../../adrl-world-class/reports/adrl-w3-2b2b1-key-revocation-2026-09-08.md),
[failure tests](../tests/unit/test_key_revocation.py) and [data inventory](data-inventory.md).
