# Retained operator captures: internal W3.1 boundary

Primary: ADRL-MEM-003. Secondary: ADRL-MEM-001/002/005/010, ADRL-SEM-002/007,
ADRL-SAF-007, ADRL-TRU-001.

`CaptureArchive` preserves a bounded copy of the workspace when a trusted local operator invokes
it. If the working folder later changes from A to B, materialization still yields A and its
original source reference. This is `operator_capture`; the schema cannot claim exact task-close
attribution or verification success. The trusted close supervisor is W3.2, and receipt binding,
CLI/timeline integration and a native Claude task demonstration remain W3.3.

This slice is an internal Python API exercised on synthetic fixtures. It adds no CLI or public
HTTP operation. The public contract remains API preview 4. Do not enable real repository payload
capture before the plaintext-lease/crash-recovery and approved retention boundaries below are
implemented and tested. Existing temporary session verification keeps its previous behavior.

## Storage and identity

The caller supplies a previously authenticated local `Principal`. It must still name a bound,
unexpired session and the same workload. Capture also checks the signed inventory's workspace
root. This is the existing same-OS-user trusted launcher/operator boundary, not a remote verifier
role or a defense against arbitrary code running as that user. No key is created or recovered.

`CaptureRequest` contains a capture UUID, separate attempt UUID, opaque task reference and optional
parent attempt UUID. A parent must have a retained capture in the same session. This records an
operator-declared relationship; it does not implement trusted task lifecycle or infer execution
order. Every raw request field remains encrypted. The SQLite table uses session-key HMACs for
capture and attempt uniqueness. Each attempt can have one capture in this slice.

Two scans must agree. Reads use directory descriptors and no-follow opens, reject symlinks,
special files and hard-linked regular files, compare file/directory metadata around reads, and
reject observed drift. Path traversal, missing parent directories, reserved verifier paths and
duplicate manifest entries are invalid. The existing cache/version-control exclusions apply:
`.git`, `.venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, and `.pyc` entries.
These exclusions are not a secret scanner, and the capture is only of the included tree.
Repeated scans cannot establish atomic close or defeat an adversarial same-user writer.

Migration 0007 appends one authenticated encrypted envelope in a transaction. There is no separate
payload file that can become an orphan while capture commits. File bytes, names, permissions,
source references and policy are encrypted with the existing session key. A retry with identical
request, policy, workspace and content returns the original capture time. Changed content or
identity under the same capture ID conflicts. A different capture ID cannot replace an attempt's
existing capture. A failed transaction leaves no complete object. A lost acknowledgement may
follow a successful commit; reading/retrying that stable ID reconciles it without duplicate rows.

Authentication checks and AEAD integrity are repeated when reading. Missing or corrupt data
never falls back to the current workspace. A source reference can be compared with the existing
snapshot fingerprint for the included tree; it still describes capture-time input only.

## Bounds and erasure

`CapturePolicy` is versioned and retained inside the envelope. Upper/default bounds are 10,000
entries (directories count), 100,000,000 source bytes, three captures per session, and 500,000,000
stored ciphertext-plus-nonce bytes across the capture table. Operators may lower them. Quotas
are checked inside the serialized write transaction. The archive quota includes erased sessions;
key shredding does not remove ciphertext or reclaim capacity. SQLite/WAL overhead is outside this
logical byte count, so it is not a precise filesystem quota. Encoding, repeated scans and AEAD
also require more memory than the raw byte count. There is no bulk collection or automatic retry.

Materialization yields a private disposable copy with non-writable files and executable bits
preserved. Its directories permit cleanup; this is not a hostile-code execution sandbox. The
caller must use a separate scratch directory. The context cleans on ordinary exit, exceptions
and Python cancellation. Killing the process can leave plaintext. Existing leases and previously
returned in-memory objects are not retroactively withdrawn by shredding a key. Fresh reads and
new captures are denied after erasure, even if an old wrapped key is restored while the audit
remains intact. Physical storage, external backups and malicious operator copies have no new
erasure guarantee. Global host-secret/key-backup recovery remains an operator lifecycle problem.

Before real capture, W3 must implement startup leftover reconciliation, active-lease erasure
coordination, aggregate retention/recovery operation and a bounded native-run packet. DQ6 remains
open for broader payload/copy lifecycle policy. This internal slice does not settle it by storing
real data. Capture restart/atomicity tests do not qualify whole-application crash recovery.

## Verification

`tests/unit/test_capture.py` attacks output substitution, input drift, directory replacement,
unsafe paths/files, invalid identity, duplicate captures, quota failures, key erasure/restoration,
corruption, failed transactions, cancellation and lost acknowledgements. Migration tests preserve
and decrypt an existing preview-4 receipt through schema version 6 to 7. The complete engineering
runner checks regression behavior and the unchanged API export. No retained capture is yet fed
into a production verifier receipt or learned objective.
