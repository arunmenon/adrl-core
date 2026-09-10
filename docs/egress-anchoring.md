# Egress ledger anchoring (ADRL-SAF-009)

The egress ledger is a hash chain over content-free rows. A hash chain alone only proves that
rows were not edited in the middle; an attacker with write access to the SQLite file can truncate
the tail and recompute nothing. Anchoring closes that hole: every N rows and every T seconds the
ledger signs the newest (sequence, digest) pair with a checkpoint key and ships the signed record
off the machine. A verifier holding the public key set and the anchor file can prove that no row
at or before an anchored checkpoint was deleted, edited or truncated.

## Keys and custody

| Key | Signs | Private half lives | Public half lives |
|---|---|---|---|
| Manifest-signing | `config/repo-classification-v1.json` | Security team (never on a proxy host) | `config/keys/<env>/manifest-signing.pub` |
| Checkpoint-signing | Egress checkpoints | Proxy host, `ADRL_CHECKPOINT_SIGNING_KEY_PATH`, mode 0600 | Auditor's key set, pinned outside the host |

The two keys are separate on purpose. A checkpoint key on a proxy host cannot re-sign policy,
and a leaked manifest key cannot forge audit history.

Development keys live under a path containing `dev`. The proxy refuses such a key unless
`ADRL_DEV_KEYS_ALLOWED=true`, and logs a loud warning when it is. Anchors signed by a
development key have no audit value. `tools/gen_dev_keys.py` creates development keys; private
halves are excluded from git by `.gitignore`.

Key identity is derived from the public key (`ed25519:` plus the first 16 hex characters of the
SHA-256 of the raw public bytes), so a rotation is a new id, never a rename.

## Settings

| Setting | Meaning |
|---|---|
| `ADRL_CHECKPOINT_SIGNING_KEY_PATH` | Ed25519 private key PEM on the proxy host |
| `ADRL_CHECKPOINT_PUBLIC_KEY_PATH` | Public half, for operators running the verifier locally |
| `ADRL_EGRESS_CHECKPOINT_EVERY` | Checkpoint after this many rows (written before the append returns) |
| `ADRL_EGRESS_CHECKPOINT_INTERVAL_S` | Checkpoint on this cadence when rows exist since the last one |
| `ADRL_EGRESS_ANCHOR_PATH` | Append-only anchor file, intended for an off-device mount |
| `ADRL_EGRESS_ANCHOR_URL` | HTTP anchoring service; the response body is the acknowledgement |
| `ADRL_DEV_KEYS_ALLOWED` | Permit a development key; never outside a developer machine |

Shipment is asynchronous: a checkpoint is durable and signed the moment it is written, and the
background task delivers it to every configured anchor, retrying failures. Each attempt is an
append-only row in `checkpoint_shipments` with status `acked` or `failed`; a checkpoint counts
as shipped for a destination once an `acked` row exists. `/healthz` reports `unshipped_checkpoints`
and `newest_anchor_age_s`; the metrics `adrl_egress_unshipped_checkpoints` and
`adrl_egress_newest_anchor_age_seconds` carry the same numbers. Alert when the anchor age exceeds
twice the checkpoint interval.

## Verification

```bash
adrl ledger verify-egress --path egress.db \
  --public-key keys/checkpoint-2026-03.pub --public-key keys/checkpoint-2026-09.pub \
  --anchors /mnt/anchors/proxy-07.jsonl
```

The command checks, in order, the hash chain, every checkpoint signature against the key set
(a checkpoint whose `key_id` is not in the set fails), and every anchor record against the ledger:
the anchored row must exist with the anchored digest, and the ledger must extend at least to the
anchored sequence. It exits non-zero on any failure. Without `--public-key` it verifies the chain
only and says so; that is not an audit.

## Rotation

1. Generate the new keypair on the host; keep the old private key until the first checkpoint
   signed by the new key has been acknowledged by every anchor.
2. Point `ADRL_CHECKPOINT_SIGNING_KEY_PATH` at the new key and restart; the next checkpoint
   carries the new `key_id`.
3. Add the new public key to the auditor's key set. Keep the old public key in the set for as long
   as the retention horizon of rows it signed (MEM-010: 24 months for the evidence skeleton).
4. Destroy the old private key once step 1 is satisfied. Record the rotation, with both key ids,
   in the operations log.

The verifier accepts a key set, so old and new checkpoints verify together during and after the
overlap.

## When verification fails

- `prev_digest mismatch` or `digest mismatch`: a row was edited or removed in the middle. Treat the
  host as compromised from the first bad sequence; the rows before it remain trustworthy.
- `ledger truncated below anchored seq N`: rows were deleted from the tail. Everything the anchor
  file proves existed up to N is missing on the host; recover the count and time window from the
  anchors and open an incident.
- `unknown key id`: either a rotation was not recorded in the key set, or someone signed with a key
  the auditor never issued. Confirm against the operations log before accepting the key.
- `bad signature`: the checkpoint or anchor record was altered. Do not accept the ledger.

In every case stop trusting `adrl audit` answers for the affected window until the incident is
closed, and preserve the SQLite file, its WAL, and the anchor file as evidence.
