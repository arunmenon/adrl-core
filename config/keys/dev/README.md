# Development keys

Two separate Ed25519 keypairs live here on a developer machine:

- `manifest-signing.key` / `.pub` signs `config/repo-classification-v1.json` (ADRL-SAF-008).
- `checkpoint-signing.key` / `.pub` signs egress-ledger checkpoints (ADRL-SAF-009).

Only the `.pub` halves are tracked. The private halves are excluded by `.gitignore` and created
by `tools/gen_dev_keys.py`; a fresh clone verifies the committed manifest signature with the
committed public key and generates its own private keys when it needs to sign.

The proxy refuses any key under a path containing `dev` unless `ADRL_DEV_KEYS_ALLOWED=true`.
Anchors signed by a development key have no audit value. Production custody, rotation and the
verifier's key set are described in `docs/egress-anchoring.md`.

Re-sign the manifest after editing it:

```bash
.venv/bin/python -m adrl.cli.main config sign-manifest --key config/keys/dev/manifest-signing.key
```
