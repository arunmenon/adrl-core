"""Generate development keys and re-sign the manifest (ADRL-SAF-008, ADRL-SAF-009).

Private keys are never committed (.gitignore excludes config/keys/**/*.key); this tool creates
them on a developer machine. The manifest-signing key and the checkpoint-signing key are
separate so a leaked development checkpoint key cannot re-sign policy, and vice versa.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from adrl.config.loaders import canonical_json  # noqa: E402
from adrl.ledger.anchoring import key_id_for, load_private_key, write_keypair  # noqa: E402

MANIFEST = "repo-classification-v1.json"
SIGNATURE = "repo-classification-v1.sig"


def ensure_key(private_path: Path, public_path: Path, *, force: bool) -> tuple[bool, str]:
    if private_path.exists() and not force:
        private = load_private_key(private_path.read_bytes())
        return False, key_id_for(private.public_key())
    if private_path.exists():
        private_path.unlink()
    private = write_keypair(private_path, public_path)
    return True, key_id_for(private.public_key())


def sign_manifest(config_dir: Path, private_path: Path) -> None:
    private = load_private_key(private_path.read_bytes())
    payload = canonical_json(json.loads((config_dir / MANIFEST).read_bytes()))
    signature = base64.b64encode(private.sign(payload)).decode()
    (config_dir / SIGNATURE).write_text(signature + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, default=ROOT / "config")
    parser.add_argument("--force", action="store_true", help="Replace existing private keys")
    args = parser.parse_args(argv)
    keys_dir = args.config_dir / "keys" / "dev"
    created, manifest_id = ensure_key(
        keys_dir / "manifest-signing.key", keys_dir / "manifest-signing.pub", force=args.force
    )
    if created:
        sign_manifest(args.config_dir, keys_dir / "manifest-signing.key")
    _, checkpoint_id = ensure_key(
        keys_dir / "checkpoint-signing.key", keys_dir / "checkpoint-signing.pub", force=args.force
    )
    print(f"manifest-signing {manifest_id} {'created' if created else 'kept'}")
    print(f"checkpoint-signing {checkpoint_id}")
    print("dev keys are refused by the proxy unless ADRL_DEV_KEYS_ALLOWED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
