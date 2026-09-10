"""CI configuration checks. Primary: ADRL-FND-002. Secondary: ADRL-RTG-001, ADRL-SAF-005.

Runs the load-time checks and then generates the LiteLLM config to prove every fallback list
stays inside its rung.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from adrl.config.checks import all_checks  # noqa: E402
from adrl.config.loaders import load_bundle  # noqa: E402
from adrl.config.settings import Settings  # noqa: E402
from adrl.core.enums import RoutingMode  # noqa: E402
from adrl.core.errors import ConfigError  # noqa: E402
from gen_litellm_config import generate, rung_closed  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, default=Path("config"))
    parser.add_argument("--routing-mode", choices=[m.value for m in RoutingMode], default=None)
    args = parser.parse_args(argv)
    settings = Settings(config_dir=args.config_dir)
    if args.routing_mode:
        settings = Settings(config_dir=args.config_dir, routing_mode=RoutingMode(args.routing_mode))
    try:
        bundle = load_bundle(settings)
    except ConfigError as exc:
        sys.stdout.write(f"FAIL {exc}\n")
        return 1
    failed = 0
    for result in all_checks(bundle, settings):
        sys.stdout.write(
            f"{'ok  ' if result.ok else 'FAIL'} {result.name} {result.detail}".rstrip() + "\n"
        )
        failed += 0 if result.ok else 1
    config = generate(bundle, bundle.endpoint_inventory)
    problems = rung_closed(config, {g: r.value for g, r in bundle.rungs.group_to_rung.items()})
    for problem in problems:
        sys.stdout.write(f"FAIL gateway_fallback_rung_closed {problem}\n")
    failed += len(problems)
    if not problems:
        sys.stdout.write("ok   gateway_fallback_rung_closed\n")
    sys.stdout.write(
        f"{'ok  ' if bundle.inventory_signature_verified else 'FAIL'} endpoint_inventory_signed\n"
    )
    failed += 0 if bundle.inventory_signature_verified else 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
