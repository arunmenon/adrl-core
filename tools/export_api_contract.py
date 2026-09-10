"""Export the API schema deterministically. Primary: ADRL-SEM-007."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adrl.api.schema import openapi_document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Compare without writing")
    args = parser.parse_args()
    content = json.dumps(openapi_document(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not args.out.is_file() or args.out.read_text() != content:
            parser.exit(1, "API contract is stale or missing\n")
        print("API contract matches")
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(content)


if __name__ == "__main__":
    main()
