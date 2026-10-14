#!/usr/bin/env python3
"""Plan or explicitly apply quarantine of unmapped legacy Memory Crystals.

Planning is the default and only writes a hash-bearing JSON manifest. Applying
requires --apply with a previously saved manifest. This tool never assigns an
owner or reads from the live service unless an operator explicitly supplies
those paths.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys


def load_api(source: pathlib.Path):
    spec = importlib.util.spec_from_file_location("crystal_quarantine_api", source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load candidate API source: {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=pathlib.Path)
    parser.add_argument("--quarantine-root", type=pathlib.Path)
    parser.add_argument("--registered-owner-id", action="append", default=[],
                        help="explicitly registered 64-hex owner ID; repeat per mapping")
    parser.add_argument("--manifest", type=pathlib.Path, required=True,
                        help="manifest path to write in dry-run mode or read with --apply")
    parser.add_argument("--apply", action="store_true",
                        help="explicitly move files from the saved, hash-checked manifest")
    args = parser.parse_args()
    api = load_api(pathlib.Path(__file__).parent / "src" / "receipt-api.py")
    if args.apply:
        plan = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = api.apply_legacy_crystal_quarantine_plan(plan)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.source_root is None or args.quarantine_root is None:
        parser.error("dry-run planning requires --source-root and --quarantine-root")
    plan = api.plan_legacy_crystal_quarantine(
        args.source_root, args.quarantine_root, registered_owner_ids=args.registered_owner_id)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
