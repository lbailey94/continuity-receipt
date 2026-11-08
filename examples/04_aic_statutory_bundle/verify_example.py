#!/usr/bin/env python3
"""Verify the AIC statutory example bundles and print the verdict table."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from continuity_receipt import verify_bundle  # noqa: E402

HERE = Path(__file__).resolve().parent

CASES = [
    ("aic_activity_bundle.json", {}, "TRUSTED"),
    ("aic_activity_unanchored.json", {"require_anchor": True}, "PROVISIONAL"),
    ("aic_activity_rollback.json", {}, "UNTRUSTED"),
]


def main() -> int:
    ok = True
    for name, kwargs, expected in CASES:
        bundle = json.loads((HERE / name).read_text(encoding="utf-8"))
        result = verify_bundle(bundle, **kwargs)
        status = "ok" if result.verdict == expected else "FAIL"
        if result.verdict != expected:
            ok = False
        codes = ",".join(result.codes()) or "-"
        print(f"{status}  {name}: {result.verdict} (expected {expected}) codes={codes}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
