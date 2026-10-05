#!/usr/bin/env python3
"""Create the 0.6 chain_head vectors (25a-25f).

Built on the signed 24_authority_grant bundle: chain_head is a bundle-level
member (like anchors), so adding or mutating it never touches receipt
signatures. The head commits to the final receipt's canonical digest.
"""
import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuity_receipt.bundle import receipt_digest  # noqa: E402

BASE = json.loads((ROOT / "vectors" / "24_authority_grant.json").read_text(encoding="utf-8"))
LAST = BASE["receipts"][-1]
HEAD = {
    "seq": LAST["seq"],
    "receipt_id": LAST["receipt_id"],
    "digest": receipt_digest(LAST),
}
ZERO = "sha256:" + "0" * 64


def write(name: str, head: dict | None) -> None:
    bundle = deepcopy(BASE)
    if head is None:
        bundle.pop("chain_head", None)
    else:
        bundle["chain_head"] = head
    path = ROOT / "vectors" / name
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print("wrote", name)


def main() -> int:
    write("25a_head_valid.json", deepcopy(HEAD))
    write("25b_head_mismatch.json", {**HEAD, "digest": ZERO})
    write("25c_head_seq_mismatch.json", {**HEAD, "seq": HEAD["seq"] + 1})
    write("25d_head_anchor_missing.json", deepcopy(HEAD))
    write(
        "25e_head_anchor_invalid.json",
        {**HEAD, "anchored": {"type": "carrier-pigeon", "proof_ref": "urn:test:bad"}},
    )
    write(
        "25f_head_anchor_valid.json",
        {
            **HEAD,
            "anchored": {
                "type": "opentimestamps",
                "proof_ref": "https://api.whitemagic.dev/anchors/" + HEAD["digest"],
            },
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
