#!/usr/bin/env python3
"""External verifier for the `anchored-record-chain/v1` corpus using `continuity_receipt`.

Evaluates a stored history of signed memory records and an off-store signed head
anchor using `continuity_receipt.canon.canonical_bytes` (RFC 8785 / JCS) and
Ed25519 verification.

Usage:
    python3 tools/verify_anchored_chain.py <path/to/case.json> --json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from continuity_receipt.canon import canonical_bytes  # noqa: E402

GENESIS = "0" * 64
VERIFIED = "verified"
REJECTED = "rejected"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_ed25519_jcs(envelope: dict, body_key: str, pubkey_bytes: bytes) -> bool:
    if not isinstance(envelope, dict) or not isinstance(envelope.get(body_key), dict):
        return False
    try:
        sig_bytes = base64.b64decode(str(envelope.get("sig", "")), validate=True)
        canon = canonical_bytes(envelope[body_key])
        pub = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        pub.verify(sig_bytes, canon)
        return True
    except Exception:
        return False


def evaluate_case(case_path: Path) -> dict[str, str]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    lines = [ln for ln in (base / case["store"]).read_bytes().split(b"\n") if ln]
    anchor = json.loads((base / case["anchor"]).read_text(encoding="utf-8"))

    producer_pub = bytes.fromhex(case["keys"]["producer"])
    anchor_pub = bytes.fromhex(case["keys"]["anchor"])
    envelopes = [json.loads(ln) for ln in lines]

    # 1. Record signatures
    if not all(_verify_ed25519_jcs(env, "record", producer_pub) for env in envelopes):
        return {"decision": REJECTED, "reason": "signature_invalid"}

    # 2. Anchor signature
    if not _verify_ed25519_jcs(anchor, "anchor", anchor_pub):
        return {"decision": REJECTED, "reason": "anchor_signature_invalid"}

    # 3. Chain identity binding
    if any(env["record"].get("chain") != case["chain"] for env in envelopes):
        return {"decision": REJECTED, "reason": "record_from_other_chain"}

    # 4. Predecessor hash chain links
    if any(
        env["record"].get("prev") != (GENESIS if idx == 0 else _sha256_hex(lines[idx - 1]))
        for idx, env in enumerate(envelopes)
    ):
        return {"decision": REJECTED, "reason": "chain_link_broken"}

    # 5. Anchored head index present
    anchor_idx = int(anchor["anchor"]["index"])
    if anchor_idx >= len(lines):
        return {"decision": REJECTED, "reason": "anchored_head_missing"}

    # 6. Anchored head digest matches
    if _sha256_hex(lines[anchor_idx]) != anchor["anchor"]["head"]:
        return {"decision": REJECTED, "reason": "anchored_head_mismatch"}

    records_after = len(lines) - 1 - anchor_idx
    reason = "records_after_last_anchor" if records_after > 0 else "chain_anchored"
    return {"decision": VERIFIED, "reason": reason}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", help="Path to case.json")
    parser.add_argument("--json", action="store_true", help="Output JSON object")
    args = parser.parse_args(argv)

    result = evaluate_case(Path(args.case))
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"{result['decision']} {result['reason']}")
    return 0 if result["decision"] == VERIFIED else 1


if __name__ == "__main__":
    raise SystemExit(main())
