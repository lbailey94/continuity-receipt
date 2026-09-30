#!/usr/bin/env python3
"""Interop probe: ACTA signed receipts (draft-farley-acta-signed-receipts-02).

Independent implementation of the draft's sign/verify procedure using the
same JCS (RFC 8785) used by this repository, plus the asqav compliance
profile's two extra normative checks that are testable without a registry:

  1. sign + verify a minimal `protectmcp:decision` envelope (EdDSA, hex sig)
  2. payload tamper is rejected
  3. `issuer_id` MUST equal `signature.kid` (asqav §5.1.3)
  4. `action_ref` recomputation is deterministic under member reordering
     (ACTA §2.2 formula: JCS of {agentId, actionType, scopeRequired sorted,
     timestamp}, SHA-256 hex)
  5. commitment mode chain link: `previousReceiptHash` = SHA-256(JCS(prev
     payload)) — asqav §5.3's signing-input scope — recomputable, and broken
     by tampering with the predecessor

Honest limits recorded in the output: this probe does not provide the
legal-entity `issuer_id` (LEI/EIN/CIK), the mandatory RFC3161/OTS anchors,
`policy_digest`, or retention floors that the compliance profile requires.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.canon import canonical_bytes  # noqa: E402
from continuity_receipt.keys import b58encode, private_from_raw, raw_pubkey_bytes  # noqa: E402

SEED = bytes([0x02] * 32)
PRIV = private_from_raw(SEED)
PUB = PRIV.public_key()
KID = "sb:issuer:" + b58encode(raw_pubkey_bytes(PUB))[:12]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def acta_sign(payload: dict) -> dict:
    sig = PRIV.sign(canonical_bytes(payload)).hex()
    return {"payload": payload, "signature": {"alg": "EdDSA", "kid": KID, "sig": sig}}


def acta_verify(envelope: dict, pub=PUB) -> tuple[bool, str]:
    payload = envelope["payload"]
    sig_obj = envelope["signature"]
    if sig_obj.get("alg") != "EdDSA":
        return False, "alg_unsupported"
    if payload.get("issuer_id") != sig_obj.get("kid"):
        return False, "issuer_kid_mismatch"
    try:
        sig = bytes.fromhex(sig_obj["sig"])
    except ValueError:
        return False, "sig_not_hex"
    try:
        pub.verify(sig, canonical_bytes(payload))
        return True, "verified"
    except Exception:
        return False, "signature_invalid"


def action_ref(agent_id: str, action_type: str, scope_required: list[str], timestamp: str) -> str:
    canonical_action = {
        "agentId": agent_id,
        "actionType": action_type,
        "scopeRequired": sorted(scope_required),
        "timestamp": timestamp,
    }
    return sha256_hex(canonical_bytes(canonical_action))


def main() -> int:
    checks = {}

    payload1 = {
        "type": "protectmcp:decision",
        "issued_at": "2026-09-28T16:00:00Z",
        "issuer_id": KID,
        "decision": "allow",
        "tool_name": "memory.search",
        "sandbox_state": "enabled",
        "action_ref": action_ref("agent-01", "tools/call", ["memory:read", "memory:search"], "2026-09-28T16:00:00Z"),
    }
    env1 = acta_sign(payload1)
    ok, why = acta_verify(env1)
    checks["sign_verify_minimal"] = ok

    # tamper: change a signed payload member
    tampered = json.loads(json.dumps(env1))
    tampered["payload"]["decision"] = "deny"
    ok, why = acta_verify(tampered)
    checks["tamper_rejected"] = (not ok) and why == "signature_invalid"

    # issuer_id/kid mismatch (asqav §5.1.3)
    mismatched = json.loads(json.dumps(env1))
    mismatched["payload"]["issuer_id"] = "00000000000000000098"
    ok, why = acta_verify(mismatched)
    checks["issuer_kid_mismatch_rejected"] = (not ok) and why == "issuer_kid_mismatch"

    # action_ref determinism under reordering
    a = action_ref("agent-01", "tools/call", ["memory:read", "memory:search"], "2026-09-28T16:00:00Z")
    b = action_ref("agent-01", "tools/call", ["memory:search", "memory:read"], "2026-09-28T16:00:00Z")
    checks["action_ref_deterministic"] = a == b == payload1["action_ref"]

    # commitment mode chain link (asqav §5.3: JCS signing-input scope)
    payload2 = {
        "type": "protectmcp:decision",
        "issued_at": "2026-09-28T16:00:05Z",
        "issuer_id": KID,
        "decision": "allow",
        "tool_name": "memory.read",
        "previousReceiptHash": sha256_hex(canonical_bytes(payload1)),
    }
    env2 = acta_sign(payload2)
    recomputed = sha256_hex(canonical_bytes(env1["payload"]))
    checks["chain_link_recomputable"] = recomputed == payload2["previousReceiptHash"]
    tampered_prev = json.loads(json.dumps(env1))
    tampered_prev["payload"]["decision"] = "deny"
    checks["chain_link_breaks_on_tamper"] = sha256_hex(canonical_bytes(tampered_prev["payload"])) != payload2["previousReceiptHash"]
    ok2, _ = acta_verify(env2)
    checks["chained_receipt_verifies"] = ok2

    results = {
        "probe": "draft-farley-acta-signed-receipts-02",
        "kid": KID,
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "not_provided_by_this_probe": [
            "legal-entity issuer_id (LEI/EIN/CIK) — asqav §5.1.3",
            "mandatory RFC3161/OTS anchors + witness policy — asqav §5.4",
            "policy_digest requirement — asqav §5.2.2",
            "retention floors — asqav §6/§7",
        ],
        "note": "shape/signature interop only; no compliance claim",
    }
    print(json.dumps(results, indent=2))
    print("\nACTA PROBE:", "PASS" if results["all_checks_pass"] else "FAIL")
    return 0 if results["all_checks_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
