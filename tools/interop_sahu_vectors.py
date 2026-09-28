#!/usr/bin/env python3
"""Interop probe: reproduce draft-sahu-agent-action-receipts-00 vectors.

The draft gives one canonical byte sequence and one serialized line per
vector. We reproduce them with an independent implementation of the draft's
rules (fixed member order, recursively sorted `params`, compact JSON, total
omission) and check:

  1. the published public key derives from the published test seed
  2. Ed25519 verifies over the draft's canonical bytes (both vectors)
  3. SHA-256 of the serialized line 1 equals the prev_hash carried by vector 2
     (their chain-link rule digests the transmitted octets)
  4. our independent canonical reconstruction is byte-identical to theirs
  5. the tamper vector: swapping actor.user in vector 1 breaks the signature
     and the chain link at the right positions

This is a compatibility probe only: it verifies that the draft's published
bytes are reproducible by an outside implementation. It does not adopt their
format and makes no claim about their implementation.
"""
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SEED = bytes([0x01] * 32)
PUBKEY_HEX = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"

V1_CANON = (
    '{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params"'
    ':{"class":"publish","rule_id":"npm-publish","tier":"approve"},"suc'
    'cess":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","u'
    'ser":"alice"}}'
)
V1_LINE = (
    '{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params"'
    ':{"rule_id":"npm-publish","tier":"approve","class":"publish"},"suc'
    'cess":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","u'
    'ser":"alice"},"public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709'
    'bf1d94121bf3748801b40f6f5c","signature":"ab6afa750440d38f72dc5601f'
    '45b1df918de60049b2accbb438dd909222f42755a534ee67e2eb1397f9d3ca6bd0'
    'bf67f1ec078ecc60c08c92438acd2b7dc5802"}'
)
V1_SIG = bytes.fromhex(
    "ab6afa750440d38f72dc5601f45b1df918de60049b2accbb438dd909222f4275"
    "5a534ee67e2eb1397f9d3ca6bd0bf67f1ec078ecc60c08c92438acd2b7dc5802"
)
V1_PREV_OF_V2 = "18a2a79ac5e4dcc31172783a0f33efc1518d426c5cf0ccd24982d41c9aa3ee4c"

V2_CANON = (
    '{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval","params"'
    ':{"approver":"alice","decision":"approved","rule_id":"npm-publish"'
    '},"success":true,"ts_ms":1755300012000,"actor":{"agent":"claude-co'
    'de","user":"alice"},"prev_hash":"18a2a79ac5e4dcc31172783a0f33efc15'
    '18d426c5cf0ccd24982d41c9aa3ee4c"}'
)
V2_SIG = bytes.fromhex(
    "891dc88a6dc93507faca8d52eceb0baf107f325a1b3bb5c60e3e357cac86d6cc"
    "fd2a0bcf3cee3b7237040483fe1b8c4f049fa72c6a59eb97a22d2c7e97d2cc02"
)

FIXED_ORDER = ("step_id", "action_id", "params", "success", "ts_ms", "actor", "prev_hash")


def _sorted_json(value):
    """Draft §4: params sort recursively by code point; arrays keep order."""
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _sorted_json(value[k])
            for k in sorted(value, key=lambda s: [ord(c) for c in s])
        ) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_sorted_json(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _canonical(receipt):
    parts = []
    for key in FIXED_ORDER:
        if key not in receipt:
            continue
        if key == "params":
            parts.append('"params":' + _sorted_json(receipt[key]))
        elif key == "actor":
            actor = receipt[key]
            inner = ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + json.dumps(actor[k], ensure_ascii=False)
                for k in ("agent", "user")
                if k in actor
            )
            parts.append('"actor":{' + inner + "}")
        else:
            parts.append(json.dumps(key, ensure_ascii=False) + ":" + json.dumps(receipt[key], ensure_ascii=False))
    return "{" + ",".join(parts) + "}"


def main() -> int:
    results = {"probe": "sahu-agent-action-receipts-00", "checks": {}}

    # 1. seed -> public key
    pub = Ed25519PrivateKey.from_private_bytes(SEED).public_key()
    from cryptography.hazmat.primitives import serialization
    derived = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    results["checks"]["seed_derives_pubkey"] = derived == PUBKEY_HEX

    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBKEY_HEX))

    # 2. signatures over the draft's canonical bytes
    try:
        key.verify(V1_SIG, V1_CANON.encode())
        results["checks"]["vector1_signature_valid"] = True
    except Exception:
        results["checks"]["vector1_signature_valid"] = False
    try:
        key.verify(V2_SIG, V2_CANON.encode())
        results["checks"]["vector2_signature_valid"] = True
    except Exception:
        results["checks"]["vector2_signature_valid"] = False

    # 3. chain link over transmitted octets
    line1_hash = hashlib.sha256(V1_LINE.encode()).hexdigest()
    results["checks"]["chain_link_matches"] = line1_hash == V1_PREV_OF_V2
    results["line1_sha256"] = line1_hash

    # 4. independent canonical reconstruction vs the draft's bytes
    v1 = json.loads(V1_LINE)
    v1.pop("public_key", None)
    v1.pop("signature", None)
    v2 = json.loads(V2_CANON)
    results["checks"]["canonical1_reproduced"] = _canonical(v1) == V1_CANON
    results["checks"]["canonical2_reproduced"] = _canonical(v2) == V2_CANON
    if _canonical(v1) != V1_CANON:
        results["canonical1_ours"] = _canonical(v1)

    # 5. tamper vector: actor.user alice -> mallory
    tampered = dict(v1)
    tampered["actor"] = {"agent": "claude-code", "user": "mallory"}
    tampered_canon = _canonical(tampered)
    try:
        key.verify(V1_SIG, tampered_canon.encode())
        results["checks"]["tamper_signature_rejected"] = False
    except Exception:
        results["checks"]["tamper_signature_rejected"] = True
    tampered_line = V1_LINE.replace('"user":"alice"', '"user":"mallory"')
    results["checks"]["tamper_breaks_chain_link"] = (
        hashlib.sha256(tampered_line.encode()).hexdigest() != V1_PREV_OF_V2
    )

    ok = all(results["checks"].values())
    results["all_checks_pass"] = ok
    print(json.dumps(results, indent=2))
    print("\nINTEROP PROBE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
