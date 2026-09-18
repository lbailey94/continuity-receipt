"""Verify the 10 v0 test vectors against expected verdicts (spec §9)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys, records, verify_bundle  # noqa: E402
from continuity_receipt.bundle import TaskChain, receipt_digest  # noqa: E402

VECTORS = ROOT / "vectors"

EXPECTED = {
    "01_happy_minimal.json": ("TRUSTED", None, False),
    "02_happy_full.json": ("TRUSTED", None, False),
    "03_tampered_body.json": ("UNTRUSTED", "bad_signature", False),
    "04_missing_termination.json": ("UNTRUSTED", "missing_termination", False),
    "05_cap_exceeded.json": ("UNTRUSTED", "cap_exceeded", False),
    "06_delivery_before_settlement.json": ("UNTRUSTED", "delivery_before_settlement", False),
    "07_redacted_no_disclosure.json": ("PROVISIONAL", None, False),
    "08_redacted_disclosed.json": ("TRUSTED", None, False),
    "09_erased_content.json": ("INSUFFICIENT_EVIDENCE", None, False),
    "10a_anchor_invalid.json": ("UNTRUSTED", "anchor_invalid", False),
    "10b_anchor_missing.json": ("PROVISIONAL", None, True),
}


class TestVectors(unittest.TestCase):
    def test_all_vectors(self):
        for name, (verdict, code, require_anchor) in EXPECTED.items():
            path = VECTORS / name
            self.assertTrue(path.exists(), f"missing vector {name}; run tools/make_vectors.py")
            bundle = json.loads(path.read_text(encoding="utf-8"))
            result = verify_bundle(bundle, require_anchor=require_anchor)
            self.assertEqual(
                result.verdict,
                verdict,
                f"{name}: {result.verdict} != {verdict} — {result.errors}",
            )
            if code:
                self.assertIn(
                    code,
                    result.codes(),
                    f"{name}: expected error {code}, got {result.codes()}",
                )


class TestPrimitives(unittest.TestCase):
    def test_canonical_determinism(self):
        from continuity_receipt.canon import canonical_bytes

        first = canonical_bytes({"b": 1, "a": [1, 2, {"d": "x", "c": True}]})
        second = canonical_bytes({"a": [1, 2, {"c": True, "d": "x"}], "b": 1})
        self.assertEqual(first, second)

    def test_float_rejected(self):
        from continuity_receipt.canon import canonical_bytes

        with self.assertRaises(ValueError):
            canonical_bytes({"amount": 1.5})

    def test_did_key_roundtrip(self):
        did, key = keys.generate(keys.deterministic_seed("roundtrip"))
        pub = key.public_key()
        self.assertEqual(keys.pubkey_to_did_key(pub), did)
        self.assertIsNotNone(keys.did_key_to_pubkey(did))

    def test_chain_link_tamper_detected(self):
        did, key = keys.generate(keys.deterministic_seed("chain"))
        chain = TaskChain()
        chain.add("session.pass.created", "gate", did, key, {
            "gate_id": "g", "mandala_class": "gate-lite",
            "quotas": {}, "expires_at": "2026-09-18T00:00:00Z",
            "policy_version": "p", "mandate_ref": "sha256:" + "0" * 64,
            "agent_id": "did:key:zTest",
        })
        chain.add("task.termination", "gate", did, key, {
            "reason": "completed", "limits_at_stop": {}, "remaining": {},
        })
        digest_before = receipt_digest(chain.receipts[1])
        chain.receipts[1]["body"]["reason"] = "killed"
        self.assertNotEqual(digest_before, receipt_digest(chain.receipts[1]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
