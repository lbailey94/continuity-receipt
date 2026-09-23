"""Verify every vector against its expected verdict (vectors/manifest.json)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys, records, verify_bundle  # noqa: E402
from continuity_receipt.bundle import TaskChain, receipt_digest  # noqa: E402

VECTORS = ROOT / "vectors"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))


class TestVectors(unittest.TestCase):
    def test_all_vectors(self):
        for entry in MANIFEST["vectors"]:
            name = entry["file"]
            path = VECTORS / name
            self.assertTrue(path.exists(), f"missing vector {name}; run tools/make_vectors.py")
            bundle = json.loads(path.read_text(encoding="utf-8"))
            result = verify_bundle(bundle, require_anchor=entry["require_anchor"])
            self.assertEqual(
                result.verdict,
                entry["expected_verdict"],
                f"{name}: {result.verdict} != {entry['expected_verdict']} — {result.errors}",
            )
            if entry.get("expected_code"):
                self.assertIn(
                    entry["expected_code"],
                    result.codes(),
                    f"{name}: expected error {entry['expected_code']}, got {result.codes()}",
                )

    def test_unsupported_spec_refused(self):
        bundle = json.loads((VECTORS / "01_happy_minimal.json").read_text(encoding="utf-8"))
        bundle["spec"] = "continuity-receipt/9.9"
        result = verify_bundle(bundle)
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("version_unsupported", result.codes())


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
        chain = TaskChain(spec="continuity-receipt/0.2")
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

    def test_attestation_view_excludes_attestation(self):
        did, key = keys.generate(keys.deterministic_seed("attest-view"))
        body = {
            "request_hash": "sha256:" + "1" * 64,
            "response_hash": "sha256:" + "2" * 64,
            "counterparty": {"id": did},
        }
        body["counterparty"]["attestation"] = records.sign_body_attestation(body, key, did)
        view = records.attestation_view(body)
        self.assertNotIn("attestation", view["counterparty"])

    def test_supported_specs(self):
        self.assertIn("continuity-receipt/0.1", records.SUPPORTED_SPECS)
        self.assertIn("continuity-receipt/0.2", records.SUPPORTED_SPECS)
        self.assertIn("continuity-receipt/0.3", records.SUPPORTED_SPECS)
        self.assertEqual(records.SPEC_ID, "continuity-receipt/0.3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
