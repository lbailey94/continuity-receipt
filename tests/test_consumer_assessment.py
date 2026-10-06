"""Offline relying-agent assessment profile tests."""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.consumer import InputError, assess_bundle, load_raw  # noqa: E402

VECTORS = ROOT / "vectors" / "verification"


class ConsumerAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.bundle = json.loads((VECTORS / "bundle.json").read_text())
        issuer = self.bundle["receipts"][0]["issuer"]["id"]
        self.policy = {
            "id": "test-counterparty-v1",
            "accepted_specs": ["continuity-receipt/0.3"],
            "trusted_issuers": [issuer],
            "required_record_types": ["task.termination"],
        }

    def test_explicit_policy_accepts_trusted_bundle(self):
        result = assess_bundle(self.bundle, self.policy).as_dict()
        self.assertEqual(result["outcome"], "ACCEPT")
        self.assertEqual(result["reason_codes"], ["policy_satisfied"])
        self.assertEqual(result["core"]["verdict"], "TRUSTED")
        self.assertTrue(result["bundle_digest"].startswith("sha256:"))
        self.assertTrue(result["policy"]["digest"].startswith("sha256:"))
        changed = copy.deepcopy(self.bundle)
        changed["consumer_note"] = "different exact input"
        changed_result = assess_bundle(changed, self.policy).as_dict()
        self.assertNotEqual(result["bundle_digest"], changed_result["bundle_digest"])

    def test_published_04_agreement_bundle_accepts_all_envelope_issuers(self):
        bundle = json.loads((ROOT / "vectors" / "17_agreement_bound.json").read_text())
        issuers = sorted({r["issuer"]["id"] for r in bundle["receipts"]})
        policy = {
            "id": "agreement-counterparty-v1",
            "accepted_specs": ["continuity-receipt/0.4"],
            "trusted_issuers": issuers,
            "required_record_types": ["agreement.offer", "agreement.accept"],
        }
        result = assess_bundle(bundle, policy).as_dict()
        self.assertEqual(result["outcome"], "ACCEPT")
        self.assertEqual(result["core"]["verdict"], "TRUSTED")
        self.assertEqual(len(issuers), 2)
        self.assertTrue(result["bundle_digest"].startswith("sha256:"))

    def test_documented_04_policy_accepts_its_vector(self):
        bundle_path = ROOT / "vectors" / "17_agreement_bound.json"
        policy_path = ROOT / "examples" / "consumer-policy-0.4.json"
        run = subprocess.run(
            [sys.executable, "-m", "continuity_receipt.consumer", str(bundle_path), "--policy", str(policy_path)],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["outcome"], "ACCEPT")
        self.assertEqual(result["bundle_digest"], "sha256:6ec87ad89b003b998178f4bbdc72d5c521a6b8de37c2839ed0a743844bcd9767")

    def test_required_unpublished_record_types_are_rejected(self):
        for record_type in ("state.commitment", "authority.grant"):
            with self.subTest(record_type=record_type), self.assertRaisesRegex(
                InputError, "policy_record_types_invalid"
            ):
                assess_bundle(self.bundle, dict(self.policy, required_record_types=[record_type]))

    def test_future_registry_type_does_not_expand_consumer_profile(self):
        code = r'''import json
from pathlib import Path
from continuity_receipt import records
records.RECORD_TYPES += ("hypothetical.future.record",)
from continuity_receipt.consumer import InputError, assess_bundle
root = Path.cwd()
bundle = json.loads((root / "vectors/17_agreement_bound.json").read_text())
issuers = sorted({receipt["issuer"]["id"] for receipt in bundle["receipts"]})
policy = {
    "id": "future-registry-type-test",
    "accepted_specs": ["continuity-receipt/0.4"],
    "trusted_issuers": issuers,
    "required_record_types": ["hypothetical.future.record"],
}
try:
    assess_bundle(bundle, policy)
except InputError as exc:
    assert str(exc) == "policy_record_types_invalid", str(exc)
else:
    raise AssertionError("consumer profile grew with the verifier registry")
'''
        run = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_deep_direct_bundle_returns_structured_rejection(self):
        bundle = {}
        cursor = bundle
        for _ in range(1500):
            child = {}
            cursor["nested"] = child
            cursor = child
        result = assess_bundle(bundle, None).as_dict()
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIn("nesting_too_deep", [entry["code"] for entry in result["core"]["errors"]])
        self.assertIsNone(result["bundle_digest"])

    def test_policy_absent_does_not_accept(self):
        result = assess_bundle(self.bundle, None).as_dict()
        self.assertEqual((result["outcome"], result["reason_codes"]), ("NEEDS_EVIDENCE", ["policy_missing"]))

    def test_untrusted_core_rejects_even_without_policy(self):
        bundle = copy.deepcopy(self.bundle)
        bundle["receipts"][0]["sig"]["value"] = "AAAA"
        result = assess_bundle(bundle, None).as_dict()
        self.assertEqual(result["outcome"], "REJECT")
        self.assertEqual(result["reason_codes"], ["core_untrusted", "policy_missing"])

    def test_empty_issuer_trust_policy_needs_evidence(self):
        policy = dict(self.policy, trusted_issuers=[])
        result = assess_bundle(self.bundle, policy).as_dict()
        self.assertEqual(result["outcome"], "NEEDS_EVIDENCE")
        self.assertIn("trusted_issuer_policy_empty", result["reason_codes"])

    def test_explicit_untrusted_issuer_is_policy_rejection(self):
        policy = dict(self.policy, trusted_issuers=["did:key:outside-policy"])
        result = assess_bundle(self.bundle, policy).as_dict()
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIn("issuer_not_trusted", result["reason_codes"])

    def test_explicit_spec_denial_rejects_even_if_core_evidence_is_incomplete(self):
        bundle = json.loads((VECTORS / "erased_bundle.json").read_text())
        policy = dict(self.policy, accepted_specs=["continuity-receipt/0.4"])
        result = assess_bundle(bundle, policy).as_dict()
        self.assertEqual(result["core"]["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIn("spec_not_accepted", result["reason_codes"])
        self.assertIn("core_evidence_incomplete", result["reason_codes"])

    def test_tampered_signature_rejects(self):
        bundle = copy.deepcopy(self.bundle)
        bundle["receipts"][0]["sig"]["value"] = "AAAA"
        result = assess_bundle(bundle, self.policy).as_dict()
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIn("core_untrusted", result["reason_codes"])
        self.assertTrue(result["core"]["errors"])

    def test_missing_required_record_needs_evidence(self):
        policy = dict(self.policy, required_record_types=["settlement"])
        result = assess_bundle(self.bundle, policy).as_dict()
        self.assertEqual(result["outcome"], "NEEDS_EVIDENCE")
        self.assertIn("required_record_missing", result["reason_codes"])

    def test_incomplete_core_evidence_maps_to_needs_evidence(self):
        bundle = json.loads((VECTORS / "erased_bundle.json").read_text())
        policy = dict(self.policy, accepted_specs=["continuity-receipt/0.1"])
        result = assess_bundle(bundle, policy).as_dict()
        self.assertEqual(result["outcome"], "NEEDS_EVIDENCE")
        self.assertIn("core_evidence_incomplete", result["reason_codes"])

    def test_unsupported_profile_spec_is_rejected_by_policy(self):
        policy = dict(self.policy, accepted_specs=["continuity-receipt/0.5"])
        with self.assertRaises(InputError):
            assess_bundle(self.bundle, policy)
        bundle = copy.deepcopy(self.bundle)
        bundle["spec"] = "continuity-receipt/9.9"
        result = assess_bundle(bundle, self.policy).as_dict()
        self.assertEqual(result["outcome"], "REJECT")
        self.assertIn("spec_not_accepted", result["reason_codes"])

    def test_reason_order_is_deterministic(self):
        policy = dict(self.policy, trusted_issuers=[], required_record_types=["settlement"])
        first = assess_bundle(self.bundle, policy).as_dict()
        second = assess_bundle(self.bundle, policy).as_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["reason_codes"], sorted(first["reason_codes"]))

    def test_raw_loader_rejects_duplicate_members(self):
        with self.assertRaisesRegex(InputError, "bundle_invalid_json"):
            from continuity_receipt.consumer import _parse_raw
            _parse_raw(b'{"spec":"a","spec":"b"}', "bundle")

    def test_raw_loader_requires_utf8_without_bom(self):
        from continuity_receipt.consumer import _parse_raw
        for raw in (b'{"x":1}'.decode().encode("utf-16"), b'\xef\xbb\xbf{"x":1}'):
            with self.subTest(raw=raw[:4]), self.assertRaisesRegex(InputError, "bundle_invalid_json"):
                _parse_raw(raw, "bundle")

    def test_raw_loader_rejects_excessive_parser_recursion(self):
        from continuity_receipt.consumer import _parse_raw
        raw = (b"[" * 10_000) + (b"]" * 10_000)
        with self.assertRaisesRegex(InputError, "bundle_invalid_json"):
            _parse_raw(raw, "bundle")

    def test_raw_loader_requires_object_top_level(self):
        from continuity_receipt.consumer import _parse_raw
        for label, raw in (("bundle", b"[]"), ("policy", b"null")):
            with self.subTest(label=label), self.assertRaisesRegex(InputError, f"{label}_not_object"):
                _parse_raw(raw, label)

    def test_cli_rejects_duplicate_json_and_reports_machine_error(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            path.write_bytes(b'{"spec":"a","spec":"b"}')
            run = subprocess.run(
                [sys.executable, "-m", "continuity_receipt.consumer", str(path)],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["reason_codes"], ["bundle_invalid_json"])


if __name__ == "__main__":
    unittest.main()
