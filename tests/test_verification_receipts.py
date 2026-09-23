"""Verification receipts: vectors, schema, round trip, digest rule, CLI."""
import json
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt import keys, verify_bundle  # noqa: E402
from continuity_receipt import verification  # noqa: E402
from continuity_receipt._version import __version__  # noqa: E402
from continuity_receipt.canon import canonical_bytes, sha256_prefixed  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover - CI installs jsonschema
    jsonschema = None

VECTORS = ROOT / "vectors" / "verification"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
SCHEMA_PATH = ROOT / "schema" / "verification-receipt-1.schema.json"


def trusted_result() -> dict:
    return {
        "verdict": "TRUSTED",
        "errors": [],
        "provisional_reasons": [],
        "insufficient_reasons": [],
        "summary": {"receipts": 4, "terminated": True},
    }


class TestVerificationVectors(unittest.TestCase):
    def test_all_vectors(self):
        for entry in MANIFEST["vectors"]:
            path = VECTORS / entry["file"]
            self.assertTrue(path.exists(), f"missing vector {entry['file']}")
            receipt = json.loads(path.read_text(encoding="utf-8"))
            bundle = None
            if entry.get("bundle_file"):
                bundle = (VECTORS / entry["bundle_file"]).read_bytes()
            revocations = None
            if entry.get("revocations_file"):
                document = json.loads(
                    (VECTORS / entry["revocations_file"]).read_text(encoding="utf-8")
                )
                revocations = document["statements"]
            result = verification.verify_verification_receipt(receipt, bundle, revocations)
            self.assertEqual(result.valid, entry["expected_valid"], entry["file"])
            self.assertEqual(set(result.errors), set(entry["expected_errors"]), entry["file"])

    def test_schema_valid_vectors(self):
        if jsonschema is None:
            self.skipTest("jsonschema not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        for entry in MANIFEST["vectors"]:
            if not entry["expected_valid"]:
                continue
            receipt = json.loads((VECTORS / entry["file"]).read_text(encoding="utf-8"))
            errors = sorted(validator.iter_errors(receipt), key=lambda e: list(e.path))
            self.assertEqual(errors, [], f"{entry['file']}: {[e.message for e in errors][:3]}")

    def test_receipts_record_the_full_result(self):
        receipt = json.loads((VECTORS / "01_valid.json").read_text(encoding="utf-8"))
        for field in ("errors", "provisional_reasons", "insufficient_reasons", "summary"):
            self.assertIn(field, receipt, field)
        provisional = json.loads(
            (VECTORS / "15_provisional_anchor_missing.json").read_text(encoding="utf-8")
        )
        self.assertEqual(provisional["verdict"], "PROVISIONAL")
        self.assertIn("anchor_missing", provisional["provisional_reasons"])
        erased = json.loads((VECTORS / "16_insufficient_erased.json").read_text(encoding="utf-8"))
        self.assertEqual(erased["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertTrue(erased["insufficient_reasons"])


class TestVerificationReceipts(unittest.TestCase):
    def setUp(self):
        self.did, self.key = keys.generate(keys.deterministic_seed("unit-verifier"))
        self.bundle = json.loads((VECTORS / "bundle.json").read_text(encoding="utf-8"))

    def test_round_trip(self):
        result = dict(trusted_result(), verdict="PROVISIONAL", provisional_reasons=["anchor_missing"])
        receipt = verification.issue_verification_receipt(
            self.bundle,
            result,
            issuer=self.did,
            private_key=self.key,
            verified_at="2026-09-23T21:00:00Z",
        )
        checked = verification.verify_verification_receipt(receipt, self.bundle)
        self.assertTrue(checked.valid, checked.errors)
        self.assertTrue(checked.digest_match)
        self.assertEqual(checked.verdict, "PROVISIONAL")
        self.assertEqual(receipt["error_codes"], [])
        self.assertEqual(receipt["provisional_reasons"], ["anchor_missing"])

    def test_issue_refuses_inconsistent_result(self):
        result = dict(trusted_result(), provisional_reasons=["anchor_missing"])
        with self.assertRaises(ValueError):
            verification.issue_verification_receipt(
                self.bundle, result, issuer=self.did, private_key=self.key
            )

    def test_issue_accepts_verify_result_objects(self):
        result = verify_bundle(self.bundle)
        receipt = verification.issue_verification_receipt(
            self.bundle, result, issuer=self.did, private_key=self.key
        )
        self.assertEqual(receipt["verdict"], "TRUSTED")
        self.assertEqual(receipt["summary"]["terminated"], True)

    def test_digest_is_over_canonical_bytes(self):
        receipt = verification.issue_verification_receipt(
            self.bundle, trusted_result(), issuer=self.did, private_key=self.key,
            verified_at="2026-09-23T21:00:00Z",
        )
        compact = json.dumps(self.bundle, separators=(",", ":")).encode()
        pretty = json.dumps(self.bundle, indent=4).encode()
        expected = sha256_prefixed(canonical_bytes(self.bundle))
        self.assertEqual(receipt["bundle_digest"], expected)
        self.assertTrue(verification.verify_verification_receipt(receipt, compact).digest_match)
        self.assertTrue(verification.verify_verification_receipt(receipt, pretty).digest_match)

    def test_receipt_digest_matches_signed_view(self):
        receipt = verification.issue_verification_receipt(
            self.bundle, trusted_result(), issuer=self.did, private_key=self.key,
            verified_at="2026-09-23T21:00:00Z",
        )
        expected = sha256_prefixed(
            canonical_bytes({k: v for k, v in receipt.items() if k != "sig"})
        )
        self.assertEqual(verification.receipt_digest(receipt), expected)

    def test_non_canonicalizable_bundle_refused(self):
        with self.assertRaises(ValueError):
            verification.issue_verification_receipt(
                {"x": 1.5}, trusted_result(), issuer=self.did, private_key=self.key
            )

    def test_non_enum_verdict_refused(self):
        with self.assertRaises(ValueError):
            verification.issue_verification_receipt(
                self.bundle, dict(trusted_result(), verdict="MAYBE"),
                issuer=self.did, private_key=self.key,
            )

    def test_revocation_check_is_opt_in(self):
        receipt = verification.issue_verification_receipt(
            self.bundle, trusted_result(), issuer=self.did, private_key=self.key,
            verified_at="2026-09-23T21:00:00Z",
        )
        statement = {"key": self.did, "revoked_at": "2026-09-23T20:00:00Z"}
        statement["sig"] = {
            "alg": "ed25519",
            "key": self.did,
            "value": keys.sign(self.key, canonical_bytes(statement)),
        }
        self.assertTrue(verification.verify_verification_receipt(receipt).valid)
        revoked = verification.verify_verification_receipt(receipt, None, [statement])
        self.assertFalse(revoked.valid)
        self.assertIn("key_revoked", revoked.errors)

    def test_not_an_object(self):
        result = verification.verify_verification_receipt(["not", "an", "object"])
        self.assertEqual(result.errors, ["not_an_object"])

    def test_cli_exit_codes(self):
        def run(*args):
            return subprocess.run(
                [sys.executable, "-m", "continuity_receipt.verification", *args],
                capture_output=True, text=True, cwd=ROOT,
            )

        valid = run(str(VECTORS / "01_valid.json"), "--bundle", str(VECTORS / "bundle.json"))
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        self.assertTrue(json.loads(valid.stdout)["valid"])
        tampered = run(str(VECTORS / "03_tampered_verdict.json"))
        self.assertEqual(tampered.returncode, 1)
        self.assertFalse(json.loads(tampered.stdout)["valid"])
        revoked = run(
            str(VECTORS / "12_revoked_issuer.json"),
            "--bundle", str(VECTORS / "bundle.json"),
            "--revocations", str(VECTORS / "12_revoked_issuer.revocations.json"),
        )
        self.assertEqual(revoked.returncode, 1)
        self.assertIn("key_revoked", json.loads(revoked.stdout)["errors"])
        digest = run(str(VECTORS / "01_valid.json"), "--digest")
        self.assertEqual(digest.returncode, 0)
        self.assertTrue(digest.stdout.strip().startswith("sha256:"))

    def test_cli_canonical_view_matches_digest(self):
        import hashlib
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            canonical_path = Path(tmp) / "receipt.canonical"
            proc = subprocess.run(
                [sys.executable, "-m", "continuity_receipt.verification",
                 str(VECTORS / "01_valid.json"), "--canonical", str(canonical_path)],
                capture_output=True, text=True, cwd=ROOT,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            digest = proc.stdout.strip()
            file_hash = "sha256:" + hashlib.sha256(canonical_path.read_bytes()).hexdigest()
            self.assertEqual(digest, file_hash)


class TestVersionPin(unittest.TestCase):
    def test_version_matches_pyproject(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], __version__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
