"""Mechanics checks for the standalone public-text claim-review fixture."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "03_public_text_claim_review"
sys.path.insert(0, str(EXAMPLE))
from claim_policy import validate_claim_review  # noqa: E402
from continuity_receipt import keys, verification, verify_bundle  # noqa: E402
from continuity_receipt.bundle import receipt_digest  # noqa: E402
from continuity_receipt.records import sign_receipt  # noqa: E402

SOURCE_COMMIT = "f208268e7c706ebaed6968a694615c1ad94cb3c0"


class TestPublicTextClaimReviewExample(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture = Path(self.temp.name) / "capture"
        subprocess.run(
            [sys.executable, str(EXAMPLE / "run_example.py"), "--out", str(self.capture)],
            check=True,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def verify(self, capture=None):
        return subprocess.run(
            [sys.executable, str(EXAMPLE / "verify_capture.py"), str(capture or self.capture)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_capture_hashes_artifacts_and_checks_signed_verification_receipt(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["capture_files"], "MATCH")
        self.assertEqual(report["bundle_verdict"], "TRUSTED")
        self.assertFalse(report["independent_verification"])
        self.assertEqual(report["claim_grades"][1]["grade"], "not_established_by_excerpt")

    def test_changed_and_missing_artifact_bytes_fail(self):
        changed = Path(self.temp.name) / "changed"
        shutil.copytree(self.capture, changed)
        with (changed / "source_excerpt.txt").open("ab") as stream:
            stream.write(b"tampered\n")
        result = self.verify(changed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mismatch", result.stderr)

        missing = Path(self.temp.name) / "missing"
        shutil.copytree(self.capture, missing)
        (missing / "source_excerpt.txt").unlink()
        result = self.verify(missing)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source_excerpt.txt", result.stderr)

    def test_rehashed_manifest_does_not_override_signed_artifact_hashes(self):
        changed = Path(self.temp.name) / "rehash"
        shutil.copytree(self.capture, changed)
        source = changed / "source_excerpt.txt"
        source.write_bytes(source.read_bytes() + b" tampered\n")
        manifest_path = changed / "capture_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        import hashlib
        manifest["files"]["source_excerpt.txt"] = {
            "sha256": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
            "size": source.stat().st_size,
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.verify(changed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not bound by the signed decision", result.stderr)

    def test_omitting_an_artifact_from_unsigned_manifest_fails(self):
        omitted = Path(self.temp.name) / "omitted"
        shutil.copytree(self.capture, omitted)
        path = omitted / "capture_manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        del manifest["files"]["provenance.json"]
        path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.verify(omitted)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact required artifact set", result.stderr)

    def test_unlisted_capture_file_fails_exact_inventory_check(self):
        extra = Path(self.temp.name) / "extra"
        shutil.copytree(self.capture, extra)
        (extra / "unlisted.txt").write_text("unbound bytes\n", encoding="utf-8")
        result = self.verify(extra)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact required artifact inventory", result.stderr)

    def test_duplicate_manifest_member_is_rejected_as_raw_input(self):
        malformed = Path(self.temp.name) / "duplicate"
        shutil.copytree(self.capture, malformed)
        path = malformed / "capture_manifest.json"
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace("{\n", "{\n  \"kind\": \"other\",\n", 1), encoding="utf-8")
        result = self.verify(malformed)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr.lower())

    def test_grader_rejects_a_supported_label_without_an_exact_source_span(self):
        bad = {
            "source": {
                "url": "https://example.invalid/source",
                "snapshot_path": "source_excerpt.txt",
                "snapshot_commit": SOURCE_COMMIT,
                "capture_note": "test fixture",
            },
            "claims": [{
                "id": "installability",
                "claim": "Package is installable today.",
                "limit": "Not established by this text.",
                "grade": "supported_by_excerpt",
                "supporting_text": "package is installable today",
            }]
        }
        with self.assertRaisesRegex(ValueError, "quote bytes present"):
            validate_claim_review(bad, "`continuity-receipt/0.5` — published 2026-09-30.\n".encode("utf-8"))

    def test_grader_rejects_malformed_row_without_leaking_key_errors(self):
        fixture = json.loads((EXAMPLE / "claims.json").read_text(encoding="utf-8"))
        del fixture["claims"][0]["id"]
        with self.assertRaisesRegex(ValueError, "claim row id"):
            validate_claim_review(fixture, (EXAMPLE / "source_excerpt.txt").read_bytes())

    def test_pinned_excerpt_is_verbatim_in_the_named_public_readme_revision(self):
        source = (EXAMPLE / "source_excerpt.txt").read_bytes()
        readme = subprocess.check_output(
            ["git", "show", f"{SOURCE_COMMIT}:README.md"], cwd=ROOT
        )
        self.assertIn(source, readme)
        claims = json.loads((EXAMPLE / "claims.json").read_text(encoding="utf-8"))
        self.assertEqual(claims["source"]["snapshot_commit"], SOURCE_COMMIT)

    def test_signed_grade_summary_must_mirror_the_hashed_claim_artifact(self):
        tampered = Path(self.temp.name) / "signed-summary-mismatch"
        shutil.copytree(self.capture, tampered)
        bundle_path = tampered / "bundle.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        did, key = keys.generate(keys.deterministic_seed("public-text-claim-review-example-only"))
        decision = bundle["receipts"][1]
        decision["body"]["claim_review"]["claim_grades"][0]["claim"] = "a different signed summary"
        bundle["receipts"][1] = sign_receipt(
            {name: value for name, value in decision.items() if name != "sig"}, key, did
        )
        termination = bundle["receipts"][2]
        termination["prev"] = receipt_digest(bundle["receipts"][1])
        bundle["receipts"][2] = sign_receipt(
            {name: value for name, value in termination.items() if name != "sig"}, key, did
        )
        self.assertEqual(verify_bundle(bundle).verdict, "TRUSTED")
        bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result = verify_bundle(bundle)
        verification_receipt = verification.issue_verification_receipt(
            bundle,
            result,
            issuer=did,
            private_key=key,
            implementation="python-reference-fixture",
            verified_at="2026-10-05T12:00:03Z",
        )
        receipt_path = tampered / "verification_receipt.json"
        receipt_path.write_text(json.dumps(verification_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest_path = tampered / "capture_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name in ("bundle.json", "verification_receipt.json"):
            raw = (tampered / name).read_bytes()
            import hashlib
            manifest["files"][name] = {
                "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        verified = self.verify(tampered)
        self.assertNotEqual(verified.returncode, 0)
        self.assertIn("signed claim-grade summary differs", verified.stderr)


if __name__ == "__main__":
    unittest.main()
