"""Evidence pack export — round-trip and honest-failure behavior."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TOOL = ROOT / "tools" / "pack_evidence.py"
VECTORS = ROOT / "vectors"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
MANIFEST["vectors"] += json.loads((VECTORS / "manifest-0.5.json").read_text(encoding="utf-8"))["vectors"]


class TestPackEvidence(unittest.TestCase):
    def _pack(self, vector: str, out: Path):
        return subprocess.run(
            [sys.executable, str(TOOL), str(VECTORS / vector), "--out", str(out), "--label", "unit test pack"],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )

    def _verify_script(self, out: Path):
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        return subprocess.run(["sh", "verify.sh"], cwd=out, capture_output=True, text=True, env=env)

    def test_trusted_pack_roundtrip(self):
        vector = next(e["file"] for e in MANIFEST["vectors"] if e["expected_verdict"] == "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack"
            res = self._pack(vector, out)
            self.assertEqual(res.returncode, 0, res.stderr)
            for name in ("bundle.json", "verify.sh", "README.txt", "certificate.html", "manifest.json"):
                self.assertTrue((out / name).is_file(), f"missing {name}")
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            for name, digest in manifest["files"].items():
                self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), digest, name)
            self.assertEqual(manifest["verdict"], "TRUSTED")
            self.assertIn("TRUSTED", (out / "certificate.html").read_text(encoding="utf-8"))
            sh = self._verify_script(out)
            self.assertEqual(sh.returncode, 0, sh.stdout + sh.stderr)
            self.assertIn("TRUSTED", sh.stdout)

    def test_failing_pack_marks_failure(self):
        vector = next(e["file"] for e in MANIFEST["vectors"] if e["expected_verdict"] != "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack"
            res = self._pack(vector, out)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertNotEqual(manifest["verdict"], "TRUSTED")
            sh = self._verify_script(out)
            self.assertNotEqual(sh.returncode, 0)
            self.assertIn(manifest["verdict"], (out / "certificate.html").read_text(encoding="utf-8"))

    def test_duplicate_object_member_is_rejected_at_export_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "duplicate.json"
            source.write_bytes((VECTORS / "02_happy_full.json").read_bytes()[:-2] + b',"duplicate_probe":1,"duplicate_probe":2}\n')
            out = Path(tmp) / "pack"
            result = subprocess.run([sys.executable, str(TOOL), str(source), "--out", str(out)], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 2)
            self.assertIn("duplicate JSON object member", result.stderr)
            self.assertFalse((out / "certificate.html").exists())

    def test_offline_verifier_checks_bundle_hash_before_verdict(self):
        vector = next(e["file"] for e in MANIFEST["vectors"] if e["expected_verdict"] == "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack"
            self.assertEqual(self._pack(vector, out).returncode, 0)
            with (out / "bundle.json").open("ab") as f:
                f.write(b" ")
            result = self._verify_script(out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pack hash mismatch: bundle.json", result.stdout + result.stderr)
            self.assertNotIn("TRUSTED", result.stdout)

    def test_offline_verifier_requires_complete_pack_file_inventory(self):
        vector = next(e["file"] for e in MANIFEST["vectors"] if e["expected_verdict"] == "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack"
            self.assertEqual(self._pack(vector, out).returncode, 0)
            manifest_path = out / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            del manifest["files"]["certificate.html"]
            manifest_path.write_text(json.dumps(manifest))
            result = self._verify_script(out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact evidence-pack file set", result.stderr)
            self.assertNotIn("TRUSTED", result.stdout)

    def test_offline_verifier_rejects_duplicate_manifest_members(self):
        vector = next(e["file"] for e in MANIFEST["vectors"] if e["expected_verdict"] == "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack"
            self.assertEqual(self._pack(vector, out).returncode, 0)
            manifest_path = out / "manifest.json"
            manifest = manifest_path.read_text()
            manifest_path.write_text(manifest.replace('"kind": "continuity-receipt-evidence-pack/1",', '"kind": "continuity-receipt-evidence-pack/1",\n  "kind": "other",', 1))
            result = self._verify_script(out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate member 'kind'", result.stderr)
            self.assertNotIn("TRUSTED", result.stdout)

    def test_non_object_json_is_a_clean_export_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "array.json"
            source.write_text("[]")
            result = subprocess.run([sys.executable, str(TOOL), str(source)], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 2)
            self.assertIn("top-level value must be an object", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_bundle_size_limit_matches_cli_input_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "oversized.json"
            source.write_bytes((VECTORS / "02_happy_full.json").read_bytes() + b" " * (8 * 1024 * 1024))
            out = Path(tmp) / "pack"
            result = subprocess.run([sys.executable, str(TOOL), str(source), "--out", str(out)], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 2)
            self.assertIn("exceeds verifier input limit", result.stderr)
            self.assertFalse((out / "certificate.html").exists())

    def test_deep_json_fails_cleanly_in_exporter(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "deep.json"
            source.write_text("[" * 1200 + "0" + "]" * 1200)
            result = subprocess.run([sys.executable, str(TOOL), str(source)], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 2)
            self.assertIn("malformed bundle JSON", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_utf16_bundle_is_rejected_like_utf8_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "utf16.json"
            source.write_bytes((VECTORS / "02_happy_full.json").read_text(encoding="utf-8").encode("utf-16"))
            result = subprocess.run([sys.executable, str(TOOL), str(source)], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 2)
            self.assertIn("malformed bundle JSON", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_offline_python_fallback_handles_apostrophe_in_pack_path(self):
        vector = next(e["file"] for e in MANIFEST["vectors"] if e["expected_verdict"] == "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "reviewer's pack"
            self.assertEqual(self._pack(vector, out).returncode, 0)
            env = {**os.environ, "PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"}
            result = subprocess.run(["sh", "verify.sh"], cwd=out, capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("TRUSTED", result.stdout)

    def test_draft_spec_pack_names_accurate_verifier_requirement(self):
        vector = next(e["file"] for e in json.loads((VECTORS / "manifest-0.6.json").read_text())["vectors"] if e["expected_verdict"] == "TRUSTED")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "pack"
            self.assertEqual(self._pack(vector, out).returncode, 0)
            manifest = json.loads((out / "manifest.json").read_text())
            self.assertEqual(manifest["spec"], "continuity-receipt/0.6")
            self.assertIn("development build explicitly supporting continuity-receipt/0.6", manifest["verifier_requirement"])
            readme = (out / "README.txt").read_text()
            self.assertIn("Published 0.4.0 packages do not support them", readme)


if __name__ == "__main__":
    unittest.main()
