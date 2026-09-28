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


if __name__ == "__main__":
    unittest.main()
