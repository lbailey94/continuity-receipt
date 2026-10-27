import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.memory_snapshot import build_manifest  # noqa: E402


class ReceiverSnapshotVectorTests(unittest.TestCase):
    def test_frozen_local_receiver_vectors(self):
        packet = json.loads((ROOT / "vectors" / "receiver-file-snapshot-v1.json").read_text(encoding="utf-8"))
        self.assertEqual(packet["suite"], "cpr-python-local-file-snapshot-v1")
        self.assertIn("not a CPR wire specification", packet["scope"])
        for vector in packet["vectors"]:
            with self.subTest(vector=vector["id"]):
                files = {item["path"]: bytes.fromhex(item["bytes_hex"]) for item in vector["files"]}
                if vector["expected_outcome"] == "ACCEPT":
                    manifest = build_manifest(files)
                    self.assertEqual(manifest.decode("utf-8"), vector["expected_manifest_utf8"])
                    self.assertEqual(hashlib.sha256(manifest).hexdigest(), vector["expected_manifest_sha256"])
                else:
                    with self.assertRaisesRegex(ValueError, f"^{vector['expected_reason']}$"):
                        build_manifest(files)


if __name__ == "__main__":
    unittest.main()
