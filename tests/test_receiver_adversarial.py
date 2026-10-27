"""Black-box adversarial checks for the experimental memory receiver."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.receiver_store import ReceiverStore  # noqa: E402
from continuity_receipt.memory_snapshot import MAX_DIRECTORY_DEPTH  # noqa: E402


class ReceiverAdversarialTests(unittest.TestCase):
    def test_api_publish_rejects_unreadable_depth_without_advancing_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
            store = ReceiverStore(
                base / "data", base / "trust.sqlite", context="adversarial-test",
                scope="memory:test", trusted_public_key=key.public_key(),
            )
            self.assertEqual(store.initialize()["outcome"], "ACCEPT")
            path = "/".join(["d"] * (MAX_DIRECTORY_DEPTH + 1) + ["resume.txt"])
            result = store.publish(
                {path: b"deeper than receiver policy"}, private_key=key,
                expected_checkpoint_digest=None, now="2026-10-23T12:00:00Z",
            )
            self.assertEqual(result["outcome"], "REJECT", result)
            self.assertIsNone(store.current_reference())

    def test_recall_bounds_unmanifested_empty_directory_walk(self):
        """Empty directory padding must not turn a bounded snapshot into unbounded work."""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
            store = ReceiverStore(
                base / "data", base / "trust.sqlite", context="adversarial-test",
                scope="memory:test", trusted_public_key=key.public_key(),
            )
            self.assertEqual(store.initialize()["outcome"], "ACCEPT")
            published = store.publish(
                {"resume.txt": b"only signed file\n"}, private_key=key,
                expected_checkpoint_digest=None, now="2026-10-23T12:00:00Z",
            )
            self.assertEqual(published["outcome"], "ACCEPT", published)

            files = (base / "data" / "generations" /
                     published["reference"]["generation_id"] / "files")
            # The snapshot format permits at most 64 files and the publisher
            # capture path caps the whole tree at 4096 entries. These empty
            # directories are outside its signed file set, but recall still
            # traverses them today unless it enforces an entry bound itself.
            for index in range(4097):
                (files / f"padding-{index:04d}").mkdir()

            result = store.recall(now="2026-10-23T12:00:00Z")
            self.assertEqual(result["outcome"], "REJECT", result)
            self.assertIsNone(result["files"])


if __name__ == "__main__":
    unittest.main()
