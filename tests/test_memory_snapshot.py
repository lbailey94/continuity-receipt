import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from continuity_receipt.canon import canonical_bytes, sha256_prefixed
from continuity_receipt.keys import deterministic_seed
from continuity_receipt.memory_snapshot import assess_snapshot, build_bundle, build_manifest
from continuity_receipt.receiver_checkpoint import issue_checkpoint, checkpoint_digest


class DecodeOverrideBytes(bytes):
    def __new__(cls, content, decoded):
        value = super().__new__(cls, content)
        value.decoded = decoded
        return value

    def decode(self, *args, **kwargs):
        return self.decoded.decode(*args, **kwargs)


class MemorySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.from_private_bytes(deterministic_seed("memory-snapshot-test"))
        self.public = self.private.public_key()
        self.files = {"notes/today.txt": b"keep this exact\n", "empty.txt": b""}
        self.manifest = build_manifest(self.files)
        self.bundle = build_bundle(self.manifest, scope="user:local", private_key=self.private,
                                   issued_at="2026-10-23T12:00:00Z")
        checkpoint = issue_checkpoint(self.bundle, context="test-receiver", issued_at="2026-10-23T12:00:00Z",
                                      max_age_seconds=3600, private_key=self.private)
        self.checkpoint = canonical_bytes(checkpoint)
        self.reference = checkpoint_digest(checkpoint)

    def assess(self, **overrides):
        args = dict(bundle_bytes=self.bundle, checkpoint_bytes=self.checkpoint,
                    manifest_bytes=self.manifest, files=self.files,
                    expected_scope="user:local", trusted_public_key=self.public,
                    expected_context="test-receiver", accepted_checkpoint_digest=self.reference,
                    now="2026-10-23T12:30:00Z", max_age_seconds=3600)
        args.update(overrides)
        return assess_snapshot(**args)

    def test_builds_canonical_sorted_manifest_and_one_core_trusted_commitment(self):
        self.assertEqual(self.manifest, canonical_bytes({"files": [
            {"path": "empty.txt", "size": 0, "sha256": sha256_prefixed(b"")},
            {"path": "notes/today.txt", "size": 16, "sha256": sha256_prefixed(b"keep this exact\n")},
        ]}))
        bundle = json.loads(self.bundle)
        types = [receipt["type"] for receipt in bundle["receipts"]]
        self.assertEqual(types.count("state.commitment"), 1)
        self.assertNotIn("task.execution", types)
        self.assertEqual(self.assess().outcome, "ACCEPT")

    def test_refuses_changed_bytes_even_when_manifest_and_checkpoint_are_valid(self):
        result = self.assess(files={**self.files, "notes/today.txt": b"changed"})
        self.assertEqual(result.outcome, "REJECT")
        self.assertEqual(result.reason_codes, ["snapshot_bytes_mismatch"])

    def test_bundle_bytes_subclass_cannot_substitute_a_different_commitment_after_checkpoint_check(self):
        forged_files = {"notes/today.txt": b"forged memory"}
        forged_manifest = build_manifest(forged_files)
        forged_bundle = build_bundle(forged_manifest, scope="user:local", private_key=self.private,
                                     issued_at="2026-10-23T12:00:00Z")
        hostile_buffer = DecodeOverrideBytes(self.bundle, forged_bundle)
        result = self.assess(bundle_bytes=hostile_buffer, manifest_bytes=forged_manifest,
                             files=forged_files)
        self.assertEqual(result.outcome, "REJECT")
        self.assertEqual(result.reason_codes, ["snapshot_commitment_mismatch"])

    def test_refuses_scope_mismatch_and_unpinned_commitment_signer(self):
        self.assertEqual(self.assess(expected_scope="other").reason_codes, ["snapshot_commitment_mismatch"])
        other = Ed25519PrivateKey.from_private_bytes(deterministic_seed("other-memory-signer"))
        bundle = build_bundle(self.manifest, scope="user:local", private_key=other,
                              issued_at="2026-10-23T12:00:00Z")
        checkpoint = issue_checkpoint(bundle, context="test-receiver", issued_at="2026-10-23T12:00:00Z",
                                      max_age_seconds=3600, private_key=self.private)
        result = self.assess(bundle_bytes=bundle, checkpoint_bytes=canonical_bytes(checkpoint),
                             accepted_checkpoint_digest=checkpoint_digest(checkpoint))
        self.assertEqual(result.reason_codes, ["snapshot_signer_mismatch"])

    def test_rejects_duplicate_manifest_members_noncanonical_shape_and_wrong_fileset(self):
        duplicate = b'{"files":[],"files":[]}'
        self.assertEqual(self.assess(manifest_bytes=duplicate).reason_codes, ["snapshot_invalid"])
        wrong_shape = canonical_bytes({"files": [], "extra": True})
        self.assertEqual(self.assess(manifest_bytes=wrong_shape).reason_codes, ["snapshot_invalid"])
        self.assertEqual(self.assess(files={"other.txt": b""}).reason_codes, ["snapshot_bytes_mismatch"])

    def test_rejects_bad_paths_unicode_floats_and_limits(self):
        for files in ({"../escape": b"x"}, {"a\\b": b"x"}, {"a//b": b"x"}, {"bad\ud800": b"x"}):
            with self.subTest(files=repr(files)), self.assertRaises(ValueError):
                build_manifest(files)
        with self.assertRaises(ValueError):
            build_manifest({"a" * 5: b"x" * (1024 * 1024 + 1)})
        for data in (b'{"files":[{"path":"x","size":0.0,"sha256":"sha256:' + b"0" * 64 + b'"}]}',
                     b'{"files":[{"path":"x","size":0,"sha256":"sha256:' + b"0" * 64 + b'","path":"x"}]}'):
            with self.assertRaises(ValueError):
                from continuity_receipt.memory_snapshot import _parse_manifest
                _parse_manifest(data)


if __name__ == "__main__":
    unittest.main()
