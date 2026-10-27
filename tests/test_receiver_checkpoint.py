import copy
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.receiver_checkpoint import (  # noqa: E402
    assess_import, checkpoint_digest, issue_checkpoint, receive_bundle,
)
from continuity_receipt.canon import canonical_bytes
from continuity_receipt.keys import b64u
from tools.receiver_checkpoint_demo import appended_bundle


class ReceiverCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.bundle = (ROOT / "vectors/22_local_state_commitment.json").read_bytes()
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.pub = self.key.public_key()
        self.context = "conversation:demo-7"
        self.now = "2026-10-22T12:00:00Z"
        self.checkpoint = issue_checkpoint(self.bundle, context=self.context, issued_at=self.now,
                                           max_age_seconds=3600, private_key=self.key)
        self.cp_bytes = json.dumps(self.checkpoint, separators=(",", ":")).encode()
        self.ref = checkpoint_digest(self.checkpoint)

    def assess(self, **kw):
        args = dict(bundle_bytes=self.bundle, checkpoint_bytes=self.cp_bytes,
                    trusted_public_key=self.pub, expected_context=self.context,
                    accepted_checkpoint_digest=self.ref, now=self.now, max_age_seconds=3600)
        args.update(kw)
        return assess_import(**args)

    def test_accept_and_sink_release(self):
        got = []
        assessment = receive_bundle(
            self.bundle, self.cp_bytes, sink=got.append,
            trusted_public_key=self.pub, expected_context=self.context,
            accepted_checkpoint_digest=self.ref, now=self.now, max_age_seconds=3600,
        )
        self.assertEqual(assessment.outcome, "ACCEPT")
        self.assertEqual(got, [json.loads(self.bundle)])

    def test_missing_checkpoint_and_reference_are_missing_evidence(self):
        self.assertEqual(self.assess(checkpoint_bytes=None).reason_codes, ["checkpoint_missing"])
        self.assertEqual(self.assess(accepted_checkpoint_digest=None).reason_codes, ["accepted_reference_missing"])

    def test_malformed_and_duplicate_member_checkpoints_fail_closed(self):
        for malformed in (b"{}", b'{"kind":"x","kind":"y"}'):
            with self.subTest(malformed=malformed):
                self.assertEqual(self.assess(checkpoint_bytes=malformed).outcome, "REJECT")

    def test_bad_signature_key_context_and_bundle_are_rejected(self):
        bad = copy.deepcopy(self.checkpoint)
        bad["context"] = "conversation:other"
        self.assertEqual(self.assess(checkpoint_bytes=json.dumps(bad).encode()).reason_codes, ["checkpoint_bad_signature"])
        wrong_pub = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32)))).public_key()
        self.assertEqual(self.assess(trusted_public_key=wrong_pub).reason_codes, ["checkpoint_bad_signature"])
        self.assertEqual(self.assess(expected_context="conversation:other").reason_codes, ["checkpoint_context_mismatch"])
        self.assertEqual(self.assess(bundle_bytes=self.bundle + b" ").reason_codes, ["checkpoint_bundle_mismatch"])

    def test_authentic_historical_checkpoint_and_stale_reference_fail(self):
        newer = issue_checkpoint(self.bundle, context=self.context, issued_at="2026-10-22T10:00:00Z",
                                 max_age_seconds=3600, private_key=self.key)
        newer_bytes = json.dumps(newer).encode()
        assessment = self.assess(checkpoint_bytes=newer_bytes, accepted_checkpoint_digest=checkpoint_digest(newer))
        self.assertEqual(assessment.reason_codes, ["checkpoint_not_current"])
        # A valid newer checkpoint is still refused until the separate reference is refreshed.
        fresh = issue_checkpoint(self.bundle, context=self.context, issued_at="2026-10-22T11:30:00Z",
                                 max_age_seconds=3600, private_key=self.key)
        self.assertEqual(self.assess(checkpoint_bytes=json.dumps(fresh).encode()).reason_codes,
                         ["checkpoint_reference_mismatch"])

    def test_append_requires_explicit_trusted_refresh(self):
        appended = appended_bundle(self.bundle)
        self.assertEqual(json.loads(appended)["receipts"][:-1], json.loads(self.bundle)["receipts"])
        self.assertEqual(self.assess(bundle_bytes=appended).reason_codes, ["checkpoint_bundle_mismatch"])
        refreshed = issue_checkpoint(appended, context=self.context, issued_at=self.now,
                                     max_age_seconds=3600, private_key=self.key)
        result = self.assess(bundle_bytes=appended, checkpoint_bytes=json.dumps(refreshed).encode(),
                             accepted_checkpoint_digest=checkpoint_digest(refreshed))
        self.assertEqual(result.outcome, "ACCEPT")

    def test_rejected_assessment_never_releases(self):
        got = []
        result = receive_bundle(
            self.bundle, self.cp_bytes, sink=got.append, trusted_public_key=self.pub,
            expected_context=self.context, accepted_checkpoint_digest=None,
            now=self.now, max_age_seconds=3600,
        )
        self.assertEqual(result.outcome, "NEEDS_EVIDENCE")
        self.assertEqual(got, [])

    def test_binding_prevents_releasing_a_different_bundle(self):
        got = []
        result = receive_bundle(
            appended_bundle(self.bundle), self.cp_bytes, sink=got.append,
            trusted_public_key=self.pub, expected_context=self.context,
            accepted_checkpoint_digest=self.ref, now=self.now, max_age_seconds=3600,
        )
        self.assertEqual(result.reason_codes, ["checkpoint_bundle_mismatch"])
        self.assertEqual(got, [])

    def test_bytes_subclass_cannot_substitute_decoded_or_converted_context(self):
        modified = json.loads(self.bundle)
        modified["task_id"] = "attacker-task"
        altered = json.dumps(modified).encode()

        class DeceptiveBytes(bytes):
            calls = 0

            def decode(self, *args, **kwargs):
                self.calls += 1
                return bytes.decode(self) if self.calls == 1 else altered.decode()

            def __bytes__(self):
                return altered

        payload = DeceptiveBytes(self.bundle)
        got = []
        result = receive_bundle(
            payload, self.cp_bytes, sink=got.append, trusted_public_key=self.pub,
            expected_context=self.context, accepted_checkpoint_digest=self.ref,
            now=self.now, max_age_seconds=3600,
        )
        self.assertEqual(result.outcome, "ACCEPT")
        self.assertEqual(got, [json.loads(self.bundle)])
        self.assertEqual(payload.calls, 0)

    def test_rejects_non_canonical_numeric_and_unicode_inputs(self):
        for extension in (b'"extra":NaN', b'"extra":Infinity', b'"extra":1.5', b'"extra":"\\ud800"'):
            payload = self.bundle.rstrip()[:-1] + b',' + extension + b'}'
            with self.subTest(extension=extension):
                self.assertEqual(self.assess(bundle_bytes=payload).reason_codes, ["bundle_invalid_json"])
        for payload in (b'\xff', b'{"a":1,"a":2}', b'\xef\xbb\xbf{}', b'[' * 2000):
            with self.subTest(payload=payload[:20]):
                self.assertEqual(self.assess(bundle_bytes=payload).outcome, "REJECT")

    def test_rejects_bad_policy_types_and_unsupported_versions(self):
        for value in (True, 0, -1, 1.5, "3600"):
            with self.subTest(value=value):
                self.assertEqual(self.assess(max_age_seconds=value).outcome, "REJECT")
        for reference in (True, "", "sha256:nope", 1):
            with self.subTest(reference=reference):
                self.assertEqual(self.assess(accepted_checkpoint_digest=reference).reason_codes,
                                 ["accepted_reference_invalid"])
        old = (ROOT / "vectors/verification/bundle.json").read_bytes()
        self.assertEqual(self.assess(bundle_bytes=old).reason_codes, ["receiver_version_unsupported"])

    def test_invalid_calendar_date_is_a_structured_rejection_without_release(self):
        changed = json.loads(self.bundle)
        changed["receipts"][0]["issued_at"] = "2026-99-24T18:00:00Z"
        got = []
        result = receive_bundle(
            json.dumps(changed).encode(), self.cp_bytes, sink=got.append,
            trusted_public_key=self.pub, expected_context=self.context,
            accepted_checkpoint_digest=self.ref, now=self.now, max_age_seconds=3600,
        )
        self.assertEqual(result.reason_codes, ["core_invalid_input"])
        self.assertEqual(got, [])

    def test_rejects_signed_bad_checkpoint_types_and_signature_aliases(self):
        for field, value in (("version", True), ("max_age_seconds", True),
                             ("expires_at", "2026-10-22T13:00:01Z"),
                             ("issued_at", "2026-99-22T12:00:00Z")):
            bad = copy.deepcopy(self.checkpoint)
            bad[field] = value
            unsigned = {k: v for k, v in bad.items() if k != "sig"}
            bad["sig"]["value"] = b64u(self.key.sign(canonical_bytes(unsigned)))
            with self.subTest(field=field):
                self.assertEqual(self.assess(checkpoint_bytes=json.dumps(bad).encode(),
                                 accepted_checkpoint_digest=checkpoint_digest(bad)).outcome, "REJECT")
        bad = copy.deepcopy(self.checkpoint)
        bad["sig"]["value"] += "!"
        self.assertEqual(self.assess(checkpoint_bytes=json.dumps(bad).encode()).reason_codes,
                         ["checkpoint_signature_invalid"])


if __name__ == "__main__":
    unittest.main()
