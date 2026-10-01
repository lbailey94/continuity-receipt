"""Synthetic signed 0.4 regression checks for the opt-in local action."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("pilot_action", Path(__file__).with_name("run_action.py"))
action = importlib.util.module_from_spec(spec)
spec.loader.exec_module(action)

generator_spec = importlib.util.spec_from_file_location("make_vectors", ROOT / "tools" / "make_vectors.py")
vectors = importlib.util.module_from_spec(generator_spec)
generator_spec.loader.exec_module(vectors)


def raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fresh_signed_inputs():
    chain = vectors.chain(vectors.SPEC_04)
    session = vectors.pass_body(spend_cap={"minor": 1000, "currency": "USD"})
    session["expires_at"] = "2030-01-01T00:00:00Z"
    vectors.add(chain, "session.pass.created", session)
    offer = vectors.add(chain, "agreement.offer", vectors.offer_body(valid_until="2030-01-01T00:00:00Z"))
    accepted = vectors.add_as(
        chain, "agreement.accept", "agent", vectors.COUNTERPARTY_DID,
        vectors.COUNTERPARTY_KEY, vectors.accept_body_04(vectors.receipt_digest(offer)),
    )
    accept_ref = vectors.receipt_digest(accepted)
    vectors.add_bound(chain, "task.decision", vectors.decision_body(), accept_ref)
    vectors.add_bound(chain, "task.execution", vectors.execution_body(), accept_ref)
    vectors.add_as(chain, "task.termination", "agent", vectors.COUNTERPARTY_DID,
                   vectors.COUNTERPARTY_KEY, vectors.termination_body())
    bundle = chain.bundle()
    policy = {
        "id": "synthetic-fresh-0.4-test-v1",
        "accepted_specs": ["continuity-receipt/0.4"],
        "trusted_issuers": sorted([vectors.GATE_DID, vectors.COUNTERPARTY_DID]),
        "required_record_types": ["agreement.offer", "agreement.accept"],
    }
    return bundle, policy


class PilotActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.output_dir = base / "operator"
        self.output_dir.mkdir(mode=0o700)
        self.bundle, self.policy = fresh_signed_inputs()
        self.bundle_raw = json.dumps(self.bundle, sort_keys=True, separators=(",", ":")).encode()
        self.policy_raw = json.dumps(self.policy, sort_keys=True, separators=(",", ":")).encode()
        self.now_utc = (datetime.now(timezone.utc) + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def tearDown(self):
        self.tmp.cleanup()

    def run_record(self, bundle=None, policy=None, **kwargs):
        bundle = self.bundle_raw if bundle is None else bundle
        policy = self.policy_raw if policy is None else policy
        return action.record_assessment(
            bundle_raw=bundle, policy_raw=policy, now_utc=self.now_utc,
            max_age_seconds=86400, output_dir=self.output_dir,
            expected_bundle_sha256=raw_digest(bundle), expected_policy_sha256=raw_digest(policy), **kwargs,
        )

    def test_positive_assessment_is_actual_fixed_file_write(self):
        result = self.run_record()
        output_path = self.output_dir / action.OUTPUT_NAME
        saved = json.loads(output_path.read_bytes())
        self.assertEqual(result["consumer_assessment"]["outcome"], "ACCEPT")
        self.assertEqual(saved["result"], "LOCAL_ASSESSMENT_RECORDED_NOT_AUTHORIZATION")
        self.assertEqual(saved["local_action"], "write_fixed_local_assessment_json")
        self.assertTrue(saved["local_action_performed"])
        self.assertFalse(saved["receipt_claimed_action_executed"])
        self.assertFalse(saved["caller_freshness_policy"]["trusted_time_oracle_used"])
        self.assertEqual(saved["caller_freshness_policy"]["now_utc_supplied_by_operator"], self.now_utc)
        self.assertEqual(saved["input_pins"]["bundle_raw_sha256"], raw_digest(self.bundle_raw))
        self.assertEqual(saved["input_pins"]["policy_raw_sha256"], raw_digest(self.policy_raw))

    def test_denied_issuer_refuses_before_output(self):
        policy = copy.deepcopy(self.policy)
        policy["trusted_issuers"] = ["did:key:synthetic-untrusted"]
        with self.assertRaisesRegex(action.ActionRefused, "consumer_assessment_not_accept"):
            self.run_record(policy=json.dumps(policy, sort_keys=True, separators=(",", ":")).encode())
        self.assertFalse((self.output_dir / action.OUTPUT_NAME).exists())

    def test_unsupported_spec_refuses_before_output(self):
        bundle = copy.deepcopy(self.bundle)
        bundle["spec"] = "continuity-receipt/0.5"
        with self.assertRaisesRegex(action.ActionRefused, "consumer_assessment_not_accept"):
            self.run_record(bundle=json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode())
        self.assertFalse((self.output_dir / action.OUTPUT_NAME).exists())

    def test_missing_required_record_refuses_before_output(self):
        policy = copy.deepcopy(self.policy)
        policy["required_record_types"] = ["authority.succession"]
        with self.assertRaisesRegex(action.ActionRefused, "consumer_assessment_not_accept"):
            self.run_record(policy=json.dumps(policy, sort_keys=True, separators=(",", ":")).encode())
        self.assertFalse((self.output_dir / action.OUTPUT_NAME).exists())

    def test_replay_refuses_after_first_record(self):
        self.run_record()
        with self.assertRaisesRegex(action.ActionRefused, "assessment_replay_refused"):
            self.run_record()

    def test_tampered_output_refuses_on_replay_check(self):
        self.run_record()
        output_path = self.output_dir / action.OUTPUT_NAME
        output_path.write_bytes(output_path.read_bytes() + b"tamper")
        with self.assertRaisesRegex(action.ActionRefused, "completed_output_tampered_fail_closed"):
            self.run_record()

    def test_expired_fixture_and_stale_receipt_refuse(self):
        fixture_bundle = (action.EXAMPLE / "bundle.json").read_bytes()
        fixture_policy = (action.EXAMPLE / "policy.json").read_bytes()
        stale_now = "2026-10-01T12:00:00Z"
        with self.assertRaisesRegex(action.ActionRefused, "freshness_max_age_exceeded|freshness_expired"):
            action.record_assessment(
                bundle_raw=fixture_bundle, policy_raw=fixture_policy,
                now_utc=stale_now, max_age_seconds=86400, output_dir=self.output_dir,
                expected_bundle_sha256=raw_digest(fixture_bundle), expected_policy_sha256=raw_digest(fixture_policy),
            )
        self.assertFalse((self.output_dir / action.OUTPUT_NAME).exists())

    def test_interrupted_prepared_operation_never_resumes(self):
        with self.assertRaisesRegex(action.ActionRefused, "test_interruption_after_prepare"):
            self.run_record(interrupt_after_prepare=True)
        with self.assertRaisesRegex(action.ActionRefused, "interrupted_prepared_operation_fail_closed"):
            self.run_record()
        self.assertFalse((self.output_dir / action.OUTPUT_NAME).exists())

    def test_output_directory_symlink_and_untracked_output_refuse(self):
        extra = self.output_dir.parent / "target"
        extra.mkdir(mode=0o700)
        link = self.output_dir.parent / "linked"
        link.symlink_to(extra, target_is_directory=True)
        with self.assertRaisesRegex(action.ActionRefused, "operator_directory_not_a_plain_directory"):
            action.record_assessment(
                bundle_raw=self.bundle_raw, policy_raw=self.policy_raw, now_utc=self.now_utc,
                max_age_seconds=86400, output_dir=link,
                expected_bundle_sha256=raw_digest(self.bundle_raw), expected_policy_sha256=raw_digest(self.policy_raw),
            )
        (self.output_dir / action.OUTPUT_NAME).write_text("untracked", encoding="utf-8")
        with self.assertRaisesRegex(action.ActionRefused, "untracked_existing_output_refused"):
            self.run_record()

    def test_concurrent_callers_record_only_once(self):
        gate = threading.Barrier(2)
        results = []
        errors = []

        def caller():
            try:
                gate.wait(timeout=5)
                results.append(self.run_record())
            except Exception as exc:  # each losing race must fail closed
                errors.append(exc)

        workers = [threading.Thread(target=caller) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertTrue((self.output_dir / action.OUTPUT_NAME).is_file())

    def test_wrong_raw_pin_refuses_without_state(self):
        with self.assertRaisesRegex(action.ActionRefused, "bundle_raw_pin_mismatch"):
            action.record_assessment(
                bundle_raw=self.bundle_raw, policy_raw=self.policy_raw,
                now_utc=self.now_utc, max_age_seconds=86400, output_dir=self.output_dir,
                expected_bundle_sha256="sha256:" + "0" * 64,
                expected_policy_sha256=raw_digest(self.policy_raw),
            )
        self.assertFalse((self.output_dir / action.STATE_NAME).exists())

    def test_malformed_caller_time_and_bool_age_refuse(self):
        for supplied in (None, "bad", "2026-10-01T00:00:00+00:00"):
            with self.subTest(time=supplied), self.assertRaises(action.ActionRefused):
                action.check_caller_freshness(self.bundle, now_utc=supplied, max_age_seconds=60)
        with self.assertRaises(action.ActionRefused):
            action.check_caller_freshness(self.bundle, now_utc=self.now_utc, max_age_seconds=True)

    def test_oversize_file_refuses_at_boundary(self):
        path = Path(self.tmp.name) / "oversize.json"
        path.write_bytes(b" " * (action.MAX_INPUT_BYTES + 1))
        with self.assertRaisesRegex(action.ActionRefused, "too_large"):
            action.read_pinned(path, raw_digest(path.read_bytes()), "bundle")


if __name__ == "__main__":
    unittest.main()
