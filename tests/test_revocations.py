"""Tests for external revocation list distribution (0.3 tooling)."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from continuity_receipt import keys, records
from continuity_receipt.bundle import receipt_digest
from continuity_receipt.canon import canonical_bytes
from continuity_receipt.revocations import (
    RevocationError,
    load_statements,
    merge_statements,
)
from continuity_receipt.verify import main as verify_main
from continuity_receipt.verify import verify_bundle

TASK_ID = "urn:uuid:11111111-1111-7111-8111-111111111111"
SPEC = "continuity-receipt/0.4"  # historical test body uses a legacy class label
BODY = {
    "gate_id": "gate-revocation-tests",
    "mandala_class": "containment",
    "quotas": {"cpu_ms": 1000, "mem_mb": 128, "disk_mb": 16, "wall_ms": 60000},
    "expires_at": "2026-12-31T00:00:00Z",
    "policy_version": "1.0.0",
    "mandate_ref": "urn:uuid:22222222-2222-7222-8222-222222222222",
    "agent_id": "agent-1",
}


TERMINATION_BODY = {
    "reason": "completed",
    "limits_at_stop": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
    "remaining": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
}


def make_bundle(issued_at: str, did: str, key) -> dict:
    """A minimal valid chain: pass created + termination (cross-record rule)."""
    first = records.new_envelope(
        TASK_ID, "agent", did, "session.pass.created", 0, None, BODY, spec=SPEC, issued_at=issued_at
    )
    first = records.sign_receipt(first, key, did)
    second = records.new_envelope(
        TASK_ID,
        "agent",
        did,
        "task.termination",
        1,
        receipt_digest(first),
        TERMINATION_BODY,
        spec=SPEC,
        issued_at=issued_at,
    )
    second = records.sign_receipt(second, key, did)
    return {"spec": SPEC, "task_id": TASK_ID, "receipts": [first, second]}


def make_statement(did: str, key, revoked_at: str, reason: str | None = None) -> dict:
    statement = {"key": did, "revoked_at": revoked_at}
    if reason:
        statement["reason"] = reason
    statement["sig"] = {
        "alg": "ed25519",
        "value": keys.sign(key, canonical_bytes(statement)),
    }
    return statement


def write_document(path: Path, statements: list) -> None:
    path.write_text(
        json.dumps(
            {
                "kind": "continuity-receipt-revocations",
                "version": 1,
                "statements": statements,
            }
        ),
        encoding="utf-8",
    )


class TestRevocationLists(unittest.TestCase):
    def setUp(self):
        self.did, self.key = keys.generate(
            seed=keys.deterministic_seed("revocation-tests")
        )
        self.other_did, self.other_key = keys.generate(
            seed=keys.deterministic_seed("revocation-tests-other")
        )

    def test_receipt_after_revocation_is_untrusted(self):
        bundle = make_bundle("2026-01-02T00:00:00Z", self.did, self.key)
        statement = make_statement(self.did, self.key, "2026-01-01T00:00:00Z")
        result = verify_bundle(bundle, external_revocations=[statement])
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("key_revoked", result.codes())
        self.assertEqual(result.summary["revocations_checked"], 1)
        self.assertEqual(result.summary["revocations_external"], 1)

    def test_receipt_before_revocation_stays_trusted(self):
        bundle = make_bundle("2025-12-31T00:00:00Z", self.did, self.key)
        statement = make_statement(self.did, self.key, "2026-01-01T00:00:00Z")
        result = verify_bundle(bundle, external_revocations=[statement])
        self.assertEqual(result.verdict, "TRUSTED")
        self.assertEqual(result.summary["revocations_checked"], 1)

    def test_forged_statement_fails_closed(self):
        bundle = make_bundle("2026-01-02T00:00:00Z", self.did, self.key)
        statement = make_statement(self.did, self.other_key, "2026-01-01T00:00:00Z")
        result = verify_bundle(bundle, external_revocations=[statement])
        self.assertEqual(result.verdict, "UNTRUSTED")
        self.assertIn("bad_revocation", result.codes())

    def test_merge_deduplicates_identical_statements(self):
        statement = make_statement(self.did, self.key, "2026-01-01T00:00:00Z")
        bundle = make_bundle("2026-01-02T00:00:00Z", self.did, self.key)
        bundle["revocations"] = [statement]
        result = verify_bundle(bundle, external_revocations=[statement])
        self.assertEqual(result.summary["revocations_checked"], 1)
        self.assertEqual(len(merge_statements([statement], [statement])), 1)

    def test_load_document_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "revocations.json"
            write_document(
                path, [make_statement(self.did, self.key, "2026-01-01T00:00:00Z")]
            )
            statements = load_statements(str(path))
            self.assertEqual(len(statements), 1)
            self.assertEqual(statements[0]["key"], self.did)

    def test_bad_documents_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cases = {
                "not-json.json": "{",
                "wrong-kind.json": json.dumps(
                    {"kind": "other", "version": 1, "statements": []}
                ),
                "wrong-version.json": json.dumps(
                    {
                        "kind": "continuity-receipt-revocations",
                        "version": 2,
                        "statements": [],
                    }
                ),
                "no-statements.json": json.dumps(
                    {"kind": "continuity-receipt-revocations", "version": 1}
                ),
            }
            for name, content in cases.items():
                path = tmp_path / name
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(RevocationError) as raised:
                    load_statements(str(path))
                self.assertEqual(raised.exception.code, "bad_revocations_document", name)

    def test_missing_source_and_insecure_url(self):
        with self.assertRaises(RevocationError) as raised:
            load_statements("/nonexistent/revocations.json")
        self.assertEqual(raised.exception.code, "revocations_unreachable")
        with self.assertRaises(RevocationError) as raised:
            load_statements("http://example.com/revocations.json")
        self.assertEqual(raised.exception.code, "revocations_insecure_url")

    def test_cli_revocation_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle_path = tmp_path / "bundle.json"
            list_path = tmp_path / "revocations.json"
            bundle_path.write_text(
                json.dumps(make_bundle("2026-01-02T00:00:00Z", self.did, self.key)),
                encoding="utf-8",
            )
            write_document(
                list_path, [make_statement(self.did, self.key, "2026-01-01T00:00:00Z")]
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = verify_main([str(bundle_path), "--revocations", str(list_path)])
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["verdict"], "UNTRUSTED")
            self.assertIn("key_revoked", [e["code"] for e in payload["errors"]])

            # A supplied-but-unreachable list is INSUFFICIENT_EVIDENCE, not a
            # silent pass.
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = verify_main(
                    [str(bundle_path), "--revocations", str(tmp_path / "missing.json")]
                )
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["verdict"], "INSUFFICIENT_EVIDENCE")
            self.assertEqual(payload["errors"][0]["code"], "revocations_unreachable")


if __name__ == "__main__":
    unittest.main()
