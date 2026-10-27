#!/usr/bin/env python3
"""Reproducible fresh-process demonstration of the experimental receiver gate."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from continuity_receipt.receiver_checkpoint import receive_bundle, checkpoint_digest, issue_checkpoint
from continuity_receipt.keys import raw_pubkey_bytes
from continuity_receipt import keys, records, verify_bundle
from continuity_receipt.bundle import receipt_digest

NOW = "2026-10-22T12:00:00Z"
CONTEXT = "conversation:demo-7"
AGE = 3600
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
WRONG_KEY = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))


def appended_bundle(bundle_bytes):
    """Append a real signed settlement to the published, terminated test task."""
    bundle = json.loads(bundle_bytes)
    did, private = keys.generate(keys.deterministic_seed("local-05-vector-key"))
    receipt = records.new_envelope(
        bundle["task_id"], "agent", did, "settlement", len(bundle["receipts"]),
        receipt_digest(bundle["receipts"][-1]),
        {"rail": "invoice", "rail_ref": "receiver-demo-fixture",
         "amount": {"minor": 0, "currency": "USD"},
         "gated_on_delivery": False, "settled_at": "2026-09-24T18:00:05Z"},
        spec="continuity-receipt/0.5", issued_at="2026-09-24T18:00:05Z",
    )
    receipt["receipt_id"] = "urn:uuid:004164d4-087c-4db0-8e2f-580db241f904"
    bundle["receipts"].append(records.sign_receipt(receipt, private, did))
    if verify_bundle(bundle).verdict != "TRUSTED":
        raise ValueError("demo append must be an authentic valid CPR bundle")
    return json.dumps(bundle, separators=(",", ":")).encode()


def _worker(args):
    bundle = Path(args.bundle).read_bytes()
    cp = Path(args.checkpoint).read_bytes() if args.checkpoint != "-" else None
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(args.public_key))
    delivered = []
    def sink(received):
        delivered.append({"task_id": received["task_id"],
                          "receipt_ids": [r["receipt_id"] for r in received["receipts"]]})
    result = receive_bundle(bundle, cp, sink=sink, trusted_public_key=pub, expected_context=args.context,
                           accepted_checkpoint_digest=None if args.reference == "-" else args.reference, now=args.now,
                           max_age_seconds=args.max_age)
    print(json.dumps({"assessment": result.as_dict(), "delivered_to_sink": delivered}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--bundle")
    parser.add_argument("--checkpoint")
    parser.add_argument("--public-key")
    parser.add_argument("--reference")
    parser.add_argument("--context", default=CONTEXT)
    parser.add_argument("--now", default=NOW)
    parser.add_argument("--max-age", type=int, default=AGE)
    args = parser.parse_args()
    if args.worker:
        return _worker(args)

    source = ROOT / "vectors" / "22_local_state_commitment.json"
    bundle = source.read_bytes()
    current = issue_checkpoint(bundle, context=CONTEXT, issued_at=NOW, max_age_seconds=AGE, private_key=KEY)
    historical = issue_checkpoint(bundle, context=CONTEXT, issued_at="2026-10-22T10:00:00Z", max_age_seconds=AGE, private_key=KEY)
    prior = issue_checkpoint(bundle, context=CONTEXT, issued_at="2026-10-22T11:30:00Z", max_age_seconds=AGE, private_key=KEY)
    appended = appended_bundle(bundle)
    refreshed = issue_checkpoint(appended, context=CONTEXT, issued_at=NOW, max_age_seconds=AGE, private_key=KEY)
    tampered = dict(current)
    tampered["context"] = "conversation:tampered"

    cases = [
        ("valid", bundle, current, KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("missing_checkpoint", bundle, None, KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("wrong_key", bundle, current, WRONG_KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("bad_signature", bundle, tampered, KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("wrong_context", bundle, current, KEY, checkpoint_digest(current), "conversation:other", NOW),
        ("authentic_historical", bundle, historical, KEY, checkpoint_digest(historical), CONTEXT, NOW),
        ("historical_against_current_reference", bundle, prior, KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("missing_reference", bundle, current, KEY, None, CONTEXT, NOW),
        ("append_stale_reference", appended, current, KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("append_new_checkpoint_old_reference", appended, refreshed, KEY, checkpoint_digest(current), CONTEXT, NOW),
        ("append_after_explicit_refresh", appended, refreshed, KEY, checkpoint_digest(refreshed), CONTEXT, NOW),
    ]
    expected = {
        "valid": ("ACCEPT", "checkpoint_current"),
        "missing_checkpoint": ("NEEDS_EVIDENCE", "checkpoint_missing"),
        "wrong_key": ("REJECT", "checkpoint_bad_signature"),
        "bad_signature": ("REJECT", "checkpoint_bad_signature"),
        "wrong_context": ("REJECT", "checkpoint_context_mismatch"),
        "authentic_historical": ("REJECT", "checkpoint_not_current"),
        "historical_against_current_reference": ("REJECT", "checkpoint_reference_mismatch"),
        "missing_reference": ("NEEDS_EVIDENCE", "accepted_reference_missing"),
        "append_stale_reference": ("REJECT", "checkpoint_bundle_mismatch"),
        "append_new_checkpoint_old_reference": ("REJECT", "checkpoint_reference_mismatch"),
        "append_after_explicit_refresh": ("ACCEPT", "checkpoint_current"),
    }
    results = {}
    with tempfile.TemporaryDirectory(prefix="cpr-receiver-demo-") as temp:
        folder = Path(temp)
        for name, data, checkpoint, key, reference, context, now in cases:
            bundle_path = folder / f"{name}.bundle.json"
            cp_path = folder / f"{name}.checkpoint.json"
            bundle_path.write_bytes(data)
            if checkpoint is None:
                cp_arg = "-"
            else:
                cp_path.write_text(json.dumps(checkpoint, separators=(",", ":")))
                cp_arg = str(cp_path)
            pub = base64.b64encode(raw_pubkey_bytes(key.public_key())).decode()
            proc = subprocess.run([sys.executable, __file__, "--worker", "--bundle", str(bundle_path),
                                   "--checkpoint", cp_arg, "--public-key", pub,
                                   "--reference", reference or "-", "--context", context,
                                   "--now", now, "--max-age", str(AGE)],
                                  cwd=ROOT, text=True, capture_output=True, check=True)
            results[name] = json.loads(proc.stdout)
            outcome, reason = expected[name]
            observed = results[name]
            received = observed["delivered_to_sink"]
            expected_receipts = [r["receipt_id"] for r in json.loads(data)["receipts"]]
            matches = (observed["assessment"]["outcome"] == outcome
                       and observed["assessment"]["reason_codes"] == [reason]
                       and bool(received) == (outcome == "ACCEPT")
                       and (not received or received[0]["receipt_ids"] == expected_receipts))
            observed["expected_outcome"] = outcome
            observed["expected_reason"] = reason
            observed["matches_expected"] = matches
            observed["bundle_sha256"] = hashlib.sha256(data).hexdigest()
            if not matches:
                raise RuntimeError(f"receiver case {name} did not match its outcome and sink control")
    print(json.dumps({"demo": "cpr-experimental-receiver-checkpoint-v1", "fresh_process_per_case": True,
                      "fixture": str(source.relative_to(ROOT)),
                      "fixture_sha256": hashlib.sha256(bundle).hexdigest(),
                      "append_preserves_signed_prefix": json.loads(appended)["receipts"][:-1] == json.loads(bundle)["receipts"],
                      "operator_independent": False, "expected_answers_visible": True,
                      "results": results}, sort_keys=True, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
