#!/usr/bin/env python3
"""Create the 0.6 candidate vectors; never regenerate frozen older files."""
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuity_receipt import keys, records, verify_bundle  # noqa: E402
from continuity_receipt.bundle import TaskChain, receipt_digest  # noqa: E402

SPEC = "continuity-receipt/0.6"
OUT = ROOT / "vectors"
DID, KEY = keys.generate(keys.deterministic_seed("authority-06-vector-key"))
OTHER_DID, _ = keys.generate(keys.deterministic_seed("authority-06-other-key"))
SHA = "sha256:" + "1" * 64
MISSING_REF = "sha256:" + "0" * 64
POLICY = "authority-policy/1"
GRANT_ID = "urn:uuid:00000000-0000-7000-8000-000000000024"


def make(label, *, before=False, expired=False, mismatch=False, unreferenced=False,
         missing=False, bad_review=False, bad_principal=False, bad_scope=False):
    counter = 0
    original = records.uuid7

    def next_uuid():
        nonlocal counter
        counter += 1
        return uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/0.6/{label}/{counter}")

    records.uuid7 = next_uuid
    try:
        chain = TaskChain(
            task_id="urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/0.6/{label}")),
            spec=SPEC,
        )

        def add(kind, body, second):
            chain.add(kind, "agent", DID, KEY, body, issued_at=f"2026-09-28T18:00:{second:02d}Z")

        add("session.pass.created", {
            "gate_id": "local:authority-test", "mandala_class": "local",
            "quotas": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
            "expires_at": "2026-09-29T18:00:00Z", "policy_version": POLICY,
            "mandate_ref": SHA, "agent_id": "local-agent",
        }, 0)

        grant = {
            "grant_id": GRANT_ID,
            "principal": {"id": "did:web:lab.example", "assurance": "self_asserted"},
            "agent": OTHER_DID if mismatch else DID,
            "scope": [] if bad_scope else ["memory.read", "receipts.emit"],
            "granted_at": "2026-09-28T18:00:10Z" if before else "2026-09-28T18:00:01Z",
            "review_policy": "always" if bad_review else "none",
            "constraints": {"memory.read": {"max_rows": 100}},
            "policy_ref": SHA,
            "gate_ref": "urn:local:gate-pass:0001",
        }
        if bad_principal:
            grant["principal"] = {"id": "did:web:lab.example", "assurance": "verified"}
        if expired:
            grant["expires_at"] = "2026-09-28T18:00:02Z"
        else:
            grant["expires_at"] = "2026-09-29T18:00:00Z"
        add("authority.grant", grant, 10 if before else 1)

        decision_ref = None
        if missing:
            decision_ref = MISSING_REF
        elif not unreferenced:
            # the grant's digest is not known until it is in the chain; use the
            # receipt we just appended.
            decision_ref = receipt_digest(chain.receipts[-1])

        add("task.decision", {
            "action": "authority.test", "action_args_hash": SHA,
            "model": {"provider": "local", "id": "none"},
            "input_provenance": {"policy_id": POLICY, "allowed_sources": ["local"],
                                 "observed_sources_hash": SHA},
            "decision": "allow", "policy_version": POLICY,
            **({"authority_ref": decision_ref} if decision_ref else {}),
        }, 2)

        execution = {
            "tool_calls": [{"name": "read", "args_hash": SHA, "result_hash": SHA}],
            "egress": [], "resources": {"cpu_ms": 0, "mem_peak_mb": 0, "disk_peak_mb": 0},
            "sandbox_class": "none",
        }
        if decision_ref:
            execution["authority_ref"] = decision_ref
        add("task.execution", execution, 3)
        add("task.termination", {"reason": "completed", "limits_at_stop": {}, "remaining": {}}, 4)
        return chain.bundle()
    finally:
        records.uuid7 = original


def make_legacy():
    """A 0.5/0.4-style chain whose authority.grant receipt is not 0.6."""
    bundle = make("legacy_authority_type")
    receipts = bundle["receipts"]
    receipts[1]["spec"] = "continuity-receipt/0.5"
    for index in range(1, len(receipts)):
        if index > 1:
            receipts[index]["prev"] = receipt_digest(receipts[index - 1])
        receipts[index] = records.sign_receipt(
            {k: v for k, v in receipts[index].items() if k != "sig"}, KEY, DID
        )
    return bundle


CASES = [
    ("24_authority_grant.json", {}, "TRUSTED", None, True,
     "0.6 authority grant referenced by decision and execution"),
    ("24b_missing_authority.json", {"missing": True}, "INSUFFICIENT_EVIDENCE", None, True,
     "0.6 keeps a missing authority reference insufficient, not fatal"),
    ("24c_authority_before_grant.json", {"before": True}, "UNTRUSTED", "authority_before_grant", True,
     "0.6 refuses a bound receipt issued before its authority grant"),
    ("24d_authority_expired.json", {"expired": True}, "UNTRUSTED", "authority_expired", True,
     "0.6 refuses a bound receipt issued after the authority window"),
    ("24e_authority_agent_mismatch.json", {"mismatch": True}, "UNTRUSTED", "authority_agent_mismatch", True,
     "0.6 requires the grant's agent to sign the bound receipt"),
    ("24f_authority_unreferenced.json", {"unreferenced": True}, "PROVISIONAL", None, True,
     "0.6 marks a grant nothing references provisional, not trusted"),
    ("24g_legacy_authority_type.json", {"legacy": True}, "UNTRUSTED", "unknown_type", False,
     "0.5 records cannot use the new authority.grant type"),
    ("24h_bad_review_policy.json", {"bad_review": True}, "UNTRUSTED", "malformed", False,
     "0.6 refuses an unknown review_policy value"),
    ("24i_bad_principal_assurance.json", {"bad_principal": True}, "UNTRUSTED", "malformed", False,
     "0.6 refuses an unknown principal assurance value"),
    ("24j_empty_scope.json", {"bad_scope": True}, "UNTRUSTED", "malformed", False,
     "0.6 refuses an empty authority scope list"),
]


def main():
    manifest_path = OUT / "manifest-0.6.json"
    manifest = {"spec": SPEC, "vectors": []}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
    rows = []
    for filename, options, verdict, code, schema_valid, note in CASES:
        if options.get("legacy"):
            bundle = make_legacy()
        else:
            bundle = make(filename, **options)
        (OUT / filename).write_text(json.dumps(bundle, indent=2) + "\n")
        result = verify_bundle(bundle)
        assert result.verdict == verdict and (code is None or code in result.codes()), (
            filename, result.as_dict()
        )
        rows.append({"file": filename, "expected_verdict": verdict, "expected_code": code,
                     "require_anchor": False, "note": note, "schema_valid": schema_valid})
    manifest["vectors"] = rows
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    lines = ["# Continuity Receipt 0.6 candidate vectors", "",
             "Published 0.1–0.5 fixtures and their manifests remain frozen. Generated by `tools/make_06_vectors.py`.",
             "", "| Vector | Expected verdict | Primary error | Notes |", "|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['file']} | {row['expected_verdict']} | {row['expected_code'] or '—'} | {row['note']} |")
    (OUT / "INDEX_0.6.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
