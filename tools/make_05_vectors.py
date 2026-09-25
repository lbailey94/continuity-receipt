#!/usr/bin/env python3
"""Create only the new 0.5 vectors; never regenerate the frozen older files."""
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuity_receipt import keys, records, verify_bundle  # noqa: E402
from continuity_receipt.agreements import accept_body, bind_body, offer_body  # noqa: E402
from continuity_receipt.bundle import TaskChain, receipt_digest  # noqa: E402

SPEC = "continuity-receipt/0.5"
OUT = ROOT / "vectors"
DID, KEY = keys.generate(keys.deterministic_seed("local-05-vector-key"))
SHA = "sha256:" + "1" * 64
MERKLE = "merkle-sha256:" + "2" * 64


def make(label, *, klass="local", sandbox="none", count=3, head=SHA, spec=SPEC):
    counter = 0
    original = records.uuid7

    def next_uuid():
        nonlocal counter
        counter += 1
        return uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/0.5/{label}/{counter}")

    records.uuid7 = next_uuid
    try:
        chain = TaskChain(
            task_id="urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/0.5/{label}")),
            spec=spec,
        )
        def add(kind, body, second):
            chain.add(kind, "agent", DID, KEY, body, issued_at=f"2026-09-24T18:00:{second:02d}Z")

        add("session.pass.created", {
            "gate_id": "local:test-store", "mandala_class": klass,
            "quotas": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
            "expires_at": "2026-09-25T18:00:00Z", "policy_version": "local-policy/1",
            "mandate_ref": SHA, "agent_id": "local-agent",
        }, 0)
        add("task.decision", {
            "action": "local.snapshot", "action_args_hash": SHA,
            "model": {"provider": "local", "id": "none"},
            "input_provenance": {"policy_id": "local-policy/1", "allowed_sources": ["local"],
                                 "observed_sources_hash": SHA},
            "decision": "allow", "policy_version": "local-policy/1",
        }, 1)
        add("task.execution", {
            "tool_calls": [{"name": "snapshot", "args_hash": SHA, "result_hash": SHA}],
            "egress": [], "resources": {"cpu_ms": 0, "mem_peak_mb": 0, "disk_peak_mb": 0},
            "sandbox_class": sandbox,
        }, 2)
        add("state.commitment", {
            "state_kind": "chain-head", "scope": "local:test-store",
            "count": count, "head_digest": head, "merkle_root": MERKLE,
        }, 3)
        add("task.termination", {
            "reason": "completed", "limits_at_stop": {"cpu_ms": 0, "wall_ms": 0,
            "spend_minor": 0, "currency": "USD"}, "remaining": {},
        }, 4)
        return chain.bundle()
    finally:
        records.uuid7 = original


def make_agreement_binding(label, *, omit_execution_ref=False):
    """Emit a 0.5 carried binding case across decision and execution."""
    counter = 0
    original = records.uuid7

    def next_uuid():
        nonlocal counter
        counter += 1
        return uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/0.5/{label}/{counter}")

    records.uuid7 = next_uuid
    try:
        gate_did, gate_key = keys.generate(keys.deterministic_seed("local-05-agreement-gate"))
        agent_did, agent_key = keys.generate(keys.deterministic_seed("local-05-agreement-agent"))
        chain = TaskChain(task_id="urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/0.5/{label}")), spec=SPEC)
        when = "2026-09-24T18:00:00Z"
        chain.add("session.pass.created", "gate", gate_did, gate_key, {
            "gate_id": "local:agreement-test", "mandala_class": "local",
            "quotas": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
            "expires_at": "2026-09-25T18:00:00Z", "policy_version": "local-policy/1",
            "mandate_ref": SHA, "agent_id": agent_did,
        }, issued_at=when)
        terms = {"service": "local snapshot", "calls": 1, "price_minor": 0, "currency": "USD"}
        offer = chain.add("agreement.offer", "gate", gate_did, gate_key,
                          offer_body("local-snapshot-05", agent_did, terms, "2030-01-01T00:00:00Z", "local-05-nonce"),
                          issued_at=when)
        accept = chain.add("agreement.accept", "agent", agent_did, agent_key, accept_body(offer), issued_at=when)
        agreement_ref = receipt_digest(accept)
        decision = {
            "action": "local.snapshot", "action_args_hash": SHA,
            "model": {"provider": "local", "id": "none"},
            "input_provenance": {"policy_id": "local-policy/1", "allowed_sources": ["local"], "observed_sources_hash": SHA},
            "decision": "allow", "policy_version": "local-policy/1",
        }
        chain.add("task.decision", "agent", agent_did, agent_key, bind_body(decision, accept), issued_at=when)
        execution = {
            "tool_calls": [{"name": "snapshot", "args_hash": SHA, "result_hash": SHA}],
            "egress": [], "resources": {"cpu_ms": 0, "mem_peak_mb": 0, "disk_peak_mb": 0},
            "sandbox_class": "none",
        }
        if not omit_execution_ref:
            execution["agreement_ref"] = agreement_ref
        chain.add("task.execution", "agent", agent_did, agent_key, execution, issued_at=when)
        chain.add("state.commitment", "agent", agent_did, agent_key, {
            "state_kind": "chain-head", "scope": "local:agreement-test", "count": 3,
            "head_digest": SHA, "merkle_root": MERKLE,
        }, issued_at=when)
        chain.add("task.termination", "agent", agent_did, agent_key, {
            "reason": "completed", "limits_at_stop": {}, "remaining": {},
        }, issued_at=when)
        return chain.bundle()
    finally:
        records.uuid7 = original


CASES = [
    ("22_local_state_commitment.json", {}, "TRUSTED", None, True,
     "0.5 local authority, unconfined execution, and a signed state commitment"),
    ("22b_unknown_local_class.json", {"klass": "pretend-gate"}, "UNTRUSTED", "malformed", False,
     "0.5 refuses an unknown authority class"),
    ("22h_bwrap_sandbox.json", {"sandbox": "bwrap"}, "TRUSTED", None, True,
     "0.5 accepts the Bubblewrap namespace claim without implying Landlock"),
    ("22i_landlock_sandbox.json", {"sandbox": "landlock"}, "TRUSTED", None, True,
     "0.5 accepts the pure Landlock claim without implying namespaces"),
    ("22j_legacy_combined_sandbox.json", {"sandbox": "bwrap-landlock"}, "TRUSTED", None, True,
     "0.5 retains the legacy combined sandbox claim"),
    ("22c_unknown_sandbox.json", {"sandbox": "magic"}, "UNTRUSTED", "malformed", False,
     "0.5 refuses an unknown sandbox class"),
    ("22k_empty_sandbox.json", {"sandbox": ""}, "UNTRUSTED", "malformed", False,
     "0.5 refuses an empty sandbox class"),
    ("22l_non_string_sandbox.json", {"sandbox": []}, "UNTRUSTED", "malformed", False,
     "0.5 refuses a non-string sandbox class"),
    ("22d_bad_state_count.json", {"count": -1}, "UNTRUSTED", "malformed", False,
     "0.5 refuses a negative state count"),
    ("22g_count_overflow.json", {"count": 2**64}, "UNTRUSTED", "malformed", False,
     "0.5 refuses a count outside unsigned 64-bit storage range"),
    ("22m_count_unsafe_json_integer.json", {"count": 2**53}, "UNTRUSTED", "malformed", False,
     "0.5 refuses a count above the exact interoperable JSON integer range"),
    ("22n_count_safe_integer_limit.json", {"count": 2**53 - 1}, "TRUSTED", None, True,
     "0.5 accepts the largest exact interoperable JSON integer count"),
    ("22e_bad_head_digest.json", {"head": "unverified"}, "UNTRUSTED", "malformed", False,
     "0.5 refuses a malformed state digest"),
    ("22f_legacy_state_type.json", {"legacy_state": True}, "UNTRUSTED", "unknown_type", False,
     "0.4 records cannot use the new state.commitment type"),
    ("23_agreement_binding_carried.json", {"agreement_binding": True}, "TRUSTED", None, True,
     "0.5 resolves the accepted agreement and carries its binding through decision and execution"),
    ("23b_missing_carried_agreement_ref.json", {"agreement_binding": True, "omit_execution_ref": True}, "PROVISIONAL", None, True,
     "0.5 keeps agreement completeness active when execution omits the accepted agreement reference"),
]


def main():
    manifest_path = OUT / "manifest-0.5.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["spec"] = SPEC
    rows = [row for row in manifest["vectors"] if row["file"] not in {case[0] for case in CASES}]
    for filename, options, verdict, code, schema_valid, note in CASES:
        if options.get("agreement_binding"):
            bundle = make_agreement_binding(filename, omit_execution_ref=options.get("omit_execution_ref", False))
        elif options.get("legacy_state"):
            bundle = make(filename)
            state = bundle["receipts"][3]
            state["spec"] = "continuity-receipt/0.4"
            bundle["receipts"][3] = records.sign_receipt(state, KEY, DID)
            last = bundle["receipts"][4]
            last["prev"] = receipt_digest(state)
            bundle["receipts"][4] = records.sign_receipt(last, KEY, DID)
        else:
            bundle = make(filename, **options)
        (OUT / filename).write_text(json.dumps(bundle, indent=2) + "\n")
        result = verify_bundle(bundle)
        assert result.verdict == verdict and (code is None or code in result.codes()), (filename, result.as_dict())
        rows.append({"file": filename, "expected_verdict": verdict, "expected_code": code,
                     "require_anchor": False, "note": note, "schema_valid": schema_valid})
    manifest["vectors"] = rows
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    lines = ["# Continuity Receipt 0.5 candidate vectors", "",
             "Published 0.1–0.4 fixtures and their manifest remain frozen. Generated by `tools/make_05_vectors.py`.",
             "", "| Vector | Expected verdict | Primary error | Notes |", "|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['file']} | {row['expected_verdict']} | {row['expected_code'] or '—'} | {row['note']} |")
    (OUT / "INDEX_0.5.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
