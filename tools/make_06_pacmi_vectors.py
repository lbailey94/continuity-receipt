#!/usr/bin/env python3
"""Create the 0.6 PACMI at-rest threat conformance vectors (26, 26b, 26c).

Demonstrates the 10-point W3C PACMI / AGMI threat matrix, the 4-field result
schema, and the T10 erasure-resurrection counterfactual.
"""
import json
import sys
import uuid
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from continuity_receipt import keys, records, verify_bundle  # noqa: E402
from continuity_receipt.bundle import TaskChain, receipt_digest  # noqa: E402
from continuity_receipt import pacmi  # noqa: E402

SPEC = "continuity-receipt/0.6"
OUT = ROOT / "vectors"
DID, KEY = keys.generate(keys.deterministic_seed("authority-06-vector-key"))
SHA = "sha256:" + "1" * 64
POLICY = "authority-policy/1"
GRANT_ID = "urn:uuid:00000000-0000-7000-8000-000000000024"


def build_bundle(label: str, *, erasure_aware: bool = True, anchor_location: str = "offstore", anchor_head: bool = True):
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

        # 0. Session Pass Created
        add("session.pass.created", {
            "gate_id": "local:authority-test", "mandala_class": "local",
            "quotas": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
            "expires_at": "2026-09-29T18:00:00Z", "policy_version": POLICY,
            "mandate_ref": SHA, "agent_id": "local-agent",
        }, 0)

        # 1. Authority Grant
        grant = {
            "grant_id": GRANT_ID,
            "principal": {"id": "did:web:lab.example", "assurance": "self_asserted"},
            "agent": DID,
            "scope": ["memory.read", "receipts.emit"],
            "granted_at": "2026-09-28T18:00:01Z",
            "review_policy": "none",
            "constraints": {"memory.read": {"max_rows": 100}},
            "policy_ref": SHA,
            "gate_ref": "urn:local:gate-pass:0001",
            "expires_at": "2026-09-29T18:00:00Z",
        }
        add("authority.grant", grant, 1)

        # 2. Decision
        decision_ref = receipt_digest(chain.receipts[-1])
        add("task.decision", {
            "action": "authority.test", "action_args_hash": SHA,
            "model": {"provider": "local", "id": "none"},
            "input_provenance": {"policy_id": POLICY, "allowed_sources": ["local"],
                                 "observed_sources_hash": SHA},
            "decision": "allow", "policy_version": POLICY,
            "authority_ref": decision_ref,
        }, 2)

        # 3. Execution
        add("task.execution", {
            "tool_calls": [{"name": "read", "args_hash": SHA, "result_hash": SHA}],
            "egress": [], "resources": {"cpu_ms": 0, "mem_peak_mb": 0, "disk_peak_mb": 0},
            "sandbox_class": "none",
            "authority_ref": decision_ref,
        }, 3)

        # 4. State Commitment
        commitment_body = {
            "state_kind": "wm-crystal/1.0",
            "scope": "crystal-store:main",
            "count": 3,
            "head_digest": SHA,
        }
        if erasure_aware:
            commitment_body["erasure_count"] = 1
            commitment_body["erased_ids_digest"] = "sha256:" + "e" * 64
            commitment_body["revision"] = 4
        if anchor_location == "offstore":
            commitment_body["anchor_location"] = "offstore"
            commitment_body["anchor_ref"] = "https://api.whitemagic.dev/anchors/" + SHA

        add("state.commitment", commitment_body, 4)

        # 5. Termination
        add("task.termination", {
            "reason": "completed",
            "limits_at_stop": {},
            "remaining": {},
        }, 5)

        bundle = chain.bundle()
        last = bundle["receipts"][-1]
        head_digest_val = receipt_digest(last)

        head = {
            "seq": last["seq"],
            "receipt_id": last["receipt_id"],
            "digest": head_digest_val,
        }
        if anchor_head:
            head["anchored"] = {
                "type": "opentimestamps",
                "proof_ref": f"https://api.whitemagic.dev/anchors/{head_digest_val}",
            }
        bundle["chain_head"] = head
        return bundle
    finally:
        records.uuid7 = original


def write_vector(name: str, bundle: dict) -> None:
    # 1. Base verifier check
    res = verify_bundle(bundle)
    assert res.verdict == "TRUSTED", f"{name} failed base verification: {res.errors}"

    # 2. PACMI evaluation
    report = pacmi.evaluate_pacmi(bundle)

    path = OUT / name
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {name} (verdict: {res.verdict}, pacmi: {report.verdict} {report.score})")


def main() -> int:
    # Vector 26: 10/10 CONFORMANT - off-store anchor + erasure-aware commitment
    v26 = build_bundle("pacmi-conformant", erasure_aware=True, anchor_location="offstore", anchor_head=True)
    write_vector("26_pacmi_erasure_resurrection.json", v26)

    # Vector 26b: 9/10 PARTIAL - off-store anchor + high-water count only (T10 counterfactual)
    v26b = build_bundle("pacmi-high-water", erasure_aware=False, anchor_location="offstore", anchor_head=True)
    write_vector("26b_pacmi_high_water_counterfactual.json", v26b)

    # Vector 26c: 8/10 PARTIAL - in-store baseline (no off-store anchor)
    v26c = build_bundle("pacmi-in-store", erasure_aware=True, anchor_location="in-store", anchor_head=False)
    write_vector("26c_pacmi_in_store_no_anchor.json", v26c)

    return 0


if __name__ == "__main__":
    sys.exit(main())
