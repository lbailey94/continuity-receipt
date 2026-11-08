#!/usr/bin/env python3
"""Generate the AIC statutory rollback-freshness example bundles.

Produces three spec-0.6 bundles under ``examples/04_aic_statutory_bundle/``:

- ``aic_activity_bundle.json`` — anchored chain_head + off-store anchored
  ``state.commitment`` carrying the draft Delaware Ch. 51 disclosure fields.
  Verifies ``TRUSTED``.
- ``aic_activity_unanchored.json`` — same chain with the head anchor removed.
  Verifies ``PROVISIONAL`` under ``--require-anchor`` (``head_anchor_missing``).
- ``aic_activity_rollback.json`` — chain_head regressed to the prior receipt
  (a snapshot rollback). Verifies ``UNTRUSTED`` (``head_mismatch``).

The bundles are deterministic (uuid5 task/receipt ids, fixed timestamps) so
the published bytes are reproducible.
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

SPEC = "continuity-receipt/0.6"
OUT = ROOT / "examples" / "04_aic_statutory_bundle"
DID, KEY = keys.generate(keys.deterministic_seed("aic-statutory-example-key"))
SHA = "sha256:" + "1" * 64
LOG_HEAD = "sha256:" + "a1c0ffee" * 8  # illustrative activity-log head digest
POLICY = "aic-policy/1"
GRANT_ID = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "continuity-receipt/aic/grant"))
TASK_ID = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "continuity-receipt/aic/activity"))
ANCHOR_BASE = "https://api.whitemagic.dev/anchors/"


def build_bundle(*, anchor_head: bool = True) -> dict:
    counter = 0
    original = records.uuid7

    def next_uuid():
        nonlocal counter
        counter += 1
        return uuid.uuid5(uuid.NAMESPACE_URL, f"continuity-receipt/aic/{counter}")

    records.uuid7 = next_uuid
    try:
        chain = TaskChain(task_id=TASK_ID, spec=SPEC)

        def add(kind, body, second):
            chain.add(kind, "agent", DID, KEY, body, issued_at=f"2026-11-08T18:00:{second:02d}Z")

        add("session.pass.created", {
            "gate_id": "local:aic-activity-log",
            "mandala_class": "gate-lite",
            "quotas": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
            "expires_at": "2026-11-09T18:00:00Z",
            "policy_version": POLICY,
            "mandate_ref": SHA,
            "agent_id": "aic-agent",
        }, 0)

        grant = {
            "grant_id": GRANT_ID,
            "principal": {"id": "did:web:whitemagic-labs.example", "assurance": "self_asserted"},
            "agent": DID,
            "scope": ["activity.log.write", "receipts.emit", "memory.read"],
            "granted_at": "2026-11-08T18:00:01Z",
            "review_policy": "flagged",
            "constraints": {"activity.log.write": {"max_entries_per_day": 10000}},
            "policy_ref": SHA,
            "gate_ref": "urn:local:gate-pass:aic-0001",
            "expires_at": "2026-11-09T18:00:00Z",
        }
        add("authority.grant", grant, 1)

        authority_ref = receipt_digest(chain.receipts[-1])
        add("task.decision", {
            "action": "aic.activity.commit",
            "action_args_hash": SHA,
            "model": {"provider": "local", "id": "none"},
            "input_provenance": {
                "policy_id": POLICY,
                "allowed_sources": ["local"],
                "observed_sources_hash": SHA,
            },
            "decision": "allow",
            "policy_version": POLICY,
            "authority_ref": authority_ref,
        }, 2)

        add("task.execution", {
            "tool_calls": [{
                "name": "wm-gen3.commit",
                "args_hash": SHA,
                "result_hash": "sha256:" + "b2" * 32,
            }],
            "egress": [],
            "resources": {"cpu_ms": 0, "mem_peak_mb": 0, "disk_peak_mb": 0},
            "sandbox_class": "landlock",
            "trace_guard": {
                "ok": True,
                "violations": [],
                "original_len": 12,
                "shrunk_len": 0,
                "trace_sha256": "sha256:" + "c3" * 32,
            },
            "authority_ref": authority_ref,
        }, 3)

        add("state.commitment", {
            "state_kind": "aic-activity-log/1.0",
            "scope": "aic:whitemagic-autonomous-commons",
            "count": 128,
            "head_digest": LOG_HEAD,
            "revision": 7,
            "anchor_location": "offstore",
            "anchor_ref": ANCHOR_BASE + LOG_HEAD,
            "aic": {
                "member_entity": "did:web:whitemagic-labs.example",
                "aic_registered_name": "WhiteMagic Autonomous Commons, A.I.C.",
                "sandbox_disclosure": True,
                "capitalization_floor_ok": True,
                "chain_head_scitt_anchor": ANCHOR_BASE + LOG_HEAD,
            },
        }, 4)

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
                "proof_ref": ANCHOR_BASE + head_digest_val,
            }
        bundle["chain_head"] = head
        return bundle
    finally:
        records.uuid7 = original


def write(name: str, bundle: dict) -> None:
    path = OUT / name
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print("wrote", path.relative_to(ROOT))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    anchored = build_bundle(anchor_head=True)
    res = verify_bundle(anchored)
    assert res.verdict == "TRUSTED", f"anchored bundle failed: {res.errors}"
    write("aic_activity_bundle.json", anchored)

    unanchored = build_bundle(anchor_head=False)
    res_u = verify_bundle(unanchored, require_anchor=True)
    assert res_u.verdict == "PROVISIONAL", f"unanchored bundle: {res_u.verdict} {res_u.errors}"
    assert "head_anchor_missing" in res_u.provisional_reasons
    write("aic_activity_unanchored.json", unanchored)

    rollback = deepcopy(anchored)
    receipts = rollback["receipts"]
    prior = receipts[-2]
    rollback["chain_head"] = {
        "seq": prior["seq"],
        "receipt_id": prior["receipt_id"],
        "digest": receipt_digest(prior),
        "anchored": {
            "type": "opentimestamps",
            "proof_ref": ANCHOR_BASE + receipt_digest(prior),
        },
    }
    res_r = verify_bundle(rollback)
    assert res_r.verdict == "UNTRUSTED", f"rollback bundle: {res_r.verdict}"
    assert "head_mismatch" in res_r.codes(), res_r.codes()
    write("aic_activity_rollback.json", rollback)

    return 0


if __name__ == "__main__":
    sys.exit(main())
