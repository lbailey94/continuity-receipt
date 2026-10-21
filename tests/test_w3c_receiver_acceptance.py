"""Tests for W3C AI Agent Memory Interop receiver acceptance criteria:
1. erase_resurrect (Yasha Khandelwal's 10th edit / Jeongho Song's Point 5)
2. authorization -> revocation -> unresolved conflict (Matthew Hinkle)
3. derived-from scope traversal (Jeongho Song's Point 1)

Standardized 3-word verdict vocabulary: 'served', 'reported', 'refused'.
"""

import copy
import hashlib
import json
import unittest

from continuity_receipt import keys, records
from continuity_receipt.bundle import receipt_digest
from continuity_receipt.canon import canonical_bytes
from continuity_receipt.verify import verify_bundle

SPEC = "continuity-receipt/0.5"
TASK_ID = "urn:uuid:33333333-3333-7333-8333-333333333333"

PASS_BODY = {
    "gate_id": "gate-w3c-acceptance",
    "mandala_class": "containment",
    "quotas": {"cpu_ms": 1000, "mem_mb": 128, "disk_mb": 16, "wall_ms": 60000},
    "expires_at": "2026-12-31T00:00:00Z",
    "policy_version": "1.0.0",
    "mandate_ref": "urn:uuid:44444444-4444-7444-8444-444444444444",
    "agent_id": "agent-alpha",
}

EXECUTION_BODY = {
    "tool_calls": [{"tool": "read_phi_database", "args": {"patient_id": "p-12345"}}],
    "egress": "none",
    "resources": {"cpu_ms": 50, "mem_mb": 32, "disk_mb": 1, "wall_ms": 100},
    "sandbox_class": "bwrap-default",
}

TERMINATION_BODY = {
    "reason": "completed",
    "limits_at_stop": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
    "remaining": {"cpu_ms": 0, "mem_mb": 0, "disk_mb": 0, "wall_ms": 0},
}


def compute_sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class TestW3cReceiverAcceptance(unittest.TestCase):
    def setUp(self):
        self.did, self.key = keys.generate(seed=keys.deterministic_seed("w3c-acceptance-tests"))
        self.user_did, self.user_key = keys.generate(seed=keys.deterministic_seed("w3c-user-principal"))

    def test_erase_resurrect_resistance(self):
        """Test Yasha's erase_resurrect edit:
        - Store has items A, B, C.
        - Item B is erased, head moves to epoch 2, high-water anchor updated.
        - Pre-erasure snapshot (with B) is restored beneath the store.
        - Control check: unanchored store serves B ('served').
        - Anchored check: anchored store detects epoch/digest rollback and refuses B ('refused').
        """
        # 1. Genuine initial store (Epoch 1)
        item_a = {"id": "rec_1", "content": "user preferences: dark mode", "epoch": 1}
        item_b = {"id": "rec_2", "content": "user secret note to be erased", "epoch": 1}
        item_c = {"id": "rec_3", "content": "project task: compile rust", "epoch": 1}
        initial_store = [item_a, item_b, item_c]

        # Pre-erasure backup snapshot taken by attacker/operator
        backup_snapshot = copy.deepcopy(initial_store)

        # 2. API erases item B -> Post-erasure store (Epoch 2)
        post_erasure_store = [item_a, item_c]
        tombstone_receipt = {
            "kind": "wm.crystal-erasure",
            "erased_id": "rec_2",
            "pre_count": 3,
            "post_count": 2,
            "epoch": 2,
            "post_head_digest": compute_sha256(json.dumps([item_a["id"], item_c["id"]]).encode("utf-8")),
        }
        tombstone_receipt["sig"] = {
            "alg": "ed25519",
            "value": keys.sign(self.key, canonical_bytes(tombstone_receipt)),
        }

        # High-water anchor committed off-store
        offstore_anchor = {
            "kind": "wm.crystal-set-commitment",
            "count": 2,
            "epoch": 2,
            "head_digest": tombstone_receipt["post_head_digest"],
            "erased_tombstones": ["rec_2"],
        }
        offstore_anchor["sig"] = {
            "alg": "ed25519",
            "value": keys.sign(self.key, canonical_bytes(offstore_anchor)),
        }

        # 3. Attacker restores backup_snapshot beneath the API
        restored_store = copy.deepcopy(backup_snapshot)

        # --- Evaluator Check 1: Unanchored Receiver Path ---
        # Without off-store anchor, receiver opens local restored store
        unanchored_verdict = "served" if any(r["id"] == "rec_2" for r in restored_store) else "refused"
        self.assertEqual(unanchored_verdict, "served", "Unanchored store fails open by serving resurrected content")

        # --- Evaluator Check 2: Anchored Receiver Path ---
        # With off-store anchor & tombstone, receiver validates against high-water commitment
        restored_ids = [r["id"] for r in restored_store]
        restored_digest = compute_sha256(json.dumps(restored_ids).encode("utf-8"))

        if (
            len(restored_store) > offstore_anchor["count"]
            or any(r["id"] in offstore_anchor["erased_tombstones"] for r in restored_store)
            or restored_digest != offstore_anchor["head_digest"]
        ):
            anchored_verdict = "refused"
        else:
            anchored_verdict = "served"

        self.assertEqual(anchored_verdict, "refused", "Anchored store must refuse resurrected snapshot on read path")

    def test_matthew_hinkle_auth_revocation_conflict(self):
        """Test Matthew Hinkle's vector: Authorization -> Revocation -> Conflict.
        - Step 1: Authorization granted to agent (session.pass.created).
        - Step 2: Revocation emitted.
        - Step 3: Conflict action attempted using revoked authority.
        - Verdict vocabulary: 'refused'.
        """
        # Step 1: Authorization
        auth_grant = records.new_envelope(
            TASK_ID,
            "agent",
            self.did,
            "session.pass.created",
            0,
            None,
            PASS_BODY,
            spec=SPEC,
            issued_at="2026-01-01T00:00:00Z",
        )
        auth_grant = records.sign_receipt(auth_grant, self.key, self.did)
        auth_digest = receipt_digest(auth_grant)

        # Step 2: Subsequent Revocation statement for the issuer's key
        revocation_statement = {
            "key": self.did,
            "revoked_at": "2026-01-02T00:00:00Z",
            "revoked_receipt": auth_digest,
            "reason": "privilege_expired_by_policy",
        }
        revocation_statement["sig"] = {
            "alg": "ed25519",
            "value": keys.sign(self.key, canonical_bytes(revocation_statement)),
        }

        # Step 3: Task execution attempting to act under the revoked authority at a later timestamp
        conflict_action = records.new_envelope(
            TASK_ID,
            "agent",
            self.did,
            "task.execution",
            1,
            auth_digest,
            EXECUTION_BODY,
            spec=SPEC,
            issued_at="2026-01-03T00:00:00Z",  # Subsequent to revocation!
        )
        conflict_action = records.sign_receipt(conflict_action, self.key, self.did)

        term = records.new_envelope(
            TASK_ID,
            "agent",
            self.did,
            "task.termination",
            2,
            receipt_digest(conflict_action),
            TERMINATION_BODY,
            spec=SPEC,
            issued_at="2026-01-03T00:01:00Z",
        )
        term = records.sign_receipt(term, self.key, self.did)

        bundle = {"spec": SPEC, "task_id": TASK_ID, "receipts": [auth_grant, conflict_action, term]}

        # Verify bundle with revocation list
        result = verify_bundle(bundle, external_revocations=[revocation_statement])

        # Map to receiver 3-word vocabulary:
        receiver_verdict = "refused" if result.verdict in ("UNTRUSTED", "INSUFFICIENT_EVIDENCE") else "served"
        self.assertEqual(receiver_verdict, "refused")
        self.assertIn("key_revoked", result.codes())

    def test_jeongho_song_derived_from_scope(self):
        """Test Jeongho Song's Point 1: derived-from Scope.
        - Raw user prompt U1 generates synthesized notes D1 and D2.
        - When U1 is marked for erasure, causal DAG traversal finds D1 and D2.
        """
        graph = {
            "obs_user_1": {"type": "observation", "content": "I am allergic to penicillin", "derived": ["note_agent_1"]},
            "note_agent_1": {
                "type": "reconstruction",
                "content": "Patient contraindication: penicillin class",
                "derived": ["summary_agent_2"],
                "derived_from": "obs_user_1",
            },
            "summary_agent_2": {
                "type": "user_correction",
                "content": "Prescription restriction: avoid Amoxicillin",
                "derived": [],
                "derived_from": "note_agent_1",
            },
            "unrelated_obs": {"type": "observation", "content": "Patient height: 180cm", "derived": []},
        }

        # Traversal function to find all derived records starting from target
        def find_derived_scope(root_id: str, dag: dict) -> set[str]:
            visited = set()
            queue = [root_id]
            while queue:
                curr = queue.pop(0)
                if curr in dag:
                    for child in dag[curr].get("derived", []):
                        if child not in visited:
                            visited.add(child)
                            queue.append(child)
            return visited

        erasure_scope = find_derived_scope("obs_user_1", graph)
        self.assertEqual(erasure_scope, {"note_agent_1", "summary_agent_2"})
        self.assertNotIn("unrelated_obs", erasure_scope)


if __name__ == "__main__":
    unittest.main()
