"""Tests for CPR v0.6-pq semantic_predicate gate, cpr-trace-shrink, and off_host_witness."""
from __future__ import annotations

import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from continuity_receipt.receiver_store import ReceiverStore
from continuity_receipt.witness import OffHostWitness
from continuity_receipt.trace_shrink import shrink_counterexample, shrink_trace

def test_semantic_predicate_rejects_and_prevents_sink_emission():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        key = Ed25519PrivateKey.generate()
        store = ReceiverStore(
            root / "data",
            root / "trust" / "receiver.sqlite3",
            trusted_public_key=key.public_key(),
            scope="test.scope",
            context="test.context",
            max_age_seconds=3600,
        )
        store.initialize()

        now = "2026-10-31T03:00:00Z"
        files = {
            "config.json": b'{"destination": "shelter-bad", "counter": 42}',
            "marker.txt": b"ok",
        }
        pub = store.publish(files, private_key=key, expected_checkpoint_digest=None, now=now)
        assert pub["outcome"] == "ACCEPT"

        # Define predicate that forbids "shelter-bad"
        def semantic_gate(captured):
            import json
            cfg = json.loads(captured["config.json"].decode())
            if cfg.get("destination") == "shelter-bad":
                return False, "forbidden_destination:shelter-bad"
            return True, "valid"

        sink_called = []
        rec = store.recall(
            now=now,
            sink=lambda files: sink_called.append(files),
            semantic_predicate=semantic_gate,
        )

        assert rec["outcome"] == "REJECT"
        assert rec["reason_codes"] == ["forbidden_destination:shelter-bad"]
        assert len(sink_called) == 0  # SINK MUST NOT BE CALLED
        assert "shrunk_trace" in rec
        assert "config.json" in rec["shrunk_trace"]

def test_off_host_witness_detects_joint_rollback():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        key = Ed25519PrivateKey.generate()
        store = ReceiverStore(
            root / "data",
            root / "trust" / "receiver.sqlite3",
            trusted_public_key=key.public_key(),
            scope="test.scope",
            context="test.context",
            max_age_seconds=3600,
        )
        store.initialize()

        now = "2026-10-31T03:00:00Z"
        pub = store.publish({"file.txt": b"gen 1"}, private_key=key, expected_checkpoint_digest=None, now=now)
        assert pub["outcome"] == "ACCEPT"
        ref1 = pub["reference"]
        assert ref1["sequence"] == 1

        # Publish generation 2
        pub2 = store.publish(
            {"file.txt": b"gen 2"},
            private_key=key,
            expected_checkpoint_digest=ref1["checkpoint_digest"],
            now=now,
        )
        assert pub2["outcome"] == "ACCEPT"
        ref2 = pub2["reference"]
        assert ref2["sequence"] == 2

        # Create witness that knows generation 2 was committed
        witness = OffHostWitness(min_sequence=2, latest_checkpoint=ref2["checkpoint_digest"])

        # When recalling gen 2 with witness, it succeeds
        rec2 = store.recall(now=now, off_host_witness=witness)
        assert rec2["outcome"] == "ACCEPT"

        # Now simulate joint data + trust rollback by rolling reference back to sequence 1
        conn = store._connect()
        conn.execute(
            "UPDATE current_reference SET generation_id=?, sequence=?, checkpoint_digest=?, bundle_digest=?, manifest_digest=? WHERE singleton=1",
            (ref1["generation_id"], ref1["sequence"], ref1["checkpoint_digest"], ref1["bundle_digest"], ref1["manifest_digest"])
        )
        conn.commit()
        conn.close()

        # Recalling without witness would accept the rollback
        rec_no_witness = store.recall(now=now)
        assert rec_no_witness["outcome"] == "ACCEPT"

        # Recalling WITH off-host witness catches the rollback!
        rec_witness = store.recall(now=now, off_host_witness=witness)
        assert rec_witness["outcome"] == "REJECT"
        assert "joint_rollback_detected:sequence_1_below_witness_2" in rec_witness["reason_codes"][0]

def test_trace_shrink_binary_search():
    # Sequence of 10 events, invariant breaks at step 4
    events = [{"step": i, "val": i} for i in range(10)]
    def predicate(stream):
        return not any(e["val"] >= 4 for e in stream)

    shrunk = shrink_trace(events, predicate)
    assert len(shrunk) == 1
    assert shrunk[0]["val"] == 4
