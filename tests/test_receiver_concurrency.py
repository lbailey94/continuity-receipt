"""Observable concurrency guarantees inside one local SQLite trust domain."""
from __future__ import annotations

import multiprocessing
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from continuity_receipt.receiver_store import ReceiverStore

NOW = "2026-10-23T12:00:00Z"
KEY_BYTES = bytes(range(32))


def _store(data, db):
    key = Ed25519PrivateKey.from_private_bytes(KEY_BYTES)
    return ReceiverStore(data, db, context="concurrency:test", scope="memory:test",
                         trusted_public_key=key.public_key(), max_age_seconds=3600)


def _writer(data, db, expected, payload, barrier, results):
    store = _store(data, db)
    key = Ed25519PrivateKey.from_private_bytes(KEY_BYTES)
    try:
        barrier.wait(timeout=10)
        result = store.publish({"notes.txt": payload}, private_key=key,
                               expected_checkpoint_digest=expected, now=NOW)
        results.put((result["outcome"], result.get("reason_codes", []), result.get("reference")))
    except BaseException as exc:
        results.put(("WORKER_ERROR", [repr(exc)], None))


def _blocking_reader(data, db, entered, release, results):
    try:
        def sink(files):
            entered.set()
            if not release.wait(timeout=10):
                raise TimeoutError("reader release event timed out")
        results.put(_store(data, db).recall(now=NOW, sink=sink))
    except BaseException as exc:
        results.put({"outcome": "WORKER_ERROR", "error": repr(exc)})


def _publisher(data, db, expected, begin_attempt, completed, results):
    try:
        store = _store(data, db)
        connect = store._connect

        def traced_connect(*, create=False):
            conn = connect(create=create)
            if conn is not None:
                def trace(statement):
                    if statement.strip().upper() == "BEGIN IMMEDIATE":
                        begin_attempt.set()
                conn.set_trace_callback(trace)
            return conn

        # Trace fires on the BEGIN IMMEDIATE statement immediately before SQLite
        # attempts to acquire the writer lock, after publish has prepared evidence.
        store._connect = traced_connect
        result = store.publish(
            {"notes.txt": b"generation two"},
            private_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES),
            expected_checkpoint_digest=expected, now=NOW,
        )
        results.put(result)
    except BaseException as exc:
        results.put({"outcome": "WORKER_ERROR", "error": repr(exc)})
    finally:
        completed.set()


class ReceiverConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.data = self.base / "data"
        self.db = self.base / "trust" / "receiver.sqlite3"
        self.store = _store(self.data, self.db)
        self.store.initialize()
        self.ctx = multiprocessing.get_context("spawn")

    def tearDown(self):
        self.tmp.cleanup()

    def test_two_process_writers_on_same_reference_have_one_winner(self):
        barrier = self.ctx.Barrier(3)
        results = self.ctx.Queue()
        procs = [self.ctx.Process(target=_writer, args=(
            str(self.data), str(self.db), None, payload, barrier, results))
            for payload in (b"writer alpha", b"writer beta")]
        for proc in procs:
            proc.start()
        barrier.wait(timeout=10)
        outcomes = [results.get(timeout=15) for _ in procs]
        for proc in procs:
            proc.join(timeout=10)
            self.assertFalse(proc.is_alive(), "writer process did not exit")
            self.assertEqual(proc.exitcode, 0)

        accepted = [item for item in outcomes if item[0] == "ACCEPT"]
        conflicts = [item for item in outcomes if item[0] == "REJECT" and item[1] == ["reference_conflict"]]
        self.assertEqual((len(accepted), len(conflicts)), (1, 1), outcomes)
        ref = self.store.current_reference()
        self.assertEqual(ref, accepted[0][2])
        self.assertEqual(ref["sequence"], 1)
        with sqlite3.connect(self.db) as conn:
            audit = conn.execute("SELECT sequence,generation_id,checkpoint_digest FROM publication_audit ORDER BY sequence").fetchall()
        self.assertEqual(len(audit), 1, audit)
        self.assertEqual(audit[0][0], 1)
        recalled = self.store.recall(now=NOW)
        self.assertEqual(recalled["outcome"], "ACCEPT", recalled)
        self.assertEqual(recalled["reference"], ref)
        self.assertIn(recalled["files"]["notes.txt"], (b"writer alpha", b"writer beta"))

    def test_publisher_waits_until_reader_sink_returns_then_new_generation_is_visible(self):
        first = self.store.publish({"notes.txt": b"generation one"},
                                   private_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES),
                                   expected_checkpoint_digest=None, now=NOW)
        self.assertEqual(first["outcome"], "ACCEPT", first)
        entered, release, begin_attempt, completed = (self.ctx.Event(), self.ctx.Event(),
                                                       self.ctx.Event(), self.ctx.Event())
        reader_results, publisher_results = self.ctx.Queue(), self.ctx.Queue()
        reader = self.ctx.Process(target=_blocking_reader,
                                  args=(str(self.data), str(self.db), entered, release, reader_results))
        reader.start()
        self.assertTrue(entered.wait(timeout=10), "reader sink did not acquire its release point")
        publisher = self.ctx.Process(target=_publisher,
                                     args=(str(self.data), str(self.db), first["reference"]["checkpoint_digest"],
                                           begin_attempt, completed, publisher_results))
        publisher.start()
        self.assertTrue(begin_attempt.wait(timeout=10), "publisher did not reach BEGIN IMMEDIATE")
        # The publisher has attempted its write lock while the reader sink holds that lock.
        self.assertFalse(completed.wait(timeout=0.35), "publisher completed while sink held the transaction")
        release.set()
        reader_result = reader_results.get(timeout=10)
        published = publisher_results.get(timeout=15)
        reader.join(timeout=10)
        publisher.join(timeout=10)
        self.assertFalse(reader.is_alive())
        self.assertFalse(publisher.is_alive())
        self.assertEqual(reader.exitcode, 0)
        self.assertEqual(publisher.exitcode, 0)
        self.assertEqual(reader_result["outcome"], "ACCEPT", reader_result)
        self.assertEqual(reader_result["files"], {"notes.txt": b"generation one"})
        self.assertEqual(published["outcome"], "ACCEPT", published)
        self.assertEqual(published["reference"]["sequence"], 2)
        current = self.store.recall(now=NOW)
        self.assertEqual(current["outcome"], "ACCEPT", current)
        self.assertEqual(current["reference"], published["reference"])
        self.assertEqual(current["files"], {"notes.txt": b"generation two"})

    def test_stale_writer_cannot_restore_erased_content_or_advance_reference(self):
        first = self.store.publish({"memory.txt": b"erase this private text"},
                                   private_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES),
                                   expected_checkpoint_digest=None, now=NOW)
        self.assertEqual(first["outcome"], "ACCEPT", first)
        erased = self.store.publish({}, private_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES),
                                    expected_checkpoint_digest=first["reference"]["checkpoint_digest"], now=NOW)
        self.assertEqual(erased["outcome"], "ACCEPT", erased)
        stale = self.store.publish({"memory.txt": b"erase this private text"},
                                   private_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES),
                                   expected_checkpoint_digest=first["reference"]["checkpoint_digest"], now=NOW)
        self.assertEqual(stale["reason_codes"], ["reference_conflict"], stale)
        self.assertEqual(self.store.current_reference(), erased["reference"])
        recalled = self.store.recall(now=NOW)
        self.assertEqual(recalled["outcome"], "ACCEPT", recalled)
        self.assertEqual(recalled["files"], {})
        with sqlite3.connect(self.db) as conn:
            rows = conn.execute("SELECT sequence FROM publication_audit ORDER BY sequence").fetchall()
        self.assertEqual(rows, [(1,), (2,)])

    def test_read_under_mismatched_policy_does_not_mutate_reference_or_audit(self):
        first = self.store.publish({"notes.txt": b"kept"},
                                   private_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES),
                                   expected_checkpoint_digest=None, now=NOW)
        changed = ReceiverStore(self.data, self.db, context="different-context", scope="memory:test",
                                trusted_public_key=Ed25519PrivateKey.from_private_bytes(KEY_BYTES).public_key(),
                                max_age_seconds=3600)
        with self.assertRaisesRegex(ValueError, "receiver_policy_mismatch"):
            changed.current_reference()
        rejected = changed.recall(now=NOW)
        self.assertEqual(rejected["outcome"], "REJECT", rejected)
        self.assertEqual(rejected["reason_codes"], ["receiver_policy_mismatch"])
        self.assertIsNone(rejected["files"])
        self.assertEqual(self.store.current_reference(), first["reference"])
        with sqlite3.connect(self.db) as conn:
            rows = conn.execute("SELECT sequence FROM publication_audit ORDER BY sequence").fetchall()
        self.assertEqual(rows, [(1,)])


if __name__ == "__main__":
    unittest.main()
