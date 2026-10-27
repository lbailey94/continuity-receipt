import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CPR_ROOT = Path(__file__).resolve().parents[1]
RUNNER = CPR_ROOT / "tools" / "memory_receiver_journey.py"


class MemoryReceiverJourneyTests(unittest.TestCase):
    def test_disposable_subprocess_journey_records_real_output_and_refusals(self):
        with tempfile.TemporaryDirectory(prefix="journey-runner-test-") as temporary:
            output = Path(temporary) / "evidence"
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--output-dir", str(output)],
                cwd=CPR_ROOT, text=True, capture_output=True, timeout=60, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["outcome"], "PASS")
            packet = (output / "journey.json").read_bytes()
            evidence = json.loads(packet)
            self.assertTrue(evidence["same_operator"])
            self.assertTrue(evidence["answers_visible"])
            self.assertNotIn(b"BEGIN PRIVATE KEY", packet)
            self.assertEqual(evidence["optimized_mode_negative_probe"]["returncode"], 1)
            self.assertEqual(evidence["optimized_mode_negative_probe"]["stdout"], "")
            self.assertFalse(evidence["optimized_mode_negative_probe"]["output_directory_created"])
            events = {event["label"]: event for event in evidence["events"]}
            for label in (
                "missing-trust-releases-no-output",
                "restore-data-without-trust-releases-no-output",
                "restore-corrupt-payload-releases-no-output",
                "restore-different-checkpoint-releases-no-output",
                "erased-selected-path-releases-no-output",
                "pre-erasure-data-current-trust-releases-no-output",
            ):
                self.assertEqual(events[label]["stdout"], "", label)
            self.assertEqual(events["joint-old-data-and-trust-can-resurrect-erased-text"]["stdout"],
                             "This selected note must never be emitted after erasure.\n")
            self.assertEqual(
                events["resume-initial-exact-text"]["stdout"],
                "Journey starts with the red block in bay 3.\n",
            )
            self.assertEqual(
                events["resume-appended-exact-text"]["stdout"],
                "Journey starts with the red block in bay 3.\n Next action: verify the local receiver.\n",
            )
            self.assertEqual(
                events["current-selected-path-still-recovers"]["stdout"],
                "Journey starts with the red block in bay 3.\n Next action: verify the local receiver.\n",
            )
            self.assertEqual(
                events["restore-trusted-current-generation-recovers"]["stdout"],
                "Journey starts with the red block in bay 3.\n Next action: verify the local receiver.\n",
            )

    def test_optimized_mode_cannot_turn_a_failed_gate_into_pass(self):
        with tempfile.TemporaryDirectory(prefix="journey-optimized-failure-") as temporary:
            output = Path(temporary) / "evidence"
            result = subprocess.run(
                [sys.executable, "-O", str(RUNNER), "--probe-fail-closed",
                 "--output-dir", str(output)],
                cwd=CPR_ROOT, text=True, capture_output=True, timeout=20, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertIn("intentional fail-closed probe", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
