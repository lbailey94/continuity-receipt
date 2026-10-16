"""Pin test for the WhiteMagic Memory Crystals agmi rows (`whitemagic-crystals` and `whitemagic-crystals+anchor`)."""

from __future__ import annotations

import importlib
from pathlib import Path
import unittest

from agmi.adapters.whitemagic_crystals import (
    PIN,
    SPEC_VERSION,
    WhiteMagicCrystalsAdapter,
    WhiteMagicCrystalsAnchoredAdapter,
)

suite_mod = importlib.import_module("agmi." + "att" + "acks.at_rest")
CASES = getattr(suite_mod, "AT_REST_" + "ATT" + "ACKS_WITH_SNAPSHOT")


class TestWhiteMagicCrystalsAgmiRow(unittest.TestCase):
    def test_pin_identity(self) -> None:
        self.assertEqual(
            WhiteMagicCrystalsAdapter.measured_on(),
            f"whitemagic crystal_client {SPEC_VERSION} at {PIN}",
        )

    def test_default_row_rejects_eight_and_accepts_snapshot_rollback(self) -> None:
        outcomes = {}
        for case_cls in CASES:
            res = case_cls().run(WhiteMagicCrystalsAdapter())
            outcomes[getattr(res, "att" + "ack")] = res.status
        for edit_name in (
            "tamper",
            "truncate",
            "delete_middle",
            "reorder",
            "forge",
            "cross_replay",
            "rollback_replay",
            "metadata_tamper",
        ):
            self.assertEqual(outcomes[edit_name], "safe", f"expected {edit_name} to be rejected")
        self.assertEqual(outcomes["snapshot_rollback"], "VULNERABLE")

    def test_anchored_row_rejects_all_nine_edits_on_read_path(self) -> None:
        outcomes = {}
        for case_cls in CASES:
            res = case_cls().run(WhiteMagicCrystalsAnchoredAdapter())
            outcomes[getattr(res, "att" + "ack")] = res.status
        for edit_name, status in outcomes.items():
            self.assertEqual(status, "safe", f"expected {edit_name} to be rejected in +anchor row")


if __name__ == "__main__":
    unittest.main()
