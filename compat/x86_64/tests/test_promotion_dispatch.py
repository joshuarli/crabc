#!/usr/bin/env python3
"""Promotion dispatch preserves the explicit physical qualification receipt."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("core_dispatch_fixture", ROOT / "compat/x86_64/tests/test_core_image_dispatch.py")
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class PromotionDispatchTests(unittest.TestCase):
    setUp = fixture.CoreImageDispatchTests.setUp
    invoke = fixture.CoreImageDispatchTests.invoke
    calls = fixture.CoreImageDispatchTests.calls

    def test_explicit_owned_receipt_reaches_pinned_reader(self) -> None:
        receipt = self.work / "receipt.json"
        receipt.write_text("{}")
        result = self.invoke("scripts/dev-x86_64.sh", "promotion-closure", "--qualification-receipt", str(receipt))
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(runs), 1, runs)
        runner = "/workspace/compat/x86_64/campaign_promotion_closure.py"
        self.assertIn(fixture.PIN, runs[0])
        self.assertIn("--read-only", runs[0])
        self.assertEqual(runs[0][runs[0].index("--network") + 1], "none")
        mounts = [runs[0][index + 1] for index, item in enumerate(runs[0]) if item == "--volume"]
        self.assertIn(str(ROOT) + ":/workspace:ro", mounts)
        self.assertIn(str(self.work) + ":/workspace/.work/x86_64:ro", mounts)
        self.assertEqual(sum(mount.endswith(":rw") for mount in mounts), 2)
        index = runs[0].index(runner)
        expected = "/workspace/.work/x86_64/receipt.json"
        self.assertEqual(runs[0][index + 1:], ["--qualification-receipt", expected])

    def test_invalid_or_unowned_receipts_never_reach_docker(self) -> None:
        for arguments in ([], ["--qualification-receipt"],
                          ["--qualification-receipt", str(ROOT / "plan.md")],
                          ["--qualification-receipt", str(self.work / "missing.json")],
                          ["--profile", "correctness"],
                          ["--qualification-receipt", str(self.work), "extra"]):
            with self.subTest(arguments=arguments):
                result = self.invoke("scripts/dev-x86_64.sh", "promotion-closure", *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists(), "invalid receipt reached Docker")


if __name__ == "__main__":
    unittest.main()
