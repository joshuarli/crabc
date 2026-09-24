#!/usr/bin/env python3
"""Behavior of the shared native-shadow runner receipt writer and reader."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "native_shadow_receipt", ROOT / "compat/x86_64/native_shadow_receipt.py"
)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = receipt
SPEC.loader.exec_module(receipt)

RUNNER = "owned-native-allocator-stress"


class NativeShadowReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for command in (["init", "-q"], ["config", "user.email", "t@example.invalid"],
                        ["config", "user.name", "t"]):
            subprocess.run(["git", *command], cwd=self.root, check=True)
        (self.root / ".gitignore").write_text(".work/\n")
        (self.root / "source.c").write_text("int main(void) { return 0; }\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=self.root, check=True)
        self.work = self.root / ".work/x86_64/tmp/run"
        self.work.mkdir(parents=True)
        (self.work / "stress-1-1-1-static-pie.stdout").write_text("ok\n")
        (self.work / "soak-1-static-pie.stdout").write_text("summary rounds=1\n")
        (self.work / "program").write_bytes(b"\x7fELF")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self, *, canonical=True, stress_status=0):
        return receipt.write_receipt(
            self.root, RUNNER, self.work, {"stress-static-pie": self.work / "program"},
            [
                ("stress-1-1-1-static-pie", stress_status, [self.work / "stress-1-1-1-static-pie.stdout"]),
                ("soak-1-static-pie", 0, [self.work / "soak-1-static-pie.stdout"]),
            ],
            {"SOAK_ROUNDS": "1200"}, canonical,
        )

    def test_a_passing_canonical_receipt_on_its_own_tree_is_accepted(self) -> None:
        path = self.publish()
        self.assertEqual(path, self.root / receipt.RECEIPTS / RUNNER / "latest/receipt.json")
        read = receipt.read_receipt(self.root, RUNNER, case_prefix="soak-")
        self.assertEqual(read.case_ids(), ["stress-1-1-1-static-pie", "soak-1-static-pie"])
        self.assertEqual(read.case_ids("stress-"), ["stress-1-1-1-static-pie"])
        self.assertIn("stress-static-pie", read.products)

    def test_a_changed_or_untracked_source_makes_the_receipt_stale(self) -> None:
        self.publish()
        (self.root / "source.c").write_text("int main(void) { return 1; }\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "rerun the runner"):
            receipt.read_receipt(self.root, RUNNER)
        subprocess.run(["git", "checkout", "-q", "source.c"], cwd=self.root, check=True)
        receipt.read_receipt(self.root, RUNNER)
        (self.root / "new.c").write_text("int x;\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "rerun the runner"):
            receipt.read_receipt(self.root, RUNNER)

    def test_a_failed_case_a_development_run_or_a_missing_family_is_rejected(self) -> None:
        self.publish(stress_status=1)
        with self.assertRaisesRegex(receipt.ReceiptError, "exited 1"):
            receipt.read_receipt(self.root, RUNNER)
        self.publish(canonical=False)
        with self.assertRaisesRegex(receipt.ReceiptError, "non-canonical"):
            receipt.read_receipt(self.root, RUNNER)
        self.publish()
        with self.assertRaisesRegex(receipt.ReceiptError, "no 'runner' case"):
            receipt.read_receipt(self.root, RUNNER, case_prefix="runner")

    def test_a_tampered_or_missing_raw_log_is_rejected(self) -> None:
        path = self.publish()
        log = path.parent / "logs/stress-1-1-1-static-pie.stdout"
        log.write_text("different\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(self.root, RUNNER)
        log.unlink()
        with self.assertRaisesRegex(receipt.ReceiptError, "is missing"):
            receipt.read_receipt(self.root, RUNNER)

    def test_an_absent_receipt_or_a_rewritten_seal_is_rejected(self) -> None:
        with self.assertRaisesRegex(receipt.ReceiptError, "no receipt"):
            receipt.read_receipt(self.root, RUNNER)
        path = self.publish()
        record = json.loads(path.read_text())
        record["runner"] = "libc-native-mimalloc-shadow-pthread-teardown"
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(receipt.ReceiptError, "schema or runner"):
            receipt.read_receipt(self.root, RUNNER)

    def test_republishing_replaces_the_latest_receipt(self) -> None:
        self.publish(stress_status=1)
        self.publish()
        receipt.read_receipt(self.root, RUNNER)
        self.assertEqual(
            sorted(entry.name for entry in (self.root / receipt.RECEIPTS / RUNNER).iterdir()), ["latest"]
        )


if __name__ == "__main__":
    unittest.main()
