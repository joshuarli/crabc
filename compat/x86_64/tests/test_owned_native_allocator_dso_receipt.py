#!/usr/bin/env python3
"""Physical native-shadow allocator DSO receipt regression."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipt  # noqa: E402

RUNNER = "owned-native-allocator-dso"
EVIDENCE = re.compile(r"^native-allocator-dso evidence: (/workspace/\.work/x86_64/tmp/owned-native-allocator-dso\.[^\s]+)$", re.M)


class OwnedNativeAllocatorDsoReceiptTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_DSO_TEST_NATIVE") == "1", "requires native installed product")
    def test_runner_retains_dso_cases_and_products_after_work_cleanup(self) -> None:
        latest = receipt.receipt_directory(ROOT, RUNNER)
        if latest.exists():
            shutil.rmtree(latest)
        with self.assertRaisesRegex(receipt.ReceiptError, "no receipt"):
            receipt.read_receipt(ROOT, RUNNER)

        command = ["bash", str(ROOT / "compat/x86_64/run_owned_native_allocator_dso.sh")]
        dynamic = os.environ.get("CRABC_DSO_DYNAMIC_SYSROOT")
        if dynamic:
            command.append(dynamic)
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        match = EVIDENCE.search(completed.stdout)
        self.assertIsNotNone(match, completed.stdout)
        work = Path(match.group(1))
        self.assertTrue(work.is_dir() and not work.is_symlink()
                        and work.is_relative_to(ROOT / ".work/x86_64/tmp"))

        published = receipt.read_receipt(ROOT, RUNNER, case_prefix="kernel-")
        executed = {path.stem for path in work.glob("*.status")}
        self.assertEqual({case["id"] for case in published.cases}, executed)
        self.assertEqual(executed, {"oracle-pie", "oracle-non-pie", "kernel-pie", "kernel-non-pie",
                                    "direct-pie", "direct-non-pie", "runner"})
        self.assertTrue({"oracle-probe-pie", "oracle-probe-non-pie", "candidate-probe-pie",
                         "candidate-probe-non-pie", "oracle-initial-dso", "oracle-plugin-dso",
                         "candidate-initial-dso", "candidate-plugin-dso", "musl-libc",
                         "musl-interpreter", "musl-family-bindings", "candidate-family-bindings",
                         "dynamic-libc", "dynamic-loader", "dynamic-libc-provenance",
                         "dynamic-manifest", "dynamic-product-state"} <= set(published.products))

        shutil.rmtree(work)
        receipt.read_receipt(ROOT, RUNNER, case_prefix="direct-")
        retained = latest / "products/candidate-plugin-dso"
        original = retained.read_bytes()
        retained.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        retained.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)
        log = latest / "logs/kernel-pie.stdout"
        original = log.read_bytes()
        log.write_bytes(original + b"tampered\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        log.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)


if __name__ == "__main__":
    unittest.main()
