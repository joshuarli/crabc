#!/usr/bin/env python3
"""Physical native-shadow allocator-override receipt regression."""
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

RUNNER = "owned-allocator-override"
EVIDENCE = re.compile(r"^allocator-override evidence: (/workspace/\.work/x86_64/tmp/owned-allocator-override\.[^\s]+)$", re.M)


class OwnedAllocatorOverrideReceiptTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_OVERRIDE_TEST_NATIVE") == "1", "requires native installed products")
    def test_runner_retains_cases_and_products_after_work_cleanup(self) -> None:
        latest = receipt.receipt_directory(ROOT, RUNNER)
        if latest.exists():
            shutil.rmtree(latest)
        with self.assertRaisesRegex(receipt.ReceiptError, "no receipt"):
            receipt.read_receipt(ROOT, RUNNER)

        command = ["bash", str(ROOT / "compat/x86_64/run_owned_allocator_override.sh")]
        static = os.environ.get("CRABC_OVERRIDE_STATIC_SYSROOT")
        dynamic = os.environ.get("CRABC_OVERRIDE_DYNAMIC_SYSROOT")
        if static or dynamic:
            self.assertTrue(static and dynamic)
            command.extend(("--static-sysroot", static, dynamic))
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
        self.assertEqual(len(executed), 25)
        self.assertTrue({"static-full", "static-pie-trio", "dynamic-pie-full", "dynamic-non-pie-trio",
                         "override-dso-full", "dso-client-pie-trio", "static-libc-archive",
                         "dynamic-libc", "dynamic-loader", "static-libc-provenance",
                         "dynamic-libc-provenance"} <= set(published.products))

        shutil.rmtree(work)
        receipt.read_receipt(ROOT, RUNNER, case_prefix="direct-")
        retained = latest / "products/static-full"
        with retained.open("r+b") as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(bytes([first[0] ^ 1]))
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        with retained.open("r+b") as stream:
            stream.write(first)
        receipt.read_receipt(ROOT, RUNNER)
        log = latest / "logs/kernel-pie-full.stdout"
        original = log.read_bytes()
        log.write_bytes(original + b"tampered\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        log.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)


if __name__ == "__main__":
    unittest.main()
