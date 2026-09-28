#!/usr/bin/env python3
"""Physical native-shadow synthetic-loader receipt regression."""
from __future__ import annotations

import json
import hashlib
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

RUNNER = "owned-loader-synthetic"
EVIDENCE = re.compile(r"^owned synthetic loader evidence: (/workspace/\.work/x86_64/owned-loader-synthetic\.[^\s]+)$", re.M)


class OwnedLoaderSyntheticReceiptTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CRABC_LOADER_SYNTHETIC_TEST_NATIVE") == "1", "requires installed native-shadow product")
    def test_retains_all_workloads_and_executed_fixtures_after_cleanup(self) -> None:
        latest = receipt.receipt_directory(ROOT, RUNNER)
        if latest.exists():
            shutil.rmtree(latest)
        with self.assertRaisesRegex(receipt.ReceiptError, "no receipt"):
            receipt.read_receipt(ROOT, RUNNER)

        product = os.environ["CRABC_LOADER_SYNTHETIC_DYNAMIC_SYSROOT"]
        completed = subprocess.run(
            ["bash", str(ROOT / "compat/x86_64/run_owned_loader_synthetic.sh"), product],
            cwd=ROOT, capture_output=True, text=True, timeout=1800,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        match = EVIDENCE.search(completed.stdout)
        self.assertIsNotNone(match, completed.stdout)
        work = Path(match.group(1))
        self.assertTrue(work.is_dir() and not work.is_symlink()
                        and work.is_relative_to(ROOT / ".work/x86_64"))

        published = receipt.read_receipt(ROOT, RUNNER, case_prefix="nested-")
        report = json.loads((work / "report.json").read_text())
        self.assertTrue(report["component_complete"])
        self.assertEqual({case["id"] for case in published.cases}, set(report["selected"]) | {"runner"})
        self.assertEqual(len(published.cases), 22)
        self.assertTrue({"dynamic-loader", "dynamic-libc", "dynamic-manifest",
                         "dynamic-libc-provenance", "fixture-map", "pinned-musl-libc"}
                        <= set(published.products))
        for name in report["selected"]:
            case = next(case for case in published.cases if case["id"] == name)
            expected = {f"cases/{name}/case.json"}
            expected.update(path.relative_to(work).as_posix()
                            for path in (work / "cases" / name / "raw").iterdir())
            self.assertEqual(set(case["logs"]), expected)
            for observation in (work / "cases" / name / "raw").glob("*.json"):
                raw = json.loads(observation.read_text())
                self.assertEqual(bytes.fromhex(raw["stdout_hex"]), observation.with_suffix(".stdout").read_bytes())
                self.assertEqual(bytes.fromhex(raw["stderr_hex"]), observation.with_suffix(".stderr").read_bytes())

        fixture_map = json.loads((latest / "products/fixture-map").read_text())
        fixtures = fixture_map["fixtures"]
        self.assertGreater(len(fixtures), len(report["selected"]) * 2)
        self.assertEqual({item["product"] for item in fixtures},
                         {name for name in published.products if name.startswith("fixture-") and name != "fixture-map"})
        hashes = set()
        for item in fixtures:
            path = work / item["path"]
            self.assertTrue(path.is_file() and not path.is_symlink())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, item["sha256"])
            self.assertEqual(digest, published.products[item["product"]]["sha256"])
            hashes.add(digest)
        for name in report["selected"]:
            for link in report["cases"][name]["links"]:
                self.assertIn(link["output_sha256"], hashes)
                self.assertIn(link["object_sha256"], hashes)

        shutil.rmtree(work)
        receipt.read_receipt(ROOT, RUNNER, case_prefix="weak-strong")
        retained = latest / "products/dynamic-loader"
        original = retained.read_bytes()
        retained.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        retained.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)
        log = latest / "logs/cases/nested-needed/case.json"
        original = log.read_bytes()
        log.write_bytes(original + b"tampered\n")
        with self.assertRaisesRegex(receipt.ReceiptError, "does not match its digest"):
            receipt.read_receipt(ROOT, RUNNER)
        log.write_bytes(original)
        receipt.read_receipt(ROOT, RUNNER)


if __name__ == "__main__":
    unittest.main()
