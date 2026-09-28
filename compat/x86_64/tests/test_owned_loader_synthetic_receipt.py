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
import owned_loader_synthetic_receipt as semantic_receipt  # noqa: E402

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
        semantic_receipt.read_loader_synthetic_receipt(ROOT)
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

        receipt_path = latest / "receipt.json"
        original_receipt = receipt_path.read_bytes()
        report_path = latest / "logs/report.json"
        original_report = report_path.read_bytes()
        changed_report = json.loads(original_report)
        changed_report["selected"].remove("weak-strong")
        changed_report["cases"].pop("weak-strong")
        report_path.write_text(json.dumps(changed_report))
        changed_receipt = json.loads(original_receipt)
        runner = next(case for case in changed_receipt["cases"] if case["id"] == "runner")
        report_bytes = report_path.read_bytes()
        runner["logs"]["report.json"] = {
            "sha256": hashlib.sha256(report_bytes).hexdigest(), "size": len(report_bytes),
        }
        receipt_path.write_text(json.dumps(changed_receipt))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "report workload roster"):
            semantic_receipt.read_loader_synthetic_receipt(ROOT)
        report_path.write_bytes(original_report)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_loader_synthetic_receipt(ROOT)

        fixture_path = latest / "products/fixture-map"
        original_fixture = fixture_path.read_bytes()
        changed_fixture = json.loads(original_fixture)
        changed_fixture["fixtures"][0]["sha256"] = "0" * 64
        fixture_path.write_text(json.dumps(changed_fixture))
        changed_receipt = json.loads(original_receipt)
        fixture_bytes = fixture_path.read_bytes()
        changed_receipt["products"]["fixture-map"] = {
            "sha256": hashlib.sha256(fixture_bytes).hexdigest(), "size": len(fixture_bytes),
        }
        receipt_path.write_text(json.dumps(changed_receipt))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "fixture digest"):
            semantic_receipt.read_loader_synthetic_receipt(ROOT)
        fixture_path.write_bytes(original_fixture)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_loader_synthetic_receipt(ROOT)

        changed_fixture = json.loads(original_fixture)
        changed_fixture["symlinks"].pop()
        fixture_path.write_text(json.dumps(changed_fixture))
        changed_receipt = json.loads(original_receipt)
        fixture_bytes = fixture_path.read_bytes()
        changed_receipt["products"]["fixture-map"] = {
            "sha256": hashlib.sha256(fixture_bytes).hexdigest(), "size": len(fixture_bytes),
        }
        receipt_path.write_text(json.dumps(changed_receipt))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "fixture symlink map"):
            semantic_receipt.read_loader_synthetic_receipt(ROOT)
        fixture_path.write_bytes(original_fixture)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_loader_synthetic_receipt(ROOT)

        state_path = latest / "products/dynamic-product-state"
        original_state = state_path.read_bytes()
        changed_state = json.loads(original_state)
        changed_state["allocator_backend"] = "selected-c"
        state_path.write_text(json.dumps(changed_state))
        changed_receipt = json.loads(original_receipt)
        state_bytes = state_path.read_bytes()
        changed_receipt["products"]["dynamic-product-state"] = {
            "sha256": hashlib.sha256(state_bytes).hexdigest(), "size": len(state_bytes),
        }
        receipt_path.write_text(json.dumps(changed_receipt))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "product backend"):
            semantic_receipt.read_loader_synthetic_receipt(ROOT)
        state_path.write_bytes(original_state)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_loader_synthetic_receipt(ROOT)

        raw_path = next((latest / "logs/cases/nested-needed/raw").glob("*.json"))
        original_raw = raw_path.read_bytes()
        changed_raw = json.loads(original_raw)
        changed_raw["stdout_hex"] = "00"
        raw_path.write_text(json.dumps(changed_raw))
        changed_receipt = json.loads(original_receipt)
        raw_key = raw_path.relative_to(latest / "logs").as_posix()
        nested_case = next(case for case in changed_receipt["cases"] if case["id"] == "nested-needed")
        raw_bytes = raw_path.read_bytes()
        nested_case["logs"][raw_key] = {
            "sha256": hashlib.sha256(raw_bytes).hexdigest(), "size": len(raw_bytes),
        }
        receipt_path.write_text(json.dumps(changed_receipt))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "raw command streams"):
            semantic_receipt.read_loader_synthetic_receipt(ROOT)
        raw_path.write_bytes(original_raw)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_loader_synthetic_receipt(ROOT)


if __name__ == "__main__":
    unittest.main()
