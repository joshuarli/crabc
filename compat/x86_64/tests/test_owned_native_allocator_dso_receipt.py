#!/usr/bin/env python3
"""Physical native-shadow allocator DSO receipt regression."""
from __future__ import annotations

import hashlib
import json
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
import owned_native_allocator_dso_receipt as semantic_receipt  # noqa: E402

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
        semantic_receipt.read_native_allocator_dso_receipt(ROOT)
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

        receipt_path = latest / "receipt.json"
        original_receipt = receipt_path.read_bytes()
        changed = json.loads(original_receipt)
        changed["cases"] = [case for case in changed["cases"] if case["id"] != "direct-non-pie"]
        receipt_path.write_text(json.dumps(changed))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "case roster"):
            semantic_receipt.read_native_allocator_dso_receipt(ROOT)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_native_allocator_dso_receipt(ROOT)

        changed = json.loads(original_receipt)
        originals = {}
        for name in ("oracle-pie", "kernel-pie", "direct-pie"):
            path = latest / "logs" / f"{name}.stdout"
            originals[name] = path.read_bytes()
            path.write_bytes(b"wrong but matching transcript\n")
            data = path.read_bytes()
            case = next(case for case in changed["cases"] if case["id"] == name)
            case["logs"][f"{name}.stdout"] = {
                "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            }
        receipt_path.write_text(json.dumps(changed))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "pinned musl transcript"):
            semantic_receipt.read_native_allocator_dso_receipt(ROOT)
        for name, data in originals.items():
            (latest / "logs" / f"{name}.stdout").write_bytes(data)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_native_allocator_dso_receipt(ROOT)

        state = latest / "products/dynamic-product-state"
        original_state = state.read_bytes()
        changed_state = json.loads(original_state)
        changed_state["allocator_backend"] = "selected-c"
        state.write_text(json.dumps(changed_state))
        changed = json.loads(original_receipt)
        data = state.read_bytes()
        changed["products"]["dynamic-product-state"] = {
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        }
        receipt_path.write_text(json.dumps(changed))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "allocator backend"):
            semantic_receipt.read_native_allocator_dso_receipt(ROOT)
        state.write_bytes(original_state)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_native_allocator_dso_receipt(ROOT)

        candidate_dso = latest / "products/candidate-initial-dso"
        original_dso = candidate_dso.read_bytes()
        replacement = (latest / "products/oracle-initial-dso").read_bytes()
        candidate_dso.write_bytes(replacement)
        changed = json.loads(original_receipt)
        changed["products"]["candidate-initial-dso"] = {
            "sha256": hashlib.sha256(replacement).hexdigest(), "size": len(replacement),
        }
        receipt_path.write_text(json.dumps(changed))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "candidate-initial-dso runpath"):
            semantic_receipt.read_native_allocator_dso_receipt(ROOT)
        candidate_dso.write_bytes(original_dso)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_native_allocator_dso_receipt(ROOT)

        loader = latest / "products/dynamic-loader"
        manifest = latest / "products/dynamic-manifest"
        original_loader = loader.read_bytes()
        original_manifest = manifest.read_bytes()
        replacement = (latest / "products/musl-interpreter").read_bytes()
        loader.write_bytes(replacement)
        changed_manifest = json.loads(original_manifest)
        changed_manifest["files"]["lib/ld-crabc-x86_64.so.1"] = hashlib.sha256(replacement).hexdigest()
        manifest.write_text(json.dumps(changed_manifest))
        changed = json.loads(original_receipt)
        changed["products"]["dynamic-loader"] = {
            "sha256": hashlib.sha256(replacement).hexdigest(), "size": len(replacement),
        }
        changed["products"]["dynamic-manifest"] = {
            "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "size": manifest.stat().st_size,
        }
        receipt_path.write_text(json.dumps(changed))
        receipt.read_receipt(ROOT, RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "dynamic product payload"):
            semantic_receipt.read_native_allocator_dso_receipt(ROOT)
        loader.write_bytes(original_loader)
        manifest.write_bytes(original_manifest)
        receipt_path.write_bytes(original_receipt)
        semantic_receipt.read_native_allocator_dso_receipt(ROOT)


if __name__ == "__main__":
    unittest.main()
