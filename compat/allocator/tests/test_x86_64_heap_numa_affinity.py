#!/usr/bin/env python3
"""Exercise the Heap affinity runner's public receipt and replay paths."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
spec = importlib.util.spec_from_file_location("heap_numa_test_runner", ROOT / "compat/allocator/x86_64_heap_numa_affinity.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class HeapNumaReceiptTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/tmp/heap-numa-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                        "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "receipt fixture"], check=True)
        (self.root / ".git/info/exclude").write_text(".work/\n")
        for name, value in (("ROOT", self.root), ("ARTIFACT_ROOT", self.root / ".work/artifacts"),
                            ("TEMP_ROOT", self.root / ".work/tmp")):
            patch = mock.patch.object(runner.harness, name, value)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(runner, "ARTIFACTS", self.root / ".work/artifacts/numa")
        patch.start(); self.addCleanup(patch.stop)
        self.execution = {"execution_mode": "native", "host_architecture": "x86_64", "image_id": "sha256:" + "4" * 64}
        patch = mock.patch.object(runner.harness, "require_native_x86_64", return_value=self.execution)
        patch.start(); self.addCleanup(patch.stop)

    def publish(self):
        work = runner.select_output()
        products, cases = {}, []
        for side in ("c", "rust"):
            binary = work / f"numa-{side}"
            binary.write_text("#!/bin/sh\nprintf '%s,%s\\n' \"$MIMALLOC_USE_NUMA_NODES\" \"$MIMALLOC_ARENA_IS_NUMA_LOCAL\"\nprintf 'raw diagnostic\\n' >&2\n")
            binary.chmod(0o755)
            result, logs = runner.record(work, f"{side}-run", [str(binary)], work, True)
            self.assertEqual(result["status"], 0)
            self.assertEqual(runner.stress.byte_record_payload(result["stdout"], side), b"3,1\n")
            products[binary.name] = binary
            cases.append((f"{side}-run", 0, logs))
        inputs = work / "inputs.json"
        inputs.write_text(json.dumps({"execution": self.execution}))
        products[inputs.name] = inputs
        return runner.receipts.write_receipt(self.root, runner.RUNNER, work, products, cases,
                                             runner.ENVIRONMENT, True)

    def test_default_cli_dispatches_the_full_producer_without_output_argument(self):
        with mock.patch.object(sys, "argv", ["heap-numa"]), mock.patch.object(runner, "run") as produce:
            runner.main()
        produce.assert_called_once_with(None)

    def test_default_outputs_are_distinct_and_explicit_outputs_preserve_prior_attempt(self):
        first, second = runner.select_output(), runner.select_output()
        self.assertNotEqual(first, second)
        self.assertEqual(first.parent, runner.ARTIFACTS)
        with self.assertRaisesRegex(runner.harness.HarnessError, "already exists"):
            runner.select_output(first)
        escaped = self.root / ".work/outside-artifacts"
        escaped.mkdir()
        link = runner.harness.ARTIFACT_ROOT / "escape"
        link.symlink_to(escaped, target_is_directory=True)
        with self.assertRaisesRegex(runner.harness.HarnessError, "owning artifact root"):
            runner.select_output(link / "new-output")

    def test_public_reader_and_replay_use_real_generic_receipt_logs_and_products(self):
        path = self.publish()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            runner.read(True)
        self.assertIn("physical replay: PASS", output.getvalue())
        self.assertTrue(path.is_file())
        (path.parent / "products/numa-c").write_bytes(b"changed actual product")
        with self.assertRaisesRegex(runner.receipts.ReceiptError, "does not match its digest"):
            runner.read(True)

    def test_replay_rejects_a_different_execution_image_before_starting_callers(self):
        self.publish()
        wrong = dict(self.execution, image_id="sha256:" + "3" * 64)
        with mock.patch.object(runner.harness, "require_native_x86_64", return_value=wrong), \
             mock.patch.object(runner, "record") as execute:
            with self.assertRaisesRegex(runner.harness.HarnessError, "image"):
                runner.read(True)
        execute.assert_not_called()

    def test_changed_recorded_stderr_is_rejected_by_the_public_reader(self):
        path = self.publish()
        log = next((path.parent / "logs").glob("*.stderr"))
        log.write_bytes(b"changed raw diagnostic")
        with self.assertRaisesRegex(runner.receipts.ReceiptError, "log .*does not match"):
            runner.read()

    def test_changed_source_and_wrong_output_are_not_resealed_by_replay(self):
        self.publish()
        with self.assertRaisesRegex(runner.harness.HarnessError, "differs from the published"):
            runner.read(output=self.root / ".work/artifacts/another")
        (self.root / "changed-source").write_text("a different checkout\n")
        with self.assertRaisesRegex(runner.receipts.ReceiptError, "checkout is"):
            runner.read(True)


if __name__ == "__main__":
    unittest.main()
