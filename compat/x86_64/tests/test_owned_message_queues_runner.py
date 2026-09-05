"""Installed compilation ownership and containment for message-queue evidence."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_message_queues.sh"
SPEC = importlib.util.spec_from_file_location("compile_owned_message_queues", ROOT / "compat/x86_64/compile_owned_message_queues.py")
COMPILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPILER)


class OwnedMessageQueuesRunnerTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="message-queues-runner.", dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)

    def test_supplied_product_physical_escape_is_rejected_before_build_or_compilation(self):
        escape = self.work / "escape"
        escape.symlink_to(ROOT, target_is_directory=True)
        for product in (escape, ROOT / ".work/../include"):
            with self.subTest(product=product):
                before = set(self.work.iterdir())
                result = subprocess.run(["bash", str(RUNNER), str(product)], cwd=ROOT,
                    env={**os.environ, "TMPDIR": str(self.work)}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("message queues product must be a physical checkout .work directory", result.stderr)
                self.assertEqual(set(self.work.iterdir()), before)
                self.assertNotIn("message queues evidence:", result.stdout)

    def product(self):
        product = self.work / "product"
        (product / "bin").mkdir(parents=True)
        (product / "share/crabc").mkdir(parents=True)
        (product / "bin/crabc-cc-dynamic").write_bytes(b"selected installed driver")
        (product / "share/crabc/manifest.json").write_text('{"selected":true}\n')
        return product

    def test_compile_receipt_binds_one_selected_driver_invocation_and_its_object(self):
        product = self.product()
        output = self.work / "output"
        output.mkdir()
        object_bytes = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x01\x00\x3e\x00"
        def translate(command, **kwargs):
            Path(command[-1]).write_bytes(object_bytes)
        with patch.object(COMPILER.subprocess, "run", side_effect=translate) as run:
            record = COMPILER.compile_workload(product, output)
        expected = [str(product / "bin/crabc-cc-dynamic"), "--dynamic-pie", "-std=c11", "-fno-builtin",
                    "-c", str(COMPILER.SOURCE), "-o", str(output / "probe.o")]
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], expected)
        self.assertEqual(record["argv"], expected)
        self.assertEqual(record["product"], str(product))
        self.assertEqual(record["output_sha256"], hashlib.sha256(object_bytes).hexdigest())
        self.assertEqual(set(record["input_sha256"]), {str(product / "bin/crabc-cc-dynamic"),
            str(product / "share/crabc/manifest.json"), str(COMPILER.SOURCE), str(COMPILER.WITNESS_HEADER)})
        self.assertEqual(json.loads((output / "compile.json").read_text()), record)

    def test_compilation_rejects_installed_payload_outputs_before_writing(self):
        product = self.product()
        before = set(product.rglob("*"))
        with patch.object(COMPILER.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "must not write into its installed product"):
                COMPILER.compile_workload(product, product)
        run.assert_not_called()
        self.assertEqual(set(product.rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
