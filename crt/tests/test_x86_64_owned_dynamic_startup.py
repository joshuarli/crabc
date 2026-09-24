"""Host checks for the installed dynamic CRT evidence's fail-closed link reader.

The native gate itself runs through
``./scripts/dev-x86_64.sh owned-crt-dynamic-startup DYNAMIC_SYSROOT``. These
cases exercise only its receipt reader with synthetic receipts, so a driver
that reorders the CRT/libc/helper inputs or admits another input cannot pass.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "crabc_x86_64_owned_dynamic_startup",
    Path(__file__).resolve().parents[1] / "x86_64_owned_dynamic_startup.py",
)
startup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = startup
SPEC.loader.exec_module(startup)


class InstalledLinkReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.product = root / "product"
        self.library = self.product / "usr/lib"
        self.output = root / "main"
        self.output.write_bytes(b"final executable bytes")
        self.object = root / "main.o"
        self.dso = root / "libdependency.so"
        archive = self.library / "libcrabc-builtins.a"
        self.inputs = [self.library / "Scrt1.o", self.library / "crabc-dynamic-attach.o",
                       self.library / "crti.o", self.object, self.dso, self.library / "libc.so",
                       archive, self.library / "crtn.o"]
        self.receipt = {
            "output_sha256": hashlib.sha256(self.output.read_bytes()).hexdigest(),
            "owned_runtime_inputs": sorted(f"usr/lib/{name}" for name in (
                "Scrt1.o", "crabc-dynamic-attach.o", "crti.o", "libc.so", "crtn.o", "libcrabc-builtins.a")),
            "link_command": ["ld.lld", "-pie", "--dynamic-linker", startup.INTERPRETER,
                             *(str(path) for path in self.inputs), "-o", str(self.output)],
            "link_trace": [f"{archive}(crabc-builtins.o)" if path == archive else str(path)
                           for path in self.inputs],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def check(self) -> dict[str, object]:
        Path(str(self.output) + ".crabc-link.json").write_text(json.dumps(self.receipt))
        return startup.check_link_receipt(self.product, self.output, "dynamic-pie", [self.object], [self.dso])

    def test_exact_installed_input_order_and_member_trace_are_admitted(self) -> None:
        self.assertEqual(self.check()["link_trace"], self.receipt["link_trace"])

    def test_reordered_crt_inputs_are_rejected(self) -> None:
        command = self.receipt["link_command"]
        command[4], command[6] = command[6], command[4]
        with self.assertRaisesRegex(startup.EvidenceError, "link input order"):
            self.check()

    def test_unextracted_helper_archive_is_rejected(self) -> None:
        self.receipt["link_trace"] = [line for line in self.receipt["link_trace"] if "crabc-builtins.o" not in line]
        with self.assertRaisesRegex(startup.EvidenceError, "link trace"):
            self.check()

    def test_ambient_trace_input_is_rejected(self) -> None:
        self.receipt["link_trace"].insert(1, "/usr/lib/crt1.o")
        with self.assertRaisesRegex(startup.EvidenceError, "link trace"):
            self.check()

    def test_receipt_for_different_output_bytes_is_rejected(self) -> None:
        self.receipt["output_sha256"] = "0" * 64
        with self.assertRaisesRegex(startup.EvidenceError, "does not bind the output"):
            self.check()


if __name__ == "__main__":
    unittest.main()
