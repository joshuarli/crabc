#!/usr/bin/env python3
"""Physical startup-errno receipts retain the complete executed matrix."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipt
from owned_mimalloc_startup_errno_receipt import read_startup_errno_receipt


RUNNER = "owned-mimalloc-startup-errno"
MODES = (
    "oracle-static", "oracle-dynamic", "static-static", "static-static-pie",
    "dynamic-pie-kernel", "dynamic-pie-direct",
    "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
)
PRODUCTS = (
    "input-startup-source", "input-success-source", "input-startup-object",
    "input-startup-dynamic-object",
    "input-success-object", "input-success-cases", "input-passwd", "input-group",
    "input-hosts", "input-data", "input-static-manifest",
    "input-dynamic-manifest", "input-static-libc-provenance",
    "input-dynamic-libc-provenance", "input-dynamic-loader-provenance",
    "input-static-libc", "input-dynamic-libc", "input-dynamic-loader",
    "link-static-static", "link-static-static-pie",
    "link-success-static-static", "link-success-static-static-pie",
)


class StartupErrnoReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for command in (("init", "-q"), ("config", "user.email", "t@example.invalid"),
                        ("config", "user.name", "t")):
            subprocess.run(("git", *command), cwd=self.root, check=True)
        (self.root / ".gitignore").write_text(".work/\n")
        (self.root / "source.c").write_text("int main(void) { return 0; }\n")
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-qm", "base"), cwd=self.root, check=True)
        self.work = self.root / ".work/x86_64/tmp/startup-errno"
        self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self, *, missing_case: str = "", differing_mode: str = "",
                static_dlopen: bool = False, mismatched_link: bool = False,
                shared_startup_object: bool = False) -> Path:
        products = {}
        for name in (*PRODUCTS, *(f"program-startup-{mode}" for mode in MODES),
                     *(f"program-success-{mode}" for mode in MODES)):
            path = self.work / name
            if name == "input-dynamic-libc-provenance":
                path.write_text(json.dumps({"allocator_backend": "native-shadow"}))
            elif name == "input-success-cases":
                path.write_text("malloc\ndlopen-libc\n" if static_dlopen else "malloc\n")
            else:
                contents = ("input-startup-object" if shared_startup_object
                            and name == "input-startup-dynamic-object" else
                            name.removesuffix("-kernel").removesuffix("-direct"))
                path.write_bytes(contents.encode())
            products[name] = path
        def digest(name: str) -> str:
            return hashlib.sha256(products[name].read_bytes()).hexdigest()
        products["input-static-manifest"].write_text(json.dumps({
            "allocator_backend": "native-shadow",
            "installed": {"files": {
                "usr/lib/libc.a": digest("input-static-libc"),
                "share/crabc/libc-static.provenance.json": digest("input-static-libc-provenance"),
            }},
        }))
        products["input-dynamic-manifest"].write_text(json.dumps({"files": {
            "usr/lib/libc.so": digest("input-dynamic-libc"),
            "lib/ld-crabc-x86_64.so.1": digest("input-dynamic-loader"),
            "share/crabc/libc-shared.provenance.json": digest("input-dynamic-libc-provenance"),
            "share/crabc/loader.provenance.json": digest("input-dynamic-loader-provenance"),
        }}))
        for mode in ("static", "static-pie"):
            for kind in ("startup", "success"):
                link = f"link-success-static-{mode}" if kind == "success" else f"link-static-{mode}"
                products[link].write_text(json.dumps({
                    "output": {"sha256": ("0" * 64 if mismatched_link and mode == "static" and kind == "startup"
                                           else digest(f"program-{kind}-static-{mode}"))},
                    "input_receipts": [
                        {"role": "application", "sha256": digest(f"input-{kind}-object")},
                        {"role": "libc", "sha256": digest("input-static-libc")},
                    ],
                }))
        cases = []
        for mode in MODES:
            status = self.work / f"{mode}.status"
            stdout = self.work / f"{mode}.stdout"
            stderr = self.work / f"{mode}.stderr"
            status.write_text("0\n")
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            startup_id = f"startup-{mode}"
            if startup_id != missing_case:
                cases.append((startup_id, 0, (status, stdout, stderr)))
            transcript = self.work / f"success-{mode}.transcript"
            measured = (
                "malloc first status=0\nerrno=79\nmalloc later status=0\nerrno=79\n"
                if mode != differing_mode else
                "malloc first status=0\nerrno=80\nmalloc later status=0\nerrno=79\n"
            )
            if static_dlopen:
                if mode == "oracle-static" or mode.startswith("static-"):
                    measured += "dlopen-libc first status=100\ndlopen-libc later status=100\n"
                else:
                    measured += ("dlopen-libc first status=0\nerrno=79\n"
                                 "dlopen-libc later status=0\nerrno=79\n")
            transcript.write_text(measured)
            success_id = f"success-{mode}"
            if success_id != missing_case:
                cases.append((success_id, 0, (transcript,)))
        return receipt.write_receipt(
            self.root, RUNNER, self.work, products, cases,
            {"STATIC_BACKEND": "native-shadow", "DYNAMIC_BACKEND": "native-shadow",
             "STATIC_SUPPLIED": "yes", "DYNAMIC_SUPPLIED": "yes"}, True,
        )

    def test_complete_receipt_is_rereadable(self) -> None:
        self.publish()
        self.assertEqual(len(read_startup_errno_receipt(self.root).cases), 16)

    def test_static_and_dynamic_startup_require_distinct_application_objects(self) -> None:
        self.publish(shared_startup_object=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "share one application object"):
            read_startup_errno_receipt(self.root)

    def test_pinned_static_dlopen_failure_is_retained_and_compared(self) -> None:
        self.publish(static_dlopen=True)
        self.assertEqual(len(read_startup_errno_receipt(self.root).cases), 16)

    def test_missing_mode_evidence_is_rejected(self) -> None:
        self.publish(missing_case="startup-dynamic-non-pie-direct")
        with self.assertRaisesRegex(receipt.ReceiptError, "missing|cases"):
            read_startup_errno_receipt(self.root)

    def test_tampered_transcript_or_executed_program_is_rejected(self) -> None:
        path = self.publish()
        (path.parent / "logs/success-dynamic-pie-direct.transcript").write_text("changed\n")
        with self.assertRaises(receipt.ReceiptError):
            read_startup_errno_receipt(self.root)
        self.publish()
        (path.parent / "products/program-startup-static-static").write_bytes(b"changed")
        with self.assertRaises(receipt.ReceiptError):
            read_startup_errno_receipt(self.root)

    def test_rehashed_but_mismatched_candidate_transcript_is_rejected(self) -> None:
        self.publish(differing_mode="dynamic-pie-kernel")
        with self.assertRaisesRegex(receipt.ReceiptError, "differs|transcript"):
            read_startup_errno_receipt(self.root)

    def test_missing_input_identity_is_rejected(self) -> None:
        path = self.publish()
        record = json.loads(path.read_text())
        del record["products"]["input-dynamic-manifest"]
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(receipt.ReceiptError, "missing|products"):
            read_startup_errno_receipt(self.root)

    def test_rehashed_link_receipt_must_name_the_executed_program(self) -> None:
        self.publish(mismatched_link=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "executed program"):
            read_startup_errno_receipt(self.root)


if __name__ == "__main__":
    unittest.main()
