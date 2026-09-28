#!/usr/bin/env python3
"""Retained policy evidence must reconstruct the executed musl comparison."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import native_shadow_receipt as receipt
import owned_native_allocator_policy_receipt as policy


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf(kind: int, interpreter: str | None = None) -> bytes:
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, kind, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    if interpreter:
        encoded = interpreter.encode() + b"\0"
        struct.pack_into("<I", data, 64, 3)
        struct.pack_into("<Q", data, 72, 128)
        struct.pack_into("<Q", data, 96, len(encoded))
        data[128:128 + len(encoded)] = encoded
    return bytes(data)


class PolicyReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for command in (("init", "-q"), ("config", "user.email", "t@example.invalid"),
                        ("config", "user.name", "t")):
            subprocess.run(("git", *command), cwd=self.root, check=True)
        (self.root / ".gitignore").write_text(".work/\n")
        (self.root / "source.c").write_text("int main(void) { return 0; }\n")
        upstream = self.root / "crabc-mimalloc/UPSTREAM.md"
        upstream.parent.mkdir()
        upstream.write_text("fixed upstream allocator\n")
        subprocess.run(("git", "add", "."), cwd=self.root, check=True)
        subprocess.run(("git", "commit", "-qm", "base"), cwd=self.root, check=True)
        self.work = self.root / ".work/x86_64/tmp/policy"
        self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self, *, missing_case: str = "", missing_product: str = "",
                differing_mode: str = "", stderr_mode: str = "",
                bad_archive: bool = False,
                wrong_elf_mode: bool = False) -> Path:
        files: dict[str, Path] = {}

        def product(name: str, data: bytes) -> None:
            path = self.work / name
            path.write_bytes(data)
            files[name] = path

        product("static-libc-archive", b"archive")
        product("dynamic-libc", b"shared-libc")
        product("dynamic-loader", b"loader")
        upstream_hash = digest(self.root / "crabc-mimalloc/UPSTREAM.md")
        product("static-libc-provenance", json.dumps({
            "archive": {"sha256": "0" * 64 if bad_archive else digest(files["static-libc-archive"])},
            "allocator_backend": {"upstream_sha256": upstream_hash},
        }).encode())
        product("dynamic-libc-provenance", json.dumps({
            "allocator_backend": "native-shadow",
            "native_allocator": {"path": "crabc-mimalloc/UPSTREAM.md", "sha256": upstream_hash},
        }).encode())
        product("static-manifest", json.dumps({
            "allocator_backend": "native-shadow", "installed": {"files": {
                "usr/lib/libc.a": digest(files["static-libc-archive"]),
                "share/crabc/libc-static.provenance.json": digest(files["static-libc-provenance"]),
            }},
        }).encode())
        dynamic_files = {
            "usr/lib/libc.so": digest(files["dynamic-libc"]),
            "lib/ld-crabc-x86_64.so.1": digest(files["dynamic-loader"]),
            "share/crabc/libc-shared.provenance.json": digest(files["dynamic-libc-provenance"]),
        }
        product("dynamic-product-state", json.dumps({
            "schema": "crabc.x86_64-owned-dynamic-materialization/v1",
            "allocator_backend": "native-shadow",
            "modes": ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
            "payload_files": dynamic_files,
        }).encode())
        product("dynamic-manifest", json.dumps({"files": dynamic_files | {
            "share/crabc/dynamic-product-state.json": digest(files["dynamic-product-state"]),
        }}).encode())
        for program in policy.PROGRAMS:
            product(f"oracle-{program}", elf(2))
            product(f"static-{program}", elf(2))
            product(f"static-pie-{program}", elf(2 if wrong_elf_mode else 3))
            for kind in ("pie", "non-pie"):
                product(f"dynamic-{kind}-{program}", elf(3 if kind == "pie" else 2,
                                                        "/lib/ld-crabc-x86_64.so.1"))
        cases = []
        for program in policy.PROGRAMS:
            for mode in policy.MODES:
                name = f"{mode}-{program}"
                stdout = self.work / f"{name}.stdout"
                stderr = self.work / f"{name}.stderr"
                status = self.work / f"{name}.status"
                stdout.write_bytes((b"" if program == "observability" else b"policy=" + program.encode() + b"\n") +
                                   (b"wrong\n" if name == differing_mode else b""))
                stderr.write_bytes(b"unexpected\n" if name == stderr_mode else b"")
                status.write_bytes(b"0\n")
                if name != missing_case:
                    cases.append((name, 0, (stdout, stderr, status)))
        runner = self.work / "runner.status"
        runner.write_bytes(b"0\n")
        cases.append(("runner", 0, (runner,)))
        if missing_product:
            del files[missing_product]
        return receipt.write_receipt(self.root, policy.RUNNER, self.work, files, cases,
                                     policy.PARAMETERS, True)

    def read(self) -> receipt.Receipt:
        with mock.patch.object(policy.owned_dynamic_elf, "inspect", return_value={
            "needed": ["libc.so"], "symbol_versioning": False,
        }):
            return policy.read_policy_receipt(self.root)

    def test_shared_reader_accepts_an_incomplete_policy_matrix(self) -> None:
        self.publish(missing_case="direct-non-pie-policy")
        self.assertEqual(len(receipt.read_receipt(self.root, policy.RUNNER).cases), 21)
        with self.assertRaisesRegex(receipt.ReceiptError, "22-case matrix"):
            self.read()

    def test_complete_matrix_survives_work_cleanup(self) -> None:
        self.publish()
        shutil.rmtree(self.work)
        self.assertEqual(len(self.read().cases), 22)

    def test_rehashed_wrong_candidate_transcript_is_rejected(self) -> None:
        self.publish(differing_mode="direct-pie-basic")
        receipt.read_receipt(self.root, policy.RUNNER)
        with self.assertRaisesRegex(receipt.ReceiptError, "differs from pinned musl"):
            self.read()

    def test_missing_executed_product_is_rejected(self) -> None:
        self.publish(missing_product="dynamic-non-pie-policy")
        with self.assertRaisesRegex(receipt.ReceiptError, "executed products"):
            self.read()

    def test_rehashed_wrong_provenance_is_rejected(self) -> None:
        self.publish(bad_archive=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "provenance"):
            self.read()

    def test_stderr_and_elf_mode_are_checked(self) -> None:
        self.publish(stderr_mode="kernel-pie-policy")
        with self.assertRaisesRegex(receipt.ReceiptError, "wrote stderr"):
            self.read()
        self.publish(wrong_elf_mode=True)
        with self.assertRaisesRegex(receipt.ReceiptError, "static ELF link mode"):
            self.read()

    def test_wrong_dynamic_linkage_is_rejected(self) -> None:
        self.publish()
        with mock.patch.object(policy.owned_dynamic_elf, "inspect", return_value={
            "needed": ["libc.so.6"], "symbol_versioning": False,
        }):
            with self.assertRaisesRegex(receipt.ReceiptError, "dynamic libc linkage"):
                policy.read_policy_receipt(self.root)


if __name__ == "__main__":
    unittest.main()
