#!/usr/bin/env python3
"""Tamper tests for one owned POSIX product link-evidence boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat" / "x86_64" / "owned_posix_product_evidence.py"
SPEC = importlib.util.spec_from_file_location("owned_posix_product_evidence_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwnedPosixProductEvidenceTests(unittest.TestCase):
    """Use files with injected ELF inspections; this is not a native build test."""

    def setUp(self) -> None:
        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="owned-posix-product-evidence.", dir=temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workload = self.put("workload.o", b"one owned workload object\n")
        self.executable = self.put("consumer", b"owned executable bytes\n")
        self.linker = self.put("tools/ld.lld", b"sealed linker bytes\n")
        self.static = self.install_static()
        self.dynamic = self.install_dynamic()

    def put(self, relative: str, payload: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def payload_manifest(self, product: Path) -> dict[str, str]:
        return {
            path.relative_to(product).as_posix(): digest(path)
            for path in sorted(product.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def install_static(self) -> Path:
        product = self.root / "static-product"
        for relative in (
            "bin/crabc-cc",
            "usr/include/fixture.h",
            "usr/lib/crt1.o",
            "usr/lib/Scrt1.o",
            "usr/lib/rcrt1.o",
            "usr/lib/crti.o",
            "usr/lib/crtn.o",
            "usr/lib/libc.a",
            "usr/lib/libcrabc-builtins.a",
        ):
            self.put(str(product.relative_to(self.root) / relative), relative.encode())
        os.chmod(product / "bin/crabc-cc", 0o755)
        manifest = {
            "schema": 1,
            "format": "crabc-x86-64-owned-static-sysroot-v1",
            "target": "x86_64-unknown-linux-musl",
            "installed": {
                "headers": "usr/include",
                "crt_objects": [
                    "usr/lib/crt1.o", "usr/lib/Scrt1.o", "usr/lib/rcrt1.o",
                    "usr/lib/crti.o", "usr/lib/crtn.o",
                ],
                "static_libc": "usr/lib/libc.a",
                "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
                "sealed_static_driver": "bin/crabc-cc",
                "files": self.payload_manifest(product),
            },
            "sealed_static_driver": {
                "format": "crabc-x86-64-sealed-static-driver-v1",
                "path": "bin/crabc-cc",
                "status": "planned-owned-static-product-seed-not-family-completion-not-public-support",
                "modes": [
                    {"id": "static-et-exec", "elf_type": "ET_EXEC", "crt_object": "crt1.o"},
                    {"id": "static-pie", "elf_type": "ET_DYN", "crt_object": "rcrt1.o"},
                ],
            },
        }
        self.write_json(product / "share/crabc/manifest.json", manifest)
        return product

    def install_dynamic(self) -> Path:
        product = self.root / "dynamic-product"
        for relative in (
            "bin/crabc-cc-dynamic",
            "share/crabc/crabc_cc_static.py",
            "share/crabc/dynamic-product-state.json",
            "usr/include/fixture.h",
            "lib/ld-crabc-x86_64.so.1",
            "usr/lib/crt1.o",
            "usr/lib/Scrt1.o",
            "usr/lib/crti.o",
            "usr/lib/crtn.o",
            "usr/lib/crabc-dynamic-attach.o",
            "usr/lib/libc.so",
            "usr/lib/libcrabc-builtins.a",
        ):
            self.put(str(product.relative_to(self.root) / relative), relative.encode())
        os.chmod(product / "bin/crabc-cc-dynamic", 0o755)
        os.chmod(product / "lib/ld-crabc-x86_64.so.1", 0o755)
        alias = product / "lib/ld-musl-x86_64.so.1"
        alias.symlink_to("ld-crabc-x86_64.so.1")
        manifest = {
            "schema": 1,
            "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "target": "x86_64-unknown-linux-musl",
            "files": self.payload_manifest(product),
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
        }
        self.write_json(product / "share/crabc/manifest.json", manifest)
        return product

    def refresh_dynamic_manifest(self) -> None:
        manifest_path = self.dynamic / "share/crabc/manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"] = {
            relative: value
            for relative, value in self.payload_manifest(self.dynamic).items()
            if relative != "share/crabc/manifest.json"
        }
        self.write_json(manifest_path, manifest)

    def static_receipt(self, linkage: str = "static") -> Path:
        mode = {
            "static": ("static-et-exec", "ET_EXEC", "crt1.o"),
            "static-pie": ("static-pie", "ET_DYN", "rcrt1.o"),
        }[linkage]
        receipt = self.root / f"{linkage}.receipt.json"
        map_path = receipt.with_suffix(".map")
        trace_path = receipt.with_suffix(".trace")
        map_path.write_bytes(b"owned link map\n")
        runtime = self.static / "usr/lib"
        trace_path.write_text(
            "\n".join(
                (
                    str(runtime / mode[2]),
                    str(runtime / "crti.o"),
                    str(self.workload),
                    str(runtime / "libc.a") + "(selected.o)",
                    str(runtime / "libcrabc-builtins.a") + "(builtins.o)",
                    str(runtime / "crtn.o"),
                )
            ) + "\n",
            encoding="utf-8",
        )
        records = [
            ("crt-entry", runtime / mode[2]),
            ("crt-prologue", runtime / "crti.o"),
            ("libc", runtime / "libc.a"),
            ("builtins", runtime / "libcrabc-builtins.a"),
            ("crt-epilogue", runtime / "crtn.o"),
            ("application", self.workload),
        ]
        self.write_json(receipt, {
            "schema": 1,
            "format": "crabc-x86-64-sealed-static-driver-v1",
            "target": "x86_64-unknown-linux-musl",
            "mode": {"id": mode[0], "elf_type": mode[1], "crt_object": mode[2], "interpreter": "absent"},
            "resolved_linker": {"path": str(self.linker), "sha256": digest(self.linker)},
            "owned_link_contract": self.static_plan(mode[2], linkage == "static-pie"),
            "input_receipts": [
                {"role": role, "path": path.relative_to(self.static).as_posix() if role != "application" else str(path), "sha256": digest(path)}
                for role, path in records
            ],
            "output": {"path": str(self.executable), "sha256": digest(self.executable)},
            "map": {"path": str(map_path), "sha256": digest(map_path)},
            "trace": {"path": str(trace_path), "sha256": digest(trace_path)},
        })
        return receipt

    def static_plan(self, crt: str, pie: bool) -> list[str]:
        library = self.static / "usr/lib"
        return [
            "ld.lld", "-static", *( ["-pie"] if pie else []), "--no-dynamic-linker",
            "--no-undefined", "--gc-sections", "-z", "relro", "-z", "now", "-e", "_start",
            str(library / crt), str(library / "crti.o"), "<application-objects>",
            str(library / "libc.a"), str(library / "libcrabc-builtins.a"),
            str(library / "crtn.o"), "-o", "<output>",
        ]

    def dynamic_receipt(self, linkage: str = "pie") -> Path:
        mode, entry = {"pie": ("pie", "Scrt1.o"), "non-pie": ("exec", "crt1.o")}[linkage]
        receipt = self.root / f"{linkage}.crabc-link.json"
        runtime = self.dynamic / "usr/lib"
        direct = [
            runtime / "crti.o", runtime / "libc.so", runtime / "crtn.o",
            runtime / entry, runtime / "crabc-dynamic-attach.o",
        ]
        inputs = [*direct, self.workload, runtime / "libcrabc-builtins.a"]
        link = [
            str(self.linker), *( ["-pie"] if linkage == "pie" else []), "--hash-style=sysv",
            "-z", "relro", "-z", "now", "-z", "noexecstack", "-z", "text", "--no-undefined",
            "--allow-shlib-undefined", "--enable-new-dtags", "-rpath", "/usr/lib",
            "--dynamic-linker", "/lib/ld-crabc-x86_64.so.1", str(runtime / entry),
            str(runtime / "crabc-dynamic-attach.o"), str(runtime / "crti.o"), str(self.workload),
            str(runtime / "libc.so"), str(runtime / "libcrabc-builtins.a"), str(runtime / "crtn.o"),
            "-o", str(self.executable),
        ]
        manifest = self.dynamic / "share/crabc/manifest.json"
        self.write_json(receipt, {
            "schema": 1,
            "format": "crabc-x86-64-owned-dynamic-sysroot-v1",
            "mode": mode,
            "binding": "now",
            "runtime_imports": [],
            "application_runpath": "/usr/lib",
            "output_path": str(self.executable),
            "output_sha256": digest(self.executable),
            "manifest_sha256": digest(manifest),
            "application_dsos": {},
            "owned_runtime_inputs": sorted(path.relative_to(self.dynamic).as_posix() for path in [*direct, runtime / "libcrabc-builtins.a"]),
            "input_receipts": [{"path": str(path), "sha256": digest(path)} for path in inputs],
            "resolved_linker": {"path": str(self.linker), "sha256": digest(self.linker)},
            "link_command": link,
            "link_trace": [str(path) for path in [runtime / entry, runtime / "crabc-dynamic-attach.o", runtime / "crti.o", self.workload, runtime / "libc.so", runtime / "crtn.o"]],
            "campaign_complete": False,
        })
        return receipt

    @staticmethod
    def readelf(linkage: str) -> dict[str, str]:
        dynamic = linkage in {"pie", "non-pie"}
        return {
            "header": "  Machine:                           Advanced Micro Devices X86-64\n"
                      + ("  Type:                              DYN (Position-Independent Executable file)\n" if linkage in {"static-pie", "pie"} else "  Type:                              EXEC (Executable file)\n"),
            "program": ("  INTERP         0x000000 0x0000000000000000\n"
                        "      [Requesting program interpreter: /lib/ld-crabc-x86_64.so.1]\n") if dynamic else "",
            "dynamic": " 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n 0x000000000000001d (RUNPATH)            Library runpath: [/usr/lib]\n" if dynamic else "",
        }

    def validate(self, linkage: str, receipt: Path | None = None) -> dict[str, str]:
        product = self.static if linkage in {"static", "static-pie"} else self.dynamic
        if receipt is None:
            receipt = self.static_receipt(linkage) if linkage in {"static", "static-pie"} else self.dynamic_receipt(linkage)
        with mock.patch.object(evidence, "_readelf", return_value=self.readelf(linkage)):
            return evidence.validate_link(product, self.workload, self.executable, receipt, linkage)

    def test_accepts_each_sealed_linkage_and_returns_bound_identity(self) -> None:
        for linkage in ("static", "static-pie", "pie", "non-pie"):
            with self.subTest(linkage=linkage):
                identity = self.validate(linkage)
                self.assertEqual(identity["linkage"], linkage)
                self.assertEqual(identity["workload_sha256"], digest(self.workload))
                self.assertEqual(identity["executable_sha256"], digest(self.executable))

    def test_tampered_workload_object_fails(self) -> None:
        receipt = self.dynamic_receipt()
        self.workload.write_bytes(b"changed object\n")
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "workload|application"):
            self.validate("pie", receipt)

    def test_foreign_runtime_roster_fails(self) -> None:
        receipt = self.dynamic_receipt()
        record = json.loads(receipt.read_text(encoding="utf-8"))
        foreign = self.dynamic / "usr/lib/libforeign.so"
        foreign.write_bytes(b"foreign runtime\n")
        self.refresh_dynamic_manifest()
        manifest = self.dynamic / "share/crabc/manifest.json"
        record["manifest_sha256"] = digest(manifest)
        record["owned_runtime_inputs"].append("usr/lib/libforeign.so")
        self.write_json(receipt, record)
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "runtime roster"):
            self.validate("pie", receipt)

    def test_stale_runtime_and_manifest_fail(self) -> None:
        receipt = self.dynamic_receipt()
        (self.dynamic / "usr/lib/libc.so").write_bytes(b"new owned libc\n")
        self.refresh_dynamic_manifest()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "manifest hash|runtime input"):
            self.validate("pie", receipt)

    def test_tampered_output_fails(self) -> None:
        receipt = self.static_receipt()
        self.executable.write_bytes(b"different executable\n")
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "output"):
            self.validate("static", receipt)

    def test_linkage_mode_mismatch_fails(self) -> None:
        receipt = self.static_receipt()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "mode"):
            self.validate("static-pie", receipt)

    def test_missing_receipt_fails(self) -> None:
        receipt = self.dynamic_receipt()
        receipt.unlink()
        with self.assertRaisesRegex(evidence.ProductEvidenceError, "receipt"):
            self.validate("pie", receipt)

    def test_foreign_dynamic_needed_entry_fails(self) -> None:
        receipt = self.dynamic_receipt()
        elf = self.readelf("pie")
        elf["dynamic"] = elf["dynamic"].replace(
            "Shared library: [libc.so]", "Shared library: [libforeign.so]"
        )
        with mock.patch.object(evidence, "_readelf", return_value=elf):
            with self.assertRaisesRegex(evidence.ProductEvidenceError, "DT_NEEDED"):
                evidence.validate_link(self.dynamic, self.workload, self.executable, receipt, "pie")


if __name__ == "__main__":
    unittest.main()
