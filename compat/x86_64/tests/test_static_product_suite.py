#!/usr/bin/env python3
"""Focused contracts for the owned static product suite roster and receipt reader."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
VALIDATOR_PATH = ROOT / "compat" / "x86_64" / "static_product_contract.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PRODUCT = load_module("static_product_suite_test", VALIDATOR_PATH)
WORK = "/workspace/.work/x86_64/tmp/crabc-x86-64-owned-static-sysroot.Ab12Cd"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StaticProductSuiteTests(unittest.TestCase):
    def contract(self) -> dict:
        return copy.deepcopy(PRODUCT.load_contract())

    def test_checked_in_contract_maps_every_obligation_to_executed_cases(self) -> None:
        summary = PRODUCT.validate_contract(self.contract())
        self.assertEqual(summary["status"], "implemented-unqualified")
        self.assertEqual(summary["coverage_obligations"], 9)
        paths = PRODUCT.declared_paths(self.contract())
        self.assertEqual(len(paths), 2 * summary["case_count"])
        # Every consumer runs in both static link modes.
        self.assertEqual(
            {path.split("/")[0].rsplit("-", 1)[-1] for path in paths} - {"exec", "pie"}, set()
        )

    def test_obligations_must_name_known_cases_and_every_case_must_support_one(self) -> None:
        contract = self.contract()
        contract["coverage"]["evidence"][0]["cases"] = ["no-such-case"]
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "unknown cases"):
            PRODUCT.validate_contract(contract)

        contract = self.contract()
        del contract["coverage"]["evidence"][-1]
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "exactly one ordered evidence entry"):
            PRODUCT.validate_contract(contract)

        contract = self.contract()
        for entry in contract["coverage"]["evidence"]:
            entry["cases"] = [case for case in entry["cases"] if case != "termination"] or ["tls-lifecycle"]
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "support no coverage obligation"):
            PRODUCT.validate_contract(contract)

    def test_suite_rejects_unlinked_probes_and_misrooted_or_duplicate_paths(self) -> None:
        contract = self.contract()
        contract["suite"]["case"][0]["probe"] = "compat/x86_64/owned_static_sysroot_package.py"
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "C source"):
            PRODUCT.validate_contract(contract)

        contract = self.contract()
        contract["suite"]["case"][0]["probe"] = "compat/x86_64/owned_quick_exit_probe.c"
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "not linked by the runner"):
            PRODUCT.validate_contract(contract)

        contract = self.contract()
        contract["suite"]["case"][1]["paths"] = ["static-pie/pthread", "static-pie/pthread-x"]
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "not rooted in its static-et-exec job"):
            PRODUCT.validate_contract(contract)

        contract = self.contract()
        contract["suite"]["case"][1]["paths"] = list(contract["suite"]["case"][0]["paths"])
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "duplicate static product evidence path"):
            PRODUCT.validate_contract(contract)

    def test_checked_in_status_cannot_claim_qualification(self) -> None:
        contract = self.contract()
        contract["status"] = "qualified"
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "implemented-unqualified"):
            PRODUCT.validate_contract(contract)

    def write_case(self, report: Path, product: str, mode: str, case_path: str, *,
                   trace_lines: list[str] | None = None, program_headers: str | None = None,
                   relocations: str | None = None) -> tuple[dict, dict]:
        """Write one well-formed retained case; overrides model defects."""
        entry = "crt1.o" if mode == "static-et-exec" else "rcrt1.o"
        pie = mode == "static-pie"
        tree = "primary" if product == "primary" else "extracted-tree/crabc-x86_64-owned-static-sysroot"
        lib = f"{WORK}/{tree}/usr/lib"
        consumer = f"{WORK}/{product}-consumer/{case_path}"
        files = {f"usr/lib/{name}": sha(name.encode()) for name in
                 (entry, "crti.o", "crtn.o", "libc.a", "libcrabc-builtins.a")}
        base = report / "cases" / product / case_path
        base.mkdir(parents=True)
        candidate = sha(b"candidate-" + case_path.encode())
        trace = trace_lines if trace_lines is not None else [
            f"{lib}/{entry}", f"{lib}/crti.o", f"{consumer}/probe.o", f"{consumer}/peer.o",
            f"{consumer}/builtins.o", f"{lib}/libc.a(c.c.0-cgu.0.rcgu.o)",
            f"{lib}/libcrabc-builtins.a(crabc-builtins.o)", f"{lib}/crtn.o",
        ]
        (base / "link.receipt.trace").write_text("\n".join(trace) + "\n", encoding="utf-8")
        link = {
            "format": "crabc-x86-64-sealed-static-driver-v1",
            "target": "x86_64-unknown-linux-musl",
            "output": {"path": "candidate", "sha256": candidate},
            "map": {"path": "link.receipt.map", "sha256": sha(b"map")},
            "trace": {"path": "link.receipt.trace",
                      "sha256": sha((base / "link.receipt.trace").read_bytes())},
            "mode": {"id": mode, "elf_type": "ET_DYN" if pie else "ET_EXEC", "crt_object": entry,
                     "interpreter": "absent"},
            "input_receipts": [
                {"role": role, "path": f"usr/lib/{name}", "sha256": files[f"usr/lib/{name}"]}
                for role, name in (("crt-entry", entry), ("crt-prologue", "crti.o"), ("libc", "libc.a"),
                                   ("builtins", "libcrabc-builtins.a"), ("crt-epilogue", "crtn.o"))
            ] + [{"role": "application", "path": f"{consumer}/{name}", "sha256": sha(name.encode())}
                 for name in ("probe.o", "peer.o", "builtins.o")],
        }
        (base / "link.receipt.json").write_text(json.dumps(link), encoding="utf-8")
        (base / "candidate.sha256").write_text(candidate + "\n", encoding="ascii")
        (base / "file-header").write_text(
            "  Type:                              " + ("DYN (Position-Independent Executable file)" if pie
                                                    else "EXEC (Executable file)")
            + "\n  Machine:                           Advanced Micro Devices X86-64\n", encoding="utf-8")
        (base / "program-headers").write_text(program_headers if program_headers is not None else (
            ("  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x000230 0x000230 R   0x8\n"
             if pie else "")
            + "  LOAD           0x000000 0x0000000000200000 0x0000000000200000 0x0012a8 0x0012a8 R   0x1000\n"
            "  TLS            0x002000 0x0000000000203000 0x0000000000203000 0x000010 0x001020 R   0x1000\n"
            "  GNU_RELRO      0x002000 0x0000000000203000 0x0000000000203000 0x000100 0x001000 R   0x1\n"
            "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x0\n"),
            encoding="utf-8")
        (base / "dynamic").write_text(
            " 0x000000006ffffffb (FLAGS_1)            Flags: PIE\n" if pie
            else "There is no dynamic section in this file.\n", encoding="utf-8")
        (base / "relocations").write_text(relocations if relocations is not None else (
            "0000000000203ff8  0000000000000008 R_X86_64_RELATIVE                         2011d0\n" if pie
            else "There are no relocations in this file.\n"), encoding="utf-8")
        observed = {"candidate": candidate, "link.receipt.map": sha(b"map"), "symbols": sha(b"symbols")}
        return observed, {"installed": {"files": files}}

    def inspect(self, product: str, mode: str, **defects) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            case_path = f"{'static-et-exec' if mode == 'static-et-exec' else 'static-pie'}/remote"
            observed, manifest = self.write_case(report, product, mode, case_path, **defects)
            PRODUCT.inspect_case(report, product, mode, case_path, observed, manifest)

    def test_reader_accepts_well_formed_cases_in_both_modes_and_products(self) -> None:
        for product in PRODUCT.PRODUCTS:
            for mode in PRODUCT.MODE_PATHS:
                self.inspect(product, mode)

    def test_reader_rejects_ambient_or_foreign_runtime_link_inputs(self) -> None:
        lib = f"{WORK}/primary/usr/lib"
        consumer = f"{WORK}/primary-consumer/static-et-exec/remote"
        base = [f"{lib}/crt1.o", f"{lib}/crti.o", f"{consumer}/probe.o", f"{consumer}/peer.o",
                f"{consumer}/builtins.o", f"{lib}/libcrabc-builtins.a(crabc-builtins.o)", f"{lib}/crtn.o"]
        for ambient in ("/opt/musl-1.2.6/lib/libc.a(printf.o)", "/usr/lib/libc.a(printf.o)",
                        "/usr/lib/gcc/x86_64-linux-gnu/13/libgcc.a(_udivti3.o)", "/lib/ld-musl-x86_64.so.1"):
            with self.assertRaisesRegex(PRODUCT.StaticProductError, "undeclared input"):
                self.inspect("primary", "static-et-exec", trace_lines=[*base, ambient])
        # The extracted product may not satisfy its link from the primary tree.
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "undeclared input"):
            self.inspect("extracted", "static-et-exec", trace_lines=base)
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "compiler-helper member"):
            self.inspect("primary", "static-et-exec", trace_lines=[line for line in base if "builtins.a" not in line])

    def test_reader_rejects_interpreter_executable_stack_and_nonrelative_relocations(self) -> None:
        interpreter = ("  INTERP         0x000200 0x0000000000200200 0x0000000000200200 0x00001c 0x00001c R   0x1\n"
                       "  TLS            0x002000 0x0000000000203000 0x0000000000203000 0x000010 0x001020 R   0x1000\n"
                       "  GNU_RELRO      0x002000 0x0000000000203000 0x0000000000203000 0x000100 0x001000 R   0x1\n"
                       "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x0\n")
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "interpreter"):
            self.inspect("primary", "static-et-exec", program_headers=interpreter)
        executable_stack = interpreter.splitlines(keepends=True)[1:]
        executable_stack[-1] = executable_stack[-1].replace(" RW  ", " RWE ")
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "executable stack"):
            self.inspect("primary", "static-et-exec", program_headers="".join(executable_stack))
        with self.assertRaisesRegex(PRODUCT.StaticProductError, "non-relative"):
            self.inspect("primary", "static-pie",
                         relocations="0000000000203ff8  0000000100000006 R_X86_64_GLOB_DAT  0 malloc + 0\n")

    def test_missing_or_stale_publication_does_not_qualify_the_product(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as temporary:
            pointer = Path(temporary) / "owned-static-qualification.json"
            with mock.patch.object(PRODUCT, "PUBLICATION", pointer):
                self.assertIsNone(PRODUCT.load_publication())
                self.assertEqual(PRODUCT.load_current_report()["status"], "implemented-unqualified")
                pointer.write_text(json.dumps({
                    "schema": PRODUCT.RECEIPT_SCHEMA, "receipt": "missing.json",
                    "receipt_sha256": "0" * 64, "source_revision": "0" * 40,
                }), encoding="utf-8")
                self.assertIsNone(PRODUCT.load_publication())
                pointer.write_text(json.dumps({"schema": PRODUCT.RECEIPT_SCHEMA}), encoding="utf-8")
                with self.assertRaisesRegex(PRODUCT.StaticProductError, "publication fields"):
                    PRODUCT.load_publication()


if __name__ == "__main__":
    unittest.main()
