"""Installed POSIX timer runner product and callback-loaded TLS boundaries."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
import json
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
DOCUMENT = ROOT / "compat/x86_64/owned-posix-timers.md"
RUNNER = ROOT / "compat/x86_64/run_owned_posix_timers.sh"

sys.path.insert(0, str(ROOT / "compat" / "x86_64"))
import owned_posix_timers_evidence as timer_evidence
from owned_posix_timers_evidence import (
    TIMER_TLS_AUDIT_SCHEMA,
    TIMER_WORKLOAD_COMPILE_AUDIT_SCHEMA,
    _write_record,
)
from owned_posix_product_evidence import DYNAMIC_PRODUCT_FORMAT


class OwnedPosixTimersTests(unittest.TestCase):
    def test_tls_dso_elf_audit_accepts_the_sealed_shared_shape(self):
        header = "  Type:                              DYN (Shared object file)\n  Machine:                           Advanced Micro Devices X86-64\n"
        program = "  Type           Offset             VirtAddr\n  LOAD           0x0000000000000000\n"
        dynamic = " 0x000000000000001d (RUNPATH)            Library runpath: [/usr/lib]\n 0x0000000000000001 (NEEDED)             Shared library: [libc.so]\n 0x000000000000000e (SONAME)             Library soname: [libtimer-tls.so]\n"
        with patch.object(timer_evidence, "_readelf", side_effect=(header, program, dynamic)):
            self.assertEqual(
                timer_evidence._validate_tls_elf(Path("libtimer-tls.so")),
                ("libtimer-tls.so", ["libc.so"]),
            )

    def test_compile_audit_writer_emits_one_json_document(self):
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-posix-timers-audit.", dir=scratch_root
        ) as temporary:
            record = Path(temporary) / "compile-audit.json"
            _write_record(record, {"schema": "test"})
            self.assertEqual(json.loads(record.read_text(encoding="utf-8")), {"schema": "test"})
            self.assertTrue(record.read_bytes().endswith(b"\n"))

    def assert_parser_usage(self, *arguments: str) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-posix-timers-parser.", dir=scratch_root
        ) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                ["bash", str(RUNNER), *arguments],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_parser_rejects_ambiguous_or_incomplete_product_matrix_before_producers(self):
        for arguments in (
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "--dynamic"),
            ("--unexpected",),
            ("first", "second"),
            ("--static-sysroot", "one", "--static-sysroot", "two"),
        ):
            with self.subTest(arguments=arguments):
                self.assert_parser_usage(*arguments)

    def test_callback_loaded_dso_receipt_is_source_bound_and_separate_from_application_links(self):
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")

        self.assertEqual(
            TIMER_TLS_AUDIT_SCHEMA,
            "crabc.x86_64-owned-posix-timers-tls-dso/v1",
        )
        self.assertEqual(
            TIMER_WORKLOAD_COMPILE_AUDIT_SCHEMA,
            "crabc.x86_64-owned-posix-timers-compile/v1",
        )
        self.assertEqual(
            DYNAMIC_PRODUCT_FORMAT,
            "crabc-x86-64-owned-dynamic-sysroot-v1",
        )
        self.assertEqual(timer_evidence.DYNAMIC_PRODUCT_FORMAT, DYNAMIC_PRODUCT_FORMAT)
        audit = (ROOT / "compat/x86_64/owned_posix_timers_evidence.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("_validate_dynamic_product", audit)
        self.assertNotIn("DYNAMIC_PRODUCT_FORMAT =", audit)
        for required in (
            "--static-sysroot STATIC_SYSROOT",
            "static_was_supplied=0",
            "dynamic_was_supplied=0",
            '"$static_product/bin/crabc-cc" "-$mode" --link-receipt',
            "validate_timer_tls_dso",
            "validate_link",
            "record_compile_audit",
            "run_capture",
            ".stderr",
            ".status",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--application-dso", runner)
        self.assertIn("callback-time", document)
        self.assertIn("initial `DT_NEEDED`", document)
        self.assertIn("shared-mode receipt", document)

    def test_supplied_product_rejects_physical_escape_before_compilation(self):
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            scratch = Path(temporary)
            escaped = scratch / "product"
            escaped.symlink_to(ROOT, target_is_directory=True)
            for product in (ROOT, escaped):
                with self.subTest(product=product):
                    result = subprocess.run(
                        ["bash", str(RUNNER), str(product)],
                        env={**os.environ, "TMPDIR": str(scratch)},
                        text=True, capture_output=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("product must be a physical checkout .work directory", result.stderr)
                    self.assertNotIn("evidence:", result.stdout)

    def test_installed_driver_compiles_shared_objects_before_runtime_links(self):
        source = RUNNER.read_text()
        probe_compile = '"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -c "$probe" -o "$work/probe.o"'
        tls_compile = '"$installed/bin/crabc-cc-dynamic" -shared -std=c11 -c "$tls_source" -o "$work/tls.o"'
        self.assertIn(probe_compile, source)
        self.assertIn(tls_compile, source)
        self.assertLess(source.index('scripts/build_x86_64_owned_dynamic_sysroot.py'), source.index(probe_compile))
        self.assertLess(source.index(probe_compile), source.index('"$oracle_cc" -pthread "$work/probe.o"'))
        self.assertLess(source.index(tls_compile), source.index('"$oracle_cc" -shared "$work/tls.o"'))
        self.assertNotIn('-I"$ROOT/include"', source)


if __name__ == "__main__":
    unittest.main()
