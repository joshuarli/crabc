"""Installed POSIX timer runner product and callback-loaded TLS boundaries."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
import json
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
DOCUMENT = ROOT / "compat/x86_64/owned-posix-timers.md"
RUNNER = ROOT / "compat/x86_64/run_owned_posix_timers.sh"

sys.path.insert(0, str(ROOT / "compat" / "x86_64"))
import owned_posix_timers_evidence as timer_evidence
from owned_posix_timers_evidence import (
    TIMER_APPLICATION_AUDIT_SCHEMA,
    TIMER_TLS_AUDIT_SCHEMA,
    TIMER_WORKLOAD_COMPILE_AUDIT_SCHEMA,
    _write_record,
)
from owned_posix_product_evidence import DYNAMIC_PRODUCT_FORMAT


class OwnedPosixTimersTests(unittest.TestCase):
    def compile_audit_fixture(self, temporary: Path):
        product = temporary / "product"
        headers = product / "usr/include"
        headers.mkdir(parents=True)
        header = headers / "timer.h"
        header.write_text("/* installed timer header */\n", encoding="utf-8")
        source = temporary / "timer.c"
        source.write_text("#include <timer.h>\n", encoding="utf-8")
        object_path = temporary / "timer.o"
        object_path.write_bytes(b"timer object")
        driver = product / "bin/crabc-cc-dynamic"
        driver.parent.mkdir(parents=True)
        driver.write_text("#!/bin/sh\n", encoding="utf-8")
        driver.chmod(0o755)
        manifest = product / "share/crabc/manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}\n", encoding="utf-8")
        (manifest.parent / "crabc_cc_static.py").write_text("# installed compiler policy\n", encoding="utf-8")
        trace = temporary / "timer.headers"
        trace.write_text(f". {header}\n", encoding="utf-8")
        audit = temporary / "timer.compile-audit.json"
        command = [str(driver), "--dynamic-pie", "-std=c11", "-c", str(source), "-o", str(object_path)]
        return product, manifest, driver, header, source, object_path, trace, audit, command

    def record_compile_audit(self, fixture, *, role="application"):
        product, manifest, driver, header, source, object_path, _trace, audit, _command = fixture
        if role == "timer-tls-dso":
            source.write_text("static _Thread_local int value;\n", encoding="utf-8")
            header_paths = []
            trace_paths = []
        else:
            header_paths = [header]
            trace_paths = [header]
        policy = SimpleNamespace(compiler=lambda: "/usr/bin/gcc", clean_environment=lambda: {"PATH": "/usr/bin:/bin"})
        seen = []
        def dependency(command, *, stdin, stdout, stderr, env, check):
            seen.append((command, env))
            stdout.write(("timer.o: " + " ".join(str(path) for path in [source, *header_paths]) + "\n").encode())
            stderr.write("".join(f". {path}\n" for path in trace_paths).encode())
            return SimpleNamespace(returncode=0)
        with patch.object(timer_evidence, "_dynamic_product", return_value=(product, manifest, driver)), \
             patch.object(timer_evidence, "_installed_compiler", return_value=policy), \
             patch.object(timer_evidence.subprocess, "run", side_effect=dependency):
            record = timer_evidence.record_compile_audit(product, role, source, object_path, driver, audit)
        _write_record(audit, record)
        return record, seen, policy

    def test_compile_audit_revalidates_source_installed_header_and_driver_before_retention(self):
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            fixture = self.compile_audit_fixture(Path(temporary))
            product, manifest, driver, header, source, object_path, _trace, audit, _command = fixture
            _record, _seen, policy = self.record_compile_audit(fixture)
            with patch.object(timer_evidence, "_dynamic_product", return_value=(product, manifest, driver)), \
                 patch.object(timer_evidence, "_installed_compiler", return_value=policy):
                identity = timer_evidence.validate_timer_application_compile(
                    product, source, object_path, audit,
                )
                self.assertEqual(identity["schema"], TIMER_APPLICATION_AUDIT_SCHEMA)
                self.assertEqual(identity["object_sha256"], timer_evidence._sha256(object_path))
                for path in (source, header, driver):
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed")
                    with self.subTest(path=path), self.assertRaises(timer_evidence.TimerEvidenceError):
                        timer_evidence.validate_timer_application_compile(
                            product, source, object_path, audit,
                        )
                    path.write_bytes(original)

    def test_compile_audit_rejects_empty_relative_and_unowned_header_trace_entries(self):
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            fixture = self.compile_audit_fixture(Path(temporary))
            product, _manifest, _driver, header, source, _object_path, trace, _audit, _command = fixture
            trace.write_text(
                f". {header}\nMultiple include guards may be useful for:\n{header}\n",
                encoding="utf-8",
            )
            self.assertEqual(len(timer_evidence._headers(trace, product, require_installed=True)), 2)
            for text in ("", ". relative.h\n", "not a header trace\n", f". {source}\n"):
                trace.write_text(text, encoding="utf-8")
                with self.subTest(text=text), self.assertRaises(timer_evidence.TimerEvidenceError):
                    timer_evidence._headers(trace, product, require_installed=True)

    def test_compile_audit_uses_the_installed_driver_compiler_and_exact_mode_flags(self):
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            fixture = self.compile_audit_fixture(Path(temporary))
            product, _manifest, _driver, _header, source, _object_path, _trace, _audit, _command = fixture
            record, seen, _policy = self.record_compile_audit(fixture)
            self.assertEqual(len(seen), 1)
            command, environment = seen[0]
            self.assertEqual(command, record["dependency_command"])
            self.assertEqual(environment, {"PATH": "/usr/bin:/bin"})
            self.assertEqual(
                command,
                ["/usr/bin/gcc", "-nostdinc", "-isystem", str(product / "usr/include"),
                 "-ffreestanding", "-fno-builtin", "-fstack-protector-strong", "-std=c11",
                 "-fPIE", "-M", "-H", str(source)],
            )
            self.assertEqual(record["compiler"]["path"], str(Path("/usr/bin/gcc").resolve()))
            self.assertEqual(record["compiler_helper"]["path"], str(product / "share/crabc/crabc_cc_static.py"))

    def test_shared_receipt_metadata_rejects_python_equal_wrong_json_types(self):
        record = {
            "schema": 1,
            "format": DYNAMIC_PRODUCT_FORMAT,
            "mode": "shared",
            "binding": "now",
            "runtime_imports": [],
            "application_runpath": "/usr/lib",
            "application_dsos": {},
            "campaign_complete": False,
        }
        timer_evidence._validate_shared_metadata(record)
        for field, value in (("schema", True), ("schema", 1.0), ("campaign_complete", 0), ("campaign_complete", 0.0)):
            changed = {**record, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(timer_evidence.TimerEvidenceError):
                timer_evidence._validate_shared_metadata(changed)

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
            "crabc.x86_64-owned-posix-timers-compile/v2",
        )
        self.assertEqual(
            TIMER_APPLICATION_AUDIT_SCHEMA,
            "crabc.x86_64-owned-posix-timers-application/v1",
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
            "validate_timer_application_compile",
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
