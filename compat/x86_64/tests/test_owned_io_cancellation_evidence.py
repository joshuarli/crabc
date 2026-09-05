"""The whole I/O cancellation case binds ten objects and every raw result."""

import os
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/x86_64"))
import owned_io_cancellation_evidence as evidence

RUNNER = ROOT / "compat/x86_64/run_owned_dynamic_io_cancellation.sh"
ROSTER = ROOT / "compat/x86_64/owned_io_cancellation_fixtures.sh"
PROBES = (
    "owned_io_cancellation", "owned_descriptor_cancellation", "owned_socket_cancellation",
    "owned_sleep_wait_cancellation", "owned_open_lock_cancellation",
    "owned_semaphore_wait_cancellation", "owned_semaphore_cancellation",
    "owned_signal_wait_cancellation", "owned_entropy_cancellation", "owned_sysv_message_cancellation",
)


class IoCancellationEvidenceTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.product = self.root / ".work/product"
        self.headers = self.product / "usr/include"
        self.headers.mkdir(parents=True)
        self.source = self.root / "compat/x86_64/owned_io_cancellation_probe.c"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("/* fixture */\n")
        self.witness = self.source.with_name("owned_cancellation_proc_witness.h")
        self.witness.write_text("/* exact local helper */\n")
        self.header = self.headers / "pthread.h"
        self.header.write_text("/* installed header */\n")

    def dependency_identity(self, paths):
        dependency_text = "fixture.o: " + " \\\n ".join(str(path).replace(" ", "\\ ") for path in paths) + "\n"
        return evidence.dependency_identity(self.root, self.product, self.source, dependency_text, ["pthread.h"])

    def test_dependencies_allow_only_installed_headers_and_exact_local_witness(self):
        paths = [self.source, self.header, self.witness]
        result = self.dependency_identity(paths)
        self.assertEqual(set(result), {str(path) for path in paths})
        for extra in (self.root / "include/errno.h", self.source.with_name("other_local_header.h")):
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_text("/* disallowed dependency */\n")
            with self.subTest(extra=extra), self.assertRaises(evidence.EvidenceError):
                self.dependency_identity(paths + [extra])

    def test_each_probe_requires_exactly_its_declared_local_header_closure(self):
        witness_free = {"owned_semaphore_wait_cancellation", "owned_entropy_cancellation"}
        for probe in PROBES:
            self.source = self.source.with_name(f"{probe}_probe.c")
            self.source.write_text("/* fixture */\n")
            paths = [self.source, self.header]
            with self.subTest(probe=probe):
                if probe in witness_free:
                    self.assertNotIn(str(self.witness), self.dependency_identity(paths))
                    with self.assertRaisesRegex(evidence.EvidenceError, "unowned header dependency"):
                        self.dependency_identity(paths + [self.witness])
                else:
                    self.assertIn(str(self.witness), self.dependency_identity(paths + [self.witness]))
                    with self.assertRaisesRegex(evidence.EvidenceError, "required local header absent"):
                        self.dependency_identity(paths)

    def test_unknown_fixture_cannot_acquire_a_local_header_contract(self):
        self.source = self.source.with_name("other_probe.c")
        self.source.write_text("/* unknown fixture */\n")
        with self.assertRaisesRegex(evidence.EvidenceError, "unknown cancellation fixture"):
            self.dependency_identity([self.source, self.header, self.witness])

    def test_missing_required_header_source_and_symlink_dependency_rejected(self):
        for paths in ([self.source, self.witness], [self.header, self.witness]):
            with self.assertRaises(evidence.EvidenceError):
                self.dependency_identity(paths)
        alias = self.headers / "alias.h"
        alias.symlink_to(self.witness)
        with self.assertRaises(evidence.EvidenceError):
            self.dependency_identity([self.source, self.header, alias])

    def test_dependency_identity_changes_when_local_header_changes(self):
        paths = [self.source, self.header, self.witness]
        before = self.dependency_identity(paths)
        self.witness.write_text("/* changed local witness */\n")
        self.assertNotEqual(before, self.dependency_identity(paths))

    def test_compile_record_rejects_object_source_header_driver_and_scalar_tampering(self):
        metadata = self.product / "share/crabc"
        metadata.mkdir(parents=True)
        (self.product / "bin").mkdir()
        driver = self.product / "bin/crabc-cc-dynamic"
        driver.write_text("fixture driver\n")
        (metadata / "manifest.json").write_text("{}\n")
        (metadata / "crabc_cc_static.py").write_text(
            f"def compiler(): return {str(Path(sys.executable).resolve())!r}\n")
        workload = self.root / ".work/workload.o"
        workload.write_bytes(b"one fixture object")
        record = self.root / ".work/compile.json"
        record.with_suffix(".dependencies").write_text(f"fixture.o: {self.source} {self.header} {self.witness}\n")
        record.with_suffix(".headers").write_text("retained header trace\n")
        record.with_suffix(".exit-status").write_text("0\n")
        with mock.patch.object(evidence, "ROOT", self.root):
            evidence.write_new(record, evidence.compile_identity(self.product, self.source, workload, record, ["pthread.h"]))
            evidence.verify_compile(self.product, self.source, workload, record, ["pthread.h"])
            for path in (workload, self.source, self.header, self.witness, driver):
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.subTest(path=path), self.assertRaises(evidence.EvidenceError):
                    evidence.verify_compile(self.product, self.source, workload, record, ["pthread.h"])
                path.write_bytes(original)
            changed = json.loads(record.read_text())
            changed["dependency_exit_status"] = False
            record.write_text(json.dumps(changed))
            with self.assertRaises(evidence.EvidenceError):
                evidence.verify_compile(self.product, self.source, workload, record, ["pthread.h"])

    def test_escaped_installed_header_name_is_parsed_without_widening_scope(self):
        spaced = self.headers / "header with spaces.h"
        spaced.write_text("/* installed */\n")
        self.assertIn(str(spaced), self.dependency_identity([self.source, self.header, self.witness, spaced]))

    def test_static_inspection_preserves_specialized_tls_and_relocation_guards(self):
        views = {
            "header": "Type: DYN (Position-Independent Executable file)\nMachine: Advanced Micro Devices X86-64\n",
            "segments": " PHDR 0 0 0 0 0 R 8\n",
            "dynamic": "There is no dynamic section in this file.\n",
            "symbols": "0: 0000000000000000 0 NOTYPE LOCAL DEFAULT UND\n",
            "relocations": "000 000 R_X86_64_RELATIVE 0\n",
        }
        evidence.audit_static_views("static-pie", views)
        for key, value in (
            ("segments", " INTERP 0 0 0\n"),
            ("segments", ""),
            ("dynamic", " (JMPREL) 0x10\n"),
            ("dynamic", " (PLTGOT) 0x10\n"),
            ("symbols", "1: 000 0 NOTYPE GLOBAL DEFAULT UND missing\n"),
            ("relocations", "000 000 R_X86_64_GOTTPOFF 0\n"),
            ("symbols", "__tls_get_addr\n"),
            ("relocations", "000 000 R_X86_64_64 0\n"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(evidence.EvidenceError):
                evidence.audit_static_views("static-pie", {**views, key: value})
        static = {**views, "header": views["header"].replace("DYN", "EXEC"), "segments": "", "relocations": ""}
        evidence.audit_static_views("static", static)
        for form in ("GLOB_DAT", "JUMP_SLOT", "TLSGD", "TLSLD", "TLSDESC", "DTPMOD64", "DTPOFF64"):
            with self.subTest(form=form), self.assertRaises(evidence.EvidenceError):
                evidence.audit_static_views("static", {**static, "relocations": "R_X86_64_" + form})

    def test_closed_roster_keeps_all_ten_sources_and_eight_local_witnesses(self):
        result = subprocess.check_output(["bash", "-c",
            'source "$1"; printf "%s\\n" "${OWNED_IO_CANCELLATION_PROBES[@]}"', "roster", str(ROSTER)], text=True)
        self.assertEqual(tuple(result.splitlines()), PROBES)
        witness_probes = [probe for probe in PROBES if '"owned_cancellation_proc_witness.h"' in
            (ROOT / "compat/x86_64" / f"{probe}_probe.c").read_text()]
        self.assertEqual(len(witness_probes), 8)
        self.assertNotIn("owned_semaphore_wait_cancellation", witness_probes)
        self.assertNotIn("owned_entropy_cancellation", witness_probes)
        self.assertEqual(set(evidence.LOCAL_HEADERS_BY_SOURCE), {f"{probe}_probe.c" for probe in PROBES})
        for probe in PROBES:
            expected = (evidence.LOCAL_WITNESS,) if probe in witness_probes else ()
            self.assertEqual(evidence.LOCAL_HEADERS_BY_SOURCE[f"{probe}_probe.c"], expected)


class IoCancellationRunnerTests(unittest.TestCase):
    def scratch(self):
        root = ROOT / ".work/x86_64/tmp"
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def function(self, name):
        match = re.search(r"^" + name + r"\(\) \{\n.*?^\}", RUNNER.read_text(), re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        return match.group(0)

    def test_invalid_product_arguments_create_no_output(self):
        work = self.scratch()
        for arguments in ([""], ["--static-sysroot"], ["--static-sysroot", ""],
            ["--static-sysroot", "--unknown"], ["--static-sysroot", "-x"], ["-x"],
            [str(ROOT), str(ROOT)], [str(ROOT), ""],
            ["--static-sysroot", str(ROOT), "--static-sysroot", str(ROOT)]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(["bash", str(RUNNER), *arguments], cwd=ROOT,
                    env={**os.environ, "TMPDIR": str(work)}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(list(work.iterdir()), [])

    def test_raw_capture_retains_actual_success_failure_timeout_and_argv(self):
        work = self.scratch()
        function = self.function("run_fixture")
        for status in (0, 7, 124):
            output = work / f"case-{status}.stdout"
            witness = work / f"witness-{status}.py"
            witness.write_text(f"import sys\nprint('raw output')\nprint('raw error', file=sys.stderr)\nsys.exit({status})\n")
            command = ["bash", "-c", "set -euo pipefail\nwitness=$1\n" + function
                + '\nrun_fixture "" "$2" /consumer /scratch\n', "raw-capture", str(witness), str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, status)
            self.assertEqual(output.read_text(), "raw output\n")
            self.assertEqual(output.with_suffix(".stderr").read_text(), "raw error\n")
            self.assertEqual(output.with_suffix(".status").read_text(), f"{status}\n")
            self.assertTrue(output.with_suffix(".command.json").is_file())

    def test_comparison_rejects_each_raw_stream_mismatch(self):
        work = self.scratch()
        function = self.function("compare_oracle")
        for suffix, value in (("stdout", "owned-io-cancellation-ok\n"), ("stderr", ""), ("status", "0\n")):
            (work / f"owned_io_cancellation-oracle.{suffix}").write_text(value)
            (work / f"candidate.{suffix}").write_text(value)
        command = ["bash", "-c", "set -euo pipefail\nwork=$1\nprobe=owned_io_cancellation\n" + function
            + '\ncompare_oracle "$work/candidate"\n', "compare", str(work)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        for suffix in ("stdout", "stderr", "status"):
            path = work / f"candidate.{suffix}"
            original = path.read_text()
            path.write_text("different\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            path.write_text(original)

    def test_each_fixture_is_compiled_once_as_installed_pie_for_all_links(self):
        runner = RUNNER.read_text()
        self.assertIn('for probe in "${OWNED_IO_CANCELLATION_PROBES[@]}"', runner)
        self.assertEqual(runner.count('-c "$source_file" -o "$object"'), 1)
        self.assertIn('"$driver" --dynamic-pie', runner)
        self.assertNotIn('"$ROOT/include"', runner)
        self.assertNotIn('"$candidate.o"', runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("-fPIC", runner)
        self.assertIn('"$oracle_cc" -pthread "$object"', runner)
        self.assertIn("verify-compile", runner)


if __name__ == "__main__":
    unittest.main()
