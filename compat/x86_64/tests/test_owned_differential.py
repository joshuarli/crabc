#!/usr/bin/env python3
"""Contract tests for the owned-product differential aggregate."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_differential.sh"
HELPER = ROOT / "compat/x86_64/owned_differential_evidence.py"
DOCUMENT = ROOT / "compat/x86_64/owned-differential.md"
DIFFERENTIAL_RUNNER = ROOT / "compat/differential/run.py"


def load_helper():
    specification = importlib.util.spec_from_file_location("owned_differential_evidence", HELPER)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load owned differential evidence helper")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_differential_runner():
    specification = importlib.util.spec_from_file_location("differential_runner", DIFFERENTIAL_RUNNER)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load frozen differential runner")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class OwnedDifferentialTests(unittest.TestCase):
    def temporary_directory(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(prefix="owned-differential-test.", dir=scratch)

    def test_parser_requires_exactly_one_dynamic_product_before_running_tools(self) -> None:
        with self.temporary_directory() as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = {**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"}
            for arguments in (
                (),
                ("--static-sysroot",),
                ("--static-sysroot", ""),
                ("--static-sysroot", "-not-a-product"),
                ("-x",),
                ("first", "second"),
                ("--static-sysroot", "first", "--static-sysroot", "second", "dynamic"),
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(RUNNER), *arguments], cwd=ROOT, env=environment,
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        "usage: "
                        f"{RUNNER} [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n",
                    )

    def test_frozen_case_roster_and_direct_headers_are_explicit(self) -> None:
        helper = load_helper()
        differential = load_differential_runner()
        self.assertEqual(
            helper.CASES,
            ("foundational", "string-memory", "allocator", "fd-filesystem", "stdio-fdopen"),
        )
        self.assertEqual(helper.CASES, differential.CASES)
        self.assertEqual(
            helper.REQUIRED_HEADERS["fd-filesystem"],
            ("errno.h", "fcntl.h", "stdio.h", "string.h", "sys/stat.h", "unistd.h"),
        )
        for case in helper.CASES:
            with self.subTest(case=case):
                self.assertTrue((ROOT / "compat/differential/tests" / f"{case}.c").is_file())

    def test_raw_comparison_keeps_status_streams_and_errno_distinct(self) -> None:
        helper = load_helper()
        with self.temporary_directory() as temporary:
            root = Path(temporary)
            reference = helper.RawObservation(
                status_path=root / "reference.status",
                stdout_path=root / "reference.stdout",
                stderr_path=root / "reference.stderr",
            )
            candidate = helper.RawObservation(
                status_path=root / "candidate.status",
                stdout_path=root / "candidate.stdout",
                stderr_path=root / "candidate.stderr",
            )
            for observation in (reference, candidate):
                observation.status_path.write_text("0\n", encoding="ascii")
                observation.stdout_path.write_bytes(b"foundational: errno=34 len=5 value-ok\n")
                observation.stderr_path.write_bytes(b"foundational: stderr\n")

            passed = helper.compare_observations("foundational", "musl", reference, "candidate", candidate)
            self.assertTrue(passed["passed"])
            self.assertEqual(passed["reference"]["errno"], 34)
            self.assertEqual(passed["candidate"]["errno"], 34)

            candidate.stdout_path.write_bytes(b"foundational: errno=0 len=5 value-ok\n")
            errno_drift = helper.compare_observations(
                "foundational", "musl", reference, "candidate", candidate,
            )
            self.assertFalse(errno_drift["passed"])
            self.assertIn("stdout differs", errno_drift["differences"])
            self.assertIn("errno differs", errno_drift["differences"])

            candidate.stdout_path.write_bytes(b"foundational: errno=34 len=5 value-ok\n")
            candidate.stderr_path.write_bytes(b"candidate diagnostic\n")
            stderr_drift = helper.compare_observations(
                "foundational", "musl", reference, "candidate", candidate,
            )
            self.assertFalse(stderr_drift["passed"])
            self.assertEqual(stderr_drift["differences"], ["stderr differs"])

            candidate.stderr_path.write_bytes(b"foundational: stderr\n")
            reference.status_path.write_text("7\n", encoding="ascii")
            candidate.status_path.write_text("7\n", encoding="ascii")
            failed_together = helper.compare_observations(
                "foundational", "musl", reference, "candidate", candidate,
            )
            self.assertFalse(failed_together["passed"])
            self.assertIn("pinned musl reference status is 7", failed_together["differences"])
            self.assertIn("candidate status is 7", failed_together["differences"])

    def test_summary_matrix_requires_all_five_dynamic_four_entry_comparisons(self) -> None:
        helper = load_helper()
        dynamic = helper.frozen_matrix(False)
        full = helper.frozen_matrix(True)

        self.assertEqual(len(dynamic["observations"]), 20)
        self.assertEqual(len(full["observations"]), 30)
        self.assertEqual(len(dynamic["links"]), 15)
        self.assertEqual(len(full["links"]), 25)
        self.assertEqual(len(dynamic["copies"]), 95)
        self.assertEqual(len(full["copies"]), 125)
        for case in helper.CASES:
            with self.subTest(case=case):
                labels = [
                    item["label"] for item in dynamic["observations"] if item["case"] == case
                ]
                self.assertEqual(
                    labels,
                    [
                        "dynamic-pie-kernel",
                        "dynamic-pie-direct",
                        "dynamic-non-pie-kernel",
                        "dynamic-non-pie-direct",
                    ],
                )

    def test_observation_validator_recomputes_retained_zero_status_raw_files(self) -> None:
        helper = load_helper()
        with self.temporary_directory() as temporary:
            work = Path(temporary)
            executions = work / "executions"
            observations = work / "observations"
            executions.mkdir()
            observations.mkdir()
            for label in ("musl", "dynamic-pie-kernel"):
                (executions / f"foundational-{label}.status").write_text("0\n", encoding="ascii")
                (executions / f"foundational-{label}.stdout").write_bytes(
                    b"foundational: errno=34 len=5 value-ok\n"
                )
                (executions / f"foundational-{label}.stderr").write_bytes(b"foundational: stderr\n")
            reference, candidate = helper.observation_paths(work, "foundational", "dynamic-pie-kernel")
            record = helper.compare_observations(
                "foundational", "musl", reference, "dynamic-pie-kernel", candidate,
            )
            record_path = observations / "foundational-dynamic-pie-kernel.json"
            record_path.write_text(json.dumps(record), encoding="utf-8")
            helper.validate_observation_record(work, "foundational", "dynamic-pie-kernel", record_path)

            (executions / "foundational-dynamic-pie-kernel.status").write_text("7\n", encoding="ascii")
            with self.assertRaisesRegex(helper.EvidenceError, "zero-status passing result"):
                helper.validate_observation_record(work, "foundational", "dynamic-pie-kernel", record_path)

    def test_dependency_audit_rejects_ambient_headers(self) -> None:
        helper = load_helper()
        with self.temporary_directory() as temporary:
            root = Path(temporary)
            source = root / "workload.c"
            headers = root / "installed-headers"
            header = headers / "stdio.h"
            headers.mkdir()
            source.write_text("#include <stdio.h>\n", encoding="utf-8")
            header.write_text("/* installed */\n", encoding="utf-8")
            record = f"workload.o: {source} {header} /usr/include/stdio.h\n"
            with self.assertRaisesRegex(helper.EvidenceError, "escapes installed headers"):
                helper.dependency_paths_text(record, source, headers)

    def test_file_copy_identity_rejects_mode_drift(self) -> None:
        helper = load_helper()
        with self.temporary_directory() as temporary:
            root = Path(temporary)
            source = root / "source"
            copied = root / "copied"
            source.write_bytes(b"candidate\n")
            source.chmod(0o755)
            copied.write_bytes(source.read_bytes())
            copied.chmod(0o755)
            identity = helper.file_copy_identity(source, copied)
            self.assertEqual(identity["source"]["sha256"], identity["copy"]["sha256"])
            copied.chmod(0o644)
            with self.assertRaisesRegex(helper.EvidenceError, "mode differs"):
                helper.file_copy_identity(source, copied)

    def test_file_execution_root_is_attested_before_and_after_the_run(self) -> None:
        helper = load_helper()
        with self.temporary_directory() as temporary:
            root = Path(temporary)
            source = root / "source"
            execution_root = root / "execution-root"
            source.write_bytes(b"candidate\n")
            source.chmod(0o755)
            execution_root.mkdir()
            consumer = execution_root / "consumer"
            consumer.write_bytes(source.read_bytes())
            consumer.chmod(0o755)
            temporary_root = execution_root / "tmp"
            temporary_root.mkdir()
            temporary_root.chmod(0o1777)
            before = helper.file_root_identity(source, execution_root)
            self.assertEqual(before["tmp"]["mode"], "1777")
            temporary_root.chmod(0o3777)
            with self.assertRaisesRegex(helper.EvidenceError, "tmp mode differs"):
                helper.file_root_identity(source, execution_root)
            temporary_root.chmod(0o1777)
            (temporary_root / "left-behind").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(helper.EvidenceError, "tmp is not empty"):
                helper.file_root_identity(source, execution_root)

    def test_runner_is_a_consumer_only_non_promoting_component(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = " ".join(DOCUMENT.read_text(encoding="utf-8").split())
        for required in (
            "provided_dynamic", "--static-sysroot", "record-compile", "record-oracle-link",
            "validate-link", "record-product-copy", "attest-file-root", "attest-dynamic-root",
            "--phase pre", "--phase post", "compare", "summarize", "--static-replayed",
            "chmod g-s \"$root/tmp\"", "--dynamic-$mode", "static-pie", "chroot",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("build_x86_64_owned_dynamic_sysroot.py", runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        for required in (
            "one unchanged object", "pinned musl", "static/static-PIE", "dynamic PIE/non-PIE",
            "kernel and direct interpreter", "full raw status, stdout, stderr, and errno", "does not build",
            "does not qualify", "does not claim",
        ):
            self.assertIn(required, document)


if __name__ == "__main__":
    unittest.main()
