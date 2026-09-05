#!/usr/bin/env python3
"""Contract tests for the native owned-product signal/process aggregate."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_signal_process.sh"
EVIDENCE = ROOT / "compat/x86_64/owned_signal_process_evidence.py"
DOCUMENT = ROOT / "compat/x86_64/owned-signal-process.md"
SOURCE = ROOT / "compat/signal-process/tests/signal_process.c"
SUBCASES = (
    "siginfo", "nodefer", "mask-pending", "sa-restart", "altstack",
    "thread-mask", "sigwait", "timer", "wait-signal", "wait-nohang",
    "atfork", "fork-worker-exec",
)


def load_evidence():
    spec = importlib.util.spec_from_file_location("owned_signal_process_evidence", EVIDENCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OwnedSignalProcessTests(unittest.TestCase):
    def test_frozen_workload_is_architecture_neutral_and_has_the_full_roster(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("aarch", source.lower())
        self.assertNotIn("x86", source.lower())
        for subcase in SUBCASES:
            self.assertIn(f'"{subcase}"', source)
        self.assertIn('strcmp(argv[1], "exec-check")', source)

    def test_runner_requires_a_supplied_dynamic_product_and_never_builds_one(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT", source)
        self.assertIn('"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin', source)
        self.assertNotIn("build_x86_64_owned_dynamic_sysroot.py", source)
        self.assertNotIn("build_x86_64_owned_sysroot.py", source)
        self.assertNotIn("-D", source)
        for subcase in SUBCASES:
            self.assertIn(subcase, source)

    def test_runner_records_raw_process_group_observations_for_every_entry(self) -> None:
        source = RUNNER.read_text(encoding="utf-8") + EVIDENCE.read_text(encoding="utf-8")
        for required in (
            "record-compile", "validate-compile", "validate_link", "start_new_session=True",
            "os.killpg", "TIMEOUT", ".stdout", ".stderr", ".status",
            "pie-kernel", "pie-direct", "non-pie-kernel", "non-pie-direct",
        ):
            self.assertIn(required, source)

    def test_evidence_contract_binds_the_one_installed_driver_object(self) -> None:
        evidence = load_evidence()
        self.assertEqual(evidence.SIGNAL_PROCESS_SUBCASES, SUBCASES)
        self.assertEqual(
            evidence.COMPILE_SCHEMA,
            "crabc.x86_64-owned-signal-process-compile/v1",
        )
        self.assertEqual(
            evidence.OBSERVATION_SCHEMA,
            "crabc.x86_64-owned-signal-process-observations/v1",
        )
        self.assertTrue(callable(evidence.record_compile))
        self.assertTrue(callable(evidence.validate_compile))
        self.assertTrue(callable(evidence.record_observations))
        self.assertTrue(callable(evidence.run_in_process_group))

    def test_cli_rejects_missing_or_ambiguous_products_before_evidence(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        for arguments in (
            (),
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "one"),
            ("dynamic", "second"),
            ("--unexpected",),
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    env={"PATH": "/usr/bin:/bin", "TMPDIR": temporary},
                    text=True,
                    capture_output=True,
                    check=False,
                )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n",
            )

    def test_document_names_the_frozen_source_and_non_promotion_boundary(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("`compat/signal-process/tests/signal_process.c`", document)
        self.assertIn("fresh process group", document)
        self.assertIn("does not promote", document)
        for subcase in SUBCASES:
            self.assertIn(f"`{subcase}`", document)


if __name__ == "__main__":
    unittest.main()
