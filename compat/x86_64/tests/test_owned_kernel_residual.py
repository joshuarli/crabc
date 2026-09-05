#!/usr/bin/env python3
"""Contracts for the installed residual `system.kernel-admin` workload."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
FROZEN_CONFIGURATION = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_configuration.rs"
OWNED_CONFIGURATION = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_system_configuration.rs"
PROBE = ROOT / "compat" / "x86_64" / "owned_kernel_residual_probe.c"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_kernel_residual.sh"
QUALIFICATION = ROOT / "compat" / "x86_64" / "owned_dynamic_qualification.py"
CATALOG = ROOT / "compat" / "x86_64" / "owned-posix-runtime-catalog.toml"

RESIDUAL = {
    "__sched_cpucount", "confstr", "fpathconf", "getdtablesize", "gethostid",
    "membarrier", "pathconf", "personality", "prctl", "sched_getparam",
    "sched_getscheduler", "sched_setparam", "sched_setscheduler", "setdomainname",
    "sethostname", "syscall", "sysconf", "ulimit",
}
CONFIGURATION_REPLACEMENTS = {
    "confstr", "fpathconf", "getdtablesize", "getpagesize", "pathconf", "sysconf",
}


class OwnedKernelResidualTests(unittest.TestCase):
    def test_exact_residual_roster_and_source_bindings_are_recorded(self) -> None:
        document = tomllib.loads(CATALOG.read_text(encoding="utf-8"))
        row = next(item for item in document["capability"] if item["id"] == "system.kernel-admin")
        evidence = " ".join(row["current_installed_evidence"])
        self.assertTrue(RESIDUAL <= set(row["symbols"]))
        runner = RUNNER.read_text(encoding="utf-8")
        for name in RESIDUAL:
            self.assertIn(name, runner)
        for name in RESIDUAL:
            self.assertIn(name, evidence)
        for source in (
            "sched_cpucount.rs", "owned_system_configuration.rs", "gethostid.rs",
            "membarrier.rs", "personality.rs", "owned_static_prctl.rs",
            "sched_getparam.rs", "sched_getscheduler.rs", "sched_setparam.rs",
            "sched_setscheduler.rs", "uts_identity.rs", "owned_static_syscall.rs",
            "ulimit.rs",
        ):
            self.assertTrue(any(binding.endswith(source) for binding in row["source_bindings"]))

    def test_owned_configuration_replaces_only_the_aggregate_selection(self) -> None:
        root = STATIC_ROOT.read_text(encoding="utf-8")
        frozen = FROZEN_CONFIGURATION.read_text(encoding="utf-8")
        owned = OWNED_CONFIGURATION.read_text(encoding="utf-8")
        self.assertIn(
            '#[cfg(not(feature = "x86-owned-static-runtime"))]\n'
            '#[path = "system_configuration.rs"]\nmod system_configuration;',
            root,
        )
        self.assertIn(
            '#[cfg(feature = "x86-owned-static-runtime")]\n'
            '#[path = "owned_system_configuration.rs"]\nmod system_configuration;',
            root,
        )
        self.assertNotIn("SC_MINSIGSTKSZ", frozen)
        for required in (
            "src/conf/sysconf.c", "AT_MINSIGSTKSZ", "minimum_signal_stack_size",
            "signal_stack_size", "SC_MINSIGSTKSZ", "SC_SIGSTKSZ",
        ):
            self.assertIn(required, owned)

    def test_runner_replays_one_object_and_retains_contained_negative_paths(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        for required in (
            '"$installed/bin/crabc-cc-dynamic" --dynamic-pie',
            '"$ORACLE_CC" -static', "run_static_mode", "run_dynamic_mode",
            "compare_case_output", "run_in_root", "run_static_mode \"$work/static-product\" static",
            "run_static_mode \"$work/static-product\" static-pie", "kernel/direct",
            "provided_dynamic", "provided dynamic PIE/non-PIE kernel/direct",
            "assert_static_symbols", "assert_dynamic_symbols",
        ):
            self.assertIn(required, runner)
        for selector in (
            "sysconf-signal-stack", "scheduler", "uts-namespace", "uts-seccomp",
        ):
            self.assertIn(selector, runner)
        for required in (
            "AT_MINSIGSTKSZ", "untouched", "SECCOMP_RET_ERRNO | EPERM",
            "sethostname", "setdomainname", "raw6",
        ):
            self.assertIn(required, probe)

    def test_dynamic_qualification_reuses_the_same_runner(self) -> None:
        qualification = QUALIFICATION.read_text(encoding="utf-8")
        self.assertIn(
            '"kernel-residual": ("run_owned_kernel_residual.sh", None)',
            qualification,
        )

    def test_provider_projection_records_the_configuration_replacement(self) -> None:
        ledger = tomllib.loads((ROOT / "compat" / "x86_64" / "parity.toml").read_text())
        feature = next(row for row in ledger["feature_archive"]
                       if row["id"] == "x86-owned-static-runtime")
        self.assertTrue(CONFIGURATION_REPLACEMENTS <= set(feature["replacement_callables"]))

    def test_supplied_product_escape_is_rejected_before_building(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER), str(ROOT)],
                env={**os.environ, "TMPDIR": temporary},
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "owned kernel residual product must be a checkout .work directory",
            result.stderr,
        )
        self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
