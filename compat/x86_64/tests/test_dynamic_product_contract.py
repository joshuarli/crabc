#!/usr/bin/env python3
"""Focused contracts for the x86 owned-dynamic product contract and state."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "dynamic-product.toml"
STATE_PATH = ROOT / "compat" / "x86_64" / "dynamic-product-state.json"
VALIDATOR_PATH = ROOT / "compat" / "x86_64" / "dynamic_product_contract.py"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_owned_dynamic_sysroot.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PRODUCT = load_module("dynamic_product_contract_test", VALIDATOR_PATH)


class DynamicProductContractTests(unittest.TestCase):
    def test_checked_in_qualification_roster_matches_executable_catalog(self) -> None:
        import owned_dynamic_qualification as qualification

        self.assertEqual(
            self.contract_data()["qualification"]["required_cases"],
            list(qualification.CASES),
        )

    def contract_data(self) -> dict[str, object]:
        return copy.deepcopy(PRODUCT.load_toml(CONTRACT_PATH))

    def state_data(self) -> dict[str, object]:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))

    def test_checked_in_seed_is_planned_and_non_promoting(self) -> None:
        contract = self.contract_data()
        state = self.state_data()
        report = PRODUCT.validate_contract_and_state(contract, state)

        self.assertEqual(contract["status"], "implemented-unqualified")
        self.assertEqual(contract["owner_family"], "sysroot.owned-artifact")
        self.assertEqual(
            [mode["id"] for mode in contract["mode"]],
            ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
        )
        self.assertEqual(
            contract["qualification"]["required_cases"],
            [
                "cycle",
                "cli",
                "elf-scope-alias",
                "dlopen-pie",
                "dlopen-non-pie",
                "lazy-pie",
                "lazy-non-pie",
                "constructor-exit",
                "crt-dynamic-startup",
                "pthread-signal",
                "pthread-exit",
                "fork",
                "signal-handler-fork",
                "atfork-registry",
                "posix-timers",
                "pthread-scheduling",
                "pthread-cpuclock",
                "signal-helpers",
                "signal-full",
                "fcntl",
                "named-ipc",
                "message-queues",
                "pthread-getattr",
                "pthread-join-cancel",
                "pthread-cond-cancel",
                "pthread-cond-timed",
                "pthread-mutex",
                "io-cancellation",
                "system-cancellation",
                "spawn",
                "linux-control",
                "kernel-residual",
                "vm-mechanisms",
                "group",
                "assert",
                "quick-exit",
                "legacy-time",
                "environment-lifecycle",
                "syslog",
                "credentials-profile",
                "pthread-spin",
                "process-trio",
                "underscore-fork",
                "process-control",
                "filesystem-mechanisms",
                "error-reporting",
                "c-allocation-interposition",
                "stdio-allocator-interposition",
                "mimalloc-startup-errno",
                "pty",
                "passwd",
                "account-files",
                "utmpx",
                "aio",
                "locale",
                "stdio",
                "numeric-calendar",
                "math-fenv-all-entry",
                "rand",
                "pattern",
                "regex",
                "wordexp",
                "wide-calendar",
                "monetary",
                "fmtmsg",
                "classic-netdb",
                "posix-filesystem",
                "unix-mechanisms",
                "posix-composition",
                "resolver-cancellation",
                "loader-synthetic",
                "package-corpus",
                "cross-dso",
            ],
        )
        self.assertEqual(report["status"], "implemented-unqualified")
        self.assertEqual(contract["non_promotion"]["driver_execution"], "installed-translation-and-linking")
        self.assertEqual(
            report["dynamic_family_ids"],
            ["ldso.dynamic-runtime", "crt.dynamic-startup", "sysroot.owned-artifact"],
        )
        self.assertEqual(
            report["prerequisite_families"],
            ["ldso.dynamic-runtime", "crt.dynamic-startup", "sysroot.static-tls"],
        )
        self.assertFalse(report["promotion"]["family_completion"])
        self.assertFalse(report["promotion"]["promotion_ready"])
        self.assertFalse(report["promotion"]["public_support"])

    def test_contract_rejects_diluted_dynamic_modes_and_product_obligations(self) -> None:
        mutations = (
            (
                "dynamic non-PIE mode",
                lambda contract: contract["mode"].pop(1),
                "mode contract",
            ),
            (
                "interpreter alias",
                lambda contract: contract["layout"].pop("compatibility_interpreter_alias"),
                "layout contract",
            ),
            (
                "shared libc",
                lambda contract: contract["product"]["required_target_inputs"].remove("libc.so"),
                "target-input contract",
            ),
            (
                "runtime loaded DSO coverage",
                lambda contract: contract["coverage"]["required"].pop(),
                "coverage contract",
            ),
            (
                "unmapped coverage obligation",
                lambda contract: contract["coverage"]["evidence"].pop(),
                "exactly one ordered evidence entry",
            ),
            (
                "coverage evidence without a registered case",
                lambda contract: contract["coverage"]["evidence"][6]["cases"].__setitem__(0, "initial-ie"),
                "unknown cases",
            ),
            (
                "coverage evidence without cases",
                lambda contract: contract["coverage"]["evidence"][8].__setitem__("cases", []),
                "distinct case names",
            ),
            (
                "reproducible installs",
                lambda contract: contract["reproducibility"].__setitem__(
                    "clean_installed_builds", 1
                ),
                "reproducibility contract",
            ),
            (
                "oracle isolation",
                lambda contract: contract["oracle"].__setitem__(
                    "candidate_fallback", "allowed"
                ),
                "oracle contract",
            ),
            (
                "driver execution before materialization",
                lambda contract: contract["non_promotion"].__setitem__(
                    "driver_execution", "translation-and-linking"
                ),
                "driver execution",
            ),
        )
        state = self.state_data()
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                contract = self.contract_data()
                mutate(contract)
                with self.assertRaisesRegex(PRODUCT.ProductContractError, message):
                    PRODUCT.validate_dynamic_product_contract(contract)

    def test_seed_state_cannot_promote(self) -> None:
        contract = self.contract_data()
        state = self.state_data()
        state["promotion"]["public_support"] = True
        with self.assertRaisesRegex(PRODUCT.ProductContractError, "non-promoting"):
            PRODUCT.validate_dynamic_product_state(contract, state)

    def test_runner_contract_check_is_unqualified_and_default_routes_to_product_gate(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER_PATH)],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER_PATH.stat().st_mode), 0o755)

        contract_only = subprocess.run(
            [str(RUNNER_PATH), "--check-contract"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(contract_only.returncode, 0, contract_only.stderr)
        self.assertIn("implemented-unqualified", contract_only.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "compat/x86_64"
            fixture.mkdir(parents=True)
            runner = fixture / RUNNER_PATH.name
            shutil.copyfile(RUNNER_PATH, runner)
            (fixture / "run_materialized_dynamic_sysroot.sh").write_text(
                "#!/usr/bin/env bash\nprintf 'isolated materialized gate\\n'\nexit 37\n"
            )
            completed = subprocess.run(["bash", str(runner)], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 37)
            self.assertEqual(completed.stdout, "isolated materialized gate\n")



if __name__ == "__main__":
    unittest.main()
