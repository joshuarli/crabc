#!/usr/bin/env python3
"""Focused contracts for the planned x86 owned-dynamic product seed."""

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
DRIVER_PATH = ROOT / "compat" / "x86_64" / "crabc_cc_dynamic.py"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_owned_dynamic_sysroot.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PRODUCT = load_module("dynamic_product_contract_test", VALIDATOR_PATH)
DRIVER = load_module("dynamic_product_driver_test", DRIVER_PATH)


class DynamicProductContractTests(unittest.TestCase):
    def contract_data(self) -> dict[str, object]:
        return copy.deepcopy(PRODUCT.load_toml(CONTRACT_PATH))

    def state_data(self) -> dict[str, object]:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))

    def install_planned_dynamic_state(self, root: Path) -> Path:
        """Install the checked-in, explicitly non-materialized seed receipt."""

        destination = root / "share" / "crabc" / "dynamic-product-state.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        state = self.state_data()
        state["status"] = "not-materialized"
        state["contract_sha256"] = DRIVER.PLANNED_PRODUCT_CONTRACT_SHA256
        destination.write_text(json.dumps(state))
        return destination

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
                "pthread-signal",
                "pthread-exit",
                "fork",
                "atfork-registry",
                "posix-timers",
                "pthread-scheduling",
                "signal-helpers",
                "fcntl",
                "named-ipc",
                "pthread-getattr",
                "pthread-join-cancel",
                "pthread-cond-cancel",
                "pthread-cond-timed",
                "pthread-mutex",
                "io-cancellation",
                "system-cancellation",
                "spawn",
                "linux-control",
                "vm-mechanisms",
                "assert",
                "quick-exit",
                "syslog",
                "pthread-spin",
                "process-trio",
                "filesystem-mechanisms",
                "error-reporting",
                "pty",
                "passwd",
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

    def test_seed_state_is_bound_to_contract_and_cannot_promote(self) -> None:
        contract = self.contract_data()
        state = self.state_data()

        state["contract_sha256"] = "0" * 64
        with self.assertRaisesRegex(PRODUCT.ProductContractError, "contract digest"):
            PRODUCT.validate_dynamic_product_state(contract, state)

        state = self.state_data()
        state["promotion"]["public_support"] = True
        with self.assertRaisesRegex(PRODUCT.ProductContractError, "non-promoting"):
            PRODUCT.validate_dynamic_product_state(contract, state)

    def test_contract_binds_the_driver_to_its_plan_only_seed(self) -> None:
        contract = self.contract_data()
        state = self.state_data()
        plan = PRODUCT.dynamic_driver.parse_invocation(
            ("--print-link-plan", "--dynamic-pie")
        )

        with mock.patch.object(
            PRODUCT.dynamic_driver,
            "parse_invocation",
            side_effect=(plan, plan),
        ):
            with self.assertRaisesRegex(PRODUCT.ProductContractError, "driver seed"):
                PRODUCT.validate_plan_only_driver_seed(contract)

    def test_dynamic_driver_seed_has_no_translation_or_link_execution_surface(self) -> None:
        execution_surface = (
            PRODUCT.PLAN_ONLY_EXECUTION_HELPERS | PRODUCT.PLAN_ONLY_EXECUTION_MODULES
        ).intersection(vars(DRIVER))
        self.assertFalse(execution_surface)

        with mock.patch.object(PRODUCT.dynamic_driver, "compile_source", object(), create=True):
            with self.assertRaisesRegex(PRODUCT.ProductContractError, "executable helper surface"):
                PRODUCT.validate_plan_only_driver_seed(self.contract_data())

    def test_dynamic_driver_plans_owned_pie_non_pie_and_shared_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "sysroot"
            (root / "bin").mkdir(parents=True)
            (root / "usr" / "include").mkdir(parents=True)
            (root / "usr" / "include" / "stdint.h").write_text("\n", encoding="utf-8")
            library = root / "usr" / "lib"
            library.mkdir()
            for relative in DRIVER.REQUIRED_RUNTIME_PATHS:
                artifact = root / relative
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b"owned\n")
            alias = root / DRIVER.COMPATIBILITY_INTERPRETER_RELATIVE_PATH
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.symlink_to(Path(DRIVER.CANONICAL_INTERPRETER).name)
            self.install_planned_dynamic_state(root)
            installed = root / "bin" / "crabc-cc-dynamic"
            shutil.copyfile(DRIVER_PATH, installed)
            installed.chmod(0o755)

            expected = {
                "--dynamic-pie": ("ET_DYN", "Scrt1.o", DRIVER.CANONICAL_INTERPRETER),
                "--dynamic-non-pie": ("ET_EXEC", "crt1.o", DRIVER.CANONICAL_INTERPRETER),
                "--dynamic-shared-object": ("ET_DYN", None, "absent"),
            }
            for mode, (elf_type, crt, interpreter) in expected.items():
                with self.subTest(mode=mode):
                    completed = subprocess.run(
                        [str(installed), "--print-link-plan", mode],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    plan = json.loads(completed.stdout)
                    self.assertEqual(plan["mode"]["elf_type"], elf_type)
                    self.assertEqual(plan["mode"]["crt_object"], crt)
                    self.assertEqual(plan["mode"]["interpreter"], interpreter)
                    self.assertEqual(plan["headers"], str(root / "usr" / "include"))
                    self.assertIn(str(root / "usr" / "lib" / "libc.so"), plan["linker"])
                    self.assertIn(
                        str(root / "usr" / "lib" / "libcrabc-builtins.a"), plan["linker"]
                    )
                    self.assertIn(DRIVER.APPLICATION_DSOS, plan["linker"])
                    if crt is not None:
                        self.assertIn(str(root / "usr" / "lib" / crt), plan["linker"])
                    else:
                        self.assertNotIn("--dynamic-linker", plan["linker"])
                    for item in plan["linker"]:
                        if isinstance(item, str) and item.startswith("/"):
                            self.assertTrue(item.startswith(str(root)) or item == DRIVER.CANONICAL_INTERPRETER)

    def test_dynamic_driver_rejects_ambient_runtime_injection_and_bad_alias(self) -> None:
        for arguments in (
            ("--dynamic-pie", "-I", "/ambient/headers", "application.c"),
            ("--dynamic-pie", "-L/ambient/lib", "application.c"),
            ("--dynamic-pie", "-l:libc.so", "application.c"),
            ("--dynamic-pie", "-Wl,--dynamic-linker,/ambient/loader", "application.c"),
            ("--dynamic-pie", "-static", "application.c"),
            ("--dynamic-pie", "--dynamic-non-pie", "application.c"),
            ("--dynamic-pie", "/ambient/crt1.o"),
            ("--dynamic-pie", "/ambient/libgcc.o"),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(DRIVER.DriverError, "rejected|exactly one"):
                    DRIVER.parse_invocation(arguments)

        with self.assertRaisesRegex(DRIVER.DriverError, "plan-only"):
            DRIVER.parse_invocation(
                ("--dynamic-pie", "--application-dso", "fixture-dependency.so", "application.o")
            )
        with self.assertRaisesRegex(DRIVER.DriverError, "DSO is rejected"):
            DRIVER.parse_invocation(
                ("--dynamic-pie", "--application-dso", "libc.so", "application.o")
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "sysroot"
            (root / "usr" / "include").mkdir(parents=True)
            for relative in DRIVER.REQUIRED_RUNTIME_PATHS:
                artifact = root / relative
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b"owned\n")
            alias = root / DRIVER.COMPATIBILITY_INTERPRETER_RELATIVE_PATH
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.symlink_to("/ambient/ld-musl-x86_64.so.1")
            self.install_planned_dynamic_state(root)
            with self.assertRaisesRegex(DRIVER.DriverError, "compatibility interpreter alias"):
                DRIVER.validate_installed_runtime(root)

    def test_dynamic_driver_seed_requires_a_checked_nonmaterialized_state_and_is_plan_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "sysroot"
            (root / "bin").mkdir(parents=True)
            (root / "usr" / "include").mkdir(parents=True)
            (root / "usr" / "include" / "stdint.h").write_text("\n", encoding="utf-8")
            for relative in DRIVER.REQUIRED_RUNTIME_PATHS:
                artifact = root / relative
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(b"owned\n")
            alias = root / DRIVER.COMPATIBILITY_INTERPRETER_RELATIVE_PATH
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.symlink_to(Path(DRIVER.CANONICAL_INTERPRETER).name)
            installed = root / "bin" / "crabc-cc-dynamic"
            shutil.copyfile(DRIVER_PATH, installed)
            installed.chmod(0o755)

            missing_state = subprocess.run(
                [str(installed), "--print-link-plan", "--dynamic-pie"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(missing_state.returncode, 1)
            self.assertIn("dynamic product state", missing_state.stderr)

            state_path = self.install_planned_dynamic_state(root)
            plan = subprocess.run(
                [str(installed), "--print-link-plan", "--dynamic-pie"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(plan.returncode, 0, plan.stderr)

            source = Path(temporary) / "application.c"
            output = Path(temporary) / "application.o"
            source.write_text("int application(void) { return 0; }\n", encoding="utf-8")
            attempted_translation = subprocess.run(
                [str(installed), "--dynamic-pie", "-c", str(source), "-o", str(output)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(attempted_translation.returncode, 1)
            self.assertIn("plan-only", attempted_translation.stderr)
            self.assertFalse(output.exists())

            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["status"] = "materialized"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            materialized_claim = subprocess.run(
                [str(installed), "--print-link-plan", "--dynamic-pie"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(materialized_claim.returncode, 1)
            self.assertIn("not-materialized", materialized_claim.stderr)

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
