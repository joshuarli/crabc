#!/usr/bin/env python3
"""Contract tests for the derived x86 AArch64-parity inventory."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "aarch64_parity_inventory.py"
SPEC = importlib.util.spec_from_file_location("aarch64_parity_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class AArch64ParityInventoryTests(unittest.TestCase):
    @staticmethod
    def family(data: dict[str, object], identifier: str) -> dict[str, object]:
        families = data["family"]
        assert isinstance(families, list)
        for family in families:
            assert isinstance(family, dict)
            if family["id"] == identifier:
                return family
        raise AssertionError(f"missing family: {identifier}")

    def build_with_x86_ledger(self, data: dict[str, object]) -> dict[str, object]:
        original_load_toml = inventory.load_toml

        def load_toml(path: Path) -> dict[str, object]:
            if path == inventory.X86_LEDGER_PATH:
                return copy.deepcopy(data)
            return original_load_toml(path)

        with patch.object(inventory, "load_toml", side_effect=load_toml):
            return inventory.build_inventory()

    def test_frozen_baseline_record_captures_the_settlement_identity(self) -> None:
        frozen = inventory.validate_frozen_baseline()
        self.assertEqual(
            frozen["schema"], "crabc.x86_64-frozen-aarch64-baseline/v1"
        )
        self.assertEqual(
            frozen["source_commit"], "3e100d45c5a0798c2d3862d5e2eef584c610ccf9"
        )
        self.assertEqual(frozen["platform"], "Linux/AArch64 little-endian")
        self.assertEqual(frozen["capability_count"], 223)
        self.assertEqual(frozen["required_family_count"], 26)
        self.assertEqual(
            frozen["aarch64_inputs"]["capability_ledger"]["sha256"],
            "128458dde00073bc0320b94972d864e66fa10d5f54e92b1b1c83081e2b4955e0",
        )

    def test_frozen_baseline_rejects_changed_live_aarch64_input(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            changed_ledger = Path(directory) / "coverage.toml"
            changed_ledger.write_bytes(
                inventory.BASELINE_CAPABILITIES_PATH.read_bytes() + b"\n# drift\n"
            )
            original_sha256 = inventory.sha256

            def sha256(path: Path) -> str:
                if path == inventory.BASELINE_CAPABILITIES_PATH:
                    return original_sha256(changed_ledger)
                return original_sha256(path)

            with patch.object(inventory, "sha256", side_effect=sha256):
                with self.assertRaisesRegex(
                    inventory.InventoryError,
                    "frozen AArch64 input capability_ledger digest drifted",
                ):
                    inventory.validate_frozen_baseline()

    def test_inventory_has_no_baseline_refresh_mode(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--write"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments: --write", result.stderr)

    def test_inventory_rejects_frozen_required_family_count_drift(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            changed_record = Path(directory) / "frozen-baseline.json"
            record = json.loads(inventory.FROZEN_BASELINE_PATH.read_text(encoding="utf-8"))
            record["required_family_count"] = 25
            changed_record.write_text(json.dumps(record), encoding="utf-8")
            with patch.object(inventory, "FROZEN_BASELINE_PATH", changed_record):
                with self.assertRaisesRegex(
                    inventory.InventoryError, "frozen required family count"
                ):
                    inventory.build_inventory()

    def test_inventory_rejects_dependencies_outside_frozen_roster_order(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        self.family(data, "oracle.musl-toolchain")["depends_on"] = [
            "performance.release"
        ]

        with self.assertRaisesRegex(
            inventory.InventoryError, "is not earlier in the frozen roster"
        ):
            self.build_with_x86_ledger(data)

    def test_checked_snapshot_is_source_derived_and_non_promoting(self) -> None:
        report = inventory.validate_inventory()
        self.assertEqual(report["schema"], "crabc.x86_64-aarch64-parity-inventory/v1")
        self.assertEqual(report["baseline"]["capability_count"], 223)
        self.assertEqual(report["frozen_baseline"]["capability_count"], 223)
        self.assertEqual(report["baseline"]["aarch64_public_header_count"], 183)
        self.assertEqual(report["x86_boundary"]["promotion_family_count"], 26)
        self.assertFalse(report["x86_boundary"]["promotion_ready"])
        self.assertFalse(report["x86_boundary"]["public_support"])
        self.assertEqual(sum(report["capability_state_counts"].values()), 223)
        self.assertEqual(
            report["capability_state_counts"],
            {
                "implemented-foundation": 180,
                "missing": 19,
                "selected-private": 24,
            },
        )
        self.assertEqual(len(report["families"]), 26)
        self.assertEqual(len(report["capabilities"]), 223)
        for identifier in ("crypto.crypt", "crypto.crypt-helpers"):
            crypt_capability = next(
                row for row in report["capabilities"] if row["id"] == identifier
            )
            self.assertEqual(crypt_capability["x86_family"], "libc.c-abi-compat")
            self.assertEqual(crypt_capability["contract_state"], "selected-private")
        allocator_basic = next(
            row
            for row in report["capabilities"]
            if row["id"] == "memory.allocator-basic"
        )
        self.assertEqual(allocator_basic["x86_family"], "libc.c-abi-compat")
        self.assertEqual(allocator_basic["contract_state"], "selected-private")
        locale_core = next(
            row for row in report["capabilities"] if row["id"] == "locale.core"
        )
        self.assertEqual(locale_core["x86_family"], "libc.text-math-locale-stdio")
        self.assertEqual(locale_core["contract_state"], "selected-private")
        elementary_fenv_sensitive = next(
            row
            for row in report["capabilities"]
            if row["id"] == "math.elementary-fenv-sensitive"
        )
        self.assertEqual(
            elementary_fenv_sensitive["x86_family"],
            "libc.text-math-locale-stdio",
        )
        self.assertEqual(
            elementary_fenv_sensitive["contract_state"], "selected-private"
        )
        environment_mutation = next(
            row
            for row in report["capabilities"]
            if row["id"] == "process.environment-mutation"
        )
        self.assertEqual(environment_mutation["x86_family"], "libc.posix-runtime")
        self.assertEqual(
            environment_mutation["contract_state"], "selected-private"
        )
        filesystem_directory = next(
            row
            for row in report["capabilities"]
            if row["id"] == "filesystem.directory"
        )
        self.assertEqual(filesystem_directory["x86_family"], "libc.posix-runtime")
        self.assertEqual(
            filesystem_directory["contract_state"], "selected-private"
        )
        for identifier, family in (
            ("legacy.misc", "libc.c-abi-compat"),
            ("process.signal", "libc.posix-runtime"),
            ("stdio.fopen64-alias", "libc.text-math-locale-stdio"),
        ):
            capability = next(
                row for row in report["capabilities"] if row["id"] == identifier
            )
            self.assertEqual(capability["x86_family"], family)
            self.assertEqual(capability["contract_state"], "selected-private")
        process_globals = next(
            row for row in report["capabilities"] if row["id"] == "process.globals"
        )
        self.assertEqual(process_globals["x86_family"], "libc.c-abi-compat")
        self.assertEqual(process_globals["contract_state"], "missing")
        text_math = next(
            row for row in report["families"]
            if row["id"] == "libc.text-math-locale-stdio"
        )
        self.assertEqual(text_math["verified_slice_count"], 7)
        self.assertEqual(text_math["verified_artifact_count"], 76)
        self.assertIn(
            {
                "family": "libc.text-math-locale-stdio",
                "id": "static-c-uchar-stateful",
            },
            report["selected_private_artifacts"],
        )
        c_abi_compat = next(
            row for row in report["families"] if row["id"] == "libc.c-abi-compat"
        )
        self.assertEqual(c_abi_compat["verified_slice_count"], 9)
        self.assertEqual(c_abi_compat["verified_artifact_count"], 29)
        self.assertIn(
            {"family": "libc.c-abi-compat", "id": "static-c-issetugid"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.c-abi-compat",
                "id": "static-c-posix-spawnattr-setschedparam",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.c-abi-compat",
                "id": "static-c-crypt-allocator-composition",
            },
            report["selected_private_artifacts"],
        )
        pthread_tls = next(
            row for row in report["families"] if row["id"] == "libc.pthread-tls"
        )
        self.assertEqual(pthread_tls["contract_state"], "selected-private")
        self.assertEqual(pthread_tls["verified_slice_count"], 1)
        self.assertEqual(pthread_tls["verified_artifact_count"], 39)
        self.assertIn(
            {"family": "libc.pthread-tls", "id": "static-c-pthread-barrier"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.pthread-tls", "id": "static-c-pthread-attributes"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.posix-runtime",
                "id": "static-c-posix-spawnattr-getschedparam",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-file-handles"},
            report["selected_private_artifacts"],
        )
        posix_runtime = next(
            row for row in report["families"] if row["id"] == "libc.posix-runtime"
        )
        self.assertEqual(posix_runtime["verified_artifact_count"], 168)
        self.assertEqual(posix_runtime["verified_slice_count"], 6)
        resolver = next(
            row for row in report["families"] if row["id"] == "libc.resolver"
        )
        self.assertEqual(resolver["verified_artifact_count"], 20)
        self.assertIn(
            {"family": "libc.resolver", "id": "static-c-resolver-runtime"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.resolver",
                "id": "static-c-nameser-wire-aggregate",
            },
            report["selected_private_artifacts"],
        )
        self.assertEqual(
            sum(row["verified_artifact_count"] for row in report["families"]),
            374,
        )
        self.assertEqual(
            sum(row["verified_slice_count"] for row in report["families"]),
            49,
        )
        self.assertNotIn(
            {"family": "libc.posix-runtime", "id": "static-c-environment"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-usleep"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-ualarm"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-interval-timers"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.pthread-tls", "id": "static-c-pthread-spin-operations"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-mkdirat"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.posix-runtime",
                "id": "static-c-sched-setscheduler",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.posix-runtime",
                "id": "static-c-sched-setaffinity",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-signal-legacy-aliases"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-sysv-signal-helpers"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-wait-extensions"},
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.posix-runtime",
                "id": "static-c-filesystem-traversal",
            },
            report["selected_private_artifacts"],
        )
        headers_layouts = next(
            row for row in report["families"] if row["id"] == "libc.headers-layouts"
        )
        self.assertEqual(headers_layouts["verified_artifact_count"], 16)
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "static-c-atomic-addressable",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "header-callable-disposition",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "selected-header-install-projection",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "selected-header-callable-provider-linkage-audit",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "all-header-declaration-macro-feature-visibility-matrix",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "all-header-prototype-layout-matrix",
            },
            report["selected_private_artifacts"],
        )
        self.assertIn(
            {
                "family": "libc.headers-layouts",
                "id": "all-header-record-byte-layout-matrix",
            },
            report["selected_private_artifacts"],
        )
        self.assertEqual(
            {row["contract_state"] for row in report["capabilities"]},
            {"implemented-foundation", "selected-private", "missing"},
        )
        self.assertEqual(report["x86_boundary"]["selected_static_export_count"], 1189)
        self.assertEqual(
            report["x86_boundary"]["selected_static_exports_in_aarch64_dynamic_candidate_set"],
            1162,
        )
        self.assertEqual(
            report["unsupported_contracts"],
            [{
                "id": "allocator.mimalloc-private",
                "reason": "Private fixed-allocator evidence is neither crabc-libc integration nor x86 runtime/platform support.",
            }],
        )

    def test_sleep_wrapper_remains_a_private_posix_runtime_artifact(self) -> None:
        report = inventory.validate_inventory()
        posix_runtime = next(
            row for row in report["families"] if row["id"] == "libc.posix-runtime"
        )
        self.assertEqual(posix_runtime["contract_state"], "selected-private")
        self.assertEqual(posix_runtime["verified_artifact_count"], 168)
        self.assertIn(
            {"family": "libc.posix-runtime", "id": "static-c-sleep"},
            report["selected_private_artifacts"],
        )
        self.assertFalse(report["x86_boundary"]["promotion_ready"])
        self.assertFalse(report["x86_boundary"]["public_support"])

    def test_snapshot_rejects_any_unreviewed_derived_change(self) -> None:
        actual = inventory.build_inventory()
        expected = json.loads(inventory.INVENTORY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)
        altered = copy.deepcopy(expected)
        altered["x86_boundary"]["public_support"] = True
        self.assertNotEqual(actual, altered)

    def test_inventory_rejects_a_verified_slice_from_another_family(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        slices = family.setdefault("verified_slice", [])
        assert isinstance(slices, list)
        slices.append(
            {
                "id": "accounting-cross-family-regression",
                "capabilities": ["error.reporting-termination"],
                "native_evidence": [
                    {
                        "state": "verified",
                        "command": "./scripts/dev-x86_64.sh facade",
                        "scope": "fixture",
                    }
                ],
            }
        )

        with self.assertRaisesRegex(
            inventory.InventoryError, "escapes its owning family"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_duplicate_selected_capabilities(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        slices = family.setdefault("verified_slice", [])
        assert isinstance(slices, list)
        slices.append(
            {
                "id": "accounting-duplicate-capability-regression",
                "capabilities": ["filesystem.lchmod-unsupported"],
                "native_evidence": [
                    {
                        "state": "verified",
                        "command": "./scripts/dev-x86_64.sh facade",
                        "scope": "fixture",
                    }
                ],
            }
        )

        with self.assertRaisesRegex(
            inventory.InventoryError, "selected by more than one verified slice"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_duplicate_verified_record_ids(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        artifacts = family.setdefault("verified_artifact", [])
        assert isinstance(artifacts, list)
        artifacts.append(
            {
                "id": "static-c-error-strings",
                "native_evidence": [
                    {
                        "state": "verified",
                        "command": "./scripts/dev-x86_64.sh facade",
                        "scope": "fixture",
                    }
                ],
            }
        )

        with self.assertRaisesRegex(
            inventory.InventoryError, "duplicate verified record id"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_artifacts_that_carry_capabilities(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list) and artifacts
        artifact = artifacts[0]
        assert isinstance(artifact, dict)
        artifact["capabilities"] = ["filesystem.directory"]

        with self.assertRaisesRegex(
            inventory.InventoryError, "must not carry capabilities"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_a_selected_slice_without_verified_evidence(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        slices = family["verified_slice"]
        assert isinstance(slices, list)
        selected = next(
            entry
            for entry in slices
            if entry["id"] == "filesystem.lchmod-unsupported"
        )
        assert isinstance(selected, dict)
        evidence = selected["native_evidence"]
        assert isinstance(evidence, list) and evidence
        record = evidence[0]
        assert isinstance(record, dict)
        record["state"] = "required"

        with self.assertRaisesRegex(
            inventory.InventoryError, "must be entirely verified"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_a_selected_artifact_without_verified_evidence(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.c-abi-compat")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        selected = next(
            entry for entry in artifacts if entry["id"] == "static-c-error-strings"
        )
        assert isinstance(selected, dict)
        evidence = selected["native_evidence"]
        assert isinstance(evidence, list) and evidence
        record = evidence[0]
        assert isinstance(record, dict)
        record["state"] = "required"

        with self.assertRaisesRegex(
            inventory.InventoryError, "must be entirely verified"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_a_selected_artifact_with_duplicate_evidence_command(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.c-abi-compat")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        selected = next(
            entry for entry in artifacts if entry["id"] == "static-c-error-strings"
        )
        assert isinstance(selected, dict)
        evidence = selected["native_evidence"]
        assert isinstance(evidence, list) and evidence
        record = evidence[0]
        assert isinstance(record, dict)
        evidence.append(copy.deepcopy(record))

        with self.assertRaisesRegex(
            inventory.InventoryError, "duplicates a native evidence command"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_a_selected_slice_with_a_non_verifying_evidence_command(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.posix-runtime")
        slices = family["verified_slice"]
        assert isinstance(slices, list)
        selected = next(
            entry
            for entry in slices
            if entry["id"] == "filesystem.lchmod-unsupported"
        )
        assert isinstance(selected, dict)
        evidence = selected["native_evidence"]
        assert isinstance(evidence, list) and evidence
        record = evidence[0]
        assert isinstance(record, dict)
        record["command"] = "./scripts/dev-x86_64.sh image"

        with self.assertRaisesRegex(
            inventory.InventoryError, "registered native evidence command"
        ):
            self.build_with_x86_ledger(data)

    def test_inventory_rejects_a_selected_artifact_with_an_unregistered_evidence_command(self) -> None:
        data = inventory.load_toml(inventory.X86_LEDGER_PATH)
        family = self.family(data, "libc.c-abi-compat")
        artifacts = family["verified_artifact"]
        assert isinstance(artifacts, list)
        selected = next(
            entry for entry in artifacts if entry["id"] == "static-c-error-strings"
        )
        assert isinstance(selected, dict)
        evidence = selected["native_evidence"]
        assert isinstance(evidence, list) and evidence
        record = evidence[0]
        assert isinstance(record, dict)
        record["command"] = "./crt/run-x86_64.sh invented-readiness-claim"

        with self.assertRaisesRegex(
            inventory.InventoryError, "registered native evidence command"
        ):
            self.build_with_x86_ledger(data)


if __name__ == "__main__":
    unittest.main()
