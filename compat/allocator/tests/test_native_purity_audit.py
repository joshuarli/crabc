#!/usr/bin/env python3
"""Focused contract tests for the standalone native-shadow purity audit."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
HARNESS_PATH = ROOT / "compat/allocator/native_purity_audit.py"
SPEC = importlib.util.spec_from_file_location("native_purity_audit", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def write_fingerprint(path: Path, features: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "features": json.dumps(features),
                "declared_features": json.dumps(features),
            }
        ),
        encoding="utf-8",
    )


def fingerprint_path(root: Path, identity: str) -> Path:
    return root / "target/debug/.fingerprint" / f"crabc-libc-{identity}" / "lib-c.json"


def inspection(path: Path, backend: str, embedded_symbols: list[str]) -> dict[str, object]:
    routes = (
        HARNESS.SELECTED_NATIVE_ROUTES
        if backend == HARNESS.SELECTED_BACKEND
        else HARNESS.DEFAULT_C_ROUTES
    )
    return {
        "artifact": HARNESS.file_record(path),
        "backend": backend,
        "elf_identity": HARNESS.AARCH64_ELF_IDENTITY,
        "public_allocator_routes": [
            {
                "symbol": symbol,
                "required_direct_target_fragment": target,
                "direct_branch_targets": [f"crabc::{target}"],
                "forbidden_direct_target_fragments": [],
            }
            for symbol, target in routes.items()
        ],
        "embedded_mimalloc_api_symbols": embedded_symbols,
    }


class NativePurityAuditTests(unittest.TestCase):
    """Keep the selected-shadow boundary explicit and non-promotional."""

    def test_audit_identifies_distinct_builds_but_refuses_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "selected-libc.so"
            default = root / "default-libc.so"
            selected.write_bytes(b"selected native shadow")
            default.write_bytes(b"ordinary C backend")
            selected_fingerprint = fingerprint_path(root, "selected")
            default_fingerprint = fingerprint_path(root, "default")
            write_fingerprint(selected_fingerprint, ["default", "native-mimalloc-shadow"])
            write_fingerprint(default_fingerprint, ["default"])

            selected_observation = inspection(
                selected,
                HARNESS.SELECTED_BACKEND,
                ["mi_free", "mi_malloc_aligned"],
            )
            default_observation = inspection(default, HARNESS.DEFAULT_BACKEND, ["mi_free"])
            with mock.patch.object(
                HARNESS,
                "inspect_artifact",
                side_effect=[selected_observation, default_observation],
            ):
                report = HARNESS.audit_selected_shadow(
                    str(selected),
                    str(selected_fingerprint),
                    str(default),
                    str(default_fingerprint),
                )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["scope"]["evidence_scope"], "shadow_subset")
        self.assertTrue(report["scope"]["selected_nondefault_shadow"])
        self.assertFalse(report["scope"]["default_backend_complete"])
        self.assertFalse(report["scope"]["promotion_complete"])
        self.assertFalse(report["scope"]["full_runtime_pure_rust"])
        self.assertEqual(
            report["selected"]["cargo_features"],
            ["default", "native-mimalloc-shadow"],
        )
        self.assertEqual(report["default"]["cargo_features"], ["default"])
        self.assertEqual(
            report["selected"]["embedded_mimalloc_api_symbols"],
            ["mi_free", "mi_malloc_aligned"],
        )
        self.assertEqual(
            report["no_c_allocator_fallback"]["status"],
            "passed_at_direct_public_allocator_routes",
        )

    def test_scope_remains_non_promotional_when_no_mimalloc_symbols_are_observed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "selected-libc.so"
            default = root / "default-libc.so"
            selected.write_bytes(b"selected native shadow")
            default.write_bytes(b"ordinary C backend")
            selected_fingerprint = fingerprint_path(root, "selected")
            default_fingerprint = fingerprint_path(root, "default")
            write_fingerprint(selected_fingerprint, ["default", "native-mimalloc-shadow"])
            write_fingerprint(default_fingerprint, ["default"])

            with mock.patch.object(
                HARNESS,
                "inspect_artifact",
                side_effect=[
                    inspection(selected, HARNESS.SELECTED_BACKEND, []),
                    inspection(default, HARNESS.DEFAULT_BACKEND, []),
                ],
            ):
                report = HARNESS.audit_selected_shadow(
                    selected,
                    selected_fingerprint,
                    default,
                    default_fingerprint,
                )

        self.assertEqual(
            report["selected"]["embedded_mimalloc_artifact_fact"]["status"],
            "not_observed",
        )
        self.assertFalse(report["scope"]["promotion_complete"])
        self.assertFalse(report["scope"]["full_runtime_pure_rust"])

    def test_fingerprint_requires_the_exact_nondefault_selected_feature_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fingerprint = fingerprint_path(Path(temporary), "wrong-features")
            write_fingerprint(fingerprint, ["default"])

            with self.assertRaisesRegex(HARNESS.NativePurityAuditError, "feature identity"):
                HARNESS.cargo_fingerprint(
                    fingerprint,
                    ["default", "native-mimalloc-shadow"],
                    "selected native shadow",
                )

    def test_elf_identity_rejects_x86_instead_of_treating_it_as_native_evidence(self) -> None:
        header = """ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
"""

        with self.assertRaisesRegex(HARNESS.NativePurityAuditError, "AArch64"):
            HARNESS.attested_aarch64_elf_identity(header, "selected artifact")

    def test_selected_routes_reject_direct_mimalloc_fallback(self) -> None:
        dynamic_symbols = (
            "   1: 0000000000001000    16 FUNC    WEAK   DEFAULT   12 free\n"
        )
        disassemblies = {"free": "    1000: 94000000 bl 2000 <mi_free>\n"}

        with self.assertRaisesRegex(HARNESS.NativePurityAuditError, "forbidden"):
            HARNESS.attest_public_allocator_routes(
                dynamic_symbols,
                disassemblies,
                {"free": "native_free"},
                ("mi_",),
                "selected native shadow",
            )

    def test_default_routes_reject_a_native_shadow_artifact(self) -> None:
        dynamic_symbols = (
            "   1: 0000000000001000    16 FUNC    WEAK   DEFAULT   12 free\n"
        )
        disassemblies = {"free": "    1000: 94000000 bl 2000 <crabc::native_free>\n"}

        with self.assertRaisesRegex(HARNESS.NativePurityAuditError, "forbidden"):
            HARNESS.attest_public_allocator_routes(
                dynamic_symbols,
                disassemblies,
                {"free": "mi_free"},
                HARNESS.NATIVE_ROUTE_FRAGMENTS,
                "ordinary C backend",
            )

    def test_same_artifact_cannot_stand_for_selected_and_default_backends(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            libc = root / "libc.so"
            libc.write_bytes(b"one artifact")
            selected_fingerprint = fingerprint_path(root, "selected")
            default_fingerprint = fingerprint_path(root, "default")
            write_fingerprint(selected_fingerprint, ["default", "native-mimalloc-shadow"])
            write_fingerprint(default_fingerprint, ["default"])

            with self.assertRaisesRegex(HARNESS.NativePurityAuditError, "must differ"):
                HARNESS.audit_selected_shadow(
                    libc,
                    selected_fingerprint,
                    libc,
                    default_fingerprint,
                )

    def test_embedded_mimalloc_api_symbols_are_an_observed_artifact_fact(self) -> None:
        symbols = """\
  10: 0000000000001000    16 FUNC    LOCAL  DEFAULT   12 mi_free
  11: 0000000000001010    16 FUNC    LOCAL  DEFAULT   12 mi_malloc_aligned
  12: 0000000000001020    16 FUNC    LOCAL  DEFAULT   12 unrelated
  13: 0000000000001030    16 FUNC    LOCAL  DEFAULT   12 mi_heap_free
"""

        self.assertEqual(
            HARNESS.embedded_mimalloc_api_symbols(symbols),
            ["mi_free", "mi_malloc_aligned"],
        )


if __name__ == "__main__":
    unittest.main()
