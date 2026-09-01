#!/usr/bin/env python3
"""Focused fail-closed evidence for the no-Clang GCC backend investigation."""

from __future__ import annotations

import importlib.util
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PROBE_PATH = ROOT / "compat" / "x86_64" / "header_callable_gcc_fallback_probe.py"
PLUGIN_PATH = ROOT / "compat" / "x86_64" / "header_callable_gcc_plugin_compile_probe.cc"
DOCKERFILE_PATH = ROOT / "docker" / "Dockerfile.x86_64"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROBE = load_module("header_callable_gcc_fallback_probe_test", PROBE_PATH)


class HeaderCallableGccFallbackProbeTests(unittest.TestCase):
    def test_probe_keeps_canonical_inventory_and_promotion_boundaries_closed(self) -> None:
        source = PROBE_PATH.read_text(encoding="utf-8")
        plugin = PLUGIN_PATH.read_text(encoding="utf-8")
        self.assertIn("PLUGIN_FINISH_DECL", plugin)
        for field in ("DECL_SOURCE_FILE", "DECL_EXTERNAL", "TREE_STATIC", "DECL_DECLARED_INLINE_P", "DECL_INITIAL"):
            self.assertIn(field, plugin)
        self.assertIn("gmp-dev", source)
        self.assertIn("-E", source)
        self.assertIn("-dD", source)
        self.assertIn("header_text_parsing\": False", source)
        self.assertIn("canonical_inventory_changed\": False", source)
        self.assertNotIn("header_callable_inventory.py\"", source)
        self.assertNotIn("gmp-dev", DOCKERFILE_PATH.read_text(encoding="utf-8"))

    @unittest.skipUnless(
        platform.system() == "Linux"
        and platform.machine() in {"x86_64", "amd64"}
        and all(shutil.which(tool) for tool in ("gcc", "g++")),
        "requires native Linux/x86-64 GCC and G++",
    )
    def test_existing_toolchain_is_explicitly_blocked_without_a_docker_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            result = subprocess.run(
                [sys.executable, str(PROBE_PATH), "--require-no-docker-blocker", "--output", str(output)],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(report["schema"], PROBE.SCHEMA)
        self.assertEqual(report["summary"]["status"], "blocked-missing-gmp-dev")
        self.assertFalse(report["summary"]["no_docker_dependency_backend_available"])
        self.assertFalse(report["toolchain"]["gmp_header_installed"])
        self.assertEqual(report["custom_plugin_compile"]["status"], "compile-failed")
        self.assertTrue(report["custom_plugin_compile"]["missing_gmp_header"])
        self.assertIn("gmp.h", report["custom_plugin_compile"]["detail"])
        self.assertFalse(report["existing_compiler_routes"]["tree_original_raw"]["contains_archive_owner"])
        self.assertTrue(report["existing_compiler_routes"]["tree_original_raw"]["contains_header_local"])
        self.assertTrue(report["existing_compiler_routes"]["go_spec"]["contains_archive_owner"])
        self.assertFalse(report["existing_compiler_routes"]["go_spec"]["contains_header_local"])
        self.assertTrue(report["existing_compiler_routes"]["preprocessor_records"]["contains_callback_macro"])
        self.assertIn("gmp-dev", report["summary"]["exact_user_approval_boundary"])


if __name__ == "__main__":
    unittest.main()
