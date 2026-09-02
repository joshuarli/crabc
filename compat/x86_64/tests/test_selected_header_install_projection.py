#!/usr/bin/env python3
"""Focused contract for the x86 selected installed-header projection."""

from __future__ import annotations

import importlib.util
import stat
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PROJECTION_PATH = ROOT / "compat" / "x86_64" / "selected_header_install_projection.py"
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "selected-header-install-projection.toml"
RUNNER_PATH = ROOT / "compat" / "x86_64" / "run_selected_header_install_projection.sh"
CXX_PROBE_PATH = ROOT / "compat" / "x86_64" / "selected_header_install_projection_cxx.cpp"
PUBLIC_HEADERS_PATH = ROOT / "compat" / "x86_64" / "public_headers.txt"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROJECTION = load_module("selected_header_install_projection_test", PROJECTION_PATH)


class SelectedHeaderInstallProjectionTests(unittest.TestCase):
    def test_contract_closes_the_eight_source_only_paths_without_mutating_them(self) -> None:
        contract = PROJECTION.load_contract(CONTRACT_PATH)
        expected_public = tuple(PUBLIC_HEADERS_PATH.read_text(encoding="utf-8").splitlines())

        self.assertEqual(contract.target_family, "libc.headers-layouts")
        self.assertEqual(contract.target_obligation, "project-only-extension-policy")
        self.assertEqual(contract.selected_headers, expected_public)
        self.assertEqual(contract.profile_count, 7)
        self.assertEqual(contract.projection_row_count, 1281)
        self.assertEqual(
            [(entry.path, entry.disposition) for entry in contract.exclusions],
            [
                ("daemon.h", "excluded-from-x86-selected-install-surface"),
                ("dn_expand.h", "excluded-from-x86-selected-install-surface"),
                ("linux/capability.h", "excluded-from-x86-selected-install-surface"),
                ("lrand48.h", "excluded-from-x86-selected-install-surface"),
                ("pthread_atfork.h", "excluded-from-x86-selected-install-surface"),
                ("stdatomic.h", "excluded-from-x86-selected-install-surface"),
                ("strverscmp.h", "excluded-from-x86-selected-install-surface"),
                ("sys/module.h", "excluded-from-x86-selected-install-surface"),
            ],
        )
        self.assertTrue(all((ROOT / "include" / entry.path).is_file() for entry in contract.exclusions))

    def test_contract_rejects_an_unclassified_source_only_path(self) -> None:
        raw = PROJECTION.load_toml(CONTRACT_PATH)
        exclusions = raw["excluded_header"]
        assert isinstance(exclusions, list)
        exclusions.pop()

        with self.assertRaisesRegex(PROJECTION.ProjectionError, "source-only header roster"):
            PROJECTION.parse_contract(raw, CONTRACT_PATH)

    def test_runner_materializes_only_the_selected_x86_surface(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(RUNNER_PATH)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER_PATH.stat().st_mode), 0o755)
        runner = RUNNER_PATH.read_text(encoding="utf-8")

        for phrase in (
            "selected-header-install-projection",
            "readonly EXPECTED_SELECTED_PUBLIC_HEADER_COUNT=183",
            "readonly EXPECTED_EXCLUDED_PROJECT_ONLY_HEADER_COUNT=8",
            "readonly EXPECTED_PROFILE_COUNT=7",
            "readonly EXPECTED_PROJECTION_RECORD_COUNT=1281",
            "materialize_selected_tree",
            "selected header projection differs from the source selection",
            "excluded project-only header entered the selected install tree",
            "candidate include trace reached source include tree",
            "candidate include trace escaped selected install/builtin/Linux-5.10 roots",
            "-nostdinc",
            "-nostdinc++",
            "run_linux_5_10_uapi.sh",
            "selected_header_install_projection_cxx.cpp",
        ):
            self.assertIn(phrase, runner)

    def test_projection_cxx_probe_exercises_only_selected_headers(self) -> None:
        probe = CXX_PROBE_PATH.read_text(encoding="utf-8")
        self.assertIn("#include <aio.h>", probe)
        self.assertIn("#include <regex.h>", probe)
        self.assertIn("#include <uchar.h>", probe)
        self.assertNotIn("#include <stdatomic.h>", probe)
        self.assertIn("c16rtomb", probe)
        self.assertIn("regexec", probe)


if __name__ == "__main__":
    unittest.main()
