#!/usr/bin/env python3
"""Focused rejection checks for the installed synthetic-loader component."""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "compat" / "ldso" / "run_x86.py"


def runner():
    spec = importlib.util.spec_from_file_location("owned_loader_synthetic", SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OwnedLoaderSyntheticTests(unittest.TestCase):
    def test_roster_is_the_complete_frozen_loader_set(self) -> None:
        module = runner()
        self.assertEqual(
            tuple(module.CASES),
            (
                "nested-needed", "nested-dlopen", "search-path", "dso-origin",
                "initial-tls", "dlerror", "hash-formats", "hash-many", "relro",
                "auxv", "legacy-lifecycle", "lookup-scope", "visibility",
                "constructor-order", "main-handle", "lifecycle", "preload", "aslr",
                "dynamic-tls", "relocations", "weak-strong",
            ),
        )

    def test_wrapper_refuses_to_build_without_a_supplied_product(self) -> None:
        scratch = ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        result = subprocess.run(
            [ROOT / "compat/x86_64/run_owned_loader_synthetic.sh"],
            env={"PATH": "/usr/bin:/bin", "TMPDIR": str(scratch)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"usage:", result.stderr)

    def test_exact_observation_rejects_stream_or_status_changes(self) -> None:
        module = runner()
        good = module.ProcessResult(("/consumer",), 0, b"nested=42\n", b"", False)
        self.assertTrue(module.same_observation(good, good))
        self.assertFalse(module.same_observation(good, module.ProcessResult(("/consumer",), 1, b"nested=42\n", b"", False)))
        self.assertFalse(module.same_observation(good, module.ProcessResult(("/consumer",), 0, b"nested=42\n", b"loader\n", False)))

    def test_aslr_only_normalizes_the_required_base_relation(self) -> None:
        module = runner()
        first = module.ProcessResult(("/consumer",), 0, b"aslr=7 main=0x1000 dso=0x2000\n", b"", False)
        second = module.ProcessResult(("/consumer",), 0, b"aslr=7 main=0x3000 dso=0x4000\n", b"", False)
        self.assertTrue(module.valid_aslr_pair((first, second)))
        self.assertFalse(module.valid_aslr_pair((first, first)))
        self.assertFalse(module.valid_aslr_pair((first, module.ProcessResult(("/consumer",), 0, b"aslr=7\n", b"", False))))

    def test_lifecycle_keeps_markers_then_uses_exact_musl_stream(self) -> None:
        module = runner()
        observed = module.ProcessResult(("/consumer",), 0, b"ctor\nlifecycle=73\ndtor\nafter-close\nreopened=73\n", b"", False)
        self.assertTrue(module.valid_lifecycle_stream(observed))
        self.assertFalse(module.valid_lifecycle_stream(module.ProcessResult(("/consumer",), 0, b"ctor\nlifecycle=73\n", b"", False)))

    def test_rejects_a_symlinked_supplied_product_before_resolution(self) -> None:
        module = runner()
        scratch = ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            base = pathlib.Path(directory)
            real = base / "real"
            real.mkdir()
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(module.LoaderSyntheticError):
                module.checked_product_directory(alias)

    def test_x86_relocation_contract_requires_each_frozen_class(self) -> None:
        module = runner()
        required = {"R_X86_64_RELATIVE", "R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"}
        self.assertTrue(module.has_required_relocations(required))
        self.assertFalse(module.has_required_relocations(required - {"R_X86_64_64"}))

    def test_x86_relocation_adapter_keeps_the_original_and_local_classes_distinct(self) -> None:
        module = runner()
        original = {"R_X86_64_64", "R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"}
        self.assertTrue(module.valid_x86_relocation_fixture(original, {"R_X86_64_RELATIVE"}))
        self.assertFalse(module.valid_x86_relocation_fixture(original, set()))
        self.assertFalse(module.valid_x86_relocation_fixture(original - {"R_X86_64_64"}, {"R_X86_64_RELATIVE"}))


if __name__ == "__main__":
    unittest.main()
