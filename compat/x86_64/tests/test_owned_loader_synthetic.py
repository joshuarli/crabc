#!/usr/bin/env python3
"""Focused rejection checks for the installed synthetic-loader component."""

from __future__ import annotations

import importlib.util
import math
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "compat" / "ldso" / "run_x86.py"


def runner():
    spec = importlib.util.spec_from_file_location("owned_loader_synthetic", SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def qualification():
    directory = str(ROOT / "compat" / "x86_64")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import owned_dynamic_qualification
    return owned_dynamic_qualification


class OwnedLoaderSyntheticTests(unittest.TestCase):
    def test_recorder_timeout_reaps_a_session_escaping_descendant(self) -> None:
        """A timed-out fixture cannot leave a private session alive."""
        module = runner()
        scratch = ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            work = pathlib.Path(directory)
            pid_path = work / "escaped.pid"
            program = """\
import os
import pathlib
import sys
import time

child = os.fork()
if child == 0:
    os.setsid()
    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
    while True:
        time.sleep(1)
while not pathlib.Path(sys.argv[1]).exists():
    time.sleep(0.01)
time.sleep(30)
"""
            result = module.Recorder(work, 0.2).run(
                "session-escape", [sys.executable, "-c", program, pid_path], cwd=work
            )
            self.assertTrue(result.timed_out)
            deadline = time.monotonic() + 2
            child = int(pid_path.read_text())
            try:
                while pathlib.Path(f"/proc/{child}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(pathlib.Path(f"/proc/{child}").exists())
            finally:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass

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

    def test_selection_and_timeout_inputs_are_bounded_before_work_creation(self) -> None:
        module = runner()
        self.assertEqual(module.checked_selection(None), module.CASES)
        subset = module.checked_selection(("auxv",))
        self.assertEqual(subset, ("auxv",))
        self.assertTrue(module.selected_passed({"auxv": {"status": "pass"}}))
        self.assertFalse(module.exact_component_selection(subset))
        self.assertTrue(module.exact_component_selection(module.CASES))
        for selection in ((), ("auxv", "auxv"), ("not-a-case",)):
            with self.subTest(selection=selection), self.assertRaises(module.LoaderSyntheticError):
                module.checked_selection(selection)
        for value in (0.0, -1.0, math.inf, -math.inf, math.nan):
            with self.subTest(timeout=value), self.assertRaises(module.LoaderSyntheticError):
                module.checked_timeout(value)

    def test_invalid_product_is_rejected_before_checkout_work_is_created(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            root = pathlib.Path(directory)
            missing = root / "missing-product"
            with mock.patch.object(module, "ROOT", root), self.assertRaises(module.LoaderSyntheticError):
                module.preflight(missing, None, 20.0)
            self.assertFalse((root / ".work").exists())

    def test_checkout_scratch_rejects_a_symlink_before_mkdir(self) -> None:
        module = runner()
        with tempfile.TemporaryDirectory(dir=ROOT / ".work") as directory:
            root = pathlib.Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (root / ".work").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(module.LoaderSyntheticError):
                module.checked_scratch_directory(root)

    def test_catalogue_evidence_line_names_only_the_retained_directory(self) -> None:
        module = runner()
        catalogue = qualification()
        scratch = ROOT / ".work" / "test-owned-loader-synthetic-catalogue"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            leaf = pathlib.Path(directory)
            receipt = leaf / "report.json"
            receipt.write_text("{}\n")
            log = leaf / "runner.log"
            log.write_text("\n".join(module.summary_lines(False, leaf, receipt)) + "\n")
            self.assertEqual(catalogue.leaf_evidence_directories(log, str(ROOT)), {leaf})

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
