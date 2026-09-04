#!/usr/bin/env python3
"""Path-boundary tests for the allocator compiler-TLS evidence runners."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def load_runner(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


AARCH64 = load_runner(
    "crabc_allocator_tls_codegen_aarch64",
    "compat/allocator/tls-codegen/run.py",
)
X86_64 = load_runner(
    "crabc_allocator_tls_codegen_x86_64_work_root",
    "compat/allocator/tls-codegen/run-x86_64.py",
)


class WorkRootTests(unittest.TestCase):
    def test_default_paths_are_repository_local_for_both_architecture_judges(self) -> None:
        for runner, filename in (
            (AARCH64, "tls-codegen.json"),
            (X86_64, "tls-codegen-x86_64.json"),
        ):
            with self.subTest(filename=filename):
                work_root = runner.default_work_root()
                self.assertEqual(runner.WORK_ROOT, work_root)
                self.assertEqual(runner.TEMP_ROOT, work_root / "tmp/allocator")
                self.assertEqual(
                    runner.REPORT,
                    work_root / "reports/allocator" / filename,
                )

    def test_crabc_work_dir_override_is_shared_by_both_architecture_judges(self) -> None:
        for runner in (AARCH64, X86_64):
            with self.subTest(runner=runner.__name__), mock.patch.dict(
                runner.os.environ,
                {"CRABC_WORK_DIR": "allocator-work-root"},
                clear=True,
            ):
                self.assertEqual(
                    runner.default_work_root(),
                    ROOT / "allocator-work-root",
                )

    def test_temporary_directories_stay_below_each_runner_work_root(self) -> None:
        for runner in (AARCH64, X86_64):
            with self.subTest(runner=runner.__name__), runner.temporary_directory(
                "crabc-allocator-tls-work-root-"
            ) as temporary:
                self.assertEqual(
                    Path(temporary).resolve().parent,
                    runner.TEMP_ROOT.resolve(),
                )


if __name__ == "__main__":
    unittest.main()
