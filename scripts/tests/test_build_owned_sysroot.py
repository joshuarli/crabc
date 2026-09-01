#!/usr/bin/env python3
"""Focused contracts for the owned static-runtime archive boundary."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "crabc_build_owned_sysroot_test", ROOT / "scripts/build_owned_sysroot.py"
)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILD
SPEC.loader.exec_module(BUILD)


class StaticRuntimeArchiveTests(unittest.TestCase):
    def test_default_reports_stay_under_the_repository_work_directory(self) -> None:
        self.assertEqual(BUILD.WORK_DIR, ROOT / ".work")
        self.assertEqual(BUILD.REPORT, ROOT / ".work/reports/sysroot/latest.json")
        self.assertEqual(
            BUILD.STATIC_PTHREAD_REPORT,
            ROOT / ".work/reports/static-pthread-tls/latest.json",
        )

    def test_selects_only_runtime_and_documented_allocator_members(self) -> None:
        members = [
            "c.c.0123456789abcdef-cgu.0.rcgu.o",
            "aabb8c858634ccbb-lse_cas8_acq_rel.o",
            "b85de32113adef8e-static.o",
            "compiler_builtins-b672.compiler_builtins-cgu.000.rcgu.o",
            "45c91108d938afe8-addvdi3.o",
        ]

        selection = BUILD.select_static_runtime_members(members)

        self.assertEqual(selection.runtime_member, members[0])
        self.assertEqual(selection.allocator_member, members[2])
        self.assertEqual(selection.selected_members, (members[0], members[2]))
        self.assertEqual(selection.excluded_members, tuple(members[1:2] + members[3:]))

    def test_rejects_unclassified_staticlib_members(self) -> None:
        members = [
            "c.c.0123456789abcdef-cgu.0.rcgu.o",
            "b85de32113adef8e-static.o",
            "unreviewed-transitive-runtime.o",
        ]

        with self.assertRaises(BUILD.BuildError):
            BUILD.select_static_runtime_members(members)

    def test_runtime_build_environment_disables_outline_atomics_for_rust_and_c(self) -> None:
        environment = BUILD.deterministic_environment()

        self.assertEqual(
            environment["CFLAGS_aarch64_unknown_linux_musl"],
            "-mno-outline-atomics",
        )
        self.assertIn("target-feature=-crt-static,-outline-atomics", environment["CARGO_ENCODED_RUSTFLAGS"])
        self.assertIn("-Ztls-model=initial-exec", environment["CARGO_ENCODED_RUSTFLAGS"])

    def test_exclusive_build_lock_rejects_a_second_sysroot_producer(self) -> None:
        child = "\n".join(
            (
                "import importlib.util",
                "import sys",
                "from pathlib import Path",
                "spec = importlib.util.spec_from_file_location('child_build_owned_sysroot', sys.argv[2])",
                "assert spec is not None and spec.loader is not None",
                "build = importlib.util.module_from_spec(spec)",
                "sys.modules[spec.name] = build",
                "spec.loader.exec_module(build)",
                "try:",
                "    with build.exclusive_owned_sysroot_build_lock(Path(sys.argv[1])):",
                "        print('acquired')",
                "except build.BuildError as error:",
                "    print(error)",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "owned-sysroot.lock"
            with BUILD.exclusive_owned_sysroot_build_lock(lock_path):
                completed = subprocess.run(
                    [sys.executable, "-c", child, str(lock_path), str(ROOT / "scripts/build_owned_sysroot.py")],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.strip(),
            "owned sysroot build is already active; its producer owns the generated target trees",
        )


if __name__ == "__main__":
    unittest.main()
