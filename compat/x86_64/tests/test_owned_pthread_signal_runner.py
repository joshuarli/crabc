"""Pthread signal evidence keeps one installed-header workload across products."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_pthread_signal.sh"
LEGACY = ROOT / "compat/x86_64/run_general_dynamic_pthread_signal.sh"
PROBE = ROOT / "compat/x86_64/owned_pthread_signal_probe.c"


class OwnedPthreadSignalRunnerTests(unittest.TestCase):
    def test_supplied_dynamic_escape_is_rejected_before_evidence_creation(self) -> None:
        scratch_root = ROOT / ".work/x86_64/owned-pthread-signal-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            scratch = Path(temporary)
            escaped = scratch / "escaped-product"
            escaped.symlink_to(ROOT, target_is_directory=True)
            result = subprocess.run(
                ["bash", str(RUNNER), str(escaped)],
                cwd=ROOT,
                env={**os.environ, "TMPDIR": str(scratch)},
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "pthread-signal dynamic product must be a physical checkout .work directory",
                result.stderr,
            )
            self.assertNotIn("owned pthread signal evidence:", result.stdout)

    def test_optional_static_product_is_preflighted_before_evidence_creation(self) -> None:
        scratch_root = ROOT / ".work/x86_64/owned-pthread-signal-runner-tests"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            scratch = Path(temporary)
            dynamic = scratch / "dynamic-product"
            dynamic.mkdir()
            escaped = scratch / "escaped-static-product"
            escaped.symlink_to(ROOT, target_is_directory=True)
            result = subprocess.run(
                ["bash", str(RUNNER), "--static-sysroot", str(escaped), str(dynamic)],
                cwd=ROOT,
                env={**os.environ, "TMPDIR": str(scratch)},
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "pthread-signal static product must be a physical checkout .work directory",
                result.stderr,
            )
            self.assertNotIn("owned pthread signal evidence:", result.stdout)

    def test_one_installed_driver_object_binds_every_product_link_and_raw_run(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        compile_object = (
            '"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 '
            '-fno-builtin -c "$probe" -o "$work/workload.o"'
        )

        self.assertIn(compile_object, source)
        self.assertEqual(source.count(compile_object), 1)
        self.assertIn('"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"', source)
        self.assertIn('"$static_sysroot/bin/crabc-cc" "-$mode" --link-receipt "$mode.receipt.json"', source)
        self.assertIn('"$work/workload.o" -o "$work/$mode"', source)
        self.assertIn('"$dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o"', source)
        self.assertIn('audit_link "$static_sysroot" "$work/$mode" "$work/$mode.receipt.json" "$mode"', source)
        self.assertIn('audit_link "$dynamic_sysroot" "$work/dynamic-$mode"', source)
        self.assertIn('for entry in kernel direct; do', source)
        self.assertIn('/lib/ld-crabc-x86_64.so.1 "/consumer-$mode"', source)
        self.assertIn('"$output" 2>"${output%.stdout}.stderr"', source)
        self.assertIn('"${output%.stdout}.status"', source)
        self.assertIn('for suffix in stdout stderr status; do', source)
        self.assertIn('validate_link', source)
        self.assertIn('workload.d', source)
        self.assertIn('compile.json', source)

    def test_cli_is_strict_and_preflights_products_before_creating_evidence(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        self.assertIn('usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT', source)
        self.assertLess(source.index('python3 -B - "$ROOT"'), source.index('mktemp -d'))
        self.assertIn('pthread-signal {label} product must be a physical checkout .work directory', source)
        self.assertIn("supplied_tree(dynamic_input, 'dynamic')", source)
        self.assertIn("supplied_tree(static_input, 'static')", source)

    def test_each_execution_uses_the_original_task_retirement_witness(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")

        self.assertIn('readonly probe="$ROOT/compat/x86_64/owned_pthread_signal_probe.c"', runner)
        self.assertIn('mount -t proc -o ro,nosuid,nodev,noexec proc "$execution_root/proc"', runner)
        self.assertIn('wait_for_kernel_exit', probe)
        self.assertIn('"/proc/self/task/%ld"', probe)
        self.assertIn('CHECK(wait_for_kernel_exit(state.tid) == 0);', probe)

    def test_legacy_qualification_name_remains_a_one_argument_launcher(self) -> None:
        source = LEGACY.read_text(encoding="utf-8")

        self.assertIn('Legacy dynamic-qualification launcher.', source)
        self.assertIn('[ "$#" -eq 1 ] || exit 2', source)
        self.assertIn('exec "$ROOT/compat/x86_64/run_owned_pthread_signal.sh" "$1"', source)


if __name__ == "__main__":
    unittest.main()
