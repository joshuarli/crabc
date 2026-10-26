#!/usr/bin/env python3
"""Regression contract for installed binary80 long-double completion."""

from __future__ import annotations

from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_math_long_double_completion.sh"
FEATURE_RUNNER = ROOT / "compat/x86_64/run_libc_math_long_double_completion.sh"
PROBE = ROOT / "compat/x86_64/libc_math_long_double_completion_probe.c"
VALIDATOR = ROOT / "compat/x86_64/validate_libc_math_long_double_completion.py"
MODULE = ROOT / "libc/src/c_abi/x86_64/math_long_double_completion.rs"
ASSEMBLY = ROOT / "libc/src/c_abi/x86_64/math_long_double_completion_musl_x86_64.S"


def simulated_feature_runner(root: Path) -> Path:
    runner = root / "compat/x86_64/run_libc_math_long_double_completion.sh"
    runner.parent.mkdir(parents=True)
    fake_compiler = root / "tools/crabc-x86_64-musl-gcc"
    fake_compiler.parent.mkdir(parents=True)
    fake_compiler.write_text(f'''#!/bin/sh
set -eu
root='{root}'
preprocessor=0
for argument in "$@"; do
    [ "$argument" != -E ] || preprocessor=1
done
if [ "$preprocessor" -eq 1 ]; then
    for header in fenv.h float.h math.h stddef.h stdint.h features.h bits/alltypes.h; do
        printf '#include "%s/include/%s"\\n' "$root" "$header" >&2
    done
    exit 0
fi
output=''
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then
        output="$2"
        shift 2
    else
        shift
    fi
done
cat > "$output" <<'SH'
#!/bin/sh
printf 'fixture records\\n'
SH
chmod +x "$output"
''', encoding="utf-8")
    fake_compiler.chmod(0o755)
    original = FEATURE_RUNNER.read_text(encoding="utf-8")
    runner_text = original.replace("/usr/local/bin/crabc-x86_64-musl-gcc", str(fake_compiler))
    if runner_text == original:
        raise AssertionError("feature runner does not use its pinned musl compiler")
    runner.write_text(runner_text, encoding="utf-8")
    runner.chmod(0o755)
    fake_cargo = root / "tools/cargo"
    fake_cargo.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_cargo.chmod(0o755)
    (runner.parent / "source_runtime_libc.sh").write_text('''build_source_runtime_libc() {
    local output="$1"
    shift
    local retained_work=''
    while [ "$#" -gt 0 ]; do
        if [ "$1" = --retain-work ]; then
            retained_work="$2"
            shift 2
        else
            shift
        fi
    done
    mkdir -p "$retained_work"
    printf '{"reason":"simulated cargo invocation"}\\n' > "$retained_work/cargo.stdout.jsonl"
    printf 'raw Cargo graph stderr\\n' > "$retained_work/cargo.stderr.log"
    printf 'source-runtime libc build failed; evidence retained: %s\\n' "$retained_work" >&2
    return 1
}
''', encoding="utf-8")
    for path in (
        runner.parent / "run_musl_oracle.sh",
        runner.parent / "run_math_long_double_completion_header_abi.sh",
    ):
        path.write_text("exit 0\n", encoding="utf-8")
    (runner.parent / "validate_libc_math_long_double_completion.py").write_text("pass\n", encoding="utf-8")
    (runner.parent / "libc_math_long_double_completion_probe.c").write_text("", encoding="utf-8")
    (root / "include").mkdir()
    return runner


class OwnedMathLongDoubleCompletionTests(unittest.TestCase):
    def test_runner_retention_output_requires_a_new_physical_work_directory(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="long-double-retention.", dir=scratch_root) as temporary:
            parent = Path(temporary)
            outside = ROOT / "Cargo.toml"
            existing = parent / "existing"
            existing.mkdir()
            target = parent / "target"
            target.mkdir()
            alias = parent / "alias"
            alias.symlink_to(target, target_is_directory=True)

            tmp_root = ROOT / ".work/tmp"
            tmp_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="long-double-outside-profile.", dir=tmp_root) as outside_profile:
                for output in (outside, existing, alias, parent / "missing" / "child",
                               Path(outside_profile) / "child"):
                    with self.subTest(output=output):
                        result = subprocess.run(
                            ["bash", str(FEATURE_RUNNER), "--retain-output", str(output)], cwd=ROOT,
                            env={"PATH": "/usr/bin:/bin", "BASH_ENV": ""},
                            capture_output=True, text=True, check=False,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")
                        self.assertIn("retained output", result.stderr)
                        self.assertNotIn("requires cargo", result.stderr)
                self.assertFalse((Path(outside_profile) / "child").exists())
            self.assertEqual(set(parent.iterdir()), {existing, target, alias})

    def test_default_failure_keeps_raw_build_graph_and_explicit_retention_keeps_its_path(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="long-double-default-failure.", dir=scratch_root) as temporary:
            root = Path(temporary)
            runner = simulated_feature_runner(root)
            environment = {"PATH": f"{root}/tools:/usr/bin:/bin", "BASH_ENV": ""}
            result = subprocess.run(["bash", str(runner)], cwd=root, env=environment,
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            retained = result.stderr.split("source-runtime libc build failed; evidence retained: ", 1)[1].splitlines()[0]
            graph = Path(retained)
            self.assertTrue(graph.is_dir())
            self.assertEqual((graph / "cargo.stdout.jsonl").read_text(encoding="utf-8"),
                             '{"reason":"simulated cargo invocation"}\n')
            self.assertEqual((graph / "cargo.stderr.log").read_text(encoding="utf-8"),
                             "raw Cargo graph stderr\n")
            self.assertTrue(graph.parent.is_dir())
            self.assertIn(str(graph), result.stderr)

        with tempfile.TemporaryDirectory(prefix="long-double-explicit-failure.", dir=scratch_root) as temporary:
            root = Path(temporary)
            runner = simulated_feature_runner(root)
            environment = {"PATH": f"{root}/tools:/usr/bin:/bin", "BASH_ENV": ""}
            retained = root / ".work/x86_64/tmp/retained"
            retained.parent.mkdir(parents=True)
            result = subprocess.run(
                ["bash", str(runner), "--retain-output", str(retained)], cwd=root, env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(retained.is_dir())
            self.assertEqual(
                (retained / "source-runtime-baseline/cargo.stdout.jsonl").read_text(encoding="utf-8"),
                '{"reason":"simulated cargo invocation"}\n',
            )
            self.assertEqual(
                (retained / "source-runtime-baseline/cargo.stderr.log").read_text(encoding="utf-8"),
                "raw Cargo graph stderr\n",
            )

    def test_default_scratch_cleanup_runs_after_success_and_skips_explicit_retention(self) -> None:
        runner = FEATURE_RUNNER.read_text(encoding="utf-8")
        start = runner.index("cleanup_successful_default_work() {")
        end = runner.index("\n}\n", start) + 2
        cleanup = runner[start:end]
        passing = runner.rindex("PASS (%s records)")
        cleanup_call = runner.rindex("cleanup_successful_default_work\n")
        self.assertLess(passing, cleanup_call)
        scratch_root = ROOT / ".work/x86_64/tmp"
        with tempfile.TemporaryDirectory(prefix="long-double-cleanup.", dir=scratch_root) as temporary:
            root = Path(temporary)
            for name, retained_output, should_exist in (("default", "", False),
                                                         ("retained", "explicit", True)):
                work = root / name
                work.mkdir()
                script = cleanup + '\nwork_dir="$1"; retained_output="$2"; cleanup_successful_default_work\n'
                result = subprocess.run(
                    ["bash", "-c", script, "bash", str(work), retained_output],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(work.exists(), should_exist)

    def test_runner_usage_lists_its_optional_retained_output(self) -> None:
        result = subprocess.run(["bash", str(FEATURE_RUNNER), "--unknown"], cwd=ROOT,
                                env={"PATH": "/usr/bin:/bin", "BASH_ENV": ""},
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr,
                         f"usage: {FEATURE_RUNNER} [--retain-output RETAINED_OUTPUT]\n")

    def test_fixed_musl_binary80_source_covers_the_missing_public_spelling_contract(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        validator = VALIDATOR.read_text(encoding="utf-8")
        module = MODULE.read_text(encoding="utf-8")
        assembly = ASSEMBLY.read_text(encoding="utf-8")

        for required in (
            "direct_fdiml", "direct_exp10l", "direct_pow10l",
            "sizeof(long double) == 16", "LDBL_MANT_DIG == 64",
            "FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO",
            "HUGE_VALL", "binary80_from_parts", "LDBL_TRUE_MIN", "LDBL_MAX",
        ):
            self.assertIn(required, source)
        for required in (
            "fdiml case", "binary80 NaN result", "FE_OVERFLOW|FE_INEXACT",
            "exp10l finite boundary", "exp10l/pow10l record", "complete x87 control word",
        ):
            self.assertIn(required, validator)
        for required in (
            "src/math/fdiml.c", "src/math/exp10l.c", "weak", "same-address",
            "__fpclassifyl", "modfl", "exp2l", "powl",
        ):
            self.assertIn(required, module)
        for required in (".globl\tfdiml", ".globl\texp10l", ".weak\tpow10l", ".set\tpow10l,exp10l"):
            self.assertIn(required, assembly)

    def test_runner_is_supplied_product_only_and_compiles_one_object(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("usage: %s [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT", runner)
        self.assertNotIn("build_x86_64_owned_dynamic_sysroot.py", runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("-DCRABC_", runner)
        self.assertIn('static = Path(static_text) if static_text else None', runner)
        self.assertIn('"$dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -D_GNU_SOURCE', runner)
        self.assertIn('-c "$SOURCE" -o "$work/workload.o"', runner)
        self.assertNotIn("-frounding-math", runner)
        self.assertIn('"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -lm', runner)
        for required in (
            '"-$mode" --link-receipt', 'for mode in pie non-pie',
            'for entry in kernel direct', 'validate_link "$dynamic_sysroot"',
            'validate_link "$static_sysroot"', 'audit_execution_root',
            'cmp "$work/execution-$mode-$entry-pre.json"',
        ):
            self.assertIn(required, runner)

    def test_runner_retains_exact_raw_oracle_comparisons_and_copied_runtime_boundary(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "validate_libc_math_long_double_completion.py", "RECORDS=247",
            "record count drifted", "emitted invalid binary80 records",
            "differs from pinned musl", "stderr differs from pinned musl",
            'cp -a -- "$dynamic_sysroot" "$root"', 'cp -- "$work/dynamic-$mode" "$root/consumer"',
            "source payload drifted", "copied payload drifted", "execution consumer drifted", "manifest-bound product file",
            '"$INTERPRETER" /consumer',
        ):
            self.assertIn(required, runner)
        copied = runner.index('cp -a -- "$dynamic_sysroot" "$root"')
        pre_audit = runner.index('audit_execution_root "$root" "$work/dynamic-$mode" "$mode-$entry-pre"')
        kernel_launch = runner.index('capture "$work/dynamic-$mode-$entry" /usr/sbin/chroot "$root" /consumer')
        self.assertLess(copied, pre_audit)
        self.assertLess(pre_audit, kernel_launch)

    def test_runner_is_executable_and_rejects_ambiguous_inputs_before_product_tools(self) -> None:
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        for arguments in ((), ("--static-sysroot",), ("one", "two"), ("--unexpected",)):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments], cwd=ROOT,
                    env={"PATH": "/usr/bin:/bin", "TMPDIR": temporary},
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT\n",
            )


if __name__ == "__main__":
    unittest.main()
