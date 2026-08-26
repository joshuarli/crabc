#!/usr/bin/env python3
"""Boundary contracts for the native x86_64 core-evidence launcher."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "scripts" / "dev-x86_64.sh"


class X86_64CoreRunnerTests(unittest.TestCase):
    def test_script_is_valid_and_has_a_closed_command_set(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('readonly PLATFORM="linux/amd64"', source)
        self.assertIn('image|core|facade|libc-syscall|ldso-relocation)', source)
        self.assertIn('run_core_tests()', source)
        self.assertIn('CARGO_TARGET_DIR="$target_dir" cargo test --locked', source)
        self.assertIn('-p crabc-core --lib --no-default-features -- --test-threads=1', source)
        self.assertIn('objdump -d -- "$test_binary"', source)
        self.assertIn('fxrstor(64)?', source)
        self.assertIn(
            '-p crabc-rs --lib --no-default-features --test fenv --test x86_64_foundation',
            source,
        )
        self.assertIn('run_libc_syscall_probe()', source)
        self.assertIn('compat/x86_64/libc_syscall_probe.rs', source)
        self.assertIn('run_ldso_relocation_tests()', source)
        self.assertIn('ldso/src/x86_64_relocation.rs', source)
        self.assertIn('rustup run nightly-2026-07-24 rustc --edition=2021 --test', source)
        self.assertNotIn('"$ROOT_DIR/compat/allocator/run-x86_64.sh"', source)
        self.assertNotIn('cargo "$@"', source)
        self.assertNotIn('-p crabc-libc', source)
        self.assertNotIn('-p crabc-ldso', source)

    def test_libc_syscall_probe_stays_outside_the_libc_artifact_boundary(self) -> None:
        source = (ROOT / "compat" / "x86_64" / "libc_syscall_probe.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/syscall.rs', source)
        self.assertIn('syscall::syscall4(', source)
        self.assertIn('syscall::syscall5(', source)
        self.assertIn('syscall::syscall6(', source)
        self.assertNotIn('crabc_libc', source)

    def test_core_refuses_a_non_native_host_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'aarch64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment["PATH"] = f"{bin_directory}{os.pathsep}{environment['PATH']}"
            completed = subprocess.run(
                ["bash", str(RUNNER), "core"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("refuses emulation", completed.stderr)

    def test_core_uses_the_native_amd64_container_and_exact_cargo_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  printf '%s\\0' \"$@\" > \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "core"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            arguments = [
                argument.decode("utf-8")
                for argument in capture.read_bytes().split(bytes((0,)))
                if argument
            ]
            self.assertIn("--platform", arguments)
            platform_index = arguments.index("--platform")
            self.assertEqual(arguments[platform_index + 1], "linux/amd64")
            bash_index = arguments.index("bash")
            self.assertEqual(arguments[bash_index : bash_index + 2], ["bash", "-ceu"])
            core_test_command = arguments[bash_index + 2]
            self.assertIn(
                'CARGO_TARGET_DIR="$target_dir" cargo test --locked '
                '--target x86_64-unknown-linux-musl',
                core_test_command,
            )
            self.assertIn(
                '-p crabc-core --lib --no-default-features -- --test-threads=1',
                core_test_command,
            )
            self.assertIn('find "$target_dir/x86_64-unknown-linux-musl/debug/deps"', core_test_command)
            self.assertIn('objdump -d -- "$test_binary"', core_test_command)
            self.assertIn('fxrstor(64)?', core_test_command)

    def test_facade_uses_the_native_amd64_container_and_exact_cargo_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  printf '%s\\0' \"$@\" > \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "facade"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            arguments = [
                argument.decode("utf-8")
                for argument in capture.read_bytes().split(bytes((0,)))
                if argument
            ]
            self.assertIn("--platform", arguments)
            platform_index = arguments.index("--platform")
            self.assertEqual(arguments[platform_index + 1], "linux/amd64")
            cargo_index = arguments.index("cargo")
            self.assertEqual(
                arguments[cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--lib",
                    "--no-default-features",
                    "--test",
                    "fenv",
                    "--test",
                    "x86_64_foundation",
                    "--",
                    "--test-threads=1",
                ],
            )

    def test_ldso_relocation_uses_the_native_amd64_container_and_fixed_source_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            capture = root / "docker.args"

            fake_uname = bin_directory / "uname"
            fake_uname.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1\" in\n"
                "  -s) printf 'Linux\\n' ;;\n"
                "  -m) printf 'x86_64\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_uname.chmod(fake_uname.stat().st_mode | stat.S_IXUSR)

            fake_docker = bin_directory / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
                "  printf 'linux/amd64\\n'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = run ]; then\n"
                "  printf '%s\\0' \"$@\" > \"${FAKE_DOCKER_ARGS:?}\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'unexpected docker invocation: %s\\n' \"$*\" >&2\n"
                "exit 64\n",
                encoding="utf-8",
            )
            fake_docker.chmod(fake_docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                    "FAKE_DOCKER_ARGS": str(capture),
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), "ldso-relocation"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            arguments = [
                argument.decode("utf-8")
                for argument in capture.read_bytes().split(bytes((0,)))
                if argument
            ]
            self.assertIn("--platform", arguments)
            platform_index = arguments.index("--platform")
            self.assertEqual(arguments[platform_index + 1], "linux/amd64")
            bash_index = arguments.index("bash")
            self.assertEqual(arguments[bash_index : bash_index + 2], ["bash", "-ceu"])
            source_test_command = arguments[bash_index + 2]
            self.assertIn(
                "rustup run nightly-2026-07-24 rustc --edition=2021 --test",
                source_test_command,
            )
            self.assertIn(
                "/workspace/ldso/src/x86_64_relocation.rs",
                source_test_command,
            )
            self.assertIn('"$test_binary" --test-threads=1', source_test_command)
            self.assertNotIn("cargo", source_test_command)


if __name__ == "__main__":
    unittest.main()
