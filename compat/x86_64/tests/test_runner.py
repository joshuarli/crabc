#!/usr/bin/env python3
"""Boundary contracts for the native x86_64 core-evidence launcher."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
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
        self.assertIn(
            'image|musl-oracle|header-abi-reference|header-abi-project|sys-reg-header-abi|types-header-abi|stat-header-abi|time-header-abi|poll-header-abi|fcntl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|mman-header-abi|mm-abi-reference|rand-reference|time-abi-reference|time-observation-reference|poll-reference|ppoll-reference|process-identity-reference|process-session-reference|pidfd-open-reference|fstat-reference|system-reference|thread-reference|core|facade|libc-syscall|libc-errno-tls|libc-setjmp|ldso-relocation|ldso-image)',
            source,
        )
        self.assertIn('run_musl_oracle()', source)
        self.assertIn('compat/x86_64/run_musl_oracle.sh', source)
        self.assertIn('run_header_abi_reference()', source)
        self.assertIn('compat/x86_64/run_header_abi_reference.sh', source)
        self.assertIn('run_header_abi_project()', source)
        self.assertIn('compat/x86_64/run_project_header_abi.sh', source)
        self.assertIn('run_sys_reg_header_abi()', source)
        self.assertIn('compat/x86_64/run_sys_reg_header_abi.sh', source)
        self.assertIn('run_types_header_abi()', source)
        self.assertIn('compat/x86_64/run_types_header_abi.sh', source)
        self.assertIn('run_stat_header_abi()', source)
        self.assertIn('compat/x86_64/run_stat_header_abi.sh', source)
        self.assertIn('run_time_header_abi()', source)
        self.assertIn('compat/x86_64/run_time_header_abi.sh', source)
        self.assertIn('run_poll_header_abi()', source)
        self.assertIn('compat/x86_64/run_poll_header_abi.sh', source)
        self.assertIn('run_fcntl_header_abi()', source)
        self.assertIn('compat/x86_64/run_fcntl_header_abi.sh', source)
        self.assertIn('run_unistd_header_abi()', source)
        self.assertIn('compat/x86_64/run_unistd_header_abi.sh', source)
        self.assertIn('run_system_header_abi()', source)
        self.assertIn('compat/x86_64/run_system_header_abi.sh', source)
        self.assertIn('run_syscall_header_abi()', source)
        self.assertIn('compat/x86_64/run_x86_syscall_header.sh', source)
        self.assertIn('run_signal_header_abi()', source)
        self.assertIn('compat/x86_64/run_signal_header_abi.sh', source)
        self.assertIn('run_mman_header_abi()', source)
        self.assertIn('compat/x86_64/run_mman_header_abi.sh', source)
        self.assertIn('run_mm_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mm_reference.sh', source)
        self.assertIn('run_rand_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rand_reference.sh', source)
        self.assertIn('run_time_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_reference.sh', source)
        self.assertIn('run_time_observation_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_observation_reference.sh', source)
        self.assertIn('run_poll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_poll_reference.sh', source)
        self.assertIn('run_ppoll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_ppoll_reference.sh', source)
        self.assertIn('run_process_identity_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_identity_reference.sh', source)
        self.assertIn('run_process_session_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_session_reference.sh', source)
        self.assertIn('run_pidfd_open_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pidfd_open_reference.sh', source)
        self.assertIn('run_fstat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fstat_reference.sh', source)
        self.assertIn('run_system_reference()', source)
        self.assertIn('compat/x86_64/run_x86_system_reference.sh', source)
        self.assertIn('run_thread_reference()', source)
        self.assertIn('compat/x86_64/run_x86_thread_reference.sh', source)
        self.assertIn('run_core_tests()', source)
        self.assertIn('CARGO_TARGET_DIR="$target_dir" cargo test --locked', source)
        self.assertIn('-p crabc-core --lib --no-default-features -- --test-threads=1', source)
        self.assertIn('objdump -d -- "$test_binary"', source)
        self.assertIn('fxrstor(64)?', source)
        self.assertIn(
            '-p crabc-rs --lib --no-default-features --test fenv --test x86_64_foundation',
            source,
        )
        self.assertIn('--test x86_64_eventfd', source)
        self.assertIn('--test x86_64_fs', source)
        self.assertIn('--test x86_64_io', source)
        self.assertIn('--test x86_64_mm', source)
        self.assertIn('--test x86_64_param', source)
        self.assertIn('--test x86_64_pipe', source)
        self.assertIn('--test x86_64_poll', source)
        self.assertIn('--test x86_64_process_identity', source)
        self.assertIn('--test x86_64_process_session', source)
        self.assertIn('--test x86_64_pidfd_open', source)
        self.assertIn('--test x86_64_rand', source)
        self.assertIn('--test x86_64_system', source)
        self.assertIn('--test x86_64_thread', source)
        self.assertIn('--test x86_64_time', source)
        self.assertIn('run_libc_syscall_probe()', source)
        self.assertIn('compat/x86_64/libc_syscall_probe.rs', source)
        self.assertIn('run_libc_errno_tls_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_errno_tls.sh', source)
        self.assertIn('run_libc_setjmp_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_setjmp.sh', source)
        self.assertIn('run_ldso_relocation_tests()', source)
        self.assertIn('ldso/src/x86_64_relocation.rs', source)
        self.assertIn('rustup run nightly-2026-07-24 rustc --edition=2021 --test', source)
        self.assertIn('run_ldso_image_tests()', source)
        self.assertIn('/workspace/ldso/run-x86_64-image.sh test', source)
        self.assertNotIn('"$ROOT_DIR/compat/allocator/run-x86_64.sh"', source)
        self.assertNotIn('cargo "$@"', source)
        self.assertNotIn('-p crabc-libc', source)
        self.assertNotIn('-p crabc-ldso', source)

    def test_pinned_musl_oracle_and_reference_header_baseline_stay_closed(self) -> None:
        dockerfile = (ROOT / "docker" / "Dockerfile.x86_64").read_text(encoding="utf-8")
        wrapper = (ROOT / "docker" / "x86_64-musl-oracle-gcc").read_text(encoding="utf-8")
        oracle = (ROOT / "compat" / "x86_64" / "run_musl_oracle.sh").read_text(
            encoding="utf-8"
        )
        reference = (ROOT / "compat" / "x86_64" / "run_header_abi_reference.sh").read_text(
            encoding="utf-8"
        )
        project = (ROOT / "compat" / "x86_64" / "run_project_header_abi.sh").read_text(
            encoding="utf-8"
        )
        sys_reg = (ROOT / "compat" / "x86_64" / "run_sys_reg_header_abi.sh").read_text(
            encoding="utf-8"
        )
        types = (ROOT / "compat" / "x86_64" / "run_types_header_abi.sh").read_text(
            encoding="utf-8"
        )
        syscall = (ROOT / "compat" / "x86_64" / "run_x86_syscall_header.sh").read_text(
            encoding="utf-8"
        )
        mapping = (ROOT / "compat" / "x86_64" / "run_x86_mm_reference.sh").read_text(
            encoding="utf-8"
        )
        signal = (ROOT / "compat" / "x86_64" / "run_signal_header_abi.sh").read_text(
            encoding="utf-8"
        )
        mman = (ROOT / "compat" / "x86_64" / "run_mman_header_abi.sh").read_text(
            encoding="utf-8"
        )
        random = (ROOT / "compat" / "x86_64" / "run_x86_rand_reference.sh").read_text(
            encoding="utf-8"
        )
        stat_header = (ROOT / "compat" / "x86_64" / "run_stat_header_abi.sh").read_text(
            encoding="utf-8"
        )
        time_header = (ROOT / "compat" / "x86_64" / "run_time_header_abi.sh").read_text(
            encoding="utf-8"
        )
        poll_header = (ROOT / "compat" / "x86_64" / "run_poll_header_abi.sh").read_text(
            encoding="utf-8"
        )
        fcntl_header = (ROOT / "compat" / "x86_64" / "run_fcntl_header_abi.sh").read_text(
            encoding="utf-8"
        )
        unistd_header = (ROOT / "compat" / "x86_64" / "run_unistd_header_abi.sh").read_text(
            encoding="utf-8"
        )
        system_header = (ROOT / "compat" / "x86_64" / "run_system_header_abi.sh").read_text(
            encoding="utf-8"
        )
        time_reference = (ROOT / "compat" / "x86_64" / "run_x86_time_reference.sh").read_text(
            encoding="utf-8"
        )
        time_observation_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_time_observation_reference.sh"
        ).read_text(encoding="utf-8")
        poll_reference = (ROOT / "compat" / "x86_64" / "run_x86_poll_reference.sh").read_text(
            encoding="utf-8"
        )
        ppoll_reference = (ROOT / "compat" / "x86_64" / "run_x86_ppoll_reference.sh").read_text(
            encoding="utf-8"
        )
        process_identity_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_process_identity_reference.sh"
        ).read_text(encoding="utf-8")
        process_session_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_process_session_reference.sh"
        ).read_text(encoding="utf-8")
        pidfd_open_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_pidfd_open_reference.sh"
        ).read_text(encoding="utf-8")
        fstat_reference = (ROOT / "compat" / "x86_64" / "run_x86_fstat_reference.sh").read_text(
            encoding="utf-8"
        )
        system_reference = (ROOT / "compat" / "x86_64" / "run_x86_system_reference.sh").read_text(
            encoding="utf-8"
        )
        thread_reference = (ROOT / "compat" / "x86_64" / "run_x86_thread_reference.sh").read_text(
            encoding="utf-8"
        )
        image = (ROOT / "ldso" / "run-x86_64-image.sh").read_text(encoding="utf-8")
        sys_types = (ROOT / "include" / "sys" / "types.h").read_text(encoding="utf-8")
        unistd_include = (ROOT / "include" / "unistd.h").read_text(encoding="utf-8")

        self.assertIn('ARG MUSL_VERSION=1.2.6', dockerfile)
        self.assertIn('ARG MUSL_SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a', dockerfile)
        self.assertIn('ld-musl-x86_64.so.1', dockerfile)
        self.assertIn('/opt/musl-1.2.6/lib/musl-gcc.specs', wrapper)
        self.assertIn('CRABC_MUSL_ORACLE_LIBC_PATH', oracle)
        self.assertIn('libc\\.so\\.6', oracle)
        self.assertIn('run_musl_oracle.sh', reference)
        self.assertIn('header_abi_probe.c', reference)
        self.assertIn('fldt|fstpt', reference)
        self.assertNotIn('-p crabc-libc', reference)
        self.assertIn('run_musl_oracle.sh', project)
        self.assertIn('project_header_abi_probe.c', project)
        self.assertIn('-mfpmath=387', project)
        self.assertIn('-fsyntax-only', project)
        self.assertNotIn('-p crabc-libc', project)
        self.assertIn('run_musl_oracle.sh', sys_reg)
        self.assertIn('sys_reg_header_abi_probe.c', sys_reg)
        self.assertIn('-fsyntax-only', sys_reg)
        self.assertNotIn('-p crabc-libc', sys_reg)
        self.assertIn('types_header_abi_probe.c', types)
        self.assertIn('types_header_abi_probe.cpp', types)
        self.assertIn('-fsyntax-only', types)
        self.assertNotIn('-p crabc-libc', types)
        self.assertIn('x86_syscall_header_probe.c', syscall)
        self.assertIn('384 __NR_* plus 384 SYS_*', syscall)
        self.assertIn('-fsyntax-only', syscall)
        self.assertNotIn('-p crabc-libc', syscall)
        self.assertIn('x86_mm_reference_probe.c', mapping)
        self.assertIn('-fsyntax-only', mapping)
        self.assertNotIn('-p crabc-libc', mapping)
        self.assertIn('signal_header_abi_probe.c', signal)
        self.assertIn('signal_header_posix_abi_probe.c', signal)
        self.assertIn('-fsyntax-only', signal)
        self.assertNotIn('-p crabc-libc', signal)
        self.assertIn('mman_header_abi_probe.c', mman)
        self.assertIn('mman_header_abi_probe.cpp', mman)
        self.assertIn('include/sys/mman.h', mman)
        self.assertIn('include/bits/mman.h', mman)
        self.assertIn('-fsyntax-only', mman)
        self.assertNotIn('-p crabc-libc', mman)
        self.assertIn('x86_rand_reference_probe.c', random)
        self.assertIn('getrandom ABI/behavior reference', random)
        self.assertNotIn('-p crabc-libc', random)
        self.assertIn('stat_header_abi_probe.c', stat_header)
        self.assertIn('stat_header_abi_probe.cpp', stat_header)
        self.assertIn('include/sys/stat.h', stat_header)
        self.assertIn('include/bits/stat.h', stat_header)
        self.assertIn('-fsyntax-only', stat_header)
        self.assertNotIn('-p crabc-libc', stat_header)
        self.assertIn('time_header_abi_probe.c', time_header)
        self.assertIn('time_header_abi_probe.cpp', time_header)
        self.assertIn('include/time.h', time_header)
        self.assertIn('-fsyntax-only', time_header)
        self.assertNotIn('-p crabc-libc', time_header)
        self.assertIn('poll_header_abi_probe.c', poll_header)
        self.assertIn('poll_header_abi_probe.cpp', poll_header)
        self.assertIn('include/poll.h', poll_header)
        self.assertIn('-fsyntax-only', poll_header)
        self.assertNotIn('-p crabc-libc', poll_header)
        self.assertIn('fcntl_header_abi_probe.c', fcntl_header)
        self.assertIn('fcntl_header_abi_probe.cpp', fcntl_header)
        self.assertIn('include/fcntl.h', fcntl_header)
        self.assertIn('include/bits/fcntl.h', fcntl_header)
        self.assertIn('-fsyntax-only', fcntl_header)
        self.assertNotIn('-p crabc-libc', fcntl_header)
        self.assertIn('unistd_header_abi_probe.c', unistd_header)
        self.assertIn('unistd_header_abi_probe.cpp', unistd_header)
        self.assertIn('include/unistd.h', unistd_header)
        self.assertIn('-fsyntax-only', unistd_header)
        self.assertNotIn('-p crabc-libc', unistd_header)
        self.assertIn('system_header_abi_probe.c', system_header)
        self.assertIn('system_header_abi_probe.cpp', system_header)
        self.assertIn('include tree first', system_header)
        self.assertIn('-fsyntax-only', system_header)
        self.assertNotIn('-p crabc-libc', system_header)
        self.assertIn('x86_time_reference_probe.c', time_reference)
        self.assertIn('timespec ABI reference', time_reference)
        self.assertNotIn('-p crabc-libc', time_reference)
        self.assertIn('x86_time_observation_reference_probe.c', time_observation_reference)
        self.assertIn('realtime observation reference', time_observation_reference)
        self.assertNotIn('-p crabc-libc', time_observation_reference)
        self.assertIn('x86_poll_reference_probe.c', poll_reference)
        self.assertIn('poll ABI/behavior reference', poll_reference)
        self.assertNotIn('-p crabc-libc', poll_reference)
        self.assertIn('x86_ppoll_reference_probe.c', ppoll_reference)
        self.assertIn('ppoll/pause signal-mask reference', ppoll_reference)
        self.assertNotIn('-p crabc-libc', ppoll_reference)
        self.assertIn('x86_process_identity_reference_probe.c', process_identity_reference)
        self.assertIn('process-identity reference', process_identity_reference)
        self.assertNotIn('-p crabc-libc', process_identity_reference)
        self.assertIn('x86_process_session_reference_probe.c', process_session_reference)
        self.assertIn('process-session reference', process_session_reference)
        self.assertNotIn('-p crabc-libc', process_session_reference)
        self.assertIn('x86_pidfd_open_reference_probe.c', pidfd_open_reference)
        self.assertIn('pidfd_open reference', pidfd_open_reference)
        self.assertNotIn('-p crabc-libc', pidfd_open_reference)
        self.assertIn('x86_fstat_reference_probe.c', fstat_reference)
        self.assertIn('fstat reference', fstat_reference)
        self.assertNotIn('-p crabc-libc', fstat_reference)
        self.assertIn('x86_system_reference_probe.c', system_reference)
        self.assertIn('uname/sysinfo ABI and behavior reference', system_reference)
        self.assertNotIn('-p crabc-libc', system_reference)
        self.assertIn('x86_thread_reference_probe.c', thread_reference)
        self.assertIn('thread observation/yield reference', thread_reference)
        self.assertNotIn('-p crabc-libc', thread_reference)
        self.assertIn('x86_64_image.rs', image)
        self.assertIn('--test', image)
        self.assertNotIn('-p crabc-ldso', image)
        self.assertIn('#if defined(__x86_64__) && !defined(__cplusplus)', sys_types)
        self.assertIn('defined(__x86_64__) && defined(__LP64__)', unistd_include)
        self.assertNotIn('#if defined(__x86_64__)\n', unistd_include)

    def test_x86_parity_ledger_is_a_required_contract_check(self) -> None:
        validator = ROOT / "compat" / "x86_64" / "validate_parity_ledger.py"
        completed = subprocess.run(
            [sys.executable, str(validator), "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("x86 parity ledger: PASS", completed.stdout)

    def test_libc_syscall_probe_stays_outside_the_libc_artifact_boundary(self) -> None:
        source = (ROOT / "compat" / "x86_64" / "libc_syscall_probe.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/syscall.rs', source)
        self.assertIn('syscall::syscall4(', source)
        self.assertIn('syscall::syscall5(', source)
        self.assertIn('syscall::syscall6(', source)
        self.assertNotIn('crabc_libc', source)

    def test_libc_errno_tls_probe_is_a_fixed_source_only_static_tls_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_errno_tls_probe.rs").read_text(
            encoding="utf-8"
        )
        errno_source = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_errno_tls_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_errno_tls.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/errno.rs', rust_probe)
        self.assertIn('#[thread_local]', errno_source)
        self.assertIn('__errno_location', errno_source)
        self.assertIn('#include <errno.h>', c_probe)
        self.assertIn('pthread_create', c_probe)
        self.assertIn('R_X86_64_TPOFF', script)
        self.assertIn('__tls_get_addr', script)
        self.assertIn('-no-pie -pthread', script)
        self.assertNotIn('--allow-multiple-definition', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_setjmp_probe_is_a_fixed_source_only_control_transfer_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_setjmp_probe.rs").read_text(
            encoding="utf-8"
        )
        assembly = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "setjmp.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_setjmp_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_setjmp.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/setjmp.rs', rust_probe)
        self.assertIn('global_asm!', assembly)
        self.assertIn('.global sigsetjmp', assembly)
        self.assertIn('mov eax, 14', assembly)
        self.assertIn('struct __jmp_buf_tag', c_probe)
        self.assertIn('siglongjmp', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('-fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

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
                    "--test",
                    "x86_64_eventfd",
                    "--test",
                    "x86_64_fs",
                    "--test",
                    "x86_64_io",
                    "--test",
                    "x86_64_mm",
                    "--test",
                    "x86_64_param",
                    "--test",
                    "x86_64_pipe",
                    "--test",
                    "x86_64_poll",
                    "--test",
                    "x86_64_process_identity",
                    "--test",
                    "x86_64_process_session",
                    "--test",
                    "x86_64_pidfd_open",
                    "--test",
                    "x86_64_rand",
                    "--test",
                    "x86_64_system",
                    "--test",
                    "x86_64_thread",
                    "--test",
                    "x86_64_time",
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
