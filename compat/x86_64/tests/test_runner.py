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
            'image|musl-oracle|header-abi-reference|header-abi-project|sys-reg-header-abi|types-header-abi|stat-header-abi|time-header-abi|poll-header-abi|fcntl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|mman-header-abi|mm-abi-reference|mlock-reference|msync-reference|madvise-reference|mincore-reference|fs-advice-reference|memfd-reference|ftruncate-reference|file-position-reference|rand-reference|time-abi-reference|time-observation-reference|relative-sleep-reference|clock-nanosleep-reference|getitimer-reference|setitimer-reference|timerfd-reference|pselect-reference|poll-reference|ppoll-reference|epoll-reference|process-identity-reference|getgroups-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|scheduler-priority-bounds-reference|rr-interval-reference|sched-affinity-reference|sched-affinity-set-reference|priority-reference|setpriority-reference|rlimit-reference|rlimit-targeted-private|setrlimit-reference|umask-reference|rusage-reference|times-reference|fstat-reference|statat-reference|getcwd-reference|readlinkat-reference|system-reference|thread-reference|thread-credentials-reference|fs-credentials-reference|core|facade|libc-syscall|libc-errno-tls|libc-thread-pointer|libc-foundation|libc-fenv|libc-memory|libc-setjmp|libc-atomic|libc-clone-raw|libc-signal-foundation|ldso-relocation|ldso-image)',
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
        self.assertIn('run_mlock_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mlock_reference.sh', source)
        self.assertIn('run_msync_reference()', source)
        self.assertIn('compat/x86_64/run_x86_msync_reference.sh', source)
        self.assertIn('run_madvise_reference()', source)
        self.assertIn('compat/x86_64/run_x86_madvise_reference.sh', source)
        self.assertIn('run_mincore_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mincore_reference.sh', source)
        self.assertIn('run_fs_advice_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fs_advice_reference.sh', source)
        self.assertIn('run_memfd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_memfd_reference.sh', source)
        self.assertIn('run_ftruncate_reference()', source)
        self.assertIn('compat/x86_64/run_x86_ftruncate_reference.sh', source)
        self.assertIn('run_file_position_reference()', source)
        self.assertIn('compat/x86_64/run_x86_file_position_reference.sh', source)
        self.assertIn('run_rand_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rand_reference.sh', source)
        self.assertIn('run_time_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_reference.sh', source)
        self.assertIn('run_time_observation_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_observation_reference.sh', source)
        self.assertIn('run_relative_sleep_reference()', source)
        self.assertIn('compat/x86_64/run_x86_relative_sleep_reference.sh', source)
        self.assertIn('run_clock_nanosleep_reference()', source)
        self.assertIn('compat/x86_64/run_x86_clock_nanosleep_reference.sh', source)
        self.assertIn('run_getitimer_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getitimer_reference.sh', source)
        self.assertIn('run_setitimer_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setitimer_reference.sh', source)
        self.assertIn('run_timerfd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_timerfd_reference.sh', source)
        self.assertIn('run_pselect_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pselect_reference.sh', source)
        self.assertIn('run_poll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_poll_reference.sh', source)
        self.assertIn('run_ppoll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_ppoll_reference.sh', source)
        self.assertIn('run_epoll_reference()', source)
        self.assertIn('compat/x86_64/run_x86_epoll_reference.sh', source)
        self.assertIn('run_process_identity_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_identity_reference.sh', source)
        self.assertIn('run_getgroups_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getgroups_reference.sh', source)
        self.assertIn('run_process_session_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_session_reference.sh', source)
        self.assertIn('run_pidfd_open_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pidfd_open_reference.sh', source)
        self.assertIn('run_fcntl_getlk_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fcntl_getlk_reference.sh', source)
        self.assertIn('run_scheduler_priority_bounds_reference()', source)
        self.assertIn('compat/x86_64/run_x86_scheduler_priority_bounds_reference.sh', source)
        self.assertIn('run_priority_reference()', source)
        self.assertIn('compat/x86_64/run_x86_priority_reference.sh', source)
        self.assertIn('run_setpriority_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setpriority_reference.sh', source)
        self.assertIn('run_rlimit_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rlimit_reference.sh', source)
        self.assertIn('run_rlimit_targeted_private()', source)
        self.assertIn('--test x86_64_rlimit_targeted -- --test-threads=1', source)
        self.assertIn('run_setrlimit_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setrlimit_reference.sh', source)
        self.assertIn('run_umask_reference()', source)
        self.assertIn('compat/x86_64/run_x86_umask_reference.sh', source)
        self.assertIn('run_rusage_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rusage_reference.sh', source)
        self.assertIn('run_times_reference()', source)
        self.assertIn('compat/x86_64/run_x86_times_reference.sh', source)
        self.assertIn('run_fstat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fstat_reference.sh', source)
        self.assertIn('run_statat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statat_reference.sh', source)
        self.assertIn('run_getcwd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getcwd_reference.sh', source)
        self.assertIn('run_readlinkat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_readlinkat_reference.sh', source)
        self.assertIn('run_rr_interval_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sched_rr_interval_reference.sh', source)
        self.assertIn('run_sched_affinity_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sched_affinity_reference.sh', source)
        self.assertIn('run_sched_affinity_set_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sched_setaffinity_reference.sh', source)
        self.assertIn('run_system_reference()', source)
        self.assertIn('compat/x86_64/run_x86_system_reference.sh', source)
        self.assertIn('run_thread_reference()', source)
        self.assertIn('compat/x86_64/run_x86_thread_reference.sh', source)
        self.assertIn('run_thread_credentials_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_thread_credentials_reference.sh',
            source,
        )
        self.assertIn('run_fs_credentials_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_fs_credentials_reference.sh',
            source,
        )
        self.assertIn('run_core_tests()', source)
        self.assertIn('CARGO_TARGET_DIR="$target_dir" cargo test --locked', source)
        self.assertIn('-p crabc-core --lib --no-default-features -- --test-threads=1', source)
        self.assertIn('objdump -d -- "$test_binary"', source)
        self.assertIn('fxrstor(64)?', source)
        self.assertIn(
            '-p crabc-rs --lib --no-default-features --test fenv --test futex --test x86_64_foundation',
            source,
        )
        self.assertIn('--test x86_64_eventfd', source)
        self.assertIn('--test x86_64_epoll', source)
        self.assertIn('--test x86_64_fcntl_getlk', source)
        self.assertIn('--test x86_64_fs', source)
        self.assertIn('--test x86_64_fs_advice', source)
        self.assertIn('--test x86_64_file_position', source)
        self.assertIn('--test x86_64_ftruncate', source)
        self.assertIn('--test x86_64_fs_credentials', source)
        self.assertIn('--test x86_64_memfd', source)
        self.assertIn('--test x86_64_getgroups', source)
        self.assertIn('--test x86_64_getitimer', source)
        self.assertIn('--test x86_64_setitimer', source)
        self.assertIn('--test x86_64_io', source)
        self.assertIn('--test x86_64_mm', source)
        self.assertIn('--test x86_64_param', source)
        self.assertIn('--test x86_64_pipe', source)
        self.assertIn('--test x86_64_poll', source)
        self.assertIn('--test x86_64_priority', source)
        self.assertIn('--test x86_64_setpriority', source)
        self.assertIn('--test x86_64_process_identity', source)
        self.assertIn('--test x86_64_process_session', source)
        self.assertIn('--test x86_64_pidfd_open', source)
        self.assertIn('--test x86_64_rand', source)
        self.assertIn('--test x86_64_rlimit', source)
        self.assertIn('--test x86_64_rlimit_targeted', source)
        self.assertIn('--test x86_64_setrlimit', source)
        self.assertIn('--test x86_64_umask', source)
        self.assertIn('--test x86_64_rusage', source)
        self.assertIn('--test x86_64_times', source)
        self.assertIn('--test x86_64_scheduler_priority_bounds', source)
        self.assertIn('--test x86_64_sleep', source)
        self.assertIn('--test x86_64_clock_nanosleep', source)
        self.assertIn('--test x86_64_statat', source)
        self.assertIn('--test x86_64_getcwd', source)
        self.assertIn('--test x86_64_readlink', source)
        self.assertIn('--test x86_64_sched_rr_interval', source)
        self.assertIn('--test x86_64_sched_affinity', source)
        self.assertIn('--test x86_64_sched_setaffinity', source)
        self.assertIn('--test x86_64_system', source)
        self.assertIn('--test x86_64_thread', source)
        self.assertIn('--test x86_64_thread_credentials', source)
        self.assertIn('--test x86_64_time', source)
        self.assertIn('--test x86_64_timerfd', source)
        self.assertIn('--test x86_64_pselect', source)
        facade = source.split('    facade)\n', 1)[1].split('    libc-syscall)', 1)[0]
        self.assertNotIn('--test x86_64_rlimit_targeted', facade)
        self.assertIn('run_libc_syscall_probe()', source)
        self.assertIn('compat/x86_64/libc_syscall_probe.rs', source)
        self.assertIn('run_libc_errno_tls_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_errno_tls.sh', source)
        self.assertIn('run_libc_thread_pointer_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_thread_pointer.sh', source)
        self.assertIn('run_libc_foundation_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_foundation.sh', source)
        self.assertIn('run_libc_fenv_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_fenv.sh', source)
        self.assertIn('run_libc_memory_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_memory.sh', source)
        self.assertIn('run_libc_setjmp_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_setjmp.sh', source)
        self.assertIn('run_libc_atomic_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_atomic.sh', source)
        self.assertIn('run_libc_clone_raw_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_clone_raw.sh', source)
        self.assertIn('run_libc_signal_foundation_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_signal_foundation.sh', source)
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
        mlock = (ROOT / "compat" / "x86_64" / "run_x86_mlock_reference.sh").read_text(
            encoding="utf-8"
        )
        msync = (ROOT / "compat" / "x86_64" / "run_x86_msync_reference.sh").read_text(
            encoding="utf-8"
        )
        madvise = (ROOT / "compat" / "x86_64" / "run_x86_madvise_reference.sh").read_text(
            encoding="utf-8"
        )
        mincore = (ROOT / "compat" / "x86_64" / "run_x86_mincore_reference.sh").read_text(
            encoding="utf-8"
        )
        fs_advice = (
            ROOT / "compat" / "x86_64" / "run_x86_fs_advice_reference.sh"
        ).read_text(encoding="utf-8")
        memfd = (ROOT / "compat" / "x86_64" / "run_x86_memfd_reference.sh").read_text(
            encoding="utf-8"
        )
        ftruncate = (
            ROOT / "compat" / "x86_64" / "run_x86_ftruncate_reference.sh"
        ).read_text(encoding="utf-8")
        file_position = (
            ROOT / "compat" / "x86_64" / "run_x86_file_position_reference.sh"
        ).read_text(encoding="utf-8")
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
        relative_sleep_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_relative_sleep_reference.sh"
        ).read_text(encoding="utf-8")
        clock_nanosleep_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_clock_nanosleep_reference.sh"
        ).read_text(encoding="utf-8")
        clock_nanosleep_probe = (
            ROOT / "compat" / "x86_64" / "x86_clock_nanosleep_reference_probe.c"
        ).read_text(encoding="utf-8")
        getitimer_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getitimer_reference.sh"
        ).read_text(encoding="utf-8")
        setitimer_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_setitimer_reference.sh"
        ).read_text(encoding="utf-8")
        setitimer_probe = (
            ROOT / "compat" / "x86_64" / "x86_setitimer_reference_probe.c"
        ).read_text(encoding="utf-8")
        setitimer_test = (
            ROOT / "crabc-rs" / "tests" / "x86_64_setitimer.rs"
        ).read_text(encoding="utf-8")
        timerfd_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_timerfd_reference.sh"
        ).read_text(encoding="utf-8")
        pselect_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_pselect_reference.sh"
        ).read_text(encoding="utf-8")
        poll_reference = (ROOT / "compat" / "x86_64" / "run_x86_poll_reference.sh").read_text(
            encoding="utf-8"
        )
        ppoll_reference = (ROOT / "compat" / "x86_64" / "run_x86_ppoll_reference.sh").read_text(
            encoding="utf-8"
        )
        epoll_reference = (ROOT / "compat" / "x86_64" / "run_x86_epoll_reference.sh").read_text(
            encoding="utf-8"
        )
        process_identity_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_process_identity_reference.sh"
        ).read_text(encoding="utf-8")
        getgroups_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getgroups_reference.sh"
        ).read_text(encoding="utf-8")
        process_session_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_process_session_reference.sh"
        ).read_text(encoding="utf-8")
        pidfd_open_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_pidfd_open_reference.sh"
        ).read_text(encoding="utf-8")
        fcntl_getlk_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_fcntl_getlk_reference.sh"
        ).read_text(encoding="utf-8")
        scheduler_priority_bounds_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_scheduler_priority_bounds_reference.sh"
        ).read_text(encoding="utf-8")
        priority_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_priority_reference.sh"
        ).read_text(encoding="utf-8")
        setpriority_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_setpriority_reference.sh"
        ).read_text(encoding="utf-8")
        rlimit_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_rlimit_reference.sh"
        ).read_text(encoding="utf-8")
        rusage_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_rusage_reference.sh"
        ).read_text(encoding="utf-8")
        times_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_times_reference.sh"
        ).read_text(encoding="utf-8")
        fstat_reference = (ROOT / "compat" / "x86_64" / "run_x86_fstat_reference.sh").read_text(
            encoding="utf-8"
        )
        statat_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_statat_reference.sh"
        ).read_text(encoding="utf-8")
        getcwd_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getcwd_reference.sh"
        ).read_text(encoding="utf-8")
        readlinkat_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_readlinkat_reference.sh"
        ).read_text(encoding="utf-8")
        rr_interval_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sched_rr_interval_reference.sh"
        ).read_text(encoding="utf-8")
        sched_affinity_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sched_affinity_reference.sh"
        ).read_text(encoding="utf-8")
        sched_affinity_set_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sched_setaffinity_reference.sh"
        ).read_text(encoding="utf-8")
        system_reference = (ROOT / "compat" / "x86_64" / "run_x86_system_reference.sh").read_text(
            encoding="utf-8"
        )
        thread_reference = (ROOT / "compat" / "x86_64" / "run_x86_thread_reference.sh").read_text(
            encoding="utf-8"
        )
        thread_credentials_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_thread_credentials_reference.sh"
        ).read_text(encoding="utf-8")
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
        self.assertIn('x86_mlock_reference_probe.c', mlock)
        self.assertIn('memory-locking ABI/behavior reference', mlock)
        self.assertNotIn('-p crabc-libc', mlock)
        self.assertIn('x86_msync_reference_probe.c', msync)
        self.assertIn('msync ABI/behavior reference', msync)
        self.assertNotIn('-p crabc-libc', msync)
        self.assertIn('x86_madvise_reference_probe.c', madvise)
        self.assertIn('madvise ABI/behavior reference', madvise)
        self.assertNotIn('-p crabc-libc', madvise)
        self.assertIn('x86_mincore_reference_probe.c', mincore)
        self.assertIn('mincore ABI/behavior reference', mincore)
        self.assertNotIn('-p crabc-libc', mincore)
        self.assertIn('x86_fs_advice_reference_probe.c', fs_advice)
        self.assertIn('filesystem-advice ABI/behavior reference', fs_advice)
        self.assertNotIn('-p crabc-libc', fs_advice)
        self.assertIn('x86_memfd_reference_probe.c', memfd)
        self.assertIn('memfd/sealing ABI/behavior reference', memfd)
        self.assertIn(
            'syscall=319 commands=1033,1034 mfd=1,2,4 seals=1,2,4,8,16 name=proc-label fd=cloexec-owned lifecycle=allow-empty:add-grow-shrink:final-seal plain=seal-seal errors=EINVAL,EPERM',
            memfd,
        )
        self.assertIn('run_musl_oracle.sh', memfd)
        self.assertNotIn('-p crabc-libc', memfd)
        self.assertIn('x86_ftruncate_reference_probe.c', ftruncate)
        self.assertIn('ftruncate ABI/behavior reference', ftruncate)
        self.assertIn('ftruncate=77 loff_t=signed64', ftruncate)
        self.assertIn('run_musl_oracle.sh', ftruncate)
        self.assertNotIn('-p crabc-libc', ftruncate)
        self.assertIn('x86_file_position_reference_probe.c', file_position)
        self.assertIn('lseek/fsync/fdatasync ABI/behavior reference', file_position)
        self.assertIn('syscalls=lseek:8,fsync:74,fdatasync:75', file_position)
        self.assertIn('sparse=data4096:hole0', file_position)
        self.assertIn('SEEK_DATA/HOLE:ENXIO', file_position)
        self.assertIn('run_musl_oracle.sh', file_position)
        self.assertNotIn('-p crabc-libc', file_position)
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
        self.assertIn('c-time=whole-second', time_observation_reference)
        self.assertNotIn('-p crabc-libc', time_observation_reference)
        self.assertIn('x86_relative_sleep_reference_probe.c', relative_sleep_reference)
        self.assertIn('relative-sleep reference', relative_sleep_reference)
        self.assertNotIn('-p crabc-libc', relative_sleep_reference)
        self.assertIn('x86_clock_nanosleep_reference_probe.c', clock_nanosleep_reference)
        self.assertIn('clock_nanosleep ABI and behavior reference', clock_nanosleep_reference)
        self.assertIn('run_musl_oracle.sh', clock_nanosleep_reference)
        self.assertIn('musl-convention=positive-error/raw-errno', clock_nanosleep_reference)
        self.assertNotIn('-p crabc-libc', clock_nanosleep_reference)
        self.assertIn('(void)ualarm(20000, 0);', clock_nanosleep_probe)
        self.assertNotIn('ualarm(20000, 0) != 0', clock_nanosleep_probe)
        self.assertIn('x86_getitimer_reference_probe.c', getitimer_reference)
        self.assertIn('getitimer ABI and read-only behavior reference', getitimer_reference)
        self.assertIn('run_musl_oracle.sh', getitimer_reference)
        self.assertNotIn('-p crabc-libc', getitimer_reference)
        self.assertIn('x86_setitimer_reference_probe.c', setitimer_reference)
        self.assertIn('setitimer ABI and contained behavior reference', setitimer_reference)
        self.assertIn('run_musl_oracle.sh', setitimer_reference)
        self.assertNotIn('-p crabc-libc', setitimer_reference)
        self.assertIn('SYS_setitimer == 38', setitimer_probe)
        self.assertIn('run_in_child', setitimer_probe)
        self.assertIn('invalid=EINVAL', setitimer_probe)
        self.assertNotIn('ualarm(', setitimer_probe)
        self.assertNotIn('alarm(', setitimer_probe)
        self.assertIn('SigHandler::Ignore', setitimer_test)
        self.assertIn('Signal::ALARM', setitimer_test)
        self.assertIn('restore SIGALRM', setitimer_test)
        self.assertIn('x86_timerfd_reference_probe.c', timerfd_reference)
        self.assertIn('timerfd ABI/lifecycle reference', timerfd_reference)
        self.assertIn('run_musl_oracle.sh', timerfd_reference)
        self.assertNotIn('-p crabc-libc', timerfd_reference)
        self.assertIn('x86_pselect_reference_probe.c', pselect_reference)
        self.assertIn('pselect ABI/behavior reference', pselect_reference)
        self.assertIn('run_musl_oracle.sh', pselect_reference)
        self.assertNotIn('-p crabc-libc', pselect_reference)
        self.assertIn('x86_poll_reference_probe.c', poll_reference)
        self.assertIn('poll ABI/behavior reference', poll_reference)
        self.assertNotIn('-p crabc-libc', poll_reference)
        self.assertIn('x86_ppoll_reference_probe.c', ppoll_reference)
        self.assertIn('ppoll/pause signal-mask reference', ppoll_reference)
        self.assertNotIn('-p crabc-libc', ppoll_reference)
        self.assertIn('x86_epoll_reference_probe.c', epoll_reference)
        self.assertIn('epoll ABI/behavior reference', epoll_reference)
        self.assertIn('run_musl_oracle.sh', epoll_reference)
        self.assertNotIn('-p crabc-libc', epoll_reference)
        self.assertIn('x86_process_identity_reference_probe.c', process_identity_reference)
        self.assertIn('process-identity reference', process_identity_reference)
        self.assertNotIn('-p crabc-libc', process_identity_reference)
        self.assertIn(
            'x86_thread_credentials_reference_probe.c',
            thread_credentials_reference,
        )
        self.assertIn(
            'calling-thread credential ABI reference',
            thread_credentials_reference,
        )
        self.assertIn(
            'syscalls=setresuid:117,setresgid:119',
            thread_credentials_reference,
        )
        self.assertIn('run_musl_oracle.sh', thread_credentials_reference)
        self.assertNotIn('-p crabc-libc', thread_credentials_reference)
        self.assertIn('x86_getgroups_reference_probe.c', getgroups_reference)
        self.assertIn('getgroups ABI and supplementary-group behavior reference', getgroups_reference)
        self.assertIn('run_musl_oracle.sh', getgroups_reference)
        self.assertNotIn('-p crabc-libc', getgroups_reference)
        self.assertIn('x86_process_session_reference_probe.c', process_session_reference)
        self.assertIn('process-session reference', process_session_reference)
        self.assertNotIn('-p crabc-libc', process_session_reference)
        self.assertIn('x86_pidfd_open_reference_probe.c', pidfd_open_reference)
        self.assertIn('pidfd_open reference', pidfd_open_reference)
        self.assertNotIn('-p crabc-libc', pidfd_open_reference)
        self.assertIn('x86_fcntl_getlk_reference_probe.c', fcntl_getlk_reference)
        self.assertIn('fcntl_getlk reference', fcntl_getlk_reference)
        self.assertNotIn('-p crabc-libc', fcntl_getlk_reference)
        self.assertIn('x86_scheduler_priority_bounds_reference_probe.c', scheduler_priority_bounds_reference)
        self.assertIn('scheduler-priority bounds reference', scheduler_priority_bounds_reference)
        self.assertNotIn('-p crabc-libc', scheduler_priority_bounds_reference)
        self.assertIn('x86_priority_reference_probe.c', priority_reference)
        self.assertIn('getpriority reference', priority_reference)
        self.assertNotIn('-p crabc-libc', priority_reference)
        self.assertIn('x86_setpriority_reference_probe.c', setpriority_reference)
        self.assertIn('setpriority ABI and behavior reference', setpriority_reference)
        self.assertIn('run_musl_oracle.sh', setpriority_reference)
        self.assertNotIn('-p crabc-libc', setpriority_reference)
        self.assertIn('x86_rlimit_reference_probe.c', rlimit_reference)
        self.assertIn('getrlimit/prlimit64 reference', rlimit_reference)
        self.assertIn('run_musl_oracle.sh', rlimit_reference)
        self.assertNotIn('-p crabc-libc', rlimit_reference)
        self.assertIn('x86_rusage_reference_probe.c', rusage_reference)
        self.assertIn('getrusage ABI/behavior reference', rusage_reference)
        self.assertIn('run_musl_oracle.sh', rusage_reference)
        self.assertNotIn('-p crabc-libc', rusage_reference)
        self.assertIn('x86_times_reference_probe.c', times_reference)
        self.assertIn('times ABI and process-accounting behavior reference', times_reference)
        self.assertIn('run_musl_oracle.sh', times_reference)
        self.assertNotIn('-p crabc-libc', times_reference)
        self.assertIn('x86_fstat_reference_probe.c', fstat_reference)
        self.assertIn('fstat reference', fstat_reference)
        self.assertNotIn('-p crabc-libc', fstat_reference)
        self.assertIn('x86_statat_reference_probe.c', statat_reference)
        self.assertIn('statat reference', statat_reference)
        self.assertIn('run_musl_oracle.sh', statat_reference)
        self.assertNotIn('-p crabc-libc', statat_reference)
        self.assertIn('x86_getcwd_reference_probe.c', getcwd_reference)
        self.assertIn('getcwd reference', getcwd_reference)
        self.assertIn('run_musl_oracle.sh', getcwd_reference)
        self.assertNotIn('-p crabc-libc', getcwd_reference)
        self.assertIn('x86_readlinkat_reference_probe.c', readlinkat_reference)
        self.assertIn('readlinkat reference', readlinkat_reference)
        self.assertIn('run_musl_oracle.sh', readlinkat_reference)
        self.assertNotIn('-p crabc-libc', readlinkat_reference)
        self.assertIn('sched_getaffinity ABI and behavior reference', sched_affinity_reference)
        self.assertIn('run_musl_oracle.sh', sched_affinity_reference)
        self.assertNotIn('-p crabc-libc', sched_affinity_reference)
        self.assertIn('sched_setaffinity ABI and behavior reference', sched_affinity_set_reference)
        self.assertIn('run_musl_oracle.sh', sched_affinity_set_reference)
        self.assertIn('child-singleton', sched_affinity_set_reference)
        self.assertNotIn('-p crabc-libc', sched_affinity_set_reference)
        self.assertIn('x86_sched_rr_interval_reference_probe.c', rr_interval_reference)
        self.assertIn('sched_rr_get_interval ABI and behavior reference', rr_interval_reference)
        self.assertIn('run_musl_oracle.sh', rr_interval_reference)
        self.assertNotIn('-p crabc-libc', rr_interval_reference)
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

    def test_libc_thread_pointer_probe_stays_a_private_opaque_fs_leaf(self) -> None:
        rust_probe = (
            ROOT / "compat" / "x86_64" / "libc_thread_pointer_probe.rs"
        ).read_text(encoding="utf-8")
        thread_pointer = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "thread_pointer.rs"
        ).read_text(encoding="utf-8")
        c_probe = (
            ROOT / "compat" / "x86_64" / "libc_thread_pointer_probe.c"
        ).read_text(encoding="utf-8")
        script = (
            ROOT / "compat" / "x86_64" / "run_libc_thread_pointer.sh"
        ).read_text(encoding="utf-8")

        self.assertIn('libc/src/c_abi/x86_64/thread_pointer.rs', rust_probe)
        self.assertIn('pthread_arch.h::__get_tp()', thread_pointer)
        self.assertIn('9fa28ece75d8a2191de7c5bb53bed224c5947417', thread_pointer)
        self.assertIn("musl's MIT license", thread_pointer)
        self.assertIn('pub(crate) unsafe fn thread_pointer_identity()', thread_pointer)
        self.assertIn('options(readonly, nostack, preserves_flags)', thread_pointer)
        self.assertNotIn('#[no_mangle]', thread_pointer)
        self.assertIn('crabc_x86_64_thread_pointer_probe', c_probe)
        self.assertIn('inline_fs0', c_probe)
        self.assertIn('pthread_create', c_probe)
        self.assertNotIn('pthread_self', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('/usr/local/bin/crabc-x86_64-musl-gcc', script)
        self.assertIn('%fs:0x0', script)
        self.assertIn('R_X86_64_(TPOFF', script)
        self.assertIn('__tls_get_addr', script)
        self.assertIn('-no-pie -pthread', script)
        self.assertNotIn('-I"$ROOT_DIR/include"', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_foundation_probe_composes_only_the_narrow_x86_primitives(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_foundation_probe.rs").read_text(
            encoding="utf-8"
        )
        foundation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "foundation.rs"
        ).read_text(encoding="utf-8")
        c_probe = (ROOT / "compat" / "x86_64" / "libc_foundation_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_foundation.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/foundation.rs', rust_probe)
        self.assertIn('crabc_x86_64_foundation_syscall6', foundation)
        self.assertIn('raw_syscall::syscall6', foundation)
        self.assertIn('errno::set_errno', foundation)
        self.assertIn('target_arch = "x86_64"', foundation)
        self.assertNotIn('pub unsafe extern "C" fn syscall(', foundation)
        self.assertIn('crabc_x86_64_foundation_syscall6(', c_probe)
        self.assertIn('FE_INVALID', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('R_X86_64_TPOFF', script)
        self.assertIn('fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_clone_signal_and_umask_slices_remain_private_or_typed(self) -> None:
        clone = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clone.rs").read_text(
            encoding="utf-8"
        )
        clone_probe = (ROOT / "compat" / "x86_64" / "libc_clone_raw_probe.c").read_text(
            encoding="utf-8"
        )
        clone_runner = (ROOT / "compat" / "x86_64" / "run_libc_clone_raw.sh").read_text(
            encoding="utf-8"
        )
        signal = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_foundation.rs"
        ).read_text(encoding="utf-8")
        signal_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_foundation.sh"
        ).read_text(encoding="utf-8")
        setrlimit_probe = (
            ROOT / "compat" / "x86_64" / "x86_setrlimit_reference_probe.c"
        ).read_text(encoding="utf-8")
        setrlimit_runner = (
            ROOT / "compat" / "x86_64" / "run_x86_setrlimit_reference.sh"
        ).read_text(encoding="utf-8")
        setrlimit_test = (
            ROOT / "crabc-rs" / "tests" / "x86_64_setrlimit.rs"
        ).read_text(encoding="utf-8")
        setpriority_probe = (
            ROOT / "compat" / "x86_64" / "x86_setpriority_reference_probe.c"
        ).read_text(encoding="utf-8")
        setpriority_runner = (
            ROOT / "compat" / "x86_64" / "run_x86_setpriority_reference.sh"
        ).read_text(encoding="utf-8")
        setpriority_test = (
            ROOT / "crabc-rs" / "tests" / "x86_64_setpriority.rs"
        ).read_text(encoding="utf-8")
        umask_probe = (
            ROOT / "compat" / "x86_64" / "x86_umask_reference_probe.c"
        ).read_text(encoding="utf-8")
        umask_runner = (
            ROOT / "compat" / "x86_64" / "run_x86_umask_reference.sh"
        ).read_text(encoding="utf-8")
        umask_test = (ROOT / "crabc-rs" / "tests" / "x86_64_umask.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn("src/thread/x86_64/clone.s", clone)
        self.assertIn("__crabc_x86_clone_raw", clone)
        self.assertNotIn('fn clone(', clone)
        self.assertIn("CRABC_CLONE_ORACLE", clone_probe)
        self.assertIn("SIGCHLD", clone_probe)
        self.assertIn("run_musl_oracle.sh", clone_runner)
        self.assertIn(".note.GNU-stack", clone_runner)
        self.assertNotIn("-p crabc-libc", clone_runner)

        self.assertIn("src/signal/sigaction.c", signal)
        self.assertIn("SA_RESTORER", signal)
        self.assertIn("crabc_x86_64_signal_restorer", signal)
        self.assertIn("read_unaligned", signal)
        self.assertIn("flags as i64 as u64", signal)
        self.assertIn("run_signal_header_abi.sh", signal_runner)
        self.assertIn("run_musl_oracle.sh", signal_runner)
        self.assertNotIn("-p crabc-libc", signal_runner)

        self.assertIn("SYS_prlimit64 == 302", setrlimit_probe)
        self.assertIn("run_in_child", setrlimit_probe)
        self.assertIn("raw-set:musl-read:musl-restore:raw-read", setrlimit_probe)
        self.assertIn("run_musl_oracle.sh", setrlimit_runner)
        self.assertNotIn("-p crabc-libc", setrlimit_runner)
        self.assertIn("RestoreRlimit", setrlimit_test)
        self.assertIn("process::setrlimit", setrlimit_test)
        self.assertIn("x86_64_setrlimit_child_mutates_and_restores", setrlimit_test)
        self.assertIn("#[ignore", setrlimit_test)
        self.assertIn('"--ignored"', setrlimit_test)
        self.assertNotIn("CRABC_RS_X86_64_SETRLIMIT_CHILD", setrlimit_test)

        self.assertIn("SYS_setpriority == 141", setpriority_probe)
        self.assertIn("run_in_child", setpriority_probe)
        self.assertIn("raw-set:musl-read:musl-noop:raw-read", setpriority_probe)
        self.assertIn("raw_setpriority(PRIO_PGRP", setpriority_probe)
        self.assertIn("raw_setpriority(PRIO_USER", setpriority_probe)
        self.assertIn("run_musl_oracle.sh", setpriority_runner)
        self.assertNotIn("-p crabc-libc", setpriority_runner)
        self.assertIn("process::setpriority_process", setpriority_test)
        self.assertIn("process::setpriority_process_group", setpriority_test)
        self.assertIn("process::setpriority_user", setpriority_test)
        self.assertIn("x86_64_setpriority_child_mutates_only_the_calling_process", setpriority_test)
        self.assertIn("#[ignore", setpriority_test)
        self.assertIn('"--ignored"', setpriority_test)

        self.assertIn("SYS_umask == 95", umask_probe)
        self.assertIn("run_in_child", umask_probe)
        self.assertIn("run_musl_oracle.sh", umask_runner)
        self.assertIn("RestoreUmask", umask_test)
        self.assertIn("process::umask", umask_test)

    def test_x86_fs_credentials_are_typed_and_child_contained(self) -> None:
        process = (ROOT / "crabc-rs" / "src" / "process_x86_64.rs").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "x86_fs_credentials_reference_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_x86_fs_credentials_reference.sh"
        ).read_text(encoding="utf-8")
        test = (ROOT / "crabc-rs" / "tests" / "x86_64_fs_credentials.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn("pub unsafe fn set_fs_uid", process)
        self.assertIn("pub unsafe fn set_fs_gid", process)
        self.assertIn("setfsuid_raw(uid).map(Uid::from_raw)", process)
        self.assertIn("setfsgid_raw(gid).map(Gid::from_raw)", process)
        self.assertGreaterEqual(process.count("== u32::MAX => return Err(crate::Errno::INVAL)"), 2)
        self.assertIn("previous value even when the requested change is denied", process)
        self.assertIn("calling-task operation, not musl's synchronized", process)

        self.assertIn("SYS_setfsuid == 122", probe)
        self.assertIn("SYS_setfsgid == 123", probe)
        self.assertIn("raw_fsuid_query", probe)
        self.assertIn("raw_fsgid_query", probe)
        self.assertIn("setfsuid(effective_uid)", probe)
        self.assertIn("setfsgid(effective_gid)", probe)
        self.assertIn("run_in_child", probe)
        self.assertIn("child-contained", probe)

        self.assertIn("run_musl_oracle.sh", runner)
        self.assertIn("/usr/local/bin/crabc-x86_64-musl-gcc", runner)
        self.assertNotIn("-p crabc-libc", runner)

        self.assertIn("#[ignore", test)
        self.assertIn('"--ignored"', test)
        self.assertIn("x86_64_fs_credentials_child_queries_and_requests_current_identity", test)
        self.assertIn("Err(Errno::INVAL)", test)

    def test_libc_fenv_probe_is_a_fixed_source_only_x87_mxcsr_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_fenv_probe.rs").read_text(
            encoding="utf-8"
        )
        fenv = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "fenv.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_fenv_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_fenv.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/fenv.rs', rust_probe)
        self.assertIn('musl 1.2.6', fenv)
        self.assertIn('global_asm!', fenv)
        self.assertIn('.global feclearexcept', fenv)
        self.assertIn('stmxcsr', fenv)
        self.assertIn('ldmxcsr', fenv)
        self.assertIn('sizeof(fenv_t) == 32', c_probe)
        self.assertIn('feholdexcept', c_probe)
        self.assertIn('feupdateenv', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('-fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', rust_probe)

    def test_libc_memory_probe_is_a_fixed_source_only_string_boundary(self) -> None:
        rust_probe = (ROOT / "compat" / "x86_64" / "libc_memory_probe.rs").read_text(
            encoding="utf-8"
        )
        memory = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory.rs").read_text(
            encoding="utf-8"
        )
        c_probe = (ROOT / "compat" / "x86_64" / "libc_memory_probe.c").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_memory.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/memory.rs', rust_probe)
        self.assertIn('musl 1.2.6', memory)
        self.assertIn('global_asm!', memory)
        self.assertIn('.global __memcpy_fwd', memory)
        self.assertIn('rep movsq', memory)
        self.assertIn('rep stosq', memory)
        self.assertIn('std', memory)
        self.assertIn('cld', memory)
        self.assertIn('#include <string.h>', c_probe)
        self.assertIn('test_guard_pages', c_probe)
        self.assertIn('direction_flag_is_clear', c_probe)
        self.assertIn('run_musl_oracle.sh', script)
        self.assertIn('-fno-builtin', script)
        self.assertNotIn('-p crabc-libc', script)
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

    def test_libc_atomic_probe_is_a_fixed_source_only_atomic_boundary(self) -> None:
        probe = (ROOT / "compat" / "x86_64" / "libc_atomic_probe.rs").read_text(
            encoding="utf-8"
        )
        atomic = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "atomic.rs").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_atomic.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('libc/src/c_abi/x86_64/atomic.rs', probe)
        self.assertIn('x86_64_compare_exchange_acqrel_i32', atomic)
        self.assertIn('lock cmpxchg', atomic)
        self.assertIn('lock xadd', atomic)
        self.assertIn('x86_64_swap_acqrel_i32', atomic)
        self.assertIn('x86_64-unknown-linux-musl', script)
        self.assertIn('crabc_x86_atomic_probe_compare_exchange', script)
        self.assertIn('crabc_x86_atomic_probe_fetch_add', script)
        self.assertIn('crabc_x86_atomic_probe_fetch_sub', script)
        self.assertNotIn('-p crabc-libc', script)
        self.assertNotIn('crabc_libc', probe)

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
                    "futex",
                    "--test",
                    "x86_64_foundation",
                    "--test",
                    "x86_64_epoll",
                    "--test",
                    "x86_64_eventfd",
                    "--test",
                    "x86_64_fcntl_getlk",
                    "--test",
                    "x86_64_fs",
                    "--test",
                    "x86_64_fs_advice",
                    "--test",
                    "x86_64_file_position",
                    "--test",
                    "x86_64_ftruncate",
                    "--test",
                    "x86_64_fs_credentials",
                    "--test",
                    "x86_64_getgroups",
                    "--test",
                    "x86_64_getitimer",
                    "--test",
                    "x86_64_setitimer",
                    "--test",
                    "x86_64_io",
                    "--test",
                    "x86_64_memfd",
                    "--test",
                    "x86_64_mm",
                    "--test",
                    "x86_64_param",
                    "--test",
                    "x86_64_pipe",
                    "--test",
                    "x86_64_poll",
                    "--test",
                    "x86_64_pselect",
                    "--test",
                    "x86_64_priority",
                    "--test",
                    "x86_64_setpriority",
                    "--test",
                    "x86_64_process_identity",
                    "--test",
                    "x86_64_process_session",
                    "--test",
                    "x86_64_pidfd_open",
                    "--test",
                    "x86_64_rand",
                    "--test",
                    "x86_64_rlimit",
                    "--test",
                    "x86_64_setrlimit",
                    "--test",
                    "x86_64_umask",
                    "--test",
                    "x86_64_rusage",
                    "--test",
                    "x86_64_scheduler_priority_bounds",
                    "--test",
                    "x86_64_sleep",
                    "--test",
                    "x86_64_clock_nanosleep",
                    "--test",
                    "x86_64_statat",
                    "--test",
                    "x86_64_getcwd",
                    "--test",
                    "x86_64_readlink",
                    "--test",
                    "x86_64_sched_rr_interval",
                    "--test",
                    "x86_64_sched_affinity",
                    "--test",
                    "x86_64_sched_setaffinity",
                    "--test",
                    "x86_64_system",
                    "--test",
                    "x86_64_thread",
                    "--test",
                    "x86_64_thread_credentials",
                    "--test",
                    "x86_64_time",
                    "--test",
                    "x86_64_timerfd",
                    "--test",
                    "x86_64_times",
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
