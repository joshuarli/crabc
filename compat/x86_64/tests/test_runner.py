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
        self.assertIn("    madvise-reference) ;;", source)
        self.assertIn("    ctype-header-abi) ;;", source)
        self.assertIn("    ffs-header-abi) ;;", source)
        self.assertIn("    byte-strings-header-abi) ;;", source)
        self.assertIn("    memory-search-header-abi) ;;", source)
        self.assertIn("    string-copy-header-abi) ;;", source)
        self.assertIn("    math-complex-header-abi)", source)
        self.assertIn("    libc-math-complex)", source)
        source = source.replace(
            "msync-reference|mincore-reference",
            "msync-reference|madvise-reference|mincore-reference",
            1,
        )
        source = source.replace("resource-header-abi|socket-header-abi|", "resource-header-abi|", 1)
        source = source.replace("libc-readiness-waits|", "", 1)
        source = source.replace("libc-socket-transport|", "", 1)
        source = source.replace("libc-system-observation|", "", 1)
        source = source.replace("libc-uts-identity|", "", 1)
        source = source.replace("libc-pthread-create-join-tls|", "", 1)
        source = source.replace("resource-header-abi|random-entropy-header-abi|mm-abi-reference|", "resource-header-abi|mm-abi-reference|", 1)
        self.assertIn("public-header-surface", source)
        self.assertIn("math-complex-header-abi", source)
        source = source.replace(
            "header-abi-reference|public-header-surface|header-abi-project|math-complex-header-abi",
            "header-abi-reference|header-abi-project",
            1,
        )
        self.assertIn("libc-math-complex", source)
        source = source.replace(
            "libc-fenv|libc-math-complex|libc-memory",
            "libc-fenv|libc-memory",
            1,
        )
        self.assertIn(
            'image|musl-oracle|header-abi-reference|header-abi-project|sys-reg-header-abi|types-header-abi|stat-header-abi|time-header-abi|poll-header-abi|select-header-abi|fcntl-header-abi|unistd-header-abi|system-header-abi|syscall-header-abi|signal-header-abi|termios-header-abi|mman-header-abi|resource-header-abi|mm-abi-reference|mapping-reference|memory-vm-reference|pty-basic-reference|terminal-reference|mlock-reference|msync-reference|madvise-reference|mincore-reference|fs-advice-reference|memfd-reference|ftruncate-reference|statfs-reference|timestamp-reference|path-lifecycle-reference|namespace-reference|path-core-reference|xattr-reference|directory-reference|temporary-object-reference|statx-reference|cwd-canonicalize-reference|root-change-reference|mount-reference|thread-kill-reference|ipc-reference|shm-reference|inotify-reference|socket-transport-reference|interface-device-reference|resolver-transport-reference|resolver-facade-reference|netdb-reference|users-databases-reference|posix-fallocate-reference|fallocate-reference|file-position-reference|sync-reference|syncfs-reference|sync-file-range-reference|rand-reference|time-abi-reference|time-observation-reference|calendar-time-reference|advanced-time-reference|relative-sleep-reference|clock-nanosleep-reference|getitimer-reference|setitimer-reference|timerfd-reference|pselect-reference|poll-reference|ppoll-reference|epoll-reference|process-identity-reference|child-ownership-reference|getgroups-reference|process-session-reference|pidfd-open-reference|fcntl-getlk-reference|fcntl-status-reference|flock-reference|sendfile-reference|copy-file-range-reference|scheduler-priority-bounds-reference|rr-interval-reference|sched-affinity-reference|sched-affinity-set-reference|priority-reference|setpriority-reference|rlimit-reference|rlimit-targeted-reference|setrlimit-reference|umask-reference|rusage-reference|times-reference|fstat-reference|statat-reference|getcwd-reference|readlinkat-reference|access-reference|system-reference|thread-reference|thread-credentials-reference|fs-credentials-reference|core|facade|facade-record-owning|libc-syscall|libc-errno-tls|libc-stat-compat|libc-credentials|libc-bootstrap-primitives|libc-signal-control|libc-signal-execution|libc-termios-control|libc-process-context|libc-descriptor-io|libc-process-resources|libc-thread-pointer|libc-foundation|libc-fenv|libc-memory|libc-setjmp|libc-atomic|libc-clone-raw|libc-signal-foundation|ldso-relocation|ldso-image)',
            source,
        )
        self.assertIn("libc-stat-compat", source)
        self.assertIn("libc-credentials", source)
        self.assertIn("libc-bootstrap-primitives", source)
        self.assertIn("libc-signal-control", source)
        self.assertIn("libc-signal-execution", source)
        self.assertIn("libc-pthread-create-join-tls", source)
        self.assertIn("libc-termios-control", source)
        self.assertIn("libc-process-context", source)
        self.assertIn("libc-descriptor-io", source)
        self.assertIn("libc-process-resources", source)
        self.assertIn("libc-readiness-waits", source)
        self.assertIn("libc-socket-transport", source)
        self.assertIn("libc-system-observation", source)
        self.assertIn("libc-uts-identity", source)
        self.assertIn('run_musl_oracle()', source)
        self.assertIn('compat/x86_64/run_musl_oracle.sh', source)
        self.assertIn('run_header_abi_reference()', source)
        self.assertIn('compat/x86_64/run_header_abi_reference.sh', source)
        self.assertIn('run_public_header_surface()', source)
        self.assertIn('compat/x86_64/run_public_header_surface.sh', source)
        self.assertIn('run_header_abi_project()', source)
        self.assertIn('compat/x86_64/run_project_header_abi.sh', source)
        self.assertIn('run_math_complex_header_abi()', source)
        self.assertIn('compat/x86_64/run_math_complex_header_abi.sh', source)
        self.assertIn('run_sys_reg_header_abi()', source)
        self.assertIn('compat/x86_64/run_sys_reg_header_abi.sh', source)
        self.assertIn('run_types_header_abi()', source)
        self.assertIn('compat/x86_64/run_types_header_abi.sh', source)
        self.assertIn('run_stat_header_abi()', source)
        self.assertIn('compat/x86_64/run_stat_header_abi.sh', source)
        self.assertIn('run_ctype_header_abi()', source)
        self.assertIn('compat/x86_64/run_ctype_header_abi.sh', source)
        self.assertIn('run_integer_arithmetic_header_abi()', source)
        self.assertIn('compat/x86_64/run_integer_arithmetic_header_abi.sh', source)
        self.assertIn('run_credential_observation_header_abi()', source)
        self.assertIn(
            'compat/x86_64/run_credential_observation_header_abi.sh', source
        )
        self.assertIn('run_ffs_header_abi()', source)
        self.assertIn('compat/x86_64/run_ffs_header_abi.sh', source)
        self.assertIn('run_byte_strings_header_abi()', source)
        self.assertIn('compat/x86_64/run_byte_strings_header_abi.sh', source)
        self.assertIn('run_memory_search_header_abi()', source)
        self.assertIn('compat/x86_64/run_memory_search_header_abi.sh', source)
        self.assertIn('run_string_copy_header_abi()', source)
        self.assertIn('compat/x86_64/run_string_copy_header_abi.sh', source)
        self.assertIn('run_random_entropy_header_abi()', source)
        self.assertIn('compat/x86_64/run_random_entropy_header_abi.sh', source)
        self.assertIn('run_time_header_abi()', source)
        self.assertIn('compat/x86_64/run_time_header_abi.sh', source)
        self.assertIn('run_poll_header_abi()', source)
        self.assertIn('compat/x86_64/run_poll_header_abi.sh', source)
        self.assertIn('run_select_header_abi()', source)
        self.assertIn('compat/x86_64/run_select_header_abi.sh', source)
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
        self.assertIn('run_termios_header_abi()', source)
        self.assertIn('compat/x86_64/run_termios_header_abi.sh', source)
        self.assertIn('run_mman_header_abi()', source)
        self.assertIn('compat/x86_64/run_mman_header_abi.sh', source)
        self.assertIn('run_resource_header_abi()', source)
        self.assertIn('compat/x86_64/run_resource_header_abi.sh', source)
        self.assertIn('run_mm_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mm_reference.sh', source)
        self.assertIn('run_mapping_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mapping_reference.sh', source)
        self.assertIn('--test x86_64_memory_mapping', source)
        self.assertIn('--example mapping_direct_probe', source)
        mapping_reference = source.split('run_mapping_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', mapping_reference)
        self.assertIn('--test x86_64_memory_mapping', mapping_reference)
        self.assertIn('-- --test-threads=1', mapping_reference)
        self.assertIn('run_in_container cargo build', mapping_reference)
        self.assertIn('--example mapping_direct_probe', mapping_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_mapping_reference.sh',
            mapping_reference,
        )
        self.assertIn('run_memory_vm_reference()', source)
        self.assertIn('compat/x86_64/run_x86_memory_vm_reference.sh', source)
        self.assertIn('--test x86_64_memory_vm', source)
        self.assertIn('--example memory_vm_direct_probe', source)
        memory_vm_reference = source.split('run_memory_vm_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', memory_vm_reference)
        self.assertIn('--test x86_64_memory_vm', memory_vm_reference)
        self.assertIn('-- --test-threads=1', memory_vm_reference)
        self.assertIn('run_in_container cargo build', memory_vm_reference)
        self.assertIn('--example memory_vm_direct_probe', memory_vm_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_memory_vm_reference.sh',
            memory_vm_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', memory_vm_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', memory_vm_reference)
        self.assertIn('run_pty_basic_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pty_basic_reference.sh', source)
        self.assertIn('--test x86_64_pty_basic', source)
        self.assertIn('--example pty_basic_direct_probe', source)
        pty_basic_reference = source.split('run_pty_basic_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertEqual(pty_basic_reference.count('run_in_container cargo test'), 2)
        self.assertIn(
            '-p crabc-rs --no-default-features --test x86_64_pty_basic',
            pty_basic_reference,
        )
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_pty_basic',
            pty_basic_reference,
        )
        self.assertIn('-- --test-threads=1', pty_basic_reference)
        self.assertIn('run_in_container cargo build', pty_basic_reference)
        self.assertIn('--example pty_basic_direct_probe', pty_basic_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_pty_basic_reference.sh',
            pty_basic_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', pty_basic_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', pty_basic_reference)
        self.assertIn('run_terminal_reference()', source)
        self.assertIn('compat/x86_64/run_x86_terminal_reference.sh', source)
        terminal_reference = source.split('run_terminal_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertEqual(terminal_reference.count('run_in_container cargo test'), 2)
        self.assertIn('-p crabc-rs --no-default-features --test x86_64_terminal', terminal_reference)
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_terminal',
            terminal_reference,
        )
        self.assertIn('--example x86_64_terminal_direct_probe', terminal_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_terminal_reference.sh',
            terminal_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', terminal_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', terminal_reference)
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
        self.assertIn('run_timestamp_reference()', source)
        self.assertIn('compat/x86_64/run_x86_timestamp_reference.sh', source)
        self.assertIn('--test x86_64_futimens', source)
        self.assertIn('--test x86_64_timestamp_paths', source)
        self.assertNotIn('futimens-reference', source)
        self.assertNotIn('run_x86_futimens_reference.sh', source)
        self.assertIn('run_posix_fallocate_reference()', source)
        self.assertIn('compat/x86_64/run_x86_posix_fallocate_reference.sh', source)
        self.assertIn('--test x86_64_posix_fallocate -- --test-threads=1', source)
        self.assertIn('run_fallocate_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fallocate_reference.sh', source)
        self.assertIn('--test x86_64_fallocate -- --test-threads=1', source)
        self.assertIn('run_file_position_reference()', source)
        self.assertIn('compat/x86_64/run_x86_file_position_reference.sh', source)
        self.assertIn('run_sync_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sync_reference.sh', source)
        self.assertIn('--test x86_64_sync -- --test-threads=1', source)
        self.assertIn('run_syncfs_reference()', source)
        self.assertIn('compat/x86_64/run_x86_syncfs_reference.sh', source)
        self.assertIn('--test x86_64_syncfs -- --test-threads=1', source)
        self.assertIn('run_sync_file_range_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sync_file_range_reference.sh', source)
        self.assertIn('--test x86_64_sync_file_range -- --test-threads=1', source)
        self.assertIn('run_rand_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rand_reference.sh', source)
        self.assertIn('run_time_abi_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_reference.sh', source)
        self.assertIn('run_time_observation_reference()', source)
        self.assertIn('compat/x86_64/run_x86_time_observation_reference.sh', source)
        self.assertIn('run_calendar_time_reference()', source)
        self.assertIn('compat/x86_64/run_x86_calendar_time_reference.sh', source)
        self.assertIn(
            'x86_64_gettimeofday_writes_one_normalized_private_record',
            source,
        )
        self.assertIn('--test time --test calendar_utc --test x86_64_calendar_time', source)
        self.assertIn('--test timezone_rules --test calendar_local', source)
        self.assertIn('--example time_direct_probe --example calendar_utc_direct_probe', source)
        self.assertIn('--example calendar_local_direct_probe', source)
        self.assertIn('run_advanced_time_reference()', source)
        self.assertIn('compat/x86_64/run_x86_advanced_time_reference.sh', source)
        self.assertIn(
            'x86_64_posix_timer_writes_exact_id_and_old_setting_records',
            source,
        )
        self.assertIn('--test x86_64_advanced_time', source)
        self.assertIn('--example time_dynamic_direct_probe', source)
        self.assertIn('--example process_clock_id_direct_probe', source)
        self.assertIn('--example time_settime_direct_probe', source)
        self.assertIn('--example time_timers_direct_probe', source)
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
        self.assertIn('run_child_ownership_reference()', source)
        self.assertIn('compat/x86_64/run_x86_child_ownership_reference.sh', source)
        self.assertIn('--test x86_64_child_ownership -- --test-threads=1', source)
        self.assertIn('run_getgroups_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getgroups_reference.sh', source)
        self.assertIn('run_process_session_reference()', source)
        self.assertIn('compat/x86_64/run_x86_process_session_reference.sh', source)
        self.assertIn('run_pidfd_open_reference()', source)
        self.assertIn('compat/x86_64/run_x86_pidfd_open_reference.sh', source)
        self.assertIn('run_fcntl_getlk_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fcntl_getlk_reference.sh', source)
        self.assertIn('run_fcntl_status_reference()', source)
        self.assertIn('compat/x86_64/run_x86_fcntl_status_reference.sh', source)
        self.assertIn('--test x86_64_fcntl_flags -- --test-threads=1', source)
        self.assertIn('run_flock_reference()', source)
        self.assertIn('compat/x86_64/run_x86_flock_reference.sh', source)
        self.assertIn('--test x86_64_flock -- --test-threads=1', source)
        self.assertIn('run_sendfile_reference()', source)
        self.assertIn('compat/x86_64/run_x86_sendfile_reference.sh', source)
        self.assertIn('--test x86_64_sendfile -- --test-threads=1', source)
        self.assertIn('run_copy_file_range_reference()', source)
        self.assertIn('compat/x86_64/run_x86_copy_file_range_reference.sh', source)
        self.assertIn('--test x86_64_copy_file_range -- --test-threads=1', source)
        self.assertIn('run_scheduler_priority_bounds_reference()', source)
        self.assertIn('compat/x86_64/run_x86_scheduler_priority_bounds_reference.sh', source)
        self.assertIn('run_priority_reference()', source)
        self.assertIn('compat/x86_64/run_x86_priority_reference.sh', source)
        self.assertIn('run_setpriority_reference()', source)
        self.assertIn('compat/x86_64/run_x86_setpriority_reference.sh', source)
        self.assertIn('run_rlimit_reference()', source)
        self.assertIn('compat/x86_64/run_x86_rlimit_reference.sh', source)
        self.assertIn('run_rlimit_targeted_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_rlimit_targeted_reference.sh',
            source,
        )
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
        self.assertIn('run_statfs_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statfs_reference.sh', source)
        self.assertIn('--test x86_64_fs_capacity -- --test-threads=1', source)
        self.assertIn('run_path_lifecycle_reference()', source)
        self.assertIn('compat/x86_64/run_x86_path_lifecycle_reference.sh', source)
        self.assertIn('--test x86_64_path_lifecycle -- --test-threads=1', source)
        self.assertIn('run_namespace_reference()', source)
        self.assertIn('compat/x86_64/run_x86_namespace_reference.sh', source)
        self.assertIn('--test x86_64_namespace -- --test-threads=1', source)
        self.assertIn('run_path_core_reference()', source)
        self.assertIn('run_fstat_reference', source)
        self.assertIn('run_statat_reference', source)
        self.assertIn('run_path_lifecycle_reference', source)
        self.assertIn('run_namespace_reference', source)
        self.assertIn('run_timestamp_reference', source)
        self.assertIn('run_readlinkat_reference', source)
        self.assertIn('--features std', source)
        self.assertIn('--test x86_64_readlink', source)
        self.assertIn('--example path_core_owned_direct_probe', source)
        self.assertIn('run_xattr_reference()', source)
        self.assertIn('compat/x86_64/run_x86_xattr_reference.sh', source)
        self.assertIn('--test x86_64_xattr -- --test-threads=1', source)
        self.assertIn('--example xattr_direct_probe', source)
        self.assertIn('run_directory_reference()', source)
        self.assertIn('compat/x86_64/run_x86_directory_reference.sh', source)
        self.assertIn('--test x86_64_raw_directory', source)
        self.assertIn('--test x86_64_directory', source)
        self.assertIn('--test x86_64_directory_position', source)
        self.assertIn('--example directory_direct_probe', source)
        self.assertIn('--example directory_position_direct_probe', source)
        self.assertIn('run_temporary_object_reference()', source)
        self.assertIn('compat/x86_64/run_x86_temporary_object_reference.sh', source)
        self.assertIn('--test x86_64_temporary_objects', source)
        self.assertIn('--features alloc --test x86_64_temporary_objects', source)
        self.assertIn('--example fs_named_tempfile_direct_probe', source)
        self.assertIn('--example fs_tempfile_direct_probe', source)
        self.assertIn('--example fs_tempdir_direct_probe', source)
        self.assertIn('run_statx_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statx_reference.sh', source)
        self.assertIn('--test x86_64_statx -- --test-threads=1', source)
        self.assertIn('--example statx_direct_probe', source)
        self.assertIn('run_cwd_canonicalize_reference()', source)
        self.assertIn('compat/x86_64/run_x86_cwd_canonicalize_reference.sh', source)
        self.assertIn('--test x86_64_canonicalize', source)
        self.assertIn('--test x86_64_cwd_mutation', source)
        self.assertIn('--example fs_canonicalize_direct_probe', source)
        self.assertIn('--example process_cwd_direct_probe', source)
        self.assertIn('run_root_change_reference()', source)
        self.assertIn('compat/x86_64/run_x86_root_change_reference.sh', source)
        self.assertIn('--test x86_64_chroot -- --test-threads=1', source)
        self.assertIn('--example process_chroot_direct_probe', source)
        chroot_cap_container = source.split('run_in_chroot_cap_container() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('--cap-add=SYS_CHROOT', chroot_cap_container)
        root_change_reference = source.split('run_root_change_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_chroot_cap_container cargo test', root_change_reference)
        self.assertIn(
            '--test x86_64_chroot -- --test-threads=1',
            root_change_reference,
        )
        self.assertIn(
            'run_in_chroot_cap_container bash /workspace/compat/x86_64/run_x86_root_change_reference.sh',
            root_change_reference,
        )
        self.assertIn('run_in_container cargo build', root_change_reference)
        self.assertIn('--example process_chroot_direct_probe', root_change_reference)
        self.assertIn('run_mount_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mount_reference.sh', source)
        self.assertIn('--test x86_64_mount', source)
        self.assertIn('--example mount_direct_probe', source)
        mount_reference = source.split('run_mount_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', mount_reference)
        self.assertIn('--test x86_64_mount', mount_reference)
        self.assertIn('-- --test-threads=1', mount_reference)
        self.assertIn('run_in_container cargo build', mount_reference)
        self.assertIn('--example mount_direct_probe', mount_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_mount_reference.sh',
            mount_reference,
        )
        self.assertNotIn('run_in_chroot_cap_container', mount_reference)
        self.assertNotIn('--cap-add=SYS_ADMIN', mount_reference)
        self.assertIn('run_thread_kill_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_thread_kill_reference.sh',
            source,
        )
        self.assertIn('--test x86_64_thread_kill', source)
        self.assertIn('--example thread_kill_direct_probe', source)
        thread_kill_reference = source.split('run_thread_kill_reference() {', 1)[1].split(
            '\n}\n',
            1,
        )[0]
        self.assertIn('run_in_container cargo test', thread_kill_reference)
        self.assertIn('--test x86_64_thread_kill', thread_kill_reference)
        self.assertIn('-- --test-threads=1', thread_kill_reference)
        self.assertIn('run_in_container cargo build', thread_kill_reference)
        self.assertIn('--example thread_kill_direct_probe', thread_kill_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_thread_kill_reference.sh',
            thread_kill_reference,
        )
        self.assertIn('run_ipc_reference()', source)
        self.assertIn('compat/x86_64/run_x86_mqueue_reference.sh', source)
        self.assertIn('--test x86_64_ipc -- --test-threads=1', source)
        self.assertIn('--example ipc_direct_probe', source)
        self.assertIn('run_shm_reference()', source)
        self.assertIn('compat/x86_64/run_x86_shm_reference.sh', source)
        self.assertIn('--test x86_64_shm -- --test-threads=1', source)
        self.assertIn('--example shm_direct_probe', source)
        self.assertIn('run_inotify_reference()', source)
        self.assertIn('compat/x86_64/run_x86_inotify_reference.sh', source)
        self.assertIn('--lib --no-default-features system::inotify::', source)
        self.assertIn('--test x86_64_inotify -- --test-threads=1', source)
        self.assertIn('--example inotify_direct_probe', source)
        self.assertIn('run_socket_transport_reference()', source)
        self.assertIn('compat/x86_64/run_x86_socket_transport_reference.sh', source)
        self.assertIn('--test x86_64_socket_transport -- --test-threads=1', source)
        self.assertIn('run_interface_device_reference()', source)
        self.assertIn('compat/x86_64/run_x86_interface_device_reference.sh', source)
        self.assertIn('--test x86_64_interface_device -- --test-threads=1', source)
        self.assertIn('--lib --no-default-features --features alloc net::netdevice::', source)
        self.assertIn('--example interface_names_direct_probe', source)
        self.assertIn('--example interface_addresses_direct_probe', source)
        self.assertIn('run_resolver_transport_reference()', source)
        self.assertIn(
            '-p crabc-core --no-default-features --test x86_64_resolver_transport', source
        )
        self.assertIn('run_resolver_facade_reference()', source)
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_resolver',
            source,
        )
        self.assertIn('--example resolver_hosts_direct_probe', source)
        self.assertIn('run_netdb_reference()', source)
        self.assertIn(
            '-p crabc-rs --no-default-features --features alloc --test x86_64_netdb',
            source,
        )
        self.assertIn('--example resolver_direct_probe', source)
        self.assertIn('run_users_databases_reference()', source)
        self.assertIn(
            'compat/x86_64/run_x86_users_databases_reference.sh',
            source,
        )
        self.assertIn('--test x86_64_users_databases', source)
        self.assertIn('--example users_databases_direct_probe', source)
        users_databases_reference = source.split(
            'run_users_databases_reference() {',
            1,
        )[1].split('\n}\n', 1)[0]
        self.assertIn('run_in_container cargo test', users_databases_reference)
        self.assertIn('--no-default-features --features alloc', users_databases_reference)
        self.assertIn('--test x86_64_users_databases', users_databases_reference)
        self.assertIn('-- --test-threads=1', users_databases_reference)
        self.assertIn('run_in_container cargo build', users_databases_reference)
        self.assertIn('--example users_databases_direct_probe', users_databases_reference)
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_x86_users_databases_reference.sh',
            users_databases_reference,
        )
        path_lifecycle_runner = (
            ROOT / 'compat/x86_64/run_x86_path_lifecycle_reference.sh'
        ).read_text(encoding='utf-8')
        namespace_runner = (
            ROOT / 'compat/x86_64/run_x86_namespace_reference.sh'
        ).read_text(encoding='utf-8')
        path_lifecycle_test = (
            ROOT / 'crabc-rs/tests/x86_64_path_lifecycle.rs'
        ).read_text(encoding='utf-8')
        namespace_test = (
            ROOT / 'crabc-rs/tests/x86_64_namespace.rs'
        ).read_text(encoding='utf-8')
        xattr_runner = (
            ROOT / 'compat/x86_64/run_x86_xattr_reference.sh'
        ).read_text(encoding='utf-8')
        xattr_probe = (
            ROOT / 'compat/x86_64/x86_xattr_reference_probe.c'
        ).read_text(encoding='utf-8')
        xattr_test = (ROOT / 'crabc-rs/tests/x86_64_xattr.rs').read_text(encoding='utf-8')
        xattr_direct_probe = (
            ROOT / 'crabc-rs/examples/xattr_direct_probe.rs'
        ).read_text(encoding='utf-8')
        directory_runner = (
            ROOT / 'compat/x86_64/run_x86_directory_reference.sh'
        ).read_text(encoding='utf-8')
        directory_probe = (
            ROOT / 'compat/x86_64/x86_directory_reference_probe.c'
        ).read_text(encoding='utf-8')
        raw_directory_test = (
            ROOT / 'crabc-rs/tests/x86_64_raw_directory.rs'
        ).read_text(encoding='utf-8')
        directory_test = (
            ROOT / 'crabc-rs/tests/x86_64_directory.rs'
        ).read_text(encoding='utf-8')
        directory_position_test = (
            ROOT / 'crabc-rs/tests/x86_64_directory_position.rs'
        ).read_text(encoding='utf-8')
        directory_direct_probe = (
            ROOT / 'crabc-rs/examples/directory_direct_probe.rs'
        ).read_text(encoding='utf-8')
        directory_position_direct_probe = (
            ROOT / 'crabc-rs/examples/directory_position_direct_probe.rs'
        ).read_text(encoding='utf-8')
        temporary_object_runner = (
            ROOT / 'compat/x86_64/run_x86_temporary_object_reference.sh'
        ).read_text(encoding='utf-8')
        temporary_object_probe = (
            ROOT / 'compat/x86_64/x86_temporary_object_reference_probe.c'
        ).read_text(encoding='utf-8')
        temporary_object_test = (
            ROOT / 'crabc-rs/tests/x86_64_temporary_objects.rs'
        ).read_text(encoding='utf-8')
        named_tempfile_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_named_tempfile_direct_probe.rs'
        ).read_text(encoding='utf-8')
        tempfile_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_tempfile_direct_probe.rs'
        ).read_text(encoding='utf-8')
        tempdir_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_tempdir_direct_probe.rs'
        ).read_text(encoding='utf-8')
        statx_runner = (
            ROOT / 'compat/x86_64/run_x86_statx_reference.sh'
        ).read_text(encoding='utf-8')
        statx_probe = (
            ROOT / 'compat/x86_64/x86_statx_reference_probe.c'
        ).read_text(encoding='utf-8')
        statx_test = (ROOT / 'crabc-rs/tests/x86_64_statx.rs').read_text(encoding='utf-8')
        statx_direct_probe = (
            ROOT / 'crabc-rs/examples/statx_direct_probe.rs'
        ).read_text(encoding='utf-8')
        cwd_canonicalize_runner = (
            ROOT / 'compat/x86_64/run_x86_cwd_canonicalize_reference.sh'
        ).read_text(encoding='utf-8')
        cwd_canonicalize_probe = (
            ROOT / 'compat/x86_64/x86_cwd_canonicalize_reference_probe.c'
        ).read_text(encoding='utf-8')
        canonicalize_test = (
            ROOT / 'crabc-rs/tests/x86_64_canonicalize.rs'
        ).read_text(encoding='utf-8')
        cwd_mutation_test = (
            ROOT / 'crabc-rs/tests/x86_64_cwd_mutation.rs'
        ).read_text(encoding='utf-8')
        canonicalize_direct_probe = (
            ROOT / 'crabc-rs/examples/fs_canonicalize_direct_probe.rs'
        ).read_text(encoding='utf-8')
        cwd_direct_probe = (
            ROOT / 'crabc-rs/examples/process_cwd_direct_probe.rs'
        ).read_text(encoding='utf-8')
        root_change_runner = (
            ROOT / 'compat/x86_64/run_x86_root_change_reference.sh'
        ).read_text(encoding='utf-8')
        root_change_probe = (
            ROOT / 'compat/x86_64/x86_root_change_reference_probe.c'
        ).read_text(encoding='utf-8')
        chroot_test = (ROOT / 'crabc-rs/tests/x86_64_chroot.rs').read_text(encoding='utf-8')
        chroot_direct_probe = (
            ROOT / 'crabc-rs/examples/process_chroot_direct_probe.rs'
        ).read_text(encoding='utf-8')
        mount_runner = (
            ROOT / 'compat/x86_64/run_x86_mount_reference.sh'
        ).read_text(encoding='utf-8')
        mount_probe = (
            ROOT / 'compat/x86_64/x86_mount_reference_probe.c'
        ).read_text(encoding='utf-8')
        mount_test = (ROOT / 'crabc-rs/tests/x86_64_mount.rs').read_text(encoding='utf-8')
        mount_direct_probe = (
            ROOT / 'crabc-rs/examples/mount_direct_probe.rs'
        ).read_text(encoding='utf-8')
        thread_kill_runner = (
            ROOT / 'compat/x86_64/run_x86_thread_kill_reference.sh'
        ).read_text(encoding='utf-8')
        thread_kill_probe = (
            ROOT / 'compat/x86_64/x86_thread_kill_reference_probe.c'
        ).read_text(encoding='utf-8')
        thread_kill_test = (
            ROOT / 'crabc-rs/tests/x86_64_thread_kill.rs'
        ).read_text(encoding='utf-8')
        thread_kill_direct_probe = (
            ROOT / 'crabc-rs/examples/thread_kill_direct_probe.rs'
        ).read_text(encoding='utf-8')
        mapping_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_mapping_reference.sh'
        ).read_text(encoding='utf-8')
        mapping_reference_probe = (
            ROOT / 'compat/x86_64/x86_mapping_reference_probe.c'
        ).read_text(encoding='utf-8')
        memory_mapping_test = (
            ROOT / 'crabc-rs/tests/x86_64_memory_mapping.rs'
        ).read_text(encoding='utf-8')
        mapping_direct_probe = (
            ROOT / 'crabc-rs/examples/mapping_direct_probe.rs'
        ).read_text(encoding='utf-8')
        memory_vm_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_memory_vm_reference.sh'
        ).read_text(encoding='utf-8')
        memory_vm_reference_probe = (
            ROOT / 'compat/x86_64/x86_memory_vm_reference_probe.c'
        ).read_text(encoding='utf-8')
        memory_vm_test = (
            ROOT / 'crabc-rs/tests/x86_64_memory_vm.rs'
        ).read_text(encoding='utf-8')
        memory_vm_direct_probe = (
            ROOT / 'crabc-rs/examples/memory_vm_direct_probe.rs'
        ).read_text(encoding='utf-8')
        pty_basic_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_pty_basic_reference.sh'
        ).read_text(encoding='utf-8')
        pty_basic_reference_probe = (
            ROOT / 'compat/x86_64/x86_pty_basic_reference_probe.c'
        ).read_text(encoding='utf-8')
        pty_basic_test = (
            ROOT / 'crabc-rs/tests/x86_64_pty_basic.rs'
        ).read_text(encoding='utf-8')
        pty_basic_direct_probe = (
            ROOT / 'crabc-rs/examples/pty_basic_direct_probe.rs'
        ).read_text(encoding='utf-8')
        terminal_reference_runner = (
            ROOT / 'compat/x86_64/run_x86_terminal_reference.sh'
        ).read_text(encoding='utf-8')
        terminal_reference_probe = (
            ROOT / 'compat/x86_64/x86_terminal_reference_probe.c'
        ).read_text(encoding='utf-8')
        terminal_test = (
            ROOT / 'crabc-rs/tests/x86_64_terminal.rs'
        ).read_text(encoding='utf-8')
        terminal_direct_probe = (
            ROOT / 'crabc-rs/examples/x86_64_terminal_direct_probe.rs'
        ).read_text(encoding='utf-8')
        mqueue_runner = (
            ROOT / 'compat/x86_64/run_x86_mqueue_reference.sh'
        ).read_text(encoding='utf-8')
        mqueue_probe = (
            ROOT / 'compat/x86_64/x86_mqueue_reference_probe.c'
        ).read_text(encoding='utf-8')
        ipc_test = (ROOT / 'crabc-rs/tests/x86_64_ipc.rs').read_text(encoding='utf-8')
        ipc_direct_probe = (
            ROOT / 'crabc-rs/examples/ipc_direct_probe.rs'
        ).read_text(encoding='utf-8')
        shm_runner = (
            ROOT / 'compat/x86_64/run_x86_shm_reference.sh'
        ).read_text(encoding='utf-8')
        shm_probe = (
            ROOT / 'compat/x86_64/x86_shm_reference_probe.c'
        ).read_text(encoding='utf-8')
        shm_test = (ROOT / 'crabc-rs/tests/x86_64_shm.rs').read_text(encoding='utf-8')
        shm_direct_probe = (
            ROOT / 'crabc-rs/examples/shm_direct_probe.rs'
        ).read_text(encoding='utf-8')
        inotify_runner = (
            ROOT / 'compat/x86_64/run_x86_inotify_reference.sh'
        ).read_text(encoding='utf-8')
        inotify_probe = (
            ROOT / 'compat/x86_64/x86_inotify_reference_probe.c'
        ).read_text(encoding='utf-8')
        inotify_test = (ROOT / 'crabc-rs/tests/x86_64_inotify.rs').read_text(encoding='utf-8')
        inotify_direct_probe = (
            ROOT / 'crabc-rs/examples/inotify_direct_probe.rs'
        ).read_text(encoding='utf-8')
        calendar_time_runner = (
            ROOT / 'compat/x86_64/run_x86_calendar_time_reference.sh'
        ).read_text(encoding='utf-8')
        calendar_time_probe = (
            ROOT / 'compat/x86_64/x86_calendar_time_reference_probe.c'
        ).read_text(encoding='utf-8')
        advanced_time_runner = (
            ROOT / 'compat/x86_64/run_x86_advanced_time_reference.sh'
        ).read_text(encoding='utf-8')
        advanced_time_probe = (
            ROOT / 'compat/x86_64/x86_advanced_time_reference_probe.c'
        ).read_text(encoding='utf-8')
        advanced_time_test = (
            ROOT / 'crabc-rs/tests/x86_64_advanced_time.rs'
        ).read_text(encoding='utf-8')
        calendar_oracle = (
            'syscall=gettimeofday:96 abi=rdi-timeval:rsi-null '
            'layout=timeval16/8:offsets=0,8 raw=normalized:record-bounded '
            'utc=gmtime_r:timegm:epoch:pre-epoch:leap:400-year '
            'tz=POSIX-EST5EDT4-M3.2.0-M11.1.0 dst=start-gap:end-fold '
            'native=rule-input-only:no-c-time-abi:no-TZ-global '
            'c-api-selection=excluded'
        )
        advanced_time_oracle = (
            'layout=timespec16/8 itimerspec32/8 sigevent64/8 '
            'offsets=timespec0,8/itimerspec0,16/sigevent0,8,12,16 '
            'syscalls=timer:222,223,224,225,226/clock:227,229 '
            'process-clock=encoded,current,missing:raw-EINVAL,musl-ESRCH '
            'getres=musl+raw-normalized '
            'settime=monotonic-no-mutate:EINVAL|EPERM '
            'timers=SIGEV_NONE:initial,one-shot,periodic,'
            'disarm-interval-zero:stale-value,delete '
            'flags=ABSTIME+0x2,0x4,0x80000000-forwarded-ignored '
            'errors=invalid-nsec-EINVAL'
        )
        socket_transport_runner = (
            ROOT / 'compat/x86_64/run_x86_socket_transport_reference.sh'
        ).read_text(encoding='utf-8')
        socket_transport_probe = (
            ROOT / 'compat/x86_64/x86_socket_transport_reference_probe.c'
        ).read_text(encoding='utf-8')
        socket_transport_test = (
            ROOT / 'crabc-rs/tests/x86_64_socket_transport.rs'
        ).read_text(encoding='utf-8')
        interface_device_runner = (
            ROOT / 'compat/x86_64/run_x86_interface_device_reference.sh'
        ).read_text(encoding='utf-8')
        interface_device_probe = (
            ROOT / 'compat/x86_64/x86_interface_device_reference_probe.c'
        ).read_text(encoding='utf-8')
        interface_device_test = (
            ROOT / 'crabc-rs/tests/x86_64_interface_device.rs'
        ).read_text(encoding='utf-8')
        resolver_transport_test = (
            ROOT / 'crabc-core/tests/x86_64_resolver_transport.rs'
        ).read_text(encoding='utf-8')
        resolver_facade_test = (
            ROOT / 'crabc-rs/tests/x86_64_resolver.rs'
        ).read_text(encoding='utf-8')
        resolver_hosts_probe = (
            ROOT / 'crabc-rs/examples/resolver_hosts_direct_probe.rs'
        ).read_text(encoding='utf-8')
        netdb_test = (
            ROOT / 'crabc-rs/tests/x86_64_netdb.rs'
        ).read_text(encoding='utf-8')
        resolver_direct_probe = (
            ROOT / 'crabc-rs/examples/resolver_direct_probe.rs'
        ).read_text(encoding='utf-8')
        self.assertIn('x86_path_lifecycle_reference_probe.c', path_lifecycle_runner)
        self.assertIn('x86_namespace_reference_probe.c', namespace_runner)
        self.assertIn('x86_64_path_lifecycle_is_descriptor_relative_and_typed', path_lifecycle_test)
        self.assertIn('x86_64_namespace_lifecycle_is_descriptor_relative', namespace_test)
        self.assertIn('x86_xattr_reference_probe.c', xattr_runner)
        self.assertIn('SYS_setxattr == 188', xattr_probe)
        self.assertIn('SYS_fremovexattr == 199', xattr_probe)
        self.assertIn('XATTR_CREATE == 1', xattr_probe)
        self.assertIn('XATTR_REPLACE == 2', xattr_probe)
        self.assertIn('x86_64_xattr_preserves_path_nofollow_fd_and_caller_buffer_contracts', xattr_test)
        self.assertIn('crabc_rs_xattr_direct_probe', xattr_direct_probe)
        self.assertIn('x86_directory_reference_probe.c', directory_runner)
        self.assertIn('SYS_getdents64 == 217', directory_probe)
        self.assertIn('SYS_lseek == 8', directory_probe)
        self.assertIn('SYS_openat == 257', directory_probe)
        self.assertIn('LINUX_DIRENT64_HEADER_SIZE = 19', directory_probe)
        self.assertIn('opendir', directory_probe)
        self.assertIn('fdopendir', directory_probe)
        self.assertIn('seekdir', directory_probe)
        self.assertIn('rewinddir', directory_probe)
        self.assertIn('x86_64_raw_dir_preserves_unaligned_buffer_borrowed_names_and_small_buffer_error', raw_directory_test)
        self.assertIn('x86_64_dir_owns_close_on_exec_descriptor_and_preserves_byte_names', directory_test)
        self.assertIn('x86_64_dir_rewind_and_seek_discard_buffered_records', directory_position_test)
        self.assertIn('crabc_rs_directory_direct_probe', directory_direct_probe)
        self.assertIn('crabc_rs_directory_position_direct_probe', directory_position_direct_probe)
        self.assertIn('x86_temporary_object_reference_probe.c', temporary_object_runner)
        self.assertIn('anonymous=unavailable:EOPNOTSUPP', temporary_object_runner)
        self.assertIn('SYS_openat == 257', temporary_object_probe)
        self.assertIn('SYS_mkdirat == 258', temporary_object_probe)
        self.assertIn('SYS_unlinkat == 263', temporary_object_probe)
        self.assertIn('O_TMPFILE == 0x00410000', temporary_object_probe)
        self.assertIn('stable-parent-unlink', temporary_object_probe)
        self.assertIn('named_tempfile_is_private_cloexec_and_drop_unlinks', temporary_object_test)
        self.assertIn('anonymous_tempfile_is_cloexec_unlinked_and_read_write', temporary_object_test)
        self.assertIn('temporary_directories_are_private_byte_preserving_and_descriptor_relative', temporary_object_test)
        self.assertIn('crabc_rs_fs_named_tempfile_direct_probe', named_tempfile_direct_probe)
        self.assertIn('crabc_rs_fs_tempfile_direct_probe', tempfile_direct_probe)
        self.assertIn('crabc_rs_fs_tempdir_direct_probe', tempdir_direct_probe)
        self.assertIn('fs::rmdir(&output[..length])', tempdir_direct_probe)
        self.assertIn('x86_statx_reference_probe.c', statx_runner)
        self.assertIn('raw=ENOSYS-musl-fallback', statx_runner)
        self.assertIn('SYS_statx == 332', statx_probe)
        self.assertIn('sizeof(struct statx) == 256', statx_probe)
        self.assertIn('AT_EMPTY_PATH == 0x1000', statx_probe)
        self.assertIn('STATX__RESERVED == 0x80000000U', statx_probe)
        self.assertIn('AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC', statx_probe)
        self.assertIn('x86_64_statx_observes_descriptor_relative_metadata_only_when_masked_in', statx_test)
        self.assertIn('x86_64_statx_keeps_operation_specific_nofollow_and_empty_path_semantics', statx_test)
        self.assertIn('x86_64_statx_preserves_direct_validation_and_bounded_path_contracts', statx_test)
        self.assertIn('crabc_rs_statx_direct_probe', statx_direct_probe)
        self.assertIn('x86_cwd_canonicalize_reference_probe.c', cwd_canonicalize_runner)
        self.assertIn('SYS_getcwd == 79', cwd_canonicalize_probe)
        self.assertIn('SYS_chdir == 80', cwd_canonicalize_probe)
        self.assertIn('SYS_fchdir == 81', cwd_canonicalize_probe)
        self.assertIn('realpath', cwd_canonicalize_probe)
        self.assertIn('cwd_mutation_child', cwd_canonicalize_probe)
        self.assertIn('x86_64_canonicalize_into_is_physical_byte_preserving_and_noalloc', canonicalize_test)
        self.assertIn('x86_64_cwd_mutation_is_child_contained_and_descriptor_restorable', cwd_mutation_test)
        self.assertIn('crabc_rs_fs_canonicalize_direct_probe', canonicalize_direct_probe)
        self.assertIn('crabc_rs_process_cwd_direct_probe', cwd_direct_probe)
        self.assertIn('x86_root_change_reference_probe.c', root_change_runner)
        self.assertIn('CAP_SYS_CHROOT', root_change_runner)
        self.assertIn('SYS_chroot == 161', root_change_probe)
        self.assertIn('root_change_child', root_change_probe)
        self.assertIn(
            'x86_64_chroot_is_child_contained_and_preserves_existing_cwd',
            chroot_test,
        )
        self.assertIn('process::chroot', chroot_test)
        self.assertIn('crabc_rs_process_chroot_direct_probe', chroot_direct_probe)
        self.assertIn('x86_mount_reference_probe.c', mount_runner)
        self.assertIn('mount=165 umount2=166', mount_runner)
        self.assertIn('SYS_mount == 165', mount_probe)
        self.assertIn('SYS_umount2 == 166', mount_probe)
        self.assertIn('matching_missing_target_failure', mount_probe)
        self.assertIn('run_in_child', mount_probe)
        self.assertIn(
            'x86_64_mount_basic_checks_paths_and_preserves_direct_missing_target_errors',
            mount_test,
        )
        self.assertIn('mount::mount', mount_test)
        self.assertIn('mount::unmount', mount_test)
        self.assertIn('crabc_rs_mount_direct_probe', mount_direct_probe)
        self.assertIn('x86_thread_kill_reference_probe.c', thread_kill_runner)
        self.assertIn('pinned-musl/raw exact-thread signal-delivery reference', thread_kill_runner)
        self.assertIn('SYS_tgkill == 234', thread_kill_probe)
        self.assertIn('SYS_gettid == 186', thread_kill_probe)
        self.assertIn('pthread_kill', thread_kill_probe)
        self.assertIn('raw_missing_tid_is_esrch', thread_kill_probe)
        self.assertIn('raw_invalid_signal_is_einval', thread_kill_probe)
        self.assertIn('run_in_child', thread_kill_probe)
        self.assertIn(
            'x86_64_kill_thread_targets_the_selected_live_worker_and_preserves_errors',
            thread_kill_test,
        )
        self.assertIn('signal::kill_thread', thread_kill_test)
        self.assertIn('crabc_rs_thread_kill_direct_probe', thread_kill_direct_probe)
        self.assertIn('x86_mapping_reference_probe.c', mapping_reference_runner)
        self.assertIn(
            'mmap=9 mprotect=10 munmap=11 raw+musl=anonymous-private rw=write '
            'ro=readback rw-restored=write raw-unaligned-mprotect=EINVAL '
            'unmap=exact child-contained',
            mapping_reference_runner,
        )
        self.assertIn('SYS_mmap == 9', mapping_reference_probe)
        self.assertIn('SYS_mprotect == 10', mapping_reference_probe)
        self.assertIn('SYS_munmap == 11', mapping_reference_probe)
        self.assertIn('raw_unaligned_mprotect_is_einval', mapping_reference_probe)
        self.assertIn('run_in_child', mapping_reference_probe)
        self.assertIn(
            'x86_64_memory_mapping_preserves_protection_and_unique_unmap_lifetime',
            memory_mapping_test,
        )
        self.assertIn(
            'x86_64_memory_mapping_file_backed_boundary_and_direct_errors_are_precise',
            memory_mapping_test,
        )
        self.assertIn('mm::mmap_anonymous', memory_mapping_test)
        self.assertIn('mm::mprotect', memory_mapping_test)
        self.assertIn('mm::munmap', memory_mapping_test)
        self.assertIn('crabc_rs_mapping_direct_probe', mapping_direct_probe)
        self.assertIn('x86_memory_vm_reference_probe.c', memory_vm_reference_runner)
        self.assertIn(
            'brk=12 raw=query+same-address-replay musl=sbrk(0)-query+brk=ENOMEM '
            'mlockall=151 munlockall=152',
            memory_vm_reference_runner,
        )
        self.assertIn('SYS_brk == 12', memory_vm_reference_probe)
        self.assertIn('SYS_mlockall == 151', memory_vm_reference_probe)
        self.assertIn('SYS_munlockall == 152', memory_vm_reference_probe)
        self.assertIn('SYS_remap_file_pages == 216', memory_vm_reference_probe)
        self.assertIn('check_brk_query_and_replay', memory_vm_reference_probe)
        self.assertIn('check_mlockall_cleanup', memory_vm_reference_probe)
        self.assertIn('check_anonymous_remap_rejected', memory_vm_reference_probe)
        self.assertIn('run_in_child', memory_vm_reference_probe)
        self.assertIn(
            'x86_64_kernel_brk_queries_and_replays_without_allocator_mutation',
            memory_vm_test,
        )
        self.assertIn(
            'x86_64_mlockall_flags_are_the_closed_linux_vocabulary',
            memory_vm_test,
        )
        self.assertIn(
            'x86_64_mlockall_is_child_contained_and_unlocked_after_success',
            memory_vm_test,
        )
        self.assertIn(
            'x86_64_remap_file_pages_keeps_legacy_anonymous_error_typed',
            memory_vm_test,
        )
        self.assertIn('process::kernel_brk', memory_vm_test)
        self.assertIn('mm::mlockall', memory_vm_test)
        self.assertIn('mm::munlockall', memory_vm_test)
        self.assertIn('mm::remap_file_pages', memory_vm_test)
        self.assertIn('crabc_rs_memory_vm_direct_probe', memory_vm_direct_probe)
        self.assertIn('x86_pty_basic_reference_probe.c', pty_basic_reference_runner)
        self.assertIn(
            'ioctls=TIOCGPTN:0x80045430,TIOCSPTLCK:0x40045431,TIOCGPTPEER:0x5441',
            pty_basic_reference_runner,
        )
        self.assertIn('c-api-selection=excluded', pty_basic_reference_runner)
        self.assertIn('nonpty=raw-ENOTTY+musl-grant-noop', pty_basic_reference_runner)
        self.assertIn('SYS_ioctl == 16', pty_basic_reference_probe)
        self.assertIn('TIOCGPTN == 0x80045430UL', pty_basic_reference_probe)
        self.assertIn('TIOCSPTLCK == 0x40045431UL', pty_basic_reference_probe)
        self.assertIn('TIOCGPTPEER == 0x5441UL', pty_basic_reference_probe)
        self.assertIn('run_pty_lifecycle', pty_basic_reference_probe)
        self.assertIn('check_nonpty_rejection', pty_basic_reference_probe)
        self.assertIn('if (grantpt(null_fd) != 0)', pty_basic_reference_probe)
        self.assertIn('ptsname_r(master, short_name, sizeof(short_name)) != ERANGE', pty_basic_reference_probe)
        self.assertIn(
            'x86_64_pair_requires_read_write_before_touching_devpts',
            pty_basic_test,
        )
        self.assertIn(
            'x86_64_grantpt_validates_a_non_pty_descriptor',
            pty_basic_test,
        )
        self.assertIn("musl's C grantpt no-op wrapper", pty_basic_test)
        self.assertIn(
            'x86_64_pair_owns_both_descriptors_and_resolves_slave_name',
            pty_basic_test,
        )
        self.assertIn('x86_64_ptsname_into_rejects_short_caller_storage', pty_basic_test)
        self.assertIn('x86_64_slave_output_reaches_its_owned_master', pty_basic_test)
        self.assertIn('pty::PtyPair::open', pty_basic_test)
        self.assertIn('pty::ptsname_into', pty_basic_test)
        self.assertIn('crabc_rs_pty_basic_direct_probe', pty_basic_direct_probe)
        self.assertIn('PtyPair::open', pty_basic_direct_probe)
        self.assertIn('pty::ptsname_into', pty_basic_direct_probe)
        self.assertIn('x86_terminal_reference_probe.c', terminal_reference_runner)
        self.assertIn('kernel-termios=36/4@0,4,8,12,16,17', terminal_reference_runner)
        self.assertIn('raw+musl=pty-rawmode-termios-queue-exclusive-ttyname-session', terminal_reference_runner)
        self.assertIn('sizeof(struct kernel_termios_x86) == 36', terminal_reference_probe)
        self.assertIn('sizeof(struct termios) == 60', terminal_reference_probe)
        self.assertIn('NCCS == 32', terminal_reference_probe)
        self.assertIn('SYS_ioctl == 16', terminal_reference_probe)
        self.assertIn('SYS_setsid == 112', terminal_reference_probe)
        self.assertIn('compare_kernel_and_public', terminal_reference_probe)
        self.assertIn('make_kernel_raw', terminal_reference_probe)
        self.assertIn('terminal_session_child', terminal_reference_probe)
        self.assertIn(
            'x86_64_terminal_attributes_queue_special_codes_and_window_size_round_trip',
            terminal_test,
        )
        self.assertIn('x86_64_explicit_session_handoff_is_confined_to_a_child', terminal_test)
        self.assertIn('pair.establish_session_and_controlling_terminal(false)', terminal_test)
        self.assertIn('termios::ttyname_into', terminal_test)
        self.assertIn('raw.make_raw()', terminal_test)
        self.assertIn('changed.set_input_speed(0)', terminal_test)
        self.assertIn('crabc_rs_x86_64_terminal_direct_probe', terminal_direct_probe)
        self.assertIn('termios::tcgetattr', terminal_direct_probe)
        self.assertIn('termios::ioctl_tiocexcl', terminal_direct_probe)
        self.assertIn('changed.make_raw()', terminal_direct_probe)
        self.assertIn('changed.set_input_speed(0)', terminal_direct_probe)
        self.assertIn('pair.establish_session_and_controlling_terminal(false)', terminal_direct_probe)
        self.assertIn('x86_mqueue_reference_probe.c', mqueue_runner)
        self.assertIn('SYS_mq_open == 240', mqueue_probe)
        self.assertIn('SYS_mq_getsetattr == 245', mqueue_probe)
        self.assertIn('sizeof(struct mq_attr) == 64', mqueue_probe)
        self.assertIn('mq_unlink', mqueue_probe)
        self.assertIn('x86_64_ipc_owns_attributes_priorities_nonblocking_and_unlink_lifetime', ipc_test)
        self.assertIn('x86_64_ipc_uses_absolute_realtime_deadlines_and_validates_inputs', ipc_test)
        self.assertIn('crabc_rs_ipc_direct_probe', ipc_direct_probe)
        self.assertIn('x86_shm_reference_probe.c', shm_runner)
        self.assertIn('SYS_openat == 257', shm_probe)
        self.assertIn('SYS_unlinkat == 263', shm_probe)
        self.assertIn('O_CLOEXEC == 0x00080000', shm_probe)
        self.assertIn('O_NOFOLLOW', shm_probe)
        self.assertIn('O_NONBLOCK', shm_probe)
        self.assertIn('shm_open', shm_probe)
        self.assertIn('x86_64_shm_owns_cloexec_descriptors_and_unlink_after_open_lifetime', shm_test)
        self.assertIn('x86_64_shm_validates_posix_names_before_the_direct_syscall', shm_test)
        self.assertIn('crabc_rs_shm_direct_probe', shm_direct_probe)
        self.assertIn('x86_inotify_reference_probe.c', inotify_runner)
        self.assertIn('SYS_inotify_init1 == 294', inotify_probe)
        self.assertIn('SYS_inotify_add_watch == 254', inotify_probe)
        self.assertIn('SYS_inotify_rm_watch == 255', inotify_probe)
        self.assertIn('sizeof(struct inotify_event) == 16', inotify_probe)
        self.assertIn('IN_NONBLOCK == 0x00000800', inotify_probe)
        self.assertIn('x86_64_inotify_owns_nonblocking_cloexec_watches_and_byte_events', inotify_test)
        self.assertIn('x86_64_inotify_preserves_direct_validation_and_noalloc_path_boundaries', inotify_test)
        self.assertIn('crabc_rs_inotify_direct_probe', inotify_direct_probe)
        self.assertIn('x86_calendar_time_reference_probe.c', calendar_time_runner)
        self.assertIn('civil-time reference', calendar_time_runner)
        self.assertIn('run_musl_oracle.sh', calendar_time_runner)
        self.assertNotIn('-p crabc-libc', calendar_time_runner)
        self.assertIn(calendar_oracle, calendar_time_runner)
        self.assertIn(calendar_oracle, calendar_time_probe)
        self.assertIn('SYS_gettimeofday == 96', calendar_time_probe)
        self.assertIn('gmtime_r', calendar_time_probe)
        self.assertIn('timegm', calendar_time_probe)
        self.assertIn('setenv("TZ"', calendar_time_probe)
        self.assertIn('tzset();', calendar_time_probe)
        self.assertIn('x86_advanced_time_reference_probe.c', advanced_time_runner)
        self.assertIn('advanced-time reference', advanced_time_runner)
        self.assertIn('run_musl_oracle.sh', advanced_time_runner)
        self.assertNotIn('-p crabc-libc', advanced_time_runner)
        self.assertIn(advanced_time_oracle, advanced_time_runner)
        self.assertIn(advanced_time_oracle, advanced_time_probe)
        self.assertIn('SYS_timer_create == 222', advanced_time_probe)
        self.assertIn('SYS_clock_settime == 227', advanced_time_probe)
        self.assertIn('sizeof(struct sigevent) == 64', advanced_time_probe)
        self.assertIn('clock_getcpuclockid', advanced_time_probe)
        self.assertIn('INT_MAX - 1', advanced_time_probe)
        self.assertIn('SIGEV_NONE', advanced_time_probe)
        self.assertIn('forwarded_ignored_timer_settime_flags', advanced_time_probe)
        self.assertIn('0x00000004', advanced_time_probe)
        self.assertIn('INT_MIN', advanced_time_probe)
        self.assertIn('itimerspec_has_zero_interval', advanced_time_probe)
        self.assertIn('x86_64_advanced_clock_ids_are_validated_and_direct', advanced_time_test)
        self.assertIn('x86_64_clock_settime_preflights_and_never_mutates_realtime', advanced_time_test)
        self.assertIn('x86_64_posix_timer_owns_a_sigev_none_lifecycle', advanced_time_test)
        self.assertIn('TimerSetFlags::from_bits_retain(2)', advanced_time_test)
        self.assertIn('x86_socket_transport_reference_probe.c', socket_transport_runner)
        self.assertIn('SYS_accept4 == 288', socket_transport_probe)
        self.assertIn('SYS_accept == 43', socket_transport_probe)
        self.assertIn('SYS_ioctl == 16', socket_transport_probe)
        self.assertIn('SIOCATMARK', socket_transport_probe)
        self.assertIn('ipv6_case', socket_transport_probe)
        self.assertIn('raw_recvmmsg', socket_transport_probe)
        self.assertIn('socketpair_transports_vectored_bytes_and_shutdown_is_typed', socket_transport_test)
        self.assertIn('ipv6_datagram_round_trip_preserves_native_endpoint_encoding', socket_transport_test)
        self.assertIn('x86_interface_device_reference_probe.c', interface_device_runner)
        self.assertIn('sizeof(struct ifreq) == 40', interface_device_probe)
        self.assertIn('SIOCGIFNAME == 0x8910', interface_device_probe)
        self.assertIn('RTM_GETLINK == 18', interface_device_probe)
        self.assertIn('RTM_GETADDR == 22', interface_device_probe)
        self.assertIn('SYS_recvmsg == 47', interface_device_probe)
        self.assertIn('MSG_TRUNC == 0x20', interface_device_probe)
        self.assertIn('AF_INET6', interface_device_probe)
        self.assertIn('raw and musl loopback indexes agree', interface_device_probe)
        self.assertIn('x86_64_interface_names_are_owned_and_self_consistent', interface_device_test)
        self.assertIn('x86_64_interface_address_snapshot_keeps_the_two_netlink_phases_owned', interface_device_test)
        self.assertIn(
            'x86_64_udp_ignores_short_wrong_id_malformed_and_oversized_packets_before_an_answer',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_udp_truncation_retries_the_exact_query_over_partial_tcp',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_dns_response_rejects_an_out_of_bounds_compressed_record_owner',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_dns_response_rejects_a_compressed_record_owner_in_the_header',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_exchange_rejects_a_header_compression_pointer_in_the_caller_query',
            resolver_transport_test,
        )
        self.assertIn(
            'x86_64_failed_first_nameserver_advances_in_configured_order',
            resolver_transport_test,
        )
        self.assertIn('x86_64_all_nameserver_failures_are_bounded', resolver_transport_test)
        self.assertIn(
            'x86_64_hosts_snapshot_is_owned_case_insensitive_and_precedes_dns',
            resolver_facade_test,
        )
        self.assertIn(
            'x86_64_resolver_search_cname_and_ptr_use_the_local_configured_server',
            resolver_facade_test,
        )
        self.assertIn(
            'x86_64_resolver_aaaa_and_timeout_map_through_the_facade',
            resolver_facade_test,
        )
        self.assertIn('crabc_rs_resolver_hosts_direct_probe', resolver_hosts_probe)
        self.assertNotIn('ServiceDatabase', resolver_hosts_probe)
        self.assertNotIn('ProtocolDatabase', resolver_hosts_probe)
        self.assertIn(
            'x86_64_hosts_snapshot_is_owned_and_system_loader_matches_direct_snapshot',
            netdb_test,
        )
        self.assertIn(
            'x86_64_service_and_protocol_snapshots_are_owned_typed_and_ordered',
            netdb_test,
        )
        self.assertIn(
            'x86_64_service_and_protocol_malformed_records_reject_the_complete_snapshot',
            netdb_test,
        )
        self.assertIn(
            'x86_64_service_and_protocol_system_loaders_match_direct_snapshots',
            netdb_test,
        )
        self.assertIn('crabc_rs_resolver_direct_probe', resolver_direct_probe)
        self.assertIn('ServiceDatabase::from_bytes', resolver_direct_probe)
        self.assertIn('ProtocolDatabase::from_bytes', resolver_direct_probe)
        self.assertIn('run_statat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_statat_reference.sh', source)
        self.assertIn('run_getcwd_reference()', source)
        self.assertIn('compat/x86_64/run_x86_getcwd_reference.sh', source)
        self.assertIn(
            '--no-default-features --features alloc --test x86_64_getcwd',
            source,
        )
        self.assertIn('--test x86_64_current_dir_name -- --test-threads=1', source)
        self.assertIn('run_readlinkat_reference()', source)
        self.assertIn('compat/x86_64/run_x86_readlinkat_reference.sh', source)
        self.assertIn('run_access_reference()', source)
        self.assertIn('compat/x86_64/run_x86_access_reference.sh', source)
        self.assertIn('--test x86_64_access -- --test-threads=1', source)
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
        self.assertIn('--test x86_64_fcntl_flags', source)
        self.assertIn('--test x86_64_flock', source)
        self.assertIn('--test x86_64_sendfile', source)
        self.assertIn('--test x86_64_copy_file_range', source)
        self.assertIn('--test x86_64_fs', source)
        self.assertIn('--test x86_64_fs_advice', source)
        self.assertIn('--test x86_64_file_position', source)
        self.assertIn('--test x86_64_sync', source)
        self.assertIn('--test x86_64_syncfs', source)
        self.assertIn('--test x86_64_sync_file_range', source)
        self.assertIn('--test x86_64_ftruncate', source)
        self.assertIn('--test x86_64_futimens', source)
        self.assertIn('--test x86_64_timestamp_paths', source)
        self.assertIn('--test x86_64_fs_credentials', source)
        self.assertIn('--test x86_64_memfd', source)
        self.assertIn('--test x86_64_getgroups', source)
        self.assertIn('--test x86_64_getitimer', source)
        self.assertIn('--test x86_64_setitimer', source)
        self.assertIn('--test x86_64_io', source)
        self.assertIn('--test x86_64_mm', source)
        self.assertIn('--test x86_64_memory_mapping', source)
        self.assertIn('--test x86_64_memory_vm', source)
        self.assertIn('--test x86_64_pty_basic', source)
        self.assertIn('--test x86_64_terminal', source)
        self.assertIn('--test x86_64_mount', source)
        self.assertIn('--test x86_64_param', source)
        self.assertIn('--test x86_64_pipe', source)
        self.assertIn('--test x86_64_poll', source)
        self.assertIn('--test x86_64_priority', source)
        self.assertIn('--test x86_64_setpriority', source)
        self.assertIn('--test x86_64_process_identity', source)
        self.assertIn('--test x86_64_child_ownership', source)
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
        self.assertIn('--test x86_64_access', source)
        self.assertIn('--test x86_64_getcwd', source)
        self.assertIn('--test x86_64_current_dir_name', source)
        self.assertIn('--test x86_64_readlink', source)
        self.assertIn('--test x86_64_xattr', source)
        self.assertIn('--test x86_64_raw_directory', source)
        self.assertIn('--test x86_64_directory', source)
        self.assertIn('--test x86_64_directory_position', source)
        self.assertIn('--test x86_64_temporary_objects', source)
        self.assertIn('--test x86_64_statx', source)
        self.assertIn('--test x86_64_ipc', source)
        self.assertIn('--test x86_64_shm', source)
        self.assertIn('--test x86_64_inotify', source)
        self.assertIn('--test x86_64_sched_rr_interval', source)
        self.assertIn('--test x86_64_sched_affinity', source)
        self.assertIn('--test x86_64_sched_setaffinity', source)
        self.assertIn('--test x86_64_system', source)
        self.assertIn('--test x86_64_thread', source)
        self.assertIn('--test x86_64_thread_kill', source)
        self.assertIn('--test x86_64_thread_credentials', source)
        self.assertIn('--test x86_64_time', source)
        self.assertIn('--test time', source)
        self.assertIn('--test calendar_utc', source)
        self.assertIn('--test x86_64_calendar_time', source)
        self.assertIn('--test x86_64_advanced_time', source)
        self.assertIn('--test timezone_rules', source)
        self.assertIn('--test calendar_local', source)
        self.assertIn('--test x86_64_users_databases', source)
        self.assertIn('--test x86_64_timerfd', source)
        self.assertIn('--test x86_64_pselect', source)
        facade = source.split('    facade)\n', 1)[1].split('    libc-syscall)', 1)[0]
        self.assertIn('--test x86_64_rlimit_targeted', facade)
        self.assertIn('--test x86_64_child_ownership', facade)
        self.assertIn('run_in_chroot_cap_container cargo test', facade)
        self.assertIn('--test x86_64_chroot', facade)
        self.assertIn('--test x86_64_thread_kill', facade)
        self.assertIn('--test x86_64_memory_mapping', facade)
        self.assertIn('--test x86_64_memory_vm', facade)
        self.assertIn('--test x86_64_pty_basic', facade)
        self.assertIn('--test x86_64_terminal', facade)
        self.assertIn('--test x86_64_mount', facade)
        self.assertIn('--test x86_64_users_databases', facade)
        self.assertIn(
            '  facade-record-owning  run the closed native x86_64 record-owning facade aggregate',
            source,
        )
        self.assertIn(
            '    facade-record-owning)\n        [ "$#" -eq 0 ] || fail "facade-record-owning takes no arguments"',
            source,
        )
        aggregate = source.split('run_facade_record_owning() {\n', 1)[1].split(
            '\n}\n\nrun_relative_sleep_reference', 1
        )[0]
        self.assertEqual(
            [
                line.strip()
                for line in aggregate.splitlines()
                if line.strip().startswith('run_')
                and not line.strip().startswith('run_in_container')
            ],
            [
                'run_root_change_reference',
                'run_child_ownership_reference',
                'run_thread_kill_reference',
                'run_mapping_reference',
                'run_memory_vm_reference',
                'run_pty_basic_reference',
                'run_terminal_reference',
                'run_interface_device_reference',
                'run_resolver_transport_reference',
                'run_resolver_facade_reference',
                'run_netdb_reference',
                'run_users_databases_reference',
                'run_mount_reference',
                'run_path_core_reference',
                'run_xattr_reference',
                'run_directory_reference',
                'run_temporary_object_reference',
                'run_statx_reference',
                'run_cwd_canonicalize_reference',
                'run_ipc_reference',
                'run_shm_reference',
                'run_inotify_reference',
                'run_calendar_time_reference',
                'run_advanced_time_reference',
            ],
        )
        self.assertEqual(
            aggregate.count(
                'run_in_container cargo check --locked --target x86_64-unknown-linux-musl'
            ),
            2,
        )
        self.assertIn('-p crabc-rs --no-default-features\n', aggregate)
        self.assertIn('-p crabc-rs --no-default-features --features alloc', aggregate)
        self.assertIn('run_libc_syscall_probe()', source)
        self.assertIn('compat/x86_64/libc_syscall_probe.rs', source)
        self.assertIn('run_libc_errno_tls_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_errno_tls.sh', source)
        self.assertIn('run_libc_stat_compat_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_stat_compat.sh', source)
        self.assertIn('run_libc_credentials_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_credentials.sh', source)
        self.assertIn('run_libc_bootstrap_primitives_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_bootstrap_primitives.sh', source
        )
        self.assertIn(
            '    libc-credentials)\n        [ "$#" -eq 0 ] || fail "libc-credentials takes no arguments"',
            source,
        )
        self.assertIn(
            '    libc-bootstrap-primitives)\n        [ "$#" -eq 0 ] || fail "libc-bootstrap-primitives takes no arguments"',
            source,
        )
        self.assertIn('run_libc_signal_control_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_signal_control.sh', source
        )
        self.assertIn(
            '    libc-signal-control)\n        [ "$#" -eq 0 ] || fail "libc-signal-control takes no arguments"',
            source,
        )
        self.assertIn('run_libc_signal_execution_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_signal_execution.sh', source
        )
        self.assertIn(
            '    libc-signal-execution)\n        [ "$#" -eq 0 ] || fail "libc-signal-execution takes no arguments"',
            source,
        )
        self.assertIn('run_libc_pthread_create_join_tls_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_pthread_create_join_tls.sh', source
        )
        self.assertIn(
            '    libc-pthread-create-join-tls)\n        [ "$#" -eq 0 ] || fail "libc-pthread-create-join-tls takes no arguments"',
            source,
        )
        self.assertIn('run_libc_termios_control_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_termios_control.sh', source
        )
        self.assertIn(
            '    libc-termios-control)\n        [ "$#" -eq 0 ] || fail "libc-termios-control takes no arguments"',
            source,
        )
        self.assertIn('run_libc_process_context_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_process_context.sh', source
        )
        self.assertIn(
            '    libc-process-context)\n        [ "$#" -eq 0 ] || fail "libc-process-context takes no arguments"',
            source,
        )
        self.assertIn('run_libc_descriptor_io_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_descriptor_io.sh', source
        )
        self.assertIn(
            '    libc-descriptor-io)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-io takes no arguments"',
            source,
        )
        self.assertIn('run_libc_process_resources_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_process_resources.sh', source
        )
        self.assertIn(
            '    libc-process-resources)\n        [ "$#" -eq 0 ] || fail "libc-process-resources takes no arguments"',
            source,
        )
        self.assertIn('run_libc_readiness_waits_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_readiness_waits.sh', source
        )
        self.assertIn(
            '    libc-readiness-waits)\n        [ "$#" -eq 0 ] || fail "libc-readiness-waits takes no arguments"',
            source,
        )
        self.assertIn(
            'run_in_container bash /workspace/compat/x86_64/run_libc_socket_transport.sh',
            source,
        )
        self.assertIn(
            '    libc-socket-transport)\n        [ "$#" -eq 0 ] || fail "libc-socket-transport takes no arguments"',
            source,
        )
        self.assertIn('run_libc_system_observation_probe()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_system_observation.sh', source
        )
        self.assertIn(
            '    libc-system-observation)\n        [ "$#" -eq 0 ] || fail "libc-system-observation takes no arguments"',
            source,
        )
        self.assertIn('run_libc_uts_identity_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_uts_identity.sh', source)
        self.assertIn('run_in_uts_cap_container()', source)
        self.assertIn('--cap-add=SYS_ADMIN', source)
        self.assertIn(
            '    libc-uts-identity)\n        [ "$#" -eq 0 ] || fail "libc-uts-identity takes no arguments"',
            source,
        )
        self.assertIn('libc-ctype', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_ctype.sh', source)
        self.assertIn(
            '    libc-ctype)\n        [ "$#" -eq 0 ] || fail "libc-ctype takes no arguments"',
            source,
        )
        self.assertIn('libc-integer-arithmetic', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_integer_arithmetic.sh', source,
        )
        self.assertIn(
            '    libc-integer-arithmetic)\n        [ "$#" -eq 0 ] || fail "libc-integer-arithmetic takes no arguments"',
            source,
        )
        self.assertIn('integer-parse-header-abi', source)
        self.assertIn('run_integer_parse_header_abi()', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_integer_parse_header_abi.sh', source,
        )
        self.assertIn(
            '    integer-parse-header-abi)\n        [ "$#" -eq 0 ] || fail "integer-parse-header-abi takes no arguments"',
            source,
        )
        self.assertIn('libc-integer-parse', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_integer_parse.sh', source,
        )
        self.assertIn(
            '    libc-integer-parse)\n        [ "$#" -eq 0 ] || fail "libc-integer-parse takes no arguments"',
            source,
        )
        self.assertIn('libc-credential-observation', source)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_credential_observation.sh', source,
        )
        self.assertIn(
            '    libc-credential-observation)\n        [ "$#" -eq 0 ] || fail "libc-credential-observation takes no arguments"',
            source,
        )
        self.assertIn('libc-ffs', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_ffs.sh', source)
        self.assertIn(
            '    libc-ffs)\n        [ "$#" -eq 0 ] || fail "libc-ffs takes no arguments"',
            source,
        )
        self.assertIn('libc-byte-strings', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_byte_strings.sh', source)
        self.assertIn(
            '    libc-byte-strings)\n        [ "$#" -eq 0 ] || fail "libc-byte-strings takes no arguments"',
            source,
        )
        self.assertIn('libc-random-entropy', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_random_entropy.sh', source)
        self.assertIn(
            '    libc-random-entropy)\n        [ "$#" -eq 0 ] || fail "libc-random-entropy takes no arguments"',
            source,
        )
        self.assertIn('libc-memory-search', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_memory_search.sh', source)
        self.assertIn(
            '    libc-memory-search)\n        [ "$#" -eq 0 ] || fail "libc-memory-search takes no arguments"',
            source,
        )
        self.assertIn('libc-string-copy', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_string_copy.sh', source)
        self.assertIn(
            '    libc-string-copy)\n        [ "$#" -eq 0 ] || fail "libc-string-copy takes no arguments"',
            source,
        )
        self.assertIn('run_libc_thread_pointer_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_thread_pointer.sh', source)
        self.assertIn('run_libc_foundation_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_foundation.sh', source)
        self.assertIn('run_libc_fenv_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_fenv.sh', source)
        self.assertIn('run_libc_math_complex_probe()', source)
        self.assertIn('/workspace/compat/x86_64/run_libc_math_complex.sh', source)
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
        self.assertNotIn('-p crabc-ldso', source)

    def test_pinned_musl_oracle_and_reference_header_baseline_stay_closed(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
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
        timestamp = (
            ROOT / "compat" / "x86_64" / "run_x86_timestamp_reference.sh"
        ).read_text(encoding="utf-8")
        posix_fallocate = (
            ROOT / "compat" / "x86_64" / "run_x86_posix_fallocate_reference.sh"
        ).read_text(encoding="utf-8")
        fallocate = (
            ROOT / "compat" / "x86_64" / "run_x86_fallocate_reference.sh"
        ).read_text(encoding="utf-8")
        file_position = (
            ROOT / "compat" / "x86_64" / "run_x86_file_position_reference.sh"
        ).read_text(encoding="utf-8")
        sync = (ROOT / "compat" / "x86_64" / "run_x86_sync_reference.sh").read_text(
            encoding="utf-8"
        )
        syncfs = (
            ROOT / "compat" / "x86_64" / "run_x86_syncfs_reference.sh"
        ).read_text(encoding="utf-8")
        sync_file_range = (
            ROOT / "compat" / "x86_64" / "run_x86_sync_file_range_reference.sh"
        ).read_text(encoding="utf-8")
        signal = (ROOT / "compat" / "x86_64" / "run_signal_header_abi.sh").read_text(
            encoding="utf-8"
        )
        termios_header = (
            ROOT / "compat" / "x86_64" / "run_termios_header_abi.sh"
        ).read_text(encoding="utf-8")
        mman = (ROOT / "compat" / "x86_64" / "run_mman_header_abi.sh").read_text(
            encoding="utf-8"
        )
        resource_header = (
            ROOT / "compat" / "x86_64" / "run_resource_header_abi.sh"
        ).read_text(encoding="utf-8")
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
        select_header = (
            ROOT / "compat" / "x86_64" / "run_select_header_abi.sh"
        ).read_text(encoding="utf-8")
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
        fcntl_status_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_fcntl_status_reference.sh"
        ).read_text(encoding="utf-8")
        flock_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_flock_reference.sh"
        ).read_text(encoding="utf-8")
        sendfile_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_sendfile_reference.sh"
        ).read_text(encoding="utf-8")
        copy_file_range_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_copy_file_range_reference.sh"
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
        statfs_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_statfs_reference.sh"
        ).read_text(encoding="utf-8")
        statat_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_statat_reference.sh"
        ).read_text(encoding="utf-8")
        getcwd_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_getcwd_reference.sh"
        ).read_text(encoding="utf-8")
        readlinkat_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_readlinkat_reference.sh"
        ).read_text(encoding="utf-8")
        access_reference = (
            ROOT / "compat" / "x86_64" / "run_x86_access_reference.sh"
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
            'syscalls=319,72 commands=1033,1034 mfd=1,2,4 seals=1,2,4,8,16 name=249-ok:250-einval:proc-label fd=cloexec-owned lifecycle=allow-empty:write-live-map-ebusy:grow-shrink-enforced:write-enforced:future-write-existing-map-preserved:direct-write-rejected:new-writable-map-rejected:final-seal plain=seal-seal errors=EINVAL,EPERM,EBUSY,EBADF',
            memfd,
        )
        self.assertIn('run_musl_oracle.sh', memfd)
        self.assertNotIn('-p crabc-libc', memfd)
        self.assertIn('x86_ftruncate_reference_probe.c', ftruncate)
        self.assertIn('ftruncate ABI/behavior reference', ftruncate)
        self.assertIn('ftruncate=77 loff_t=signed64', ftruncate)
        self.assertIn('run_musl_oracle.sh', ftruncate)
        self.assertNotIn('-p crabc-libc', ftruncate)
        self.assertIn('x86_timestamp_reference_probe.c', timestamp)
        self.assertIn('run_musl_oracle.sh', timestamp)
        self.assertNotIn('-p crabc-libc', timestamp)
        self.assertIn('x86_posix_fallocate_reference_probe.c', posix_fallocate)
        self.assertIn('posix_fallocate reference', posix_fallocate)
        self.assertIn('syscall=285', posix_fallocate)
        self.assertIn('mode=zero', posix_fallocate)
        self.assertIn('bytes=retained-prefix:zero-filled', posix_fallocate)
        self.assertIn('run_musl_oracle.sh', posix_fallocate)
        self.assertNotIn('-p crabc-libc', posix_fallocate)
        self.assertIn('x86_fallocate_reference_probe.c', fallocate)
        self.assertIn('general fallocate(2) reference', fallocate)
        self.assertIn('syscall=285 off_t=signed64', fallocate)
        self.assertIn('modes=zero:keep-size:punch-hole|keep-size:zero-range:zero-range', fallocate)
        self.assertIn('fixture=unlinked-regular-file', fallocate)
        self.assertIn('success:retained-edges:zeroed-range:size-extends-or-kept|EOPNOTSUPP', fallocate)
        self.assertIn('env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH', fallocate)
        self.assertIn('run_musl_oracle.sh', fallocate)
        self.assertNotIn('-p crabc-libc', fallocate)
        self.assertIn('x86_file_position_reference_probe.c', file_position)
        self.assertIn('lseek/fsync/fdatasync ABI/behavior reference', file_position)
        self.assertIn('syscalls=lseek:8,fsync:74,fdatasync:75', file_position)
        self.assertIn('sparse=data4096:hole0', file_position)
        self.assertIn('SEEK_DATA/HOLE:ENXIO', file_position)
        self.assertIn('run_musl_oracle.sh', file_position)
        self.assertNotIn('-p crabc-libc', file_position)
        self.assertIn('x86_sync_reference_probe.c', sync)
        self.assertIn('global sync ABI reference', sync)
        self.assertIn('run_musl_oracle.sh', sync)
        self.assertIn('does not measure writeback timing', sync)
        self.assertNotIn('-p crabc-libc', sync)
        self.assertIn('x86_syncfs_reference_probe.c', syncfs)
        self.assertIn('syncfs ABI/descriptor reference', syncfs)
        self.assertIn('closed-fd=EBADF', syncfs)
        self.assertIn('run_musl_oracle.sh', syncfs)
        self.assertIn('does not claim data survives a crash', syncfs)
        self.assertNotIn('-p crabc-libc', syncfs)
        self.assertIn('x86_sync_file_range_reference_probe.c', sync_file_range)
        self.assertIn('sync_file_range ABI/behavior reference', sync_file_range)
        self.assertIn('run_musl_oracle.sh', sync_file_range)
        self.assertIn('does not claim writeback durability', sync_file_range)
        self.assertNotIn('-p crabc-libc', sync_file_range)
        self.assertIn('signal_header_abi_probe.c', signal)
        self.assertIn('signal_header_posix_abi_probe.c', signal)
        self.assertIn('-fsyntax-only', signal)
        self.assertNotIn('-p crabc-libc', signal)
        self.assertIn('termios_header_abi_probe.c', termios_header)
        self.assertIn('termios_header_abi_probe.cpp', termios_header)
        self.assertIn('include/termios.h', termios_header)
        self.assertIn('include/bits/alltypes.h', termios_header)
        self.assertIn('-fsyntax-only', termios_header)
        self.assertNotIn('-p crabc-libc', termios_header)
        self.assertIn('mman_header_abi_probe.c', mman)
        self.assertIn('mman_header_abi_probe.cpp', mman)
        self.assertIn('include/sys/mman.h', mman)
        self.assertIn('include/bits/mman.h', mman)
        self.assertIn('-fsyntax-only', mman)
        self.assertNotIn('-p crabc-libc', mman)
        self.assertIn('resource_header_abi_probe.c', resource_header)
        self.assertIn('resource_header_abi_probe.cpp', resource_header)
        self.assertIn('sys/resource.h', resource_header)
        self.assertIn('sys/time.h', resource_header)
        self.assertIn('-D_GNU_SOURCE', resource_header)
        self.assertIn('-D_LARGEFILE64_SOURCE', resource_header)
        self.assertIn('-fsyntax-only', resource_header)
        self.assertNotIn('-p crabc-libc', resource_header)
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
        self.assertIn('select_header_abi_probe.c', select_header)
        self.assertIn('select_header_abi_probe.cpp', select_header)
        self.assertIn('for header in sys/select.h time.h bits/alltypes.h', select_header)
        self.assertIn('-fsyntax-only', select_header)
        self.assertNotIn('-p crabc-libc', select_header)
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
        self.assertIn(
            '-p crabc-rs --no-default-features --test x86_64_setitimer \\\n        -- --test-threads=1',
            source,
        )
        self.assertIn('SYS_setitimer == 38', setitimer_probe)
        self.assertIn('run_in_child', setitimer_probe)
        self.assertIn('invalid=EINVAL', setitimer_probe)
        self.assertIn('ualarm(', setitimer_probe)
        self.assertIn('alarm(', setitimer_probe)
        self.assertIn('aliases=alarm-ceil,ualarm-subsecond', setitimer_probe)
        self.assertIn('ualarm-invalid=EINVAL', setitimer_probe)
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
        self.assertIn('x86_fcntl_status_reference_probe.c', fcntl_status_reference)
        self.assertIn('fcntl status reference', fcntl_status_reference)
        self.assertIn('run_musl_oracle.sh', fcntl_status_reference)
        self.assertNotIn('-p crabc-libc', fcntl_status_reference)
        self.assertIn('x86_flock_reference_probe.c', flock_reference)
        self.assertIn('flock(2) reference', flock_reference)
        self.assertIn('syscall=73 bits=SH1,EX2,NB4,UN8', flock_reference)
        self.assertIn('run_musl_oracle.sh', flock_reference)
        self.assertIn('fcntl record locks', flock_reference)
        self.assertNotIn('-p crabc-libc', flock_reference)
        self.assertIn('x86_sendfile_reference_probe.c', sendfile_reference)
        self.assertIn('sendfile(2) reference', sendfile_reference)
        self.assertIn('syscall=40 off_t=signed64', sendfile_reference)
        self.assertIn('run_musl_oracle.sh', sendfile_reference)
        self.assertIn('socket', sendfile_reference)
        self.assertNotIn('-p crabc-libc', sendfile_reference)
        self.assertIn('x86_copy_file_range_reference_probe.c', copy_file_range_reference)
        self.assertIn('copy_file_range(2) reference', copy_file_range_reference)
        self.assertIn('syscall=326 off_t=signed64', copy_file_range_reference)
        self.assertIn('run_musl_oracle.sh', copy_file_range_reference)
        self.assertIn('flags=zero-only', copy_file_range_reference)
        self.assertIn('sendfile-splice-fallback=excluded', copy_file_range_reference)
        self.assertNotIn('-p crabc-libc', copy_file_range_reference)
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
        self.assertIn('x86_statfs_reference_probe.c', statfs_reference)
        self.assertIn('statfs reference', statfs_reference)
        self.assertNotIn('-p crabc-libc', statfs_reference)
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
        self.assertIn('x86_access_reference_probe.c', access_reference)
        self.assertIn('access/faccessat/faccessat2 reference', access_reference)
        self.assertIn('run_musl_oracle.sh', access_reference)
        self.assertNotIn('-p crabc-libc', access_reference)
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

    def test_libc_static_c_abi_artifact_boundaries(self) -> None:
        libc_root = (ROOT / "libc" / "src" / "lib.rs").read_text(encoding="utf-8")
        static_c_abi = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        stat_compat = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stat_compat.rs"
        ).read_text(encoding="utf-8")
        credentials = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "credentials.rs"
        ).read_text(encoding="utf-8")
        errno = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs").read_text(
            encoding="utf-8"
        )
        probe = (ROOT / "compat" / "x86_64" / "libc_stat_compat_probe.c").read_text(
            encoding="utf-8"
        )
        start = (ROOT / "compat" / "x86_64" / "libc_stat_compat_start.S").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "compat" / "x86_64" / "run_libc_stat_compat.sh").read_text(
            encoding="utf-8"
        )
        credential_probe = (
            ROOT / "compat" / "x86_64" / "libc_credentials_probe.c"
        ).read_text(encoding="utf-8")
        credential_start = (
            ROOT / "compat" / "x86_64" / "libc_credentials_start.S"
        ).read_text(encoding="utf-8")
        credential_script = (
            ROOT / "compat" / "x86_64" / "run_libc_credentials.sh"
        ).read_text(encoding="utf-8")
        bootstrap_script = (
            ROOT / "compat" / "x86_64" / "run_libc_bootstrap_primitives.sh"
        ).read_text(encoding="utf-8")
        bootstrap_probe = (
            ROOT / "compat" / "x86_64" / "libc_bootstrap_primitives_probe.c"
        ).read_text(encoding="utf-8")
        process_context = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_context.rs"
        ).read_text(encoding="utf-8")
        process_context_probe = (
            ROOT / "compat" / "x86_64" / "libc_process_context_probe.c"
        ).read_text(encoding="utf-8")
        process_context_start = (
            ROOT / "compat" / "x86_64" / "libc_process_context_start.S"
        ).read_text(encoding="utf-8")
        process_context_script = (
            ROOT / "compat" / "x86_64" / "run_libc_process_context.sh"
        ).read_text(encoding="utf-8")
        descriptor_io = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_io.rs"
        ).read_text(encoding="utf-8")
        descriptor_io_script = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_io.sh"
        ).read_text(encoding="utf-8")
        process_resources = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_resources.rs"
        ).read_text(encoding="utf-8")
        process_resources_script = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        ).read_text(encoding="utf-8")
        readiness_waits = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "readiness_waits.rs"
        ).read_text(encoding="utf-8")
        readiness_waits_probe = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_probe.c"
        ).read_text(encoding="utf-8")
        readiness_waits_start = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_start.S"
        ).read_text(encoding="utf-8")
        readiness_waits_script = (
            ROOT / "compat" / "x86_64" / "run_libc_readiness_waits.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]

        self.assertIn('target_arch = "x86_64"', libc_root)
        self.assertIn('#[path = "c_abi/x86_64/static_c_abi.rs"]', libc_root)
        self.assertNotIn('mod c_abi_x86_64', libc_root)
        for composition_member in (
            '#[path = "errno.rs"]',
            '#[path = "syscall.rs"]',
            '#[path = "stat_compat.rs"]',
            '#[path = "credentials.rs"]',
            '#[path = "process_context.rs"]',
            '#[path = "clock_nanosleep.rs"]',
            '#[path = "descriptor_io.rs"]',
            '#[path = "process_resources.rs"]',
            '#[path = "readiness_waits.rs"]',
            'fn c_status',
            'fn c_ssize_status',
            'fn c_off_status',
            'fn rust_eh_personality',
        ):
            self.assertIn(composition_member, static_c_abi)
        self.assertIn('#[thread_local]', errno)
        self.assertIn('struct Stat', stat_compat)
        self.assertIn('size_of::<Stat>() == 144', stat_compat)
        self.assertIn('raw_syscall::SYS_FSTAT', stat_compat)
        self.assertIn('raw_syscall::SYS_NEWFSTATAT', stat_compat)
        for symbol in (
            'fn stat(',
            'fn lstat(',
            'fn fstat(',
            'fn fstatat(',
            'fn __xstat(',
            'fn __lxstat(',
            'fn __fxstat(',
            'fn __fxstatat(',
        ):
            self.assertIn(symbol, stat_compat)
        for symbol in (
            'fn setgroups(',
            'fn setuid(',
            'fn setgid(',
            'fn setresuid(',
            'fn setresgid(',
            'fn seteuid(',
            'fn setegid(',
            'fn setreuid(',
            'fn setregid(',
        ):
            self.assertIn(symbol, credentials)
        for syscall in (
            'raw_syscall::SYS_SETGROUPS',
            'raw_syscall::SYS_SETUID',
            'raw_syscall::SYS_SETGID',
            'raw_syscall::SYS_SETRESUID',
            'raw_syscall::SYS_SETRESGID',
        ):
            self.assertIn(syscall, credentials)
        self.assertIn('EOPNOTSUPP', credentials)
        for static_source in (
            static_c_abi,
            stat_compat,
            credentials,
            process_context,
            descriptor_io,
            process_resources,
            readiness_waits,
            errno,
        ):
            self.assertNotIn('crabc_core', static_source)
            self.assertNotIn('crabc_mimalloc', static_source)
        self.assertIn('_Static_assert(sizeof(struct stat) == 144', probe)
        self.assertIn('SYS_newfstatat == 262', probe)
        self.assertIn('errno != ENOENT', probe)
        self.assertIn('errno != EBADF', probe)
        self.assertIn('errno != EINVAL', probe)
        self.assertIn('ARCH_SET_FS', start)
        self.assertIn('mov %rsi, %fs:0', start)
        self.assertIn('crabc_x86_64_stat_compat_probe', start)
        self.assertIn('cargo rustc --locked -p crabc-libc --lib', script)
        self.assertIn('-nostdlib -static', script)
        self.assertIn('-Wl,-e,_start', script)
        self.assertIn('R_X86_64_TPOFF', script)
        self.assertIn('Requesting program interpreter', script)
        self.assertIn('__tls_get_addr', script)
        self.assertNotIn('-p crabc-core', script)
        self.assertNotIn('--whole-archive', script)
        self.assertIn('#include <grp.h>', credential_probe)
        self.assertIn('_Static_assert(SYS_setgroups == 116', credential_probe)
        self.assertIn('UINT32_MAX', credential_probe)
        self.assertIn('raw_syscall3', credential_probe)
        self.assertIn('same_state', credential_probe)
        self.assertIn('CRABC_CREDENTIAL_PROFILE', credential_probe)
        self.assertIn('EOPNOTSUPP', credential_probe)
        self.assertIn('ARCH_SET_FS', credential_start)
        self.assertIn('mov %rsi, %fs:0', credential_start)
        self.assertIn('crabc_x86_64_credentials_probe', credential_start)
        self.assertIn('cargo rustc --locked -p crabc-libc --lib', credential_script)
        self.assertIn('-DCRABC_CREDENTIAL_PROFILE', credential_script)
        self.assertIn('-nostdlib -static', credential_script)
        self.assertIn('-Wl,-e,_start', credential_script)
        self.assertIn('R_X86_64_TPOFF', credential_script)
        self.assertIn('Requesting program interpreter', credential_script)
        self.assertIn('__tls_get_addr', credential_script)
        self.assertNotIn('-p crabc-core', credential_script)
        self.assertNotIn('--whole-archive', credential_script)
        self.assertEqual(static_export_names, sorted(static_export_names))
        self.assertEqual(len(static_export_names), len(set(static_export_names)))
        for symbol in (
            "__errno_location",
            "stat",
            "setgroups",
            "getpid",
            "clock_nanosleep",
            "read",
            "getrlimit",
            "memcpy",
            "feclearexcept",
            "setjmp",
            "rust_eh_personality",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("raw_syscall::SYS_GETPID", process_context)
        self.assertIn("raw_syscall::SYS_SETPGID", process_context)
        self.assertIn("raw_syscall::SYS_UMASK", process_context)
        self.assertIn("raw_syscall0", process_context_probe)
        self.assertIn("raw_syscall4", process_context_probe)
        self.assertIn("child_setpgrp_case", process_context_probe)
        self.assertIn("child_setsid_case", process_context_probe)
        self.assertIn("ARCH_SET_FS", process_context_start)
        self.assertIn("mov %rsi, %fs:0", process_context_start)
        self.assertIn("crabc_x86_64_process_context_probe", process_context_start)
        self.assertIn("check_poll_and_ppoll", readiness_waits_probe)
        self.assertIn("check_atomic_signal_waits", readiness_waits_probe)
        self.assertIn("ARCH_SET_FS", readiness_waits_start)
        self.assertIn("mov %rsi, %fs:0", readiness_waits_start)
        self.assertIn("crabc_x86_64_readiness_waits_probe", readiness_waits_start)
        for artifact_script in (
            script,
            credential_script,
            bootstrap_script,
            process_context_script,
            descriptor_io_script,
            process_resources_script,
            readiness_waits_script,
        ):
            self.assertIn('TLSLD', artifact_script)
            self.assertIn('DTPMOD', artifact_script)
            self.assertIn('DTPOFF', artifact_script)
            self.assertIn(
                'candidate_relocations="$work_dir/candidate-relocations"',
                artifact_script,
            )
            self.assertIn('readelf --relocs --wide "$candidate"', artifact_script)
            self.assertIn(
                'candidate relocations retain a dynamic TLS model', artifact_script
            )
            self.assertIn('ar t "$archive_path"', artifact_script)
            self.assertIn('^c\\..+\\.rcgu\\.o$', artifact_script)
            self.assertIn("static_c_abi_exports.txt", artifact_script)
            self.assertIn('selected static C ABI export surface drifted', artifact_script)
        self.assertIn('memmove(destination_end, source_end, length)', bootstrap_probe)
        self.assertIn('memmove(overlap_source + 1, overlap_source, length)', bootstrap_probe)
        self.assertIn('memcmp(source_end, destination_end, length)', bootstrap_probe)
        self.assertIn('bcmp(source_end, destination_end, length)', bootstrap_probe)

    def test_libc_static_c_abi_signal_control_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signal_foundation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_foundation.rs"
        ).read_text(encoding="utf-8")
        signal_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_control.rs"
        ).read_text(encoding="utf-8")
        foundation_probe = (
            ROOT / "compat" / "x86_64" / "libc_signal_foundation_probe.rs"
        ).read_text(encoding="utf-8")
        control_probe = (
            ROOT / "compat" / "x86_64" / "libc_signal_control_probe.c"
        ).read_text(encoding="utf-8")
        control_start = (
            ROOT / "compat" / "x86_64" / "libc_signal_control_start.S"
        ).read_text(encoding="utf-8")
        control_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_control.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_foundation.rs"]', static_root)
        self.assertIn('#[path = "signal_control.rs"]', static_root)
        for symbol in (
            "fn sigaction(",
            "fn signal(",
            "fn sigemptyset(",
            "fn sigfillset(",
            "fn sigaddset(",
            "fn sigdelset(",
            "fn sigismember(",
            "fn sigprocmask(",
            "fn sigpending(",
            "fn __libc_current_sigrtmax(",
        ):
            self.assertIn(symbol, signal_control)
        for required in (
            "raw_syscall::SYS_RT_SIGACTION",
            "raw_syscall::SYS_RT_SIGPROCMASK",
            "raw_syscall::SYS_RT_SIGPENDING",
            "raw_syscall::syscall4(",
            "raw_syscall::syscall2(",
            "SA_RESTORER",
            "pack_public_action",
            "unpack_kernel_action",
        ):
            self.assertIn(required, signal_control)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn raise(",
            "fn kill(",
            "fn tgkill(",
            "fn sigsuspend(",
            "fn sigtimedwait(",
            "fn sigwaitinfo(",
            "fn sigwait(",
            "fn sigaltstack(",
            "fn pthread_sigmask(",
        ):
            self.assertNotIn(forbidden, signal_control)
        self.assertNotIn("#[no_mangle]", signal_foundation)
        self.assertIn("fn pack_public_action", signal_foundation)
        self.assertIn("fn unpack_kernel_action", signal_foundation)
        self.assertIn("crabc_x86_64_signal_restorer", signal_foundation)
        self.assertIn("crabc_x86_64_signal_action_pack", foundation_probe)
        self.assertIn("raw_tgkill_self", control_probe)
        self.assertIn("sigpending", control_probe)
        self.assertIn("SA_RESTART", control_probe)
        self.assertIn("ARCH_SET_FS", control_start)
        self.assertIn("mov %rsi, %fs:0", control_start)
        self.assertIn("crabc_x86_64_signal_control_probe", control_start)
        # The archive is shared with the separately selected readiness/signal-
        # waits artifact. Its `sigsuspend` export must not be treated as an
        # accidental signal-control export by this older artifact gate.
        self.assertNotIn("sigsuspend sigtimedwait", control_runner)
        self.assertIn("sigtimedwait sigwaitinfo sigwait", control_runner)
        for required in (
            "static_c_abi_exports.txt",
            'ar t "$archive_path"',
            "selected static C ABI export surface drifted",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "crabc_x86_64_signal_restorer",
            "GLOBAL +HIDDEN",
            "mov rax, 15",
            "syscall",
        ):
            self.assertIn(required, control_runner)
        self.assertNotIn("--whole-archive", control_runner)
        self.assertNotIn("crabc_x86_64_signal_action_pack", static_export_names)
        for symbol in (
            "__libc_current_sigrtmax",
            "sigaction",
            "signal",
            "sigemptyset",
            "sigfillset",
            "sigaddset",
            "sigdelset",
            "sigismember",
            "sigprocmask",
            "sigpending",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-signal-control", runner)

    def test_libc_static_c_abi_signal_execution_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        signal_execution = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_execution.rs"
        ).read_text(encoding="utf-8")
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_signal_execution_probe.c"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_signal_execution_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_signal_execution.sh"
        )
        for path in (probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing signal-execution input: {path}")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "signal_execution.rs"]', static_root)
        for source in (
            "src/signal/kill.c",
            "src/signal/killpg.c",
            "src/signal/raise.c",
            "src/signal/sigqueue.c",
            "src/signal/sigtimedwait.c",
            "src/signal/sigwaitinfo.c",
            "src/signal/sigwait.c",
        ):
            self.assertIn(source, signal_execution)
        for symbol in (
            "fn kill(",
            "fn killpg(",
            "fn raise(",
            "fn sigqueue(",
            "fn sigtimedwait(",
            "fn sigwaitinfo(",
            "fn sigwait(",
        ):
            self.assertIn(symbol, signal_execution)
        for required in (
            "APPLICATION_SIGNAL_MASK",
            "0xffff_fffc_7fff_ffff",
            "block_application_signals",
            "restore_signals",
            "SYS_TKILL",
            "SYS_RT_SIGQUEUEINFO",
            "SYS_RT_SIGTIMEDWAIT",
            "process_context::getuid()",
            "process_context::getpid()",
            "result != -EINTR",
            "return -1;",
            "positive errno value",
        ):
            self.assertIn(required, signal_execution)
        for forbidden in (
            "pub extern \"C\" fn tgkill(",
            "pub extern \"C\" fn sigaltstack(",
            "pub extern \"C\" fn signalfd(",
            "pub extern \"C\" fn pthread_kill(",
            "pub extern \"C\" fn clone(",
        ):
            self.assertNotIn(forbidden, signal_execution)

        for required in (
            "sizeof(siginfo_t) == 128",
            "offsetof(siginfo_t, si_value) == 24",
            "raw_clone_sigchld",
            "raw_wait4_cleanup",
            "check_retry_after_eintr",
            "killpg(-1, 0)",
            "sigtimedwait(0, &info, &zero_timeout)",
            "sigwait(0, &waited_signal)",
            "sigsuspend(&empty_set)",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_signal_execution_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_signal_header_abi.sh",
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "TLSGD",
            "__gxx_personality_v0",
            "pthread_create",
            "pthread_kill",
            "getauxval sysconf",
            "assert_named_syscall kill 3e",
            "assert_named_syscall killpg 3e",
            "assert_named_syscall raise e",
            "assert_named_syscall raise c8",
            "assert_named_syscall sigqueue e",
            "assert_named_syscall sigqueue 81",
            "assert_named_syscall sigtimedwait 80",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "kill",
            "killpg",
            "raise",
            "sigqueue",
            "sigtimedwait",
            "sigwaitinfo",
            "sigwait",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-process-signal-execution"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-signal-execution"',
            parity_ledger,
        )
        self.assertIn("run_libc_signal_execution_probe()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_signal_execution.sh", runner
        )
        self.assertIn(
            '    libc-signal-execution)\n        [ "$#" -eq 0 ] || fail "libc-signal-execution takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_pthread_create_exit_join_tls_artifact_stays_bounded(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        pthread_create_join = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_pthread_create_join_tls_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_pthread_create_join_tls_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_pthread_create_join_tls.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "pthread_create_join.rs"]', static_root)
        for required in (
            "src/thread/pthread_create.c::__pthread_create",
            "src/thread/pthread_create.c::__pthread_exit",
            "src/thread/x86_64/clone.s::__clone",
            "src/thread/pthread_join.c",
            "struct ThreadControl",
            "PTHREAD_CLONE_FLAGS",
            "CLONE_SETTLS",
            "CLONE_PARENT_SETTID",
            "CLONE_CHILD_CLEARTID",
            "FUTEX_WAIT",
            "raw_syscall::SYS_MMAP",
            "raw_syscall::SYS_MUNMAP",
            "raw_syscall::SYS_FUTEX",
            "initial_errno_offset",
            "SELECTED_WORKER_REGISTRY_SIZE",
            "SELECTED_WORKER_REGISTRY",
            "SELECTED_WORKER_REGISTRY_LOCK",
            "reserve_selected_worker",
            "publish_current_selected_worker_result",
            "release_selected_worker",
            "current_linux_thread_id",
            "raw_syscall::SYS_GETTID",
            "registry_retired",
            "finished",
            ".hidden __crabc_x86_pthread_clone",
            "fn pthread_create(",
            "fn pthread_exit(",
            "fn pthread_join(",
        ):
            self.assertIn(required, pthread_create_join)
        for forbidden in (
            "fn pthread_detach(",
            "fn pthread_self(",
            "fn pthread_cancel(",
            "fn pthread_key_create(",
            "fn pthread_mutex_",
            "WORKER_CONTROL_TPOFF",
            "__tls_get_addr",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, pthread_create_join)
        for required in (
            "#include <errno.h>",
            "#include <pthread.h>",
            "run_worker_round",
            "observe_explicit_exit_worker",
            "observe_held_explicit_exit_worker",
            "run_explicit_exit_round",
            "run_null_result_join",
            "run_concurrent_worker_round",
            "run_concurrent_explicit_exit_round",
            "run_registry_capacity_round",
            "pthread_exit",
            "__atomic_fetch_add",
            "first.errno_location == second.errno_location",
            "CRABC_PTHREAD_CREATE_JOIN_TLS_FREESTANDING",
            "CRABC_PTHREAD_CREATE_JOIN_TLS_SELECTED_WORKER_LIMIT",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_pthread_create_join_tls_probe",
            "CLONE_SETTLS",
        ):
            self.assertIn(required, start)
        for required in (
            "run_musl_oracle.sh",
            "run_types_header_abi.sh",
            "-pthread",
            "-nostdlib -static",
            "-DCRABC_PTHREAD_CREATE_JOIN_TLS_SELECTED_WORKER_LIMIT=64",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "__crabc_x86_pthread_clone",
            "GLOBAL +HIDDEN",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "pthread clone boundary lacks clone syscall number 56",
            "seventh-argument child-tid shuffle",
            "child exit syscall number 60",
            "pthread_exit lacks an x86 thread-exit syscall instruction",
            "candidate lacks gettid syscall number 186 identity validation",
            "pthread_exit lacks thread exit syscall number 60",
            "pthread_join lacks futex syscall number 202",
            "pthread_join lacks munmap syscall number 11",
            "pthread_detach",
            "__tls_get_addr",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        pthread_join_body = pthread_create_join.split(
            'pub unsafe extern "C" fn pthread_join', 1
        )[1]
        self.assertLess(
            pthread_join_body.index("release_selected_worker"),
            pthread_join_body.index("unmap_worker"),
        )
        explicit_exit_publish = pthread_create_join.split(
            "fn publish_current_selected_worker_result", 1
        )[1].split("/// Map one control/TLS/stack backing range", 1)[0]
        self.assertIn("worker_tid.load", explicit_exit_publish)
        self.assertIn("child_tid.load", explicit_exit_publish)
        self.assertLess(
            explicit_exit_publish.index("lock_selected_worker_registry"),
            explicit_exit_publish.index("publish_worker_result"),
        )
        for symbol in ("pthread_create", "pthread_exit", "pthread_join"):
            self.assertIn(symbol, static_export_names)
        for forbidden in (
            "pthread_detach",
            "pthread_self",
            "pthread_cancel",
            "pthread_mutex_init",
        ):
            self.assertNotIn(forbidden, static_export_names)
        self.assertIn("libc-pthread-create-join-tls", runner)

    def test_libc_static_c_abi_termios_control_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        termios_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "termios_control.rs"
        ).read_text(encoding="utf-8")
        header_c = (
            ROOT / "compat" / "x86_64" / "termios_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx = (
            ROOT / "compat" / "x86_64" / "termios_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_termios_control_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_termios_control_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_termios_control.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "termios_control.rs"]', static_root)
        for symbol in (
            "fn cfgetispeed(",
            "fn cfgetospeed(",
            "fn cfsetispeed(",
            "fn cfsetospeed(",
            "fn cfsetspeed(",
            "fn cfmakeraw(",
            "fn tcgetattr(",
            "fn tcsetattr(",
            "fn tcflush(",
            "fn tcflow(",
            "fn tcsendbreak(",
            "fn tcgetwinsize(",
            "fn tcsetwinsize(",
        ):
            self.assertIn(symbol, termios_control)
        for required in (
            "struct PublicTermios",
            "struct KernelTermios",
            "struct Winsize",
            "size_of::<PublicTermios>()",
            "size_of::<KernelTermios>()",
            "raw_syscall::SYS_IOCTL",
            "raw_syscall::syscall3(",
            "CBAUD",
            "CIBAUD",
            "TCGETS",
            "TCSETS",
            "TIOCGWINSZ",
            "TIOCSWINSZ",
            "TCSBRK, 0",
        ):
            self.assertIn(required, termios_control)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn ioctl(",
            "fn tcdrain(",
            "fn tcgetsid(",
            "fn tcgetpgrp(",
            "fn tcsetpgrp(",
            "fn openpty(",
            "fn forkpty(",
            "fn login_tty(",
        ):
            self.assertNotIn(forbidden, termios_control)
        self.assertIn('extern "C" {', header_cxx)
        self.assertIn("CBAUD == 0x100f", header_c)
        self.assertIn("B4000000", header_c)
        self.assertIn("PUBLIC_TERMIOS_TAIL_BYTES", probe)
        self.assertIn("public_tail_has_value", probe)
        self.assertIn("tcsetattr(-1, -1, 0)", probe)
        self.assertIn("tcsendbreak(master, 1)", probe)
        self.assertIn("FIXTURE_TIOCGPTPEER", probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_termios_control_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "tcgetattr lacks the fixed TCGETS request",
            "tcsetattr does not map actions onto TCSETS through TCSETSF",
            "tcflush lacks the fixed TCFLSH request",
            "tcflow lacks the fixed TCXONC request",
            "tcsendbreak does not discard duration",
            "tcgetwinsize lacks the fixed TIOCGWINSZ request",
            "tcsetwinsize lacks the fixed TIOCSWINSZ request",
        ):
            self.assertIn(required, artifact_runner)
        # qsort/bsearch are globally selected archive exports from the later
        # callback-algorithms vertical, so this older focused runner may not
        # classify either as an unselected symbol.
        for globally_selected in ("bsearch", "qsort"):
            self.assertIn(globally_selected, static_export_names)
        self.assertNotIn("qsort bsearch", artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "cfgetispeed",
            "cfgetospeed",
            "cfsetispeed",
            "cfsetospeed",
            "cfsetspeed",
            "cfmakeraw",
            "tcgetattr",
            "tcsetattr",
            "tcflush",
            "tcflow",
            "tcsendbreak",
            "tcgetwinsize",
            "tcsetwinsize",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("termios-header-abi", runner)
        self.assertIn("libc-termios-control", runner)

    def test_libc_static_c_abi_process_context_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        process_context = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_context.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_process_context_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_process_context_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_process_context.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "process_context.rs"]', static_root)
        for symbol in (
            "fn getpid(",
            "fn getppid(",
            "fn getuid(",
            "fn getgid(",
            "fn geteuid(",
            "fn getegid(",
            "fn umask(",
            "fn setsid(",
            "fn setpgid(",
            "fn getpgid(",
            "fn getsid(",
            "fn getpgrp(",
            "fn setpgrp(",
        ):
            self.assertIn(symbol, process_context)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/getpid.c",
            "src/unistd/setpgid.c",
            "src/stat/umask.c",
            "raw_syscall::SYS_GETPID",
            "raw_syscall::SYS_UMASK",
            "raw_syscall::SYS_SETSID",
            "raw_syscall::SYS_SETPGID",
            "raw_syscall::SYS_GETPGID",
            "raw_syscall::SYS_GETSID",
            "c_status(result)",
        ):
            self.assertIn(required, process_context)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn fork(",
            "fn wait(",
            "fn waitpid(",
            "fn waitid(",
            "fn execve(",
            "fn kill(",
            "fn raise(",
            "fn gettid(",
        ):
            self.assertNotIn(forbidden, process_context)
        self.assertIn("SYS_fork == 57", probe)
        self.assertIn("SYS_wait4 == 61", probe)
        self.assertIn("SYS_exit == 60", probe)
        self.assertIn("check_failure_translation", probe)
        self.assertIn("check_umask_exchange", probe)
        self.assertIn("child_setpgrp_case", probe)
        self.assertIn("child_setpgid_case", probe)
        self.assertIn("child_setsid_case", probe)
        self.assertIn("raw_syscall4", probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_process_context_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall getpid 27",
            "assert_named_syscall getppid 6e",
            "assert_named_syscall getuid 66",
            "assert_named_syscall getgid 68",
            "assert_named_syscall geteuid 6b",
            "assert_named_syscall getegid 6c",
            "assert_named_syscall umask 5f",
            "assert_named_syscall setsid 70",
            "assert_named_syscall setpgid 6d",
            "assert_named_syscall getpgid 79",
            "assert_named_syscall getsid 7c",
            "assert_named_syscall getpgrp 79",
            "setpgrp does not derive its legacy alias from setpgid(0, 0)",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "getpid",
            "getppid",
            "getuid",
            "getgid",
            "geteuid",
            "getegid",
            "umask",
            "setsid",
            "setpgid",
            "getpgid",
            "getsid",
            "getpgrp",
            "setpgrp",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-process-context", runner)

    def test_libc_static_c_abi_descriptor_io_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_io = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_io.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_io_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_io_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_io.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "descriptor_io.rs"]', static_root)
        for symbol in (
            "fn close(",
            "fn read(",
            "fn write(",
            "fn pread(",
            "fn pwrite(",
            "fn lseek(",
            "fn ftruncate(",
            "fn fsync(",
            "fn fdatasync(",
            "fn dup(",
            "fn dup2(",
            "fn dup3(",
            "fn pipe(",
            "fn pipe2(",
        ):
            self.assertIn(symbol, descriptor_io)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/pwrite.c",
            "struct IoVec",
            "raw_syscall::SYS_PWRITEV2",
            "raw_syscall::SYS_PWRITE64",
            "raw_syscall::SYS_FCNTL",
            "RWF_NOAPPEND",
            "if offset == -1 { -2 } else { offset }",
            "raw_syscall::SYS_DUP2",
            "raw_syscall::SYS_DUP3",
            "if result != -EBUSY",
            "if result == -EINTR",
            "raw_syscall::SYS_PIPE",
            "raw_syscall::SYS_PIPE2",
            "c_ssize_status(result)",
            "c_off_status(result)",
        ):
            self.assertIn(required, descriptor_io)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn open(",
            "fn openat(",
            "fn fcntl(",
            "fn readv(",
            "fn writev(",
            "fn preadv(",
            "fn pwritev(",
            "fn socket(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, descriptor_io)
        for required in (
            "raw_memfd_create",
            "raw_fcntl",
            "check_transfer_position_truncate_and_sync",
            "check_pwrite_append_boundary",
            "check_dup_and_close",
            "check_dup2_and_dup3",
            "check_pipe_and_pipe2",
            "O_APPEND",
            "#include <sys/mman.h>",
            "MFD_CLOEXEC",
            'raw_memfd_create("crabc-dup-close", MFD_CLOEXEC)',
            "raw_fcntl(file_descriptor, F_GETFD, 0) != FD_CLOEXEC",
            "raw_fcntl(duplicate, F_GETFD, 0) != 0",
            "O_CLOEXEC | O_NONBLOCK",
            "pwrite(file_descriptor, \"X\", 1, -1)",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_descriptor_io_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall close 3",
            "assert_named_syscall pread 11",
            "assert_named_syscall dup3 124",
            "assert_named_syscall pipe2 125",
            "for syscall_word in 148 12 48; do",
            "sys/mman.h",
            "assert_ebusy_retry dup2",
            "assert_ebusy_retry dup3",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "close",
            "read",
            "write",
            "pread",
            "pwrite",
            "lseek",
            "ftruncate",
            "fsync",
            "fdatasync",
            "dup",
            "dup2",
            "dup3",
            "pipe",
            "pipe2",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-descriptor-io", runner)

    def test_libc_static_c_abi_process_resources_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        process_resources = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_resources.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_process_resources_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_process_resources_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_process_resources.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "process_resources.rs"]', static_root)
        for symbol in (
            "fn getrlimit(",
            "fn setrlimit(",
            "fn prlimit(",
            "fn getrusage(",
            "fn getpriority(",
            "fn setpriority(",
            "fn nice(",
        ):
            self.assertIn(symbol, process_resources)
        for required in (
            "musl 1.2.6 release commit",
            "src/misc/getrlimit.c",
            "src/misc/getrusage.c",
            "src/linux/prlimit.c",
            "src/unistd/nice.c",
            "struct Rlimit",
            "struct Rusage",
            "size_of::<Rusage>() == 272",
            "offset_of!(Rusage, reserved) == 144",
            "raw_syscall::SYS_PRLIMIT64",
            "raw_syscall::SYS_GETRUSAGE",
            "raw_syscall::SYS_GETPRIORITY",
            "raw_syscall::SYS_SETPRIORITY",
            "errno::get_errno()",
            "EACCES",
            "EPERM",
        ):
            self.assertIn(required, process_resources)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn times(",
            "fn sched_",
            "fn fork(",
            "fn wait",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, process_resources)
        for required in (
            "check_limit_queries",
            "child_limit_transaction",
            "check_live_child_prlimit",
            "check_rusage",
            "check_priority_queries",
            "child_priority_and_nice",
            "raw_prlimit",
            "RUSAGE_CHILDREN",
            "reserved_tail_is_unchanged",
            "raw_result == -EACCES",
            "nice(-1) != -1 || errno != EPERM",
            "nice(0) != 19 || errno != EINVAL",
            "#include <sys/resource.h>",
            "#include <sys/time.h>",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_process_resources_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall getrlimit 12e",
            "assert_named_syscall getrusage 62",
            "assert_named_syscall getpriority 8c",
            "assert_named_syscall setpriority 8d",
            "prlimit lacks the x86 r10 fourth-argument path",
            "nice lacks the EACCES compatibility branch",
            "sys/resource.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "getrlimit",
            "setrlimit",
            "prlimit",
            "getrusage",
            "getpriority",
            "setpriority",
            "nice",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertNotIn("prlimit64", static_export_names)
        self.assertIn("libc-process-resources", runner)

    def test_libc_static_c_abi_readiness_signal_waits_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        readiness_waits = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "readiness_waits.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_readiness_waits_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_readiness_waits.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "readiness_waits.rs"]', static_root)
        for symbol in (
            "fn poll(",
            "fn ppoll(",
            "fn select(",
            "fn pselect(",
            "fn pause()",
            "fn sigsuspend(",
        ):
            self.assertIn(symbol, readiness_waits)
        for required in (
            "musl 1.2.6 release commit",
            "src/select/poll.c",
            "src/select/ppoll.c",
            "src/select/select.c",
            "src/select/pselect.c",
            "src/unistd/pause.c",
            "src/signal/sigsuspend.c",
            "struct PollFd",
            "struct FdSet",
            "struct Timeval",
            "struct Timespec",
            "struct PublicSigSet",
            "struct PselectMaskArgument",
            "size_of::<PollFd>() == 8",
            "size_of::<FdSet>() == 128",
            "size_of::<PublicSigSet>() == 128",
            "raw_syscall::SYS_POLL",
            "raw_syscall::SYS_PPOLL",
            "raw_syscall::SYS_SELECT",
            "raw_syscall::SYS_PSELECT6",
            "raw_syscall::SYS_PAUSE",
            "raw_syscall::SYS_RT_SIGSUSPEND",
            "raw_syscall::syscall3(",
            "raw_syscall::syscall5(",
            "raw_syscall::syscall6(",
            "raw_syscall::syscall0(",
            "raw_syscall::syscall2(",
            "KERNEL_SIGSET_SIZE",
        ):
            self.assertIn(required, readiness_waits)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn epoll",
            "fn eventfd",
            "fn open(",
            "fn fcntl(",
            "fn readv(",
            "fn writev(",
            "fn sigtimedwait(",
            "fn sigwaitinfo(",
            "fn sigwait(",
            "fn sigaltstack(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, readiness_waits)
        for required in (
            "#include <poll.h>",
            "#include <sys/select.h>",
            "sizeof(struct pollfd) == 8",
            "FD_SETSIZE == 1024",
            "sizeof(sigset_t) == 128",
            "check_poll_and_ppoll",
            "check_select_and_pselect",
            "check_atomic_signal_waits",
            "raw_tgkill_self",
            "retain_pause_without_a_racy_runtime_wait",
            "CRABC_READINESS_WAITS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_readiness_waits_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall poll 7",
            "assert_named_syscall ppoll 10f",
            "assert_named_syscall select 17",
            "assert_named_syscall pselect 10e",
            "assert_named_syscall pause 22",
            "assert_named_syscall sigsuspend 82",
            "pselect lacks the x86 ${register} argument path",
            "sigsuspend lacks Linux's eight-byte kernel signal-set size",
            "epoll_create",
            "pthread_sigmask",
            "sys/select.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("poll", "ppoll", "select", "pselect", "pause", "sigsuspend"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-readiness-signal-waits"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-readiness-waits"',
            parity_ledger,
        )
        self.assertIn("libc-readiness-waits", runner)

    def test_socket_header_ipv6_macro_regression_stays_native(self) -> None:
        header = (ROOT / "include" / "netinet" / "in.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "socket_header_ipv6_macro_probe.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_socket_header_abi.sh"
        ).read_text(encoding="utf-8")

        for macro in (
            "IN6_IS_ADDR_UNSPECIFIED",
            "IN6_IS_ADDR_LOOPBACK",
            "IN6_IS_ADDR_MULTICAST",
            "IN6_IS_ADDR_LINKLOCAL",
            "IN6_IS_ADDR_SITELOCAL",
            "IN6_IS_ADDR_V4MAPPED",
            "IN6_IS_ADDR_V4COMPAT",
            "IN6_IS_ADDR_MC_NODELOCAL",
            "IN6_IS_ADDR_MC_LINKLOCAL",
            "IN6_IS_ADDR_MC_SITELOCAL",
            "IN6_IS_ADDR_MC_ORGLOCAL",
            "IN6_IS_ADDR_MC_GLOBAL",
        ):
            self.assertIn(macro, header)
            self.assertIn(macro, probe)
        self.assertIn("__IN6_ADDR_BYTE", header)
        self.assertNotIn("#define IN6_IS_ADDR_UNSPECIFIED(a) 0", header)
        for required in (
            "socket_header_ipv6_macro_probe.c",
            '"$ORACLE_CC" -std=c11 "$ipv6_macro_probe"',
            '"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" "$ipv6_macro_probe"',
            '"$musl_ipv6_macro"',
            '"$project_ipv6_macro"',
        ):
            self.assertIn(required, runner)

    def test_libc_static_c_abi_socket_transport_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        socket_transport = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "socket_transport.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_socket_transport_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_socket_transport_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_socket_transport.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "socket_transport.rs"]', static_root)
        for symbol in (
            "fn socket(",
            "fn socketpair(",
            "fn bind(",
            "fn listen(",
            "fn accept(",
            "fn accept4(",
            "fn connect(",
            "fn send(",
            "fn recv(",
            "fn sendto(",
            "fn recvfrom(",
            "fn shutdown(",
            "fn getsockname(",
            "fn getpeername(",
        ):
            self.assertIn(symbol, socket_transport)
        for required in (
            "musl 1.2.6 release commit",
            "src/network/socket.c",
            "src/network/socketpair.c",
            "src/network/bind.c",
            "src/network/listen.c",
            "src/network/accept.c",
            "src/network/accept4.c",
            "src/network/connect.c",
            "src/network/send.c",
            "src/network/recv.c",
            "src/network/sendto.c",
            "src/network/recvfrom.c",
            "src/network/shutdown.c",
            "src/network/getsockname.c",
            "src/network/getpeername.c",
            "raw_syscall::SYS_SOCKET",
            "raw_syscall::SYS_SOCKETPAIR",
            "raw_syscall::SYS_BIND",
            "raw_syscall::SYS_LISTEN",
            "raw_syscall::SYS_ACCEPT",
            "raw_syscall::SYS_ACCEPT4",
            "raw_syscall::SYS_CONNECT",
            "raw_syscall::SYS_SENDTO",
            "raw_syscall::SYS_RECVFROM",
            "raw_syscall::SYS_SHUTDOWN",
            "raw_syscall::SYS_GETSOCKNAME",
            "raw_syscall::SYS_GETPEERNAME",
            "c_status(result)",
            "c_ssize_status(result)",
        ):
            self.assertIn(required, socket_transport)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn setsockopt(",
            "fn getsockopt(",
            "fn sendmsg(",
            "fn recvmsg(",
            "fn sendmmsg(",
            "fn recvmmsg(",
            "fn poll(",
            "fn pthread_",
            "pthread_cancel",
        ):
            self.assertNotIn(forbidden, socket_transport)
        for required in (
            "#include <sys/socket.h>",
            "check_unix_pair",
            "check_loopback_datagram",
            "check_loopback_stream",
            "check_error_translation",
            "accept4",
            "sendto",
            "recvfrom",
            "CRABC_SOCKET_TRANSPORT_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_socket_transport_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall socket 29",
            "assert_named_syscall socketpair 35",
            "assert_named_syscall bind 31",
            "assert_named_syscall listen 32",
            "assert_named_syscall accept 2b",
            "assert_named_syscall accept4 120",
            "assert_named_syscall connect 2a",
            "assert_named_syscall sendto 2c",
            "assert_named_syscall recvfrom 2d",
            "assert_named_syscall shutdown 30",
            "assert_named_syscall getsockname 33",
            "assert_named_syscall getpeername 34",
            "sys/socket.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "socket",
            "socketpair",
            "bind",
            "listen",
            "accept",
            "accept4",
            "connect",
            "send",
            "recv",
            "sendto",
            "recvfrom",
            "shutdown",
            "getsockname",
            "getpeername",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-socket-transport"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-socket-transport"',
            parity_ledger,
        )
        self.assertIn("libc-socket-transport", runner)

    def test_libc_static_c_abi_system_observation_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_observation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_observation.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_system_observation_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_system_observation_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_system_observation.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "system_observation.rs"]', static_root)
        for symbol in ("fn uname(", "fn sysinfo("):
            self.assertIn(symbol, system_observation)
        for required in (
            "musl 1.2.6 release commit",
            "src/misc/uname.c",
            "src/linux/sysinfo.c",
            "struct UtsName",
            "struct SysInfo",
            "KERNEL_SYSINFO_BYTES",
            "size_of::<UtsName>() == 390",
            "size_of::<SysInfo>() == 368",
            "offset_of!(SysInfo, compatibility_tail) == 108",
            "raw_syscall::SYS_UNAME",
            "raw_syscall::SYS_SYSINFO",
            "raw_syscall::syscall1(",
            "c_status(result)",
        ):
            self.assertIn(required, system_observation)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn sysconf(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, system_observation)
        for required in (
            "#include <sys/sysinfo.h>",
            "#include <sys/utsname.h>",
            "sizeof(struct utsname) == 390",
            "sizeof(struct sysinfo) == 368",
            "SYS_uname == 63 && SYS_sysinfo == 99",
            "check_null_pointer_errors",
            "check_uname_record",
            "check_sysinfo_record_and_tail",
            "SYSINFO_RESERVED_KERNEL_BYTES",
            "CRABC_SYSTEM_OBSERVATION_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_system_observation_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall uname 3f",
            "assert_named_syscall sysinfo 63",
            "sys/utsname.h",
            "sys/sysinfo.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("uname", "sysinfo"):
            self.assertIn(symbol, static_export_names)
        # These belong to the separately selected UTS-identity artifact. The
        # system-observation leaf remains narrow through its own exact source
        # export set, rather than by treating shared-archive exports as if
        # they all belonged to this older artifact.
        for separately_selected_uts_symbol in (
            "gethostname",
            "sethostname",
            "getdomainname",
            "setdomainname",
        ):
            self.assertIn(separately_selected_uts_symbol, static_export_names)
        self.assertIn('id = "static-c-system-observation"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-system-observation"',
            parity_ledger,
        )
        self.assertIn("libc-system-observation", runner)

    def test_libc_static_c_abi_uts_identity_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_observation = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "system_observation.rs"
        ).read_text(encoding="utf-8")
        uts_identity = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "uts_identity.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_uts_identity_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_uts_identity_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_uts_identity.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "system_observation.rs"]', static_root)
        self.assertIn('#[path = "uts_identity.rs"]', static_root)
        for required in (
            "pub(super) struct UtsName",
            "pub(super) const UTS_FIELD_BYTES: usize = 65",
            "pub(super) unsafe fn uname_raw",
        ):
            self.assertIn(required, system_observation)
        for symbol in (
            "fn gethostname(",
            "fn sethostname(",
            "fn getdomainname(",
            "fn setdomainname(",
        ):
            self.assertIn(symbol, uts_identity)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/gethostname.c",
            "src/linux/sethostname.c",
            "src/misc/getdomainname.c",
            "src/misc/setdomainname.c",
            "system_observation::UtsName",
            "system_observation::UTS_FIELD_BYTES",
            "system_observation::uname_raw",
            "MaybeUninit",
            "raw_syscall::SYS_SETHOSTNAME",
            "raw_syscall::SYS_SETDOMAINNAME",
            "raw_syscall::syscall2(",
            "errno::set_errno(EINVAL)",
            "c_status(result)",
        ):
            self.assertIn(required, uts_identity)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn gethostid(",
            "fn sysconf(",
            "fn fork(",
            "fn pthread_",
        ):
            self.assertNotIn(forbidden, uts_identity)
        for required in (
            "#define _GNU_SOURCE 1",
            "#include <sys/utsname.h>",
            "#include <unistd.h>",
            "SYS_uname == 63 && SYS_sethostname == 170",
            "SYS_setdomainname == 171",
            "check_selected_identity_setup",
            "check_hostname_copy_contract",
            "check_domain_copy_contract",
            "check_setter_error_contract_and_stability",
            "gethostname(NULL, 0)",
            "getdomainname(NULL, 0)",
            "sethostname(NULL, 1)",
            "setdomainname(NULL, 1)",
            "CRABC_UTS_IDENTITY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("crabc_x86_64_uts_identity_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "run_in_fresh_uts_namespace",
            "unshare --uts --fork",
            "assert_named_syscall gethostname 3f",
            "assert_named_syscall getdomainname 3f",
            "assert_named_syscall sethostname aa",
            "assert_named_syscall setdomainname ab",
            "sys/utsname.h",
            "unistd.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "gethostname",
            "sethostname",
            "getdomainname",
            "setdomainname",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn("libc-uts-identity", runner)

    def test_libc_static_c_abi_random_entropy_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        random_entropy = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "random_entropy.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_random_entropy_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_random_entropy_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_random_entropy.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = [
            line
            for line in static_exports.splitlines()
            if line and not line.startswith("#")
        ]
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "random_entropy.rs"]', static_root)
        for symbol in ("fn getrandom(", "fn getentropy("):
            self.assertIn(symbol, random_entropy)
        for required in (
            "musl 1.2.6 release commit",
            "src/linux/getrandom.c",
            "src/misc/getentropy.c",
            "raw_syscall::SYS_GETRANDOM",
            "raw_syscall::syscall3(",
            "GETENTROPY_MAX_BYTES: usize = 256",
            "errno::set_errno(EIO)",
            "errno::get_errno()",
            "c_ssize_status(result)",
            "syscall_cp",
            "pthread_setcancelstate",
        ):
            self.assertIn(required, random_entropy)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn random(",
            "fn srandom(",
            "fn pthread_",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, random_entropy)
        for required in (
            "#include <sys/random.h>",
            "#include <unistd.h>",
            "GRND_NONBLOCK",
            "getrandom",
            "getentropy",
            "256",
            "CRABC_RANDOM_ENTROPY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("ARCH_SET_FS", start)
        self.assertIn("mov %rsi, %fs:0", start)
        self.assertIn("libc_random_entropy_probe", start)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "R_X86_64_TPOFF",
            "candidate relocations retain a dynamic TLS model",
            "assert_named_syscall getrandom 13e",
            "sys/random.h",
            "unistd.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("getrandom", "getentropy"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-random-entropy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-random-entropy"',
            parity_ledger,
        )
        self.assertIn("libc-random-entropy", runner)

    def test_libc_static_c_abi_memory_search_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        memory_search = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_search.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_memory_search_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_memory_search.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "memory_search.rs"]', static_root)
        for symbol in ("fn memchr(", "fn memmem(", "fn memrchr("):
            self.assertIn(symbol, memory_search)
        for required in (
            "musl 1.2.6 release commit",
            "src/string/memchr.c",
            "src/string/memmem.c",
            "src/string/memrchr.c",
            "__memrchr",
            "stateless",
            "allocation-free",
        ):
            self.assertIn(required, memory_search)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "fn __memrchr(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, memory_search)
        for required in (
            "#include <string.h>",
            "memchr",
            "memmem",
            "memrchr",
            "CRABC_MEMORY_SEARCH_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "candidate retains a dynamic TLS model",
            "string.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("memchr", "memmem", "memrchr"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-memory-search"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-memory-search"',
            parity_ledger,
        )
        self.assertIn("libc-memory-search", runner)

    def test_libc_static_c_abi_string_copy_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        string_copy = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "string_copy.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_string_copy_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_string_copy.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_string_copy_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "string_copy.rs"]', static_root)
        for symbol in (
            "fn stpcpy(",
            "fn stpncpy(",
            "fn strcpy(",
            "fn strncpy(",
            "fn strcat(",
            "fn strncat(",
            "fn strlcpy(",
            "fn strlcat(",
        ):
            self.assertIn(symbol, string_copy)
        for required in (
            "musl 1.2.6 release commit",
            "src/string/stpcpy.c",
            "src/string/stpncpy.c",
            "src/string/strcpy.c",
            "src/string/strncpy.c",
            "src/string/strcat.c",
            "src/string/strncat.c",
            "src/string/strlcpy.c",
            "src/string/strlcat.c",
            "__stpcpy",
            "__stpncpy",
            "stateless",
            "allocation-free",
            "scalar fallback",
        ):
            self.assertIn(required, string_copy)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "fn __stpcpy(",
            "fn __stpncpy(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, string_copy)
        for required in (
            "#include <string.h>",
            "stpcpy",
            "stpncpy",
            "strcpy",
            "strncpy",
            "strcat",
            "strncat",
            "strlcpy",
            "strlcat",
            "CRABC_STRING_COPY_FREESTANDING",
            "check_page_edges",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate unexpectedly selects TLS",
            "candidate retains a dynamic TLS model",
            "__stpcpy",
            "__stpncpy",
            "string.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_POSIX_COPY",
            "CRABC_EXPECT_GNU_COPY",
            "CRABC_REQUIRE_POSIX_COPY_HIDDEN",
            "CRABC_REQUIRE_GNU_COPY_HIDDEN",
            "-std=c++17",
            "string.h",
        ):
            self.assertIn(required, header_runner)
        for symbol in (
            "stpcpy",
            "stpncpy",
            "strcpy",
            "strncpy",
            "strcat",
            "strncat",
            "strlcpy",
            "strlcat",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-string-copy"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-string-copy"',
            parity_ledger,
        )
        self.assertIn("libc-string-copy", runner)

    def test_libc_static_c_abi_ctype_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        ctype = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ctype.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_ctype_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_ctype.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_ctype_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = (
            "isalnum",
            "isalpha",
            "isblank",
            "iscntrl",
            "isdigit",
            "isgraph",
            "islower",
            "isprint",
            "ispunct",
            "isspace",
            "isupper",
            "isxdigit",
            "tolower",
            "toupper",
            "isascii",
            "toascii",
        )
        self.assertIn('#[path = "ctype.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", ctype)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/ctype/isalnum.c",
            "src/ctype/isalpha.c",
            "src/ctype/isblank.c",
            "src/ctype/iscntrl.c",
            "src/ctype/isdigit.c",
            "src/ctype/isgraph.c",
            "src/ctype/islower.c",
            "src/ctype/isprint.c",
            "src/ctype/ispunct.c",
            "src/ctype/isspace.c",
            "src/ctype/isupper.c",
            "src/ctype/isxdigit.c",
            "src/ctype/tolower.c",
            "src/ctype/toupper.c",
            "src/ctype/isascii.c",
            "src/ctype/toascii.c",
            "fixed C locale",
            "stateless",
            "allocation-free",
            "EOF",
        ):
            self.assertIn(required, ctype)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn free(",
            "_l(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, ctype)
        for required in (
            "#include <ctype.h>",
            "ctype_fn",
            "value = -1",
            "value <= 255",
            "isascii",
            "toascii",
            "CRABC_CTYPE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "ctype.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_EXTENDED_CTYPE",
            "CRABC_REQUIRE_EXTENDED_CTYPE_HIDDEN",
            "-std=c++17",
            "ctype.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-ctype"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-ctype"',
            parity_ledger,
        )
        self.assertIn("libc-ctype", runner)

    def test_libc_static_c_abi_integer_arithmetic_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        integer_arithmetic = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "integer_arithmetic.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_integer_arithmetic_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_integer_arithmetic.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_integer_arithmetic_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("abs", "labs", "llabs", "div", "ldiv", "lldiv")
        self.assertIn('#[path = "integer_arithmetic.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", integer_arithmetic)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/abs.c",
            "src/stdlib/labs.c",
            "src/stdlib/llabs.c",
            "src/stdlib/div.c",
            "src/stdlib/ldiv.c",
            "src/stdlib/lldiv.c",
            "stateless",
            "allocation-free",
            "wrapping_neg",
            "native signed `idiv`",
            "undefined",
            "core::arch::asm!",
        ):
            self.assertIn(required, integer_arithmetic)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn rand(",
            "wrapping_div",
            "wrapping_rem",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, integer_arithmetic)
        for required in (
            "#include <stdlib.h>",
            "abs_fn",
            "div_fn",
            "defined domain",
            "-2147483647",
            "CRABC_INTEGER_ARITHMETIC_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "strtoimax",
            "stdlib.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "stdlib.h",
            "features.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('id = "static-c-integer-arithmetic"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-integer-arithmetic"',
            parity_ledger,
        )
        self.assertIn("libc-integer-arithmetic", runner)

    def test_libc_static_c_abi_integer_parse_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        integer_parse = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "integer_parse.rs"
        ).read_text(encoding="utf-8")
        inttypes_header = (ROOT / "include" / "inttypes.h").read_text(
            encoding="utf-8"
        )
        stdlib_header = (ROOT / "include" / "stdlib.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_integer_parse_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_integer_parse.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_integer_parse_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "integer_parse_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "integer_parse_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = (
            "atoi",
            "atol",
            "atoll",
            "strtol",
            "strtoul",
            "strtoll",
            "strtoull",
            "strtoimax",
            "strtoumax",
        )
        self.assertIn('#[path = "integer_parse.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", integer_parse)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/strtol.c",
            "src/internal/intscan.c",
            "src/internal/intscan.h",
            "src/internal/shgetc.c",
            "src/internal/shgetc.h",
            "src/stdlib/atoi.c",
            "src/stdlib/atol.c",
            "src/stdlib/atoll.c",
            "base validation",
            "end-pointer",
            "EINVAL",
            "ERANGE",
            "defined-input",
            "allocation-free",
            "LP64",
        ):
            self.assertIn(required, integer_parse)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn strtod(",
            "fn wcstol(",
            "fn malloc(",
            "raw_syscall::",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, integer_parse)
        for required in (
            "#include <errno.h>",
            "#include <inttypes.h>",
            "#include <limits.h>",
            "#include <stdlib.h>",
            "expect_long",
            "expect_ulong",
            "expect_intmax",
            '"0x"',
            "CRABC_INTEGER_PARSE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate lacks the selected errno TLS segment",
            "__strtol_internal",
            "strtoimax",
            "stdlib.h",
            "run_integer_parse_header_abi.sh",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "inttypes.h",
            "stdlib.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn("strtoimax_signature", header_c_probe)
        self.assertIn("decltype(&strtol)", header_cxx_probe)
        self.assertIn('extern "C" {', inttypes_header)
        self.assertIn('extern "C" {', stdlib_header)
        self.assertIn('id = "static-c-integer-parse"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-integer-parse"',
            parity_ledger,
        )
        self.assertIn("integer-parse-header-abi", runner)
        self.assertIn("libc-integer-parse", runner)

    def test_libc_static_c_abi_intmax_arithmetic_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        intmax_arithmetic = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "intmax_arithmetic.rs"
        ).read_text(encoding="utf-8")
        inttypes_header = (ROOT / "include" / "inttypes.h").read_text(
            encoding="utf-8"
        )
        probe = (
            ROOT / "compat" / "x86_64" / "libc_intmax_arithmetic_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_intmax_arithmetic.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_intmax_arithmetic_header_abi.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("imaxabs", "imaxdiv")
        self.assertIn('#[path = "intmax_arithmetic.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", intmax_arithmetic)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/imaxabs.c",
            "src/stdlib/imaxdiv.c",
            "intmax_t",
            "imaxdiv_t",
            "stateless",
            "allocation-free",
            "wrapping_neg",
            "native signed `idiv`",
            "undefined",
            "core::arch::asm!",
        ):
            self.assertIn(required, intmax_arithmetic)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn strtoimax(",
            "wrapping_div",
            "wrapping_rem",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, intmax_arithmetic)
        for required in (
            "#include <inttypes.h>",
            "imaxabs_fn",
            "imaxdiv_fn",
            "defined domain",
            "INTMAX_MIN + INTMAX_C(1)",
            "CRABC_INTMAX_ARITHMETIC_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "strtoimax",
            "inttypes.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "inttypes.h",
            "bits/alltypes.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('extern "C" {', inttypes_header)
        self.assertIn('id = "static-c-intmax-arithmetic"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-intmax-arithmetic"',
            parity_ledger,
        )
        self.assertIn("libc-intmax-arithmetic", runner)

    def test_libc_static_c_abi_credential_observation_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        credential_observation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "credential_observation.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_credential_observation_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_credential_observation.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_credential_observation_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "credential_observation_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "credential_observation_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("getgroups", "getresuid", "getresgid")
        self.assertIn('#[path = "credential_observation.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", credential_observation)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/unistd/getgroups.c",
            "src/misc/getresuid.c",
            "src/misc/getresgid.c",
            "SYS_GETGROUPS",
            "SYS_GETRESUID",
            "SYS_GETRESGID",
            "query-then-fill race",
            "c_status",
            "EFAULT",
        ):
            self.assertIn(required, credential_observation)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn setgroups(",
            "fn setresuid(",
            "fn setresgid(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, credential_observation)
        for required in (
            "GROUP_CAPTURE_ATTEMPTS",
            "GROUP_STORAGE_CAPACITY",
            "getgroups(-1",
            "count-to-fill window",
            "SYS_getresuid",
            "SYS_getresgid",
            "EFAULT",
            "CRABC_CREDENTIAL_OBSERVATION_FREESTANDING",
            "check_user_partial_fault_order",
            "check_group_partial_fault_order",
            "for (valid_mask = 0; valid_mask < 8; ++valid_mask)",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "getlogin",
            "getgroups getresuid getresgid",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_GNU_CREDENTIAL_OBSERVATION",
            "CRABC_REQUIRE_GETRES_HIDDEN",
            "-U_GNU_SOURCE",
            "-std=c++17",
            "nm --undefined-only",
            "unistd.h",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("getresuid_must_be_hidden", header_probe)
            self.assertIn("getresgid_must_be_hidden", header_probe)
        self.assertIn('id = "static-c-credential-observation"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-credential-observation"',
            parity_ledger,
        )
        self.assertIn("libc-credential-observation", runner)

    def test_libc_static_c_abi_child_reaping_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        child_reaping = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "child_reaping.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_child_reaping_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_child_reaping.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_child_reaping_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "child_reaping_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "child_reaping_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("wait", "waitpid", "waitid")
        self.assertIn('#[path = "child_reaping.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", child_reaping)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/process/wait.c",
            "src/process/waitpid.c",
            "src/process/waitid.c",
            "SYS_WAIT4",
            "SYS_WAITID",
            "cancellation",
            "WNOWAIT",
            "initial-TLS",
        ):
            self.assertIn(required, child_reaping)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn fork(",
            "fn execve(",
            "fn wait4(",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, child_reaping)
        for required in (
            "raw_clone_sigchld",
            "returns_twice",
            "WNOHANG",
            "WNOWAIT",
            "CLD_EXITED",
            "CRABC_CHILD_REAPING_FREESTANDING",
            "raw_wait4_cleanup",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "wait waitpid waitid",
            "wait4",
            "waitid f7",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "sys/wait.h",
            "siginfo_t",
            "CRABC_CHILD_REAPING_POSIX",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("waitid_signature", header_probe)
            self.assertIn("siginfo_t", header_probe)
        self.assertIn('id = "static-c-child-reaping"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-child-reaping"',
            parity_ledger,
        )
        self.assertIn("child-reaping-header-abi", runner)
        self.assertIn("libc-child-reaping", runner)

    def test_libc_static_c_abi_immediate_termination_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        immediate_termination = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "immediate_termination.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_immediate_termination_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_immediate_termination.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_immediate_termination_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "immediate_termination_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "immediate_termination_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "immediate_termination.rs"]', static_root)
        self.assertIn("fn _Exit(", immediate_termination)
        self.assertIn("_Exit", static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/exit/_Exit.c",
            "SYS_EXIT_GROUP",
            "SYS_EXIT",
            "exit_group",
            "does not establish",
        ):
            self.assertIn(required, immediate_termination)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn at_quick_exit(",
            "fn quick_exit(",
            "fn _exit(",
            "c_status",
            "__tls_get_addr",
        ):
            self.assertNotIn(forbidden, immediate_termination)
        for required in (
            "raw_clone_sigchld",
            "returns_twice",
            "SYS_exit_group",
            "CRABC_IMMEDIATE_TERMINATION_FREESTANDING",
            "wait_for_child",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains a dynamic TLS model",
            "_Exit",
            "assert_named_syscall e7",
            "assert_named_syscall 3c",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "stdlib.h",
            "_Exit",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("immediate_exit_signature", header_probe)
            self.assertIn("_Exit", header_probe)
        self.assertIn('id = "static-c-immediate-termination"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-immediate-termination"',
            parity_ledger,
        )
        self.assertIn("immediate-termination-header-abi", runner)
        self.assertIn("libc-immediate-termination", runner)

    def test_libc_static_c_abi_callback_algorithms_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        callback_algorithms = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" /
            "callback_algorithms.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_callback_algorithms_probe.c"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" /
            "run_libc_callback_algorithms.sh"
        ).read_text(encoding="utf-8")
        header_runner = (
            ROOT / "compat" / "x86_64" /
            "run_callback_algorithms_header_abi.sh"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" /
            "callback_algorithms_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" /
            "callback_algorithms_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines()
            if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "callback_algorithms.rs"]', static_root)
        for symbol in ("bsearch", "__qsort_r", "qsort", "qsort_r"):
            self.assertIn(symbol, callback_algorithms)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/stdlib/bsearch.c",
            "src/stdlib/qsort.c",
            "src/stdlib/qsort_nr.c",
            "smoothsort",
            "14 * core::mem::size_of::<usize>() + 1",
            "12 * core::mem::size_of::<usize>()",
            ".weak qsort_r",
            ".set qsort_r, __qsort_r",
            "qsort_copy_nonoverlapping",
            "MaybeUninit",
        ):
            self.assertIn(required, callback_algorithms)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "c_status",
            "__tls_get_addr",
            "raw_syscall",
            "alloc::",
        ):
            self.assertNotIn(forbidden, callback_algorithms)
        for required in (
            "bsearch",
            "qsort",
            "qsort_r",
            "__qsort_r",
            "CRABC_CALLBACK_ALGORITHMS_FREESTANDING",
            "CRABC_CALLBACK_ALGORITHMS_OVERRIDE_QSORT_R",
            "context_mismatch",
            "wide_record",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "qsort_r",
            "weak",
            "same-address",
            "unexpectedly selects TLS",
            "Rust panic machinery",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "-std=c++17",
            "nm --undefined-only",
            "stdlib.h",
            "CRABC_EXPECT_QSORT_R",
        ):
            self.assertIn(required, header_runner)
        for header_probe in (header_c_probe, header_cxx_probe):
            self.assertIn("bsearch_signature", header_probe)
            self.assertIn("qsort_signature", header_probe)
            self.assertIn("qsort_r_signature", header_probe)
        self.assertIn('id = "static-c-callback-algorithms"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-callback-algorithms"',
            parity_ledger,
        )
        self.assertIn("callback-algorithms-header-abi", runner)
        self.assertIn("libc-callback-algorithms", runner)

    def test_libc_static_c_abi_clock_gettime_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        clock_gettime = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_gettime.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_clock_gettime_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_clock_gettime_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_clock_gettime.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "clock_gettime.rs"]', static_root)
        self.assertIn("pub unsafe extern \"C\" fn clock_gettime(", clock_gettime)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/clock_gettime.c",
            "raw_syscall::SYS_CLOCK_GETTIME",
            "raw_syscall::syscall2(",
            "c_status(result)",
            "initial-TLS errno",
            "vDSO resolver",
        ):
            self.assertIn(required, clock_gettime)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn clock_getres(",
            "fn clock_settime(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, clock_gettime)
        for required in (
            "#include <errno.h>",
            "#include <time.h>",
            "SYS_clock_gettime == 228",
            "CLOCK_REALTIME == 0",
            "check_success_and_errno",
            "check_errors",
            "CLOCK_PROCESS_CPUTIME_ID",
            "CRABC_CLOCK_GETTIME_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_clock_gettime_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall",
            "clock_gettime lacks syscall 228",
            "direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("clock_gettime", static_export_names)
        self.assertIn('id = "static-c-clock-gettime"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-clock-gettime"',
            parity_ledger,
        )
        self.assertIn("run_libc_clock_gettime()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_clock_gettime.sh", runner
        )
        self.assertIn(
            '    libc-clock-gettime)\n        [ "$#" -eq 0 ] || fail "libc-clock-gettime takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_system_configuration_artifact_stays_narrow(
        self,
    ) -> None:
        """A configuration block must be one closed static artifact, not leaves."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        system_configuration_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_configuration.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_system_configuration_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_system_configuration_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_system_configuration.sh"
        )

        for path in (
            system_configuration_path,
            probe_path,
            start_path,
            artifact_runner_path,
        ):
            self.assertTrue(path.is_file(), f"missing system-configuration artifact input: {path}")

        system_configuration = system_configuration_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "system_configuration.rs"]', static_root)
        for required in (
            'fn sysconf(',
            'fn confstr(',
            'fn fpathconf(',
            'fn pathconf(',
            'fn getpagesize()',
            'fn getdtablesize()',
            '#[inline(always)]\nfn pathconf_value',
            '#[inline(always)]\nunsafe fn selected_pathconf',
            'raw_syscall::SYS_PRLIMIT64',
            'initial-TLS errno',
            'musl 1.2.6 release commit',
        ):
            self.assertIn(required, system_configuration)
        pathconf_helpers = system_configuration[
            system_configuration.index('#[inline(always)]\nfn pathconf_value') :
            system_configuration.index(
                '/// Return a selected path configuration value for an open descriptor.'
            )
        ]
        self.assertNotIn('raw_syscall', pathconf_helpers)
        for forbidden in (
            'crabc_core',
            'crabc_mimalloc',
            '__tls_get_addr',
            'pthread_',
            'getauxval',
            'raw_syscall::SYS_STATFS',
            'raw_syscall::SYS_FSTATFS',
        ):
            self.assertNotIn(forbidden, system_configuration)
        for required in (
            '#include <errno.h>',
            '#include <limits.h>',
            '#include <sys/resource.h>',
            '#include <sys/syscall.h>',
            '#include <unistd.h>',
            'SYS_statfs == 137',
            'SYS_fstatfs == 138',
            'SYS_prlimit64 == 302',
            'check_common_contract',
            'check_musl_configuration_contract',
            'CRABC_SYSTEM_CONFIGURATION_FREESTANDING',
        ):
            self.assertIn(required, probe)
        for required in (
            'ARCH_SET_FS',
            'mov %rsi, %fs:0',
            'crabc_x86_64_system_configuration_probe',
        ):
            self.assertIn(required, start)
        for required in (
            'static_c_abi_exports.txt',
            'run_unistd_header_abi.sh',
            'run_resource_header_abi.sh',
            '-nostdlib -static',
            '-Wl,-e,_start',
            'R_X86_64_TPOFF',
            'assert_getdtablesize_syscall',
            'path configuration unexpectedly issues a syscall',
            'getdtablesize lacks syscall 302',
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn('--whole-archive', artifact_runner)
        for symbol in (
            'confstr',
            'fpathconf',
            'getdtablesize',
            'getpagesize',
            'pathconf',
            'sysconf',
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-system-configuration"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-system-configuration"',
            parity_ledger,
        )
        self.assertIn('run_libc_system_configuration()', runner)
        self.assertIn(
            '/workspace/compat/x86_64/run_libc_system_configuration.sh', runner
        )
        self.assertIn(
            '    libc-system-configuration)\n        [ "$#" -eq 0 ] || fail "libc-system-configuration takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_mapping_core_artifact_stays_narrow(self) -> None:
        """The mapping lifecycle is one closed C/header/archive artifact."""
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        mapping_core_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_mapping.rs"
        )
        probe_path = ROOT / "compat" / "x86_64" / "libc_mapping_core_probe.c"
        start_path = ROOT / "compat" / "x86_64" / "libc_mapping_core_start.S"
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_mapping_core.sh"
        )
        header_c_path = ROOT / "compat" / "x86_64" / "mman_header_abi_probe.c"
        header_cxx_path = ROOT / "compat" / "x86_64" / "mman_header_abi_probe.cpp"

        for path in (
            mapping_core_path,
            probe_path,
            start_path,
            artifact_runner_path,
            header_c_path,
            header_cxx_path,
        ):
            self.assertTrue(path.is_file(), f"missing mapping-core artifact input: {path}")

        mapping_core = mapping_core_path.read_text(encoding="utf-8")
        probe = probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        header_c = header_c_path.read_text(encoding="utf-8")
        header_cxx = header_cxx_path.read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "memory_mapping.rs"]', static_root)
        self.assertIn("fn c_pointer_status", static_root)
        for required in (
            "src/mman/mmap.c",
            "src/mman/munmap.c",
            "src/mman/mprotect.c",
            "src/mman/madvise.c",
            "src/mman/posix_madvise.c",
            "src/mman/mincore.c",
            "MMAP_OFFSET_MASK",
            "isize::MAX",
            "MAP_FIXED",
            "MAP_ANONYMOUS",
            "selected_static_vm_wait",
            "__vm_wait",
            "wrapping_add",
            "POSIX_MADV_DONTNEED",
            "c_pointer_status(result)",
            "wrapping_neg",
            "msync",
            "mremap",
            "mlock*",
        ):
            self.assertIn(required, mapping_core)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn msync(",
            "fn mremap(",
            "fn mlock(",
            "fn shm_open(",
            "fn memfd_create(",
            "extern \"C\" fn __vm_wait",
        ):
            self.assertNotIn(forbidden, mapping_core)
        for required in (
            "#include <errno.h>",
            "#include <stdint.h>",
            "#include <sys/mman.h>",
            "#include <sys/syscall.h>",
            "SYS_mmap == 9",
            "SYS_mprotect == 10",
            "SYS_munmap == 11",
            "SYS_mincore == 27",
            "SYS_madvise == 28",
            "PTRDIFF_MAX",
            "POSIX_MADV_DONTNEED",
            "CRABC_MAPPING_CORE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "madvise declaration",
            "posix_madvise declaration",
            "mincore declaration",
        ):
            self.assertIn(required, header_c)
            self.assertIn(required, header_cxx)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_mapping_core_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_mman_header_abi.sh",
            "run_x86_mapping_reference.sh",
            "run_x86_madvise_reference.sh",
            "run_x86_mincore_reference.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "__vm_wait",
            "assert_named_syscall mmap 9",
            "assert_named_syscall mprotect a",
            "assert_named_syscall munmap b",
            "assert_named_syscall madvise 1c",
            "assert_named_syscall posix_madvise 1c",
            "assert_named_syscall mincore 1b",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "posix_madvise",
            "mincore",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-mman-mapping-core"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-mapping-core"', parity_ledger
        )
        self.assertIn("run_libc_mapping_core()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_mapping_core.sh", runner
        )
        self.assertIn(
            '    libc-mapping-core)\n        [ "$#" -eq 0 ] || fail "libc-mapping-core takes no arguments"',
            runner,
        )

    def test_libc_static_header_layouts_baseline_stays_c_and_cxx_only(self) -> None:
        """The aggregate records must not smuggle in a C++ runtime or exports."""
        probe_path = (
            ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_probe.c"
        )
        cxx_probe_path = (
            ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_probe.cpp"
        )
        start_path = (
            ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_start.S"
        )
        artifact_runner_path = (
            ROOT / "compat" / "x86_64" / "run_libc_header_layouts_baseline.sh"
        )
        for path in (probe_path, cxx_probe_path, start_path, artifact_runner_path):
            self.assertTrue(path.is_file(), f"missing header-layout baseline input: {path}")

        probe = probe_path.read_text(encoding="utf-8")
        cxx_probe = cxx_probe_path.read_text(encoding="utf-8")
        start = start_path.read_text(encoding="utf-8")
        artifact_runner = artifact_runner_path.read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        for header in (
            "errno.h",
            "fcntl.h",
            "netinet/in.h",
            "poll.h",
            "signal.h",
            "sys/mman.h",
            "sys/resource.h",
            "sys/select.h",
            "sys/socket.h",
            "sys/stat.h",
            "sys/sysinfo.h",
            "sys/utsname.h",
            "termios.h",
            "time.h",
            "unistd.h",
        ):
            self.assertIn(f"#include <{header}>", probe)
            self.assertIn(f"#include <{header}>", cxx_probe)
        for required in (
            "crabc_x86_64_header_layouts_baseline_cxx_probe",
            "check_observation_records",
            "check_mapping_records",
            "check_descriptor_records",
            "check_signal_and_termios_records",
            "CRABC_HEADER_LAYOUTS_BASELINE_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            'extern "C" int crabc_x86_64_header_layouts_baseline_cxx_probe',
            "check_cpp_observation",
            "check_cpp_mapping",
            "check_cpp_descriptor_and_signal",
            "__errno_location",
            "fstat",
            "clock_gettime",
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "posix_madvise",
            "mincore",
            "getrlimit",
            "poll",
            "select",
            "socketpair",
            "close",
            "sigemptyset",
            "cfmakeraw",
            "uname",
            "sysinfo",
            "getpagesize",
        ):
            self.assertIn(required, cxx_probe)
        for forbidden in (
            "#include <vector>",
            "#include <string>",
            "#include <type_traits>",
            "throw ",
            "typeid",
            "new ",
            "delete ",
            "thread_local",
            "static std::",
        ):
            self.assertNotIn(forbidden, cxx_probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_header_layouts_baseline_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "run_types_header_abi.sh",
            "run_stat_header_abi.sh",
            "run_time_header_abi.sh",
            "run_poll_header_abi.sh",
            "run_select_header_abi.sh",
            "run_fcntl_header_abi.sh",
            "run_unistd_header_abi.sh",
            "run_system_header_abi.sh",
            "run_signal_header_abi.sh",
            "run_termios_header_abi.sh",
            "run_mman_header_abi.sh",
            "run_resource_header_abi.sh",
            "run_socket_header_abi.sh",
            "-std=c++17",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
            "-fno-use-cxa-atexit",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-nostdinc++",
            "assert_cxx_c_linkage",
            "__gxx_personality_v0",
            "__cxa",
            "_Unwind_",
            "__stack_chk_fail",
            "__tls_get_addr",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "static_c_abi_exports.txt",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in (
            "__errno_location",
            "fstat",
            "clock_gettime",
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "posix_madvise",
            "mincore",
            "getrlimit",
            "poll",
            "select",
            "socketpair",
            "close",
            "sigemptyset",
            "cfmakeraw",
            "uname",
            "sysinfo",
            "getpagesize",
        ):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-header-layouts-baseline"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-header-layouts-baseline"',
            parity_ledger,
        )
        self.assertIn("run_libc_header_layouts_baseline()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_header_layouts_baseline.sh", runner
        )
        self.assertIn(
            '    libc-header-layouts-baseline)\n        [ "$#" -eq 0 ] || fail "libc-header-layouts-baseline takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_clock_nanosleep_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        clock_nanosleep = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_nanosleep.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_clock_nanosleep_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_clock_nanosleep_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_clock_nanosleep.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "clock_nanosleep.rs"]', static_root)
        self.assertIn("fn clock_nanosleep(", clock_nanosleep)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/clock_nanosleep.c",
            "clock_nanosleep=230",
            "raw_syscall::SYS_CLOCK_NANOSLEEP",
            "raw_syscall::syscall4(",
            "LINUX_ERRNO_MAX",
            "wrapping_neg",
            "positive errno",
            "__syscall_cp",
            "special-cases a relative realtime request",
            "independent of the",
        ):
            self.assertIn(required, clock_nanosleep)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "c_status(",
            "errno::set_errno",
            "fn nanosleep(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, clock_nanosleep)
        for required in (
            "#include <errno.h>",
            "#include <signal.h>",
            "#include <time.h>",
            "raw_clock_gettime",
            "raw_arm_alarm",
            "check_immediate_and_error_conventions",
            "check_relative_interruption",
            "check_absolute_interruption",
            "CRABC_CLOCK_NANOSLEEP_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_clock_nanosleep_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall clock_nanosleep e6",
            "%r10",
            "must return positive errors without touching errno TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("clock_nanosleep", static_export_names)
        self.assertIn('id = "static-c-clock-nanosleep"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-clock-nanosleep"',
            parity_ledger,
        )
        self.assertIn("run_libc_clock_nanosleep()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_clock_nanosleep.sh", runner
        )
        self.assertIn(
            '    libc-clock-nanosleep)\n        [ "$#" -eq 0 ] || fail "libc-clock-nanosleep takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_nanosleep_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        nanosleep = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "nanosleep.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_nanosleep_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_nanosleep_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_nanosleep.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "nanosleep.rs"]', static_root)
        self.assertIn("fn nanosleep(", nanosleep)
        for required in (
            "musl 1.2.6 release commit",
            "src/time/nanosleep.c",
            "nanosleep=35",
            "raw_syscall::SYS_NANOSLEEP",
            "raw_syscall::syscall2(",
            "c_status",
            "initial-TLS errno",
            "__syscall_cp",
            "cancellation",
        ):
            self.assertIn(required, nanosleep)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn sleep(",
            "fn usleep(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, nanosleep)
        for required in (
            "#include <errno.h>",
            "#include <signal.h>",
            "#include <time.h>",
            "raw_arm_alarm",
            "check_immediate_and_error_conventions",
            "check_relative_interruption",
            "CRABC_NANOSLEEP_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_nanosleep_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_time_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_named_syscall nanosleep 23",
            "candidate errno does not use direct fs initial TLS",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("nanosleep", static_export_names)
        self.assertIn('id = "static-c-nanosleep"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-nanosleep"', parity_ledger
        )
        self.assertIn("run_libc_nanosleep()", runner)
        self.assertIn("/workspace/compat/x86_64/run_libc_nanosleep.sh", runner)
        self.assertIn(
            '    libc-nanosleep)\n        [ "$#" -eq 0 ] || fail "libc-nanosleep takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_descriptor_entry_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_entry = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_entry.rs"
        ).read_text(encoding="utf-8")
        header_c_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.c"
        ).read_text(encoding="utf-8")
        header_cxx_probe = (
            ROOT / "compat" / "x86_64" / "fcntl_header_abi_probe.cpp"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_entry_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT / "compat" / "x86_64" / "libc_descriptor_entry_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_descriptor_entry.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "descriptor_entry.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "fn open(",
            "fn openat(",
            "fn creat(",
            "src/fcntl/open.c",
            "src/fcntl/openat.c",
            "src/fcntl/creat.c",
            "raw_syscall::SYS_OPEN",
            "raw_syscall::SYS_OPENAT",
            "raw_syscall::SYS_FCNTL",
            "O_LARGEFILE",
            "O_TMPFILE",
            "(flags & O_TMPFILE) == O_TMPFILE",
            "F_SETFD",
            "FD_CLOEXEC",
            "c_status(result)",
            "__syscall_cp",
            "rdi/rsi/rdx/r10",
        ):
            self.assertIn(required, descriptor_entry)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "pub unsafe extern \"C\" fn fcntl",
            "fn fcntl(",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, descriptor_entry)
        for required in (
            "openat_signature",
            "creat_signature",
            "openat_signature)(int, const char *, int, ...)",
            "creat_signature)(const char *, mode_t)",
        ):
            self.assertIn(required, header_c_probe)
        for required in (
            "openat_function",
            "creat_function",
            "decltype(&openat)",
            "decltype(&creat)",
        ):
            self.assertIn(required, header_cxx_probe)
        for required in (
            "#include <fcntl.h>",
            "raw_fcntl",
            "check_open_without_mode",
            "check_open_create_cloexec",
            "check_openat_relative_create",
            "check_creat_truncates",
            "O_CLOEXEC",
            "F_GETFD",
            "CRABC_DESCRIPTOR_ENTRY_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_descriptor_entry_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_fcntl_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_open_syscall",
            "assert_named_syscall openat 101",
            "assert_open_cloexec_fixup",
            "%r10",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for symbol in ("open", "openat", "creat"):
            self.assertIn(symbol, static_export_names)
        self.assertIn('id = "static-c-descriptor-entry"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-descriptor-entry"',
            parity_ledger,
        )
        self.assertIn("run_libc_descriptor_entry()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_descriptor_entry.sh", runner
        )
        self.assertIn(
            '    libc-descriptor-entry)\n        [ "$#" -eq 0 ] || fail "libc-descriptor-entry takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_fcntl_status_control_artifact_stays_narrow(
        self,
    ) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        descriptor_control = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_control.rs"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT
            / "compat"
            / "x86_64"
            / "libc_fcntl_status_control_probe.c"
        ).read_text(encoding="utf-8")
        start = (
            ROOT
            / "compat"
            / "x86_64"
            / "libc_fcntl_status_control_start.S"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT
            / "compat"
            / "x86_64"
            / "run_libc_fcntl_status_control.sh"
        ).read_text(encoding="utf-8")
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn('#[path = "descriptor_control.rs"]', static_root)
        for required in (
            "musl 1.2.6 release commit",
            "src/fcntl/fcntl.c",
            "global_asm!",
            "fcntl_no_argument",
            "fcntl_scalar",
            "fcntl_unsupported",
            "raw_syscall::SYS_FCNTL",
            "F_GETFD",
            "F_SETFD",
            "F_GETFL",
            "F_SETFL",
            "O_LARGEFILE",
            "if command == F_SETFL",
            "EINVAL",
            "rdi/rsi/rdx",
        ):
            self.assertIn(required, descriptor_control)
        for forbidden in (
            "pub unsafe extern \"C\" fn fcntl",
            "__tls_get_addr",
            "pthread_",
        ):
            self.assertNotIn(forbidden, descriptor_control)
        for required in (
            "#include <fcntl.h>",
            "check_descriptor_flags",
            "check_status_flags",
            "check_unsupported_commands",
            "F_GETOWN",
            "CRABC_FCNTL_STATUS_CONTROL_FREESTANDING",
            "raw_syscall3",
            "SYS_open",
            "SYS_dup",
            "SYS_close",
            "fcntl(duplicate, F_GETFD) != FD_CLOEXEC",
        ):
            self.assertIn(required, probe)
        for required in (
            "ARCH_SET_FS",
            "mov %rsi, %fs:0",
            "crabc_x86_64_fcntl_status_control_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "static_c_abi_exports.txt",
            "run_fcntl_header_abi.sh",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "R_X86_64_TPOFF",
            "assert_fcntl_no_argument_path",
            "assert_fcntl_scalar_path",
            "assert_fcntl_unsupported_path",
            "assert_fixture_tls_capacity",
            "INITIAL_TLS_BYTES",
            "INITIAL_TLS_ALIGNMENT",
            "unexpectedly pulls",
            "O_LARGEFILE",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        self.assertIn("fcntl", static_export_names)
        self.assertIn('id = "static-c-fcntl-status-control"', parity_ledger)
        self.assertIn(
            'command = "./scripts/dev-x86_64.sh libc-fcntl-status-control"',
            parity_ledger,
        )
        self.assertIn("run_libc_fcntl_status_control()", runner)
        self.assertIn(
            "/workspace/compat/x86_64/run_libc_fcntl_status_control.sh", runner
        )
        self.assertIn(
            '    libc-fcntl-status-control)\n        [ "$#" -eq 0 ] || fail "libc-fcntl-status-control takes no arguments"',
            runner,
        )

    def test_libc_static_c_abi_ffs_artifact_stays_narrow(self) -> None:
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        ffs = (ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ffs.rs").read_text(
            encoding="utf-8"
        )
        strings_header = (ROOT / "include" / "strings.h").read_text(encoding="utf-8")
        probe = (ROOT / "compat" / "x86_64" / "libc_ffs_probe.c").read_text(
            encoding="utf-8"
        )
        artifact_runner = (ROOT / "compat" / "x86_64" / "run_libc_ffs.sh").read_text(
            encoding="utf-8"
        )
        header_runner = (ROOT / "compat" / "x86_64" / "run_ffs_header_abi.sh").read_text(
            encoding="utf-8"
        )
        static_exports = (
            ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
        ).read_text(encoding="utf-8")
        static_export_names = {
            line for line in static_exports.splitlines() if line and not line.startswith("#")
        }
        parity_ledger = (ROOT / "compat" / "x86_64" / "parity.toml").read_text(
            encoding="utf-8"
        )
        runner = RUNNER.read_text(encoding="utf-8")

        symbols = ("ffs", "ffsl", "ffsll")
        self.assertIn('#[path = "ffs.rs"]', static_root)
        for symbol in symbols:
            self.assertIn(f"fn {symbol}(", ffs)
            self.assertIn(symbol, static_export_names)
        for required in (
            "musl 1.2.6 release commit",
            "src/misc/ffs.c",
            "src/misc/ffsl.c",
            "src/misc/ffsll.c",
            "src/internal/atomic.h",
            "stateless",
            "allocation-free",
            "trailing_zeros",
            "two's-complement",
        ):
            self.assertIn(required, ffs)
        for forbidden in (
            "crabc_core",
            "crabc_mimalloc",
            "fn malloc(",
            "fn strtol(",
            "__tls_get_addr",
            "fn fls(",
        ):
            self.assertNotIn(forbidden, ffs)
        for required in (
            "#include <strings.h>",
            "ffs_fn",
            "ffsl_fn",
            "ffsll_fn",
            "first_set_u32",
            "first_set_u64",
            "-2147483647",
            "CRABC_FFS_FREESTANDING",
        ):
            self.assertIn(required, probe)
        for required in (
            "static_c_abi_exports.txt",
            "-nostdlib -static",
            "-Wl,-e,_start",
            "-Wl,--no-undefined",
            "candidate retains TLS",
            "strncasecmp",
            "strings.h",
        ):
            self.assertIn(required, artifact_runner)
        self.assertNotIn("--whole-archive", artifact_runner)
        for required in (
            "CRABC_EXPECT_FFS",
            "CRABC_REQUIRE_FFS_HIDDEN",
            "-U_GNU_SOURCE",
            "-std=c++17",
            "nm --undefined-only",
            "strings.h",
        ):
            self.assertIn(required, header_runner)
        self.assertIn('extern "C" {', strings_header)
        self.assertIn('id = "static-c-ffs"', parity_ledger)
        self.assertIn('command = "./scripts/dev-x86_64.sh libc-ffs"', parity_ledger)
        self.assertIn("libc-ffs", runner)

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

    def test_advanced_time_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "advanced-time-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 4)
            core_arguments, facade_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            core_cargo_index = core_arguments.index("cargo")
            self.assertEqual(
                core_arguments[core_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-core",
                    "--lib",
                    "--no-default-features",
                    "x86_64_posix_timer_writes_exact_id_and_old_setting_records",
                    "--",
                    "--test-threads=1",
                ],
            )

            facade_cargo_index = facade_arguments.index("cargo")
            self.assertEqual(
                facade_arguments[facade_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_advanced_time",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "time_dynamic_direct_probe",
                    "--example",
                    "process_clock_id_direct_probe",
                    "--example",
                    "time_settime_direct_probe",
                    "--example",
                    "time_timers_direct_probe",
                ],
            )
            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_advanced_time_reference.sh",
                ],
            )

    def test_mapping_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "mapping-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_memory_mapping",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "mapping_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_mapping_reference.sh",
                ],
            )

    def test_memory_vm_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "memory-vm-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_memory_vm",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "memory_vm_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_memory_vm_reference.sh",
                ],
            )

    def test_pty_basic_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "pty-basic-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 4)
            test_arguments, alloc_test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_pty_basic",
                    "--",
                    "--test-threads=1",
                ],
            )

            alloc_test_cargo_index = alloc_test_arguments.index("cargo")
            self.assertEqual(
                alloc_test_arguments[alloc_test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--test",
                    "x86_64_pty_basic",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "pty_basic_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_pty_basic_reference.sh",
                ],
            )

    def test_terminal_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "terminal-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 4)
            test_arguments, alloc_test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
                    "-p", "crabc-rs", "--no-default-features", "--test", "x86_64_terminal",
                    "--", "--test-threads=1",
                ],
            )
            alloc_test_cargo_index = alloc_test_arguments.index("cargo")
            self.assertEqual(
                alloc_test_arguments[alloc_test_cargo_index:],
                [
                    "cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
                    "-p", "crabc-rs", "--no-default-features", "--features", "alloc",
                    "--test", "x86_64_terminal", "--", "--test-threads=1",
                ],
            )
            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo", "build", "--locked", "--target", "x86_64-unknown-linux-musl",
                    "-p", "crabc-rs", "--no-default-features", "--example",
                    "x86_64_terminal_direct_probe",
                ],
            )
            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                ["bash", "/workspace/compat/x86_64/run_x86_terminal_reference.sh"],
            )

    def test_mount_reference_uses_the_native_amd64_container_and_unprivileged_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "mount-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                self.assertNotIn("--cap-add=SYS_ADMIN", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_mount",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "mount_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_mount_reference.sh",
                ],
            )

    def test_thread_kill_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "thread-kill-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_thread_kill",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--example",
                    "thread_kill_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_thread_kill_reference.sh",
                ],
            )

    def test_users_databases_reference_uses_the_native_amd64_container_and_focused_scope(
        self,
    ) -> None:
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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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
                ["bash", str(RUNNER), "users-databases-reference"],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 3)
            test_arguments, probe_arguments, oracle_arguments = invocations
            for arguments in invocations:
                self.assertIn("--platform", arguments)
                self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
                platform_index = arguments.index("--platform")
                self.assertEqual(arguments[platform_index + 1], "linux/amd64")

            test_cargo_index = test_arguments.index("cargo")
            self.assertEqual(
                test_arguments[test_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--test",
                    "x86_64_users_databases",
                    "--",
                    "--test-threads=1",
                ],
            )

            probe_cargo_index = probe_arguments.index("cargo")
            self.assertEqual(
                probe_arguments[probe_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--example",
                    "users_databases_direct_probe",
                ],
            )

            oracle_bash_index = oracle_arguments.index("bash")
            self.assertEqual(
                oracle_arguments[oracle_bash_index:],
                [
                    "bash",
                    "/workspace/compat/x86_64/run_x86_users_databases_reference.sh",
                ],
            )

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
                "  {\n"
                "    printf '%s\\0' \"$@\"\n"
                "    printf '\\0'\n"
                "  } >> \"${FAKE_DOCKER_ARGS:?}\"\n"
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

            invocations = [
                [
                    argument.decode("utf-8")
                    for argument in invocation.split(bytes((0,)))
                    if argument
                ]
                for invocation in capture.read_bytes().split(bytes((0, 0)))
                if invocation
            ]
            self.assertEqual(len(invocations), 7)
            (
                arguments,
                fnmatch_build_arguments,
                fnmatch_verifier_arguments,
                chroot_arguments,
                allocation_arguments,
                glob_build_arguments,
                glob_verifier_arguments,
            ) = invocations
            self.assertIn("--platform", arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", arguments)
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
                    "x86_64_fnmatch",
                    "--test",
                    "x86_64_memory_mapping",
                    "--test",
                    "x86_64_memory_vm",
                    "--test",
                    "x86_64_pty_basic",
                    "--test",
                    "x86_64_terminal",
                    "--test",
                    "x86_64_mount",
                    "--test",
                    "x86_64_epoll",
                    "--test",
                    "x86_64_eventfd",
                    "--test",
                    "x86_64_fcntl_getlk",
                    "--test",
                    "x86_64_fcntl_flags",
                    "--test",
                    "x86_64_flock",
                    "--test",
                    "x86_64_sendfile",
                    "--test",
                    "x86_64_copy_file_range",
                    "--test",
                    "x86_64_fs",
                    "--test",
                    "x86_64_fs_capacity",
                    "--test",
                    "x86_64_fs_advice",
                    "--test",
                    "x86_64_file_position",
                    "--test",
                    "x86_64_sync",
                    "--test",
                    "x86_64_syncfs",
                    "--test",
                    "x86_64_sync_file_range",
                    "--test",
                    "x86_64_ftruncate",
                    "--test",
                    "x86_64_futimens",
                    "--test",
                    "x86_64_timestamp_paths",
                    "--test",
                    "x86_64_path_lifecycle",
                    "--test",
                    "x86_64_namespace",
                    "--test",
                    "x86_64_xattr",
                    "--test",
                    "x86_64_raw_directory",
                    "--test",
                    "x86_64_directory",
                    "--test",
                    "x86_64_directory_position",
                    "--test",
                    "x86_64_temporary_objects",
                    "--test",
                    "x86_64_statx",
                    "--test",
                    "x86_64_canonicalize",
                    "--test",
                    "x86_64_cwd_mutation",
                    "--test",
                    "x86_64_ipc",
                    "--test",
                    "x86_64_shm",
                    "--test",
                    "x86_64_inotify",
                    "--test",
                    "x86_64_socket_transport",
                    "--test",
                    "x86_64_posix_fallocate",
                    "--test",
                    "x86_64_fallocate",
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
                    "x86_64_rlimit_targeted",
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
                    "x86_64_access",
                    "--test",
                    "x86_64_getcwd",
                    "--test",
                    "x86_64_current_dir_name",
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
                    "x86_64_thread_kill",
                    "--test",
                    "x86_64_thread_credentials",
                    "--test",
                    "x86_64_time",
                    "--test",
                    "time",
                    "--test",
                    "calendar_utc",
                    "--test",
                    "x86_64_calendar_time",
                    "--test",
                    "x86_64_advanced_time",
                    "--test",
                    "x86_64_timerfd",
                    "--test",
                    "x86_64_times",
                    "--",
                    "--test-threads=1",
                ],
            )
            self.assertIn("--platform", fnmatch_build_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", fnmatch_build_arguments)
            fnmatch_build_platform_index = fnmatch_build_arguments.index("--platform")
            self.assertEqual(
                fnmatch_build_arguments[fnmatch_build_platform_index + 1],
                "linux/amd64",
            )
            fnmatch_build_cargo_index = fnmatch_build_arguments.index("cargo")
            self.assertEqual(
                fnmatch_build_arguments[fnmatch_build_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--release",
                    "--example",
                    "fnmatch_direct_probe",
                ],
            )
            self.assertIn("--platform", fnmatch_verifier_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", fnmatch_verifier_arguments)
            fnmatch_verifier_platform_index = fnmatch_verifier_arguments.index("--platform")
            self.assertEqual(
                fnmatch_verifier_arguments[fnmatch_verifier_platform_index + 1],
                "linux/amd64",
            )
            fnmatch_verifier_bash_index = fnmatch_verifier_arguments.index("bash")
            self.assertEqual(
                fnmatch_verifier_arguments[fnmatch_verifier_bash_index:],
                ["bash", "/workspace/compat/x86_64/verify_fnmatch_direct.sh"],
            )
            self.assertIn('--cap-add=SYS_CHROOT', chroot_arguments)
            self.assertIn("--platform", chroot_arguments)
            chroot_platform_index = chroot_arguments.index("--platform")
            self.assertEqual(
                chroot_arguments[chroot_platform_index + 1],
                "linux/amd64",
            )
            chroot_cargo_index = chroot_arguments.index("cargo")
            self.assertEqual(
                chroot_arguments[chroot_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--test",
                    "x86_64_chroot",
                    "--",
                    "--test-threads=1",
                ],
            )
            self.assertIn("--platform", allocation_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", allocation_arguments)
            allocation_platform_index = allocation_arguments.index("--platform")
            self.assertEqual(
                allocation_arguments[allocation_platform_index + 1],
                "linux/amd64",
            )
            allocation_cargo_index = allocation_arguments.index("cargo")
            self.assertEqual(
                allocation_arguments[allocation_cargo_index:],
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--test",
                    "timezone_rules",
                    "--test",
                    "calendar_local",
                    "--test",
                    "x86_64_glob",
                    "--test",
                    "x86_64_child_ownership",
                    "--test",
                    "x86_64_pty_basic",
                    "--test",
                    "x86_64_terminal",
                    "--test",
                    "x86_64_users_databases",
                    "--",
                    "--test-threads=1",
                ],
            )
            self.assertIn("--platform", glob_build_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", glob_build_arguments)
            glob_build_platform_index = glob_build_arguments.index("--platform")
            self.assertEqual(
                glob_build_arguments[glob_build_platform_index + 1], "linux/amd64"
            )
            glob_build_cargo_index = glob_build_arguments.index("cargo")
            self.assertEqual(
                glob_build_arguments[glob_build_cargo_index:],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--target",
                    "x86_64-unknown-linux-musl",
                    "-p",
                    "crabc-rs",
                    "--no-default-features",
                    "--features",
                    "alloc",
                    "--release",
                    "--example",
                    "glob_direct_probe",
                ],
            )
            self.assertIn("--platform", glob_verifier_arguments)
            self.assertNotIn("--cap-add=SYS_CHROOT", glob_verifier_arguments)
            glob_verifier_platform_index = glob_verifier_arguments.index("--platform")
            self.assertEqual(
                glob_verifier_arguments[glob_verifier_platform_index + 1], "linux/amd64"
            )
            glob_verifier_bash_index = glob_verifier_arguments.index("bash")
            self.assertEqual(
                glob_verifier_arguments[glob_verifier_bash_index:],
                ["bash", "/workspace/compat/x86_64/verify_glob_direct.sh"],
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

    def test_facade_keeps_native_pattern_archives_checked(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        fnmatch_verifier = (
            ROOT / "compat" / "x86_64" / "verify_fnmatch_direct.sh"
        ).read_text(encoding="utf-8")
        glob_verifier = (
            ROOT / "compat" / "x86_64" / "verify_glob_direct.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("--test x86_64_fnmatch", source)
        self.assertIn("--release --example fnmatch_direct_probe", source)
        self.assertIn("compat/x86_64/verify_fnmatch_direct.sh", source)
        self.assertIn("allocation-free matcher", source)
        self.assertIn("--test x86_64_glob", source)
        self.assertIn("--features alloc --release --example glob_direct_probe", source)
        self.assertIn("compat/x86_64/verify_glob_direct.sh", source)
        self.assertIn("fixed Rust allocator", source)
        for required in (
            "Advanced Micro Devices X86-64",
            "crabc_rs_fnmatch_direct_probe",
            "fnmatch __errno_location malloc calloc realloc free",
            "readelf",
            "nm",
        ):
            self.assertIn(required, fnmatch_verifier)
        for required in (
            "Advanced Micro Devices X86-64",
            "crabc_rs_glob_direct_probe",
            "glob globfree fnmatch",
            "opendir readdir readdir64 closedir scandir",
            "__errno_location",
            "malloc calloc realloc reallocarray free",
            "readelf",
            "nm",
        ):
            self.assertIn(required, glob_verifier)


if __name__ == "__main__":
    unittest.main()
