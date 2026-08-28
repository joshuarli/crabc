#!/usr/bin/env python3
"""Reject repository-shape regressions that normal compilation cannot see."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".md", ".py", ".rs", ".sh", ".toml", ".yml", ".yaml"}
PRODUCTION_SOURCE = (
    ROOT / "libc" / "src",
    ROOT / "ldso" / "src",
    ROOT / "crabc-core" / "src",
    ROOT / "crabc-mimalloc" / "src",
    ROOT / "crabc-rs" / "src",
)
HISTORICAL_OR_TASK_SOURCES = {Path("cleanup.md")}
X86_ARCH_BRANCH = re.compile(r'target_arch\s*=\s*"x86_64"')
RISC_V_ARCH_BRANCH = re.compile(r'target_arch\s*=\s*"riscv64"')
# The staged native x86-64 runtime program begins with small, explicit core
# direct-facade, and source-only relocation foundations. Keep each list
# specific: later x86 libc, loader, CRT, or facade work must add its own
# reviewed source boundary rather than inheriting a directory-wide exception.
X86_RUNTIME_FOUNDATION_CORE_SOURCES = {
    Path("crabc-core/src/fenv_x86_64.rs"),
    Path("crabc-core/src/event_x86_64.rs"),
    Path("crabc-core/src/lib.rs"),
    Path("crabc-core/src/mm_x86_64.rs"),
    Path("crabc-core/src/signal_x86_64.rs"),
    Path("crabc-core/src/system_x86_64.rs"),
    Path("crabc-core/src/tests.rs"),
    Path("crabc-core/src/time_x86_64.rs"),
    Path("crabc-core/src/thread.rs"),
    Path("crabc-core/src/vdso.rs"),
}
# This facade admission is deliberately narrower than a general x86 target:
# `lib.rs` exposes only target-record-independent families, `signal.rs` owns
# the separately-proved x86 kernel signal records and restorer,
# `event_x86_64.rs` owns the scalar event-counter, exact `pollfd` record seam,
# direct select/pselect descriptor-bit-vector seam, and packed `epoll_event`
# readiness with temporary signal masks. `fs_x86_64.rs`
# owns descriptor `fstat`, direct access/accessat permission observation,
# private CWD/statat path metadata, caller-buffer-only readlinkat, plus
# file-access advice and readahead, and direct bounded anonymous memory-file/
# seal operations.
# `process_x86_64.rs` owns caller-buffer and alloc-gated `getcwd`
# observations; CWD mutation remains deferred. It also owns read-only identity/session and
# supplementary-group query/fill plus proved calling-task filesystem-credential
# query/current-effective-ID requests, calling-process resource-limit
# query/mutation plus direct read-only targeted resource-limit query, typed
# resource usage/process accounting, getpriority/scheduler-priority observations plus typed
# scheduling-priority mutation, and record-lock observations, and the
# explicitly proved process-global umask exchange
# without admitting pathname creation,
# `pipe.rs` owns the proved target-specific O_DIRECT packet-mode constant,
# `mm_x86_64.rs` owns the closed mmap/mprotect/munmap/memory-locking,
# mapping-synchronization, advice, and residency set,
# `system_x86_64.rs` owns uname/sysinfo records, `thread_x86_64.rs` owns
# three record-independent task observations, borrowed-atomic futex wait/wake,
# the direct read-only round-robin interval and bounded CPU-affinity
# observation/mutation operations,
# and `time_x86_64.rs` owns the separately proved clock-query, relative and
# direct clock-nanosleep seams, direct interval-timer query/control plus the
# bounded real-timer aliases, and timerfd seams. No other facade
# source inherits this exception.
X86_RUNTIME_FOUNDATION_FACADE_SOURCES = {
    Path("crabc-rs/src/event_x86_64.rs"),
    Path("crabc-rs/src/eventfd.rs"),
    Path("crabc-rs/src/fs_x86_64.rs"),
    Path("crabc-rs/src/lib.rs"),
    Path("crabc-rs/src/mm_x86_64.rs"),
    Path("crabc-rs/src/pipe.rs"),
    Path("crabc-rs/src/process_x86_64.rs"),
    Path("crabc-rs/src/signal.rs"),
    Path("crabc-rs/src/system_x86_64.rs"),
    Path("crabc-rs/src/time_x86_64.rs"),
    Path("crabc-rs/src/thread_x86_64.rs"),
}
# This source-only loader foundation has no `crabc-ldso` integration or public
# interpreter boundary. The image parser validates file-facing metadata before
# the relative-relocation leaf consumes it; both are listed independently so a
# later loader slice cannot inherit an artifact-wide x86 exception.
X86_RUNTIME_FOUNDATION_LDSO_SOURCES = {
    Path("ldso/src/x86_64_image.rs"),
    Path("ldso/src/x86_64_relocation.rs"),
}
# These source-only leaves are compiled only by their dedicated native probes.
# They do not select crabc-libc or make the AArch64 C-ABI composition root an
# x86 target; keeping exact file boundaries makes any later libc admission a
# deliberate review decision.
X86_RUNTIME_FOUNDATION_LIBC_SOURCES = {
    Path("libc/src/c_abi/x86_64/atomic.rs"),
    Path("libc/src/c_abi/x86_64/clone.rs"),
    Path("libc/src/c_abi/x86_64/fenv.rs"),
    Path("libc/src/c_abi/x86_64/foundation.rs"),
    Path("libc/src/c_abi/x86_64/memory.rs"),
    Path("libc/src/c_abi/x86_64/setjmp.rs"),
    Path("libc/src/c_abi/x86_64/signal_foundation.rs"),
    Path("libc/src/c_abi/x86_64/thread_pointer.rs"),
}
# The fixed-mimalloc evidence lane remains a separate, private program. Its
# historical feature is retained for compatibility but no longer governs the
# explicitly admitted shared-core foundation above.
X86_ALLOCATOR_EVIDENCE_CORE_SOURCES = {
    Path("crabc-core/src/lib.rs"),
    Path("crabc-core/src/thread.rs"),
}
X86_ALLOCATOR_EVIDENCE_MIMALLOC_SOURCES = {
    Path("crabc-mimalloc/src/abandoned.rs"),
    Path("crabc-mimalloc/src/config.rs"),
    Path("crabc-mimalloc/src/dynamic_theap.rs"),
    Path("crabc-mimalloc/src/lib.rs"),
    Path("crabc-mimalloc/src/main_heap_page.rs"),
    Path("crabc-mimalloc/src/os.rs"),
    Path("crabc-mimalloc/src/os_host_model.rs"),
    Path("crabc-mimalloc/src/os_page.rs"),
    Path("crabc-mimalloc/src/remote_free.rs"),
    Path("crabc-mimalloc/src/single_thread.rs"),
}
INLINE_CORE_MODULE = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+\w+\s*\{")
REMOVED_ROOT_LOADER = re.compile(r"src/loader_core\.rs|root[- ]loader|loader helper", re.IGNORECASE)
LIBC_C_ABI_MODULES = (
    "break_exports",
    "daemon",
    "dn_expand",
    "fanotify_exports",
    "fenv",
    "file_handle_exports",
    "init_fini_exports",
    "integer_numeric_exports",
    "ioctl_exports",
    "legacy_des_exports",
    "lrand48",
    "pthread_atfork",
    "ptrace_exports",
    "quick_exit_exports",
    "random_exports",
    "scalar_exports",
    "select_exports",
    "semtimedop_exports",
    "statvfs",
    "strverscmp",
    "syscall",
    "time_extensions_exports",
)
# These fixtures are the deliberately retained pinned-musl *oracle* side of
# differential tests. Every other root C-runtime fixture must name
# `test_support::crabc_cc()` directly; keeping the exception set here makes a
# new borrowed-CRT test path visible in the ordinary structure gate.
MUSL_ORACLE_C_TESTS = frozenset(
    {
        "aarch64_abi_layout.rs",
        "aarch64_network_headers.rs",
        "header_surface.rs",
        "cxa_finalize.rs",
        "dynamic_tls_dependency.rs",
        "fdopen_lifecycle.rs",
        "gettimeofday_regression.rs",
        "ldso_dlsym_error.rs",
        "ldso_kernel_main_mapping.rs",
        "ldso_main_self_dlopen.rs",
        "ldso_no_relro_relocation.rs",
        "memchr_regression.rs",
        "memcpy_memset_regression.rs",
        "memmem_regression.rs",
        "pthread_create_join_tls_regression.rs",
        "pthread_mutex_cond_ping_pong_regression.rs",
        "pthread_mutex_contention_regression.rs",
        "pthread_mutex_uncontended_regression.rs",
        "stdio_format_parse_regression.rs",
        "strlen_regression.rs",
        "strstr_regression.rs",
        "tls_growth_regression.rs",
    }
)
NAKED_LOADER_TESTS = frozenset({"ldso_deps.rs", "ldso_interp.rs", "ldso_tls.rs"})


def text_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if any(part in {".git", "target", "compat/reports"} for part in relative.parts):
            continue
        files.append(path)
    return files


def report_matches(
    errors: list[str], pattern: re.Pattern[str] | str, files: list[Path], message: str
) -> None:
    matcher = re.compile(pattern) if isinstance(pattern, str) else pattern
    for path in files:
        relative = path.relative_to(ROOT)
        if (
            relative.parts[:2] == ("docs", "history")
            or relative in HISTORICAL_OR_TASK_SOURCES
            or relative == Path("scripts/check_structure.py")
        ):
            continue
        for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            if matcher.search(line):
                errors.append(f"{relative}:{line_number}: {message}")


def check_root_c_link_boundaries(errors: list[str]) -> None:
    """Keep C-runtime candidate fixtures on the explicit owned driver path."""

    test_root = ROOT / "tests"
    for path in sorted(test_root.glob("*.rs")):
        text = path.read_text(errors="replace")
        relative = path.relative_to(ROOT)
        uses_musl_driver = 'Command::new("musl-gcc")' in text
        if uses_musl_driver and path.name not in MUSL_ORACLE_C_TESTS:
            errors.append(
                f"{relative}: musl-gcc is reserved for the explicit musl oracle side; "
                "crabc candidates must use test_support::crabc_cc()"
            )
        if "dynamic-linker" in text and path.name not in NAKED_LOADER_TESTS:
            errors.append(
                f"{relative}: crabc candidate fixture overrides the owned canonical interpreter"
            )
    for name in NAKED_LOADER_TESTS:
        path = test_root / name
        text = path.read_text(errors="replace")
        if "test_support::naked_aarch64_command()" not in text:
            errors.append(f"tests/{name}: naked loader probe must use the explicit raw-Clang boundary")
        if '"-nostdlib"' not in text:
            errors.append(f"tests/{name}: naked loader probe must remain no-libc")
        if '"-Wl,--dynamic-linker,/lib/ld-crabc-aarch64.so.1"' not in text:
            errors.append(f"tests/{name}: naked loader probe must name the canonical crabc interpreter")


def is_authorized_x86_branch(relative: Path, line: str) -> bool:
    """Return whether one exact production x86 cfg has a reviewed boundary.

    The staged core, direct-facade, and source-only loader foundations are
    intentionally target-specific and do not establish public runtime support.
    The separate allocator lane retains its narrow source-file allowlist. A
    new x86 cfg elsewhere must be added deliberately with its vertical slice.
    """

    if relative in X86_RUNTIME_FOUNDATION_CORE_SOURCES:
        return True
    if relative in X86_RUNTIME_FOUNDATION_FACADE_SOURCES:
        return True
    if relative in X86_RUNTIME_FOUNDATION_LDSO_SOURCES:
        return True
    if relative in X86_RUNTIME_FOUNDATION_LIBC_SOURCES:
        return True
    if relative in X86_ALLOCATOR_EVIDENCE_CORE_SOURCES:
        return 'feature = "allocator-x86-evidence"' in line
    return relative in X86_ALLOCATOR_EVIDENCE_MIMALLOC_SOURCES


def check_x86_getcwd_boundary(errors: list[str]) -> None:
    """Keep the direct x86 getcwd slice alloc-gated and read-only."""

    process_source = ROOT / "crabc-rs" / "src" / "process_x86_64.rs"
    text = process_source.read_text(errors="replace")
    if "pub fn getcwd<" not in text:
        errors.append("crabc-rs/src/process_x86_64.rs: direct x86 getcwd slice is missing")
    if '#[cfg(feature = "alloc")]\n#[inline]\npub fn getcwd_alloc<' not in text:
        errors.append(
            "crabc-rs/src/process_x86_64.rs: direct x86 getcwd_alloc must remain alloc-gated"
        )
    for forbidden in ("pub fn chdir", "pub fn fchdir"):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: direct x86 getcwd slice must defer "
                f"{forbidden}"
            )


def check_x86_rr_interval_boundary(errors: list[str]) -> None:
    """Keep the direct x86 scheduler interval slice read-only."""

    thread_source = ROOT / "crabc-rs" / "src" / "thread_x86_64.rs"
    text = thread_source.read_text(errors="replace")
    if "pub fn sched_rr_get_interval" not in text:
        errors.append("crabc-rs/src/thread_x86_64.rs: direct RR interval slice is missing")
    for forbidden in (
        "pub fn sched_setscheduler",
        "pub fn sched_getscheduler",
        "pub fn sched_setparam",
        "pub fn sched_getparam",
        "pub fn sched_getattr",
        "pub fn sched_setattr",
    ):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/thread_x86_64.rs: direct RR interval slice must defer "
                f"{forbidden}"
            )


def check_x86_sched_affinity_boundary(errors: list[str]) -> None:
    """Keep direct x86 affinity operations bounded."""

    thread_source = ROOT / "crabc-rs" / "src" / "thread_x86_64.rs"
    text = thread_source.read_text(errors="replace")
    for required in ("pub fn sched_getaffinity", "pub fn sched_setaffinity"):
        if required not in text:
            errors.append(
                "crabc-rs/src/thread_x86_64.rs: direct affinity boundary is missing "
                f"{required}"
            )
    for forbidden in (
        "pub fn sched_setscheduler",
        "pub fn sched_getscheduler",
        "pub fn sched_setparam",
        "pub fn sched_getparam",
        "pub fn sched_getattr",
        "pub fn sched_setattr",
    ):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/thread_x86_64.rs: direct affinity boundary must defer "
                f"{forbidden}"
            )


def check_x86_futex_boundary(errors: list[str]) -> None:
    """Keep the direct x86 futex facade to borrowed wait/wake operations."""

    thread_source = ROOT / "crabc-rs" / "src" / "thread_x86_64.rs"
    text = thread_source.read_text(errors="replace")
    for required in ("pub mod futex", "pub fn wait(", "pub fn wake("):
        if required not in text:
            errors.append(
                "crabc-rs/src/thread_x86_64.rs: direct x86 futex slice is missing "
                f"{required}"
            )
    for forbidden in (
        "pub fn waitv",
        "pub fn requeue",
        "pub fn cmp_requeue",
        "pub fn lock_pi",
        "pub fn unlock_pi",
        "pub fn fd",
    ):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/thread_x86_64.rs: direct x86 futex slice must defer "
                f"{forbidden}"
            )


def check_x86_clock_nanosleep_boundary(errors: list[str]) -> None:
    """Keep the direct x86 clock-sleep slice bounded."""

    time_source = ROOT / "crabc-rs" / "src" / "time_x86_64.rs"
    text = time_source.read_text(errors="replace")
    for required in (
        "pub fn clock_nanosleep_relative",
        "pub fn clock_nanosleep_absolute",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: direct clock-sleep slice is missing "
                f"{required}"
            )
    for forbidden in ("pub fn clock_settime", "pub fn clock_adjtime"):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: direct clock-sleep slice must defer "
                f"{forbidden}"
            )


def check_x86_setitimer_boundary(errors: list[str]) -> None:
    """Keep the admitted x86 process interval-timer API closed and explicit."""

    time_source = ROOT / "crabc-rs" / "src" / "time_x86_64.rs"
    text = time_source.read_text(errors="replace")
    for required in ("pub const fn new", "pub fn setitimer", "pub fn alarm", "pub fn ualarm"):
        if required not in text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: admitted x86 interval-timer-control slice is missing "
                f"{required}"
            )
    for forbidden in ("pub struct PosixTimer",):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: admitted x86 interval-timer-control slice must defer "
                f"{forbidden}"
            )


def check_x86_access_boundary(errors: list[str]) -> None:
    """Keep the admitted x86 access slice flag-specific and read-only."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    for required in (
        "pub struct Access:",
        "pub struct AccessAtFlags:",
        "pub fn access<",
        "pub fn accessat<",
        "const EACCESS",
        "const SYMLINK_NOFOLLOW",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 access slice is missing "
                f"{required}"
            )

    stat_flags = re.search(
        r"pub struct AtFlags: u32 \{(?P<body>.*?)^    \}", text, re.MULTILINE | re.DOTALL
    )
    if stat_flags is None:
        errors.append("crabc-rs/src/fs_x86_64.rs: private x86 statat flags are missing")
    elif "const EACCESS" in stat_flags.group("body"):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: private x86 statat flags must not inherit "
            "the access-only EACCESS bit"
        )

    for forbidden in ("pub fn euidaccess", "pub fn eaccess"):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 access slice must defer "
                f"{forbidden}"
            )


def check_x86_fcntl_status_flags_boundary(errors: list[str]) -> None:
    """Keep direct x86 status flags narrower than pathname or generic fcntl APIs."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    for required in (
        "pub struct OFlags: u32",
        "pub fn fcntl_getfl<",
        "pub fn fcntl_setfl<",
        "const ACCMODE = 0x0020_0003",
        "const RWMODE = 0x0000_0003",
        "const NONBLOCK = 0x0000_0800",
        "const DIRECT = 0x0000_4000",
        "const NOATIME = 0x0004_0000",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 fcntl status-flag slice "
                f"is missing {required}"
            )

    for forbidden in (
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+open(?:<|\s*\()",
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+openat(?:<|\s*\()",
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+fcntl(?:<|\s*\()",
    ):
        if re.search(forbidden, text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 fcntl status-flag slice "
                "must defer pathname opening and generic fcntl"
            )


def check_x86_flock_boundary(errors: list[str]) -> None:
    """Keep direct x86 flock separate from fcntl record locking."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub enum FlockOperation {",
        "LockShared = 1",
        "LockExclusive = 2",
        "Unlock = 8",
        "NonBlockingLockShared = 1 | 4",
        "NonBlockingLockExclusive = 2 | 4",
        "NonBlockingUnlock = 8 | 4",
        "pub fn flock<Fd: AsFd>(fd: Fd, operation: FlockOperation) -> Result<()>",
        "crabc_core::fs::flock(fd.as_fd().as_raw_fd(), operation as u32)",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 flock slice is missing "
                f"{required}"
            )

    if re.search(r"(?m)^pub\s+(?:unsafe\s+)?fn\s+fcntl_lock(?:<|\s*\()", fs_text):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: admitted x86 flock slice must defer "
            "fcntl record-lock mutation"
        )

    core_fs_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_fs_text = core_fs_source.read_text(errors="replace")
    for required in (
        "pub fn flock(fd: RawFd, operation: u32) -> Result<()>",
        "syscall2(SYS_FLOCK, fd as usize, operation as usize)",
    ):
        if required not in core_fs_text:
            errors.append(
                "crabc-core/src/fs.rs: admitted x86 flock boundary is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    if "pub(crate) const SYS_FLOCK: usize = 73" not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 flock ABI proof is "
            "missing SYS_FLOCK=73"
        )


def check_x86_sendfile_boundary(errors: list[str]) -> None:
    """Keep direct x86 sendfile descriptor-only and separate from splice/path/C APIs."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub fn sendfile<",
        "offset: Option<&mut u64>",
        "i64::MAX as u64",
        "crabc_core::io::sendfile(",
        "out_fd.as_fd().as_raw_fd()",
        "in_fd.as_fd().as_raw_fd()",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 sendfile slice is missing "
                f"{required}"
            )

    for forbidden in (
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:splice|vmsplice|tee)(?:<|\s*\()",
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:open|openat|openat2)(?:<|\s*\()",
        r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"',
    ):
        if re.search(forbidden, fs_text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 sendfile slice must defer "
                "splice-family, pathname-opening, and C ABI expansion"
            )

    core_io_source = ROOT / "crabc-core" / "src" / "io.rs"
    core_io_text = core_io_source.read_text(errors="replace")
    for required in (
        "pub fn sendfile(",
        "syscall4(",
        "SYS_SENDFILE,",
    ):
        if required not in core_io_text:
            errors.append(
                "crabc-core/src/io.rs: admitted x86 sendfile boundary is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for required in (
        "pub(crate) const SYS_SENDFILE: usize = 40",
        'in("r10") arg3',
    ):
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 sendfile ABI proof is "
                f"missing {required}"
            )


def check_x86_copy_file_range_boundary(errors: list[str]) -> None:
    """Keep x86 copy_file_range staged, flagless, and descriptor-only."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    start = fs_text.find("pub fn copy_file_range<")
    end = fs_text.find("\n/// The Linux file-position origins", start)
    if start < 0 or end < 0:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: admitted x86 copy_file_range slice is missing"
        )
        return
    copy_text = fs_text[start:end]
    for required in (
        "off_in: Option<&mut u64>",
        "off_out: Option<&mut u64>",
        "checked_add(len_as_u64)",
        "let mut in_offset = in_initial;",
        "let mut out_offset = out_initial;",
        "crabc_core::fs::copy_file_range(",
        "in_offset.as_mut(),",
        "out_offset.as_mut(),",
        "if let (Some(offset), Some(updated)) = (off_in, in_offset)",
        "if let (Some(offset), Some(updated)) = (off_out, out_offset)",
    ):
        if required not in copy_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 copy_file_range slice "
                f"is missing {required}"
            )
    if "flags:" in copy_text or "crabc_core::io::sendfile(" in copy_text:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: admitted x86 copy_file_range slice must "
            "stay flagless and must not add a sendfile fallback"
        )

    core_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_text = core_source.read_text(errors="replace")
    start = core_text.find("pub fn copy_file_range(")
    end = core_text.find("\n/// Requests synchronization", start)
    if start < 0 or end < 0:
        errors.append(
            "crabc-core/src/fs.rs: admitted x86 copy_file_range seam is missing"
        )
        return
    core_copy_text = core_text[start:end]
    for required in ("syscall6(", "SYS_COPY_FILE_RANGE,", "len,", "            0,"):
        if required not in core_copy_text:
            errors.append(
                "crabc-core/src/fs.rs: admitted x86 copy_file_range seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for required in (
        "pub(crate) const SYS_COPY_FILE_RANGE: usize = 326",
        'in("r10") arg3',
        'in("r8") arg4',
        'in("r9") arg5',
    ):
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 copy_file_range "
                f"ABI proof is missing {required}"
            )


def check_x86_sync_file_range_boundary(errors: list[str]) -> None:
    """Keep the admitted x86 range-writeback operation closed and typed."""

    io_source = ROOT / "crabc-rs" / "src" / "io.rs"
    io_text = io_source.read_text(errors="replace")
    for required in (
        "pub struct SyncFileRangeFlags: u32",
        "const WAIT_BEFORE = 0x01",
        "const WRITE = 0x02",
        "const WAIT_AFTER = 0x04",
        "pub fn sync_file_range(",
        "checked_add(length)",
    ):
        if required not in io_text:
            errors.append(
                "crabc-rs/src/io.rs: admitted x86 sync_file_range slice is missing "
                f"{required}"
            )

    if "pub fn sync_file_range2" in io_text:
        errors.append(
            "crabc-rs/src/io.rs: admitted x86 sync_file_range slice must not grow "
            "a second range-writeback API"
        )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for required in (
        "pub(crate) const SYS_SYNC_FILE_RANGE: usize = 277",
        'in("r10") arg3',
    ):
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 sync_file_range "
                f"ABI proof is missing {required}"
            )


def check_x86_syncfs_boundary(errors: list[str]) -> None:
    """Keep the admitted x86 mounted-filesystem sync operation descriptor-scoped."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub fn syncfs<",
        "crabc_core::fs::syncfs(fd.as_fd().as_raw_fd())",
        "does not admit the separate process/system-wide",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 syncfs slice is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    if "pub(crate) const SYS_SYNCFS: usize = 306" not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 syncfs ABI proof is "
            "missing SYS_SYNCFS=306"
        )


def check_x86_sync_boundary(errors: list[str]) -> None:
    """Keep the admitted x86 global sync operation separate from syncfs."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub fn sync()",
        "crabc_core::fs::sync();",
        "Unlike [`syncfs`], this operation is neither descriptor- nor",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 sync slice is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    if "pub(crate) const SYS_SYNC: usize = 162" not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 sync ABI proof is "
            "missing SYS_SYNC=162"
        )

    core_fs_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_fs_text = core_fs_source.read_text(errors="replace")
    if "let _ = unsafe { syscall0(SYS_SYNC) };" not in core_fs_text:
        errors.append(
            "crabc-core/src/fs.rs: admitted x86 sync boundary must issue "
            "SYS_SYNC through syscall0"
        )


def check_x86_readlinkat_boundary(errors: list[str]) -> None:
    """Keep the private x86 readlinkat slice caller-buffer-only and read-only."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    if "pub fn readlinkat_raw<" not in text:
        errors.append("crabc-rs/src/fs_x86_64.rs: private readlinkat slice is missing")
    for forbidden in (
        "pub fn readlinkat<",
        "pub fn readlink<",
        "pub fn unlink",
        "pub fn rename",
        "pub fn symlink",
        "CString",
        "Vec<",
    ):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: private readlinkat slice must defer "
                f"{forbidden}"
            )


def check_x86_memfd_boundary(errors: list[str]) -> None:
    """Keep the direct x86 memory-file slice narrow and descriptor-based."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    for required in (
        "pub fn memfd_create",
        "pub fn fcntl_get_seals",
        "pub fn fcntl_add_seals",
        "const HUGETLB",
        "const EXEC",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: direct memory-file slice is missing "
                f"{required}"
            )
    if re.search(r"(?m)^\s*const\s+HUGE_", text):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: direct memory-file slice must defer "
            "MFD_HUGE_* size selectors"
        )
    for forbidden in ("pub fn memfd_secret",):
        if forbidden in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: direct memory-file slice must defer "
                f"{forbidden}"
            )
    if re.search(r"(?m)^\s*pub\s+(?:unsafe\s+)?fn\s+fcntl(?:<|\s*\()", text):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: direct memory-file slice must not expose "
            "a generic fcntl API"
        )


def main() -> int:
    errors: list[str] = []
    root_manifest = (ROOT / "Cargo.toml").read_text()
    if re.search(r"(?m)^\[package\]", root_manifest):
        errors.append("Cargo.toml: root manifest must remain a virtual workspace")
    if (ROOT / "src").exists():
        errors.append("src/: obsolete root package source directory must not return")

    mimalloc_root = ROOT / "crabc-mimalloc"
    mimalloc_manifest_path = mimalloc_root / "Cargo.toml"
    if '"crabc-mimalloc"' not in root_manifest:
        errors.append("Cargo.toml: crabc-mimalloc must remain a workspace member")
    if not mimalloc_manifest_path.is_file():
        errors.append("crabc-mimalloc/Cargo.toml: allocator crate manifest is missing")
    else:
        with mimalloc_manifest_path.open("rb") as stream:
            mimalloc_manifest = tomllib.load(stream)
        dependencies = mimalloc_manifest.get("dependencies", {})
        if set(dependencies) != {"chacha20", "crabc-core", "zeroize"}:
            errors.append(
                "crabc-mimalloc/Cargo.toml: normal dependencies must be exactly "
                "chacha20, crabc-core, and zeroize"
            )
        chacha = dependencies.get("chacha20", {})
        if not isinstance(chacha, dict) or chacha.get("version") != "=0.10.1":
            errors.append(
                "crabc-mimalloc/Cargo.toml: chacha20 must remain pinned to =0.10.1"
            )
        elif chacha.get("default-features") is not False or set(chacha.get("features", [])) != {
            "legacy",
            "zeroize",
        }:
            errors.append(
                "crabc-mimalloc/Cargo.toml: chacha20 must disable defaults and select only "
                "legacy plus zeroize"
            )
        zeroize = dependencies.get("zeroize", {})
        if (
            not isinstance(zeroize, dict)
            or zeroize.get("version") != "=1.9.0"
            or zeroize.get("default-features") is not False
            or zeroize.get("features", [])
        ):
            errors.append(
                "crabc-mimalloc/Cargo.toml: zeroize must remain pinned to =1.9.0 "
                "with defaults disabled and no features"
            )
        dev_dependencies = mimalloc_manifest.get("dev-dependencies", {})
        if set(dev_dependencies) != {"loom"}:
            errors.append(
                "crabc-mimalloc/Cargo.toml: test-only dependencies must be exactly loom"
            )
        loom = dev_dependencies.get("loom", {})
        if (
            not isinstance(loom, dict)
            or loom.get("version") != "=0.7.2"
            or loom.get("default-features") is not False
            or loom.get("features", [])
        ):
            errors.append(
                "crabc-mimalloc/Cargo.toml: loom must remain test-only, pinned to =0.7.2, "
                "with defaults disabled and no features"
            )
        package = mimalloc_manifest.get("package", {})
        if package.get("license") != "MIT":
            errors.append(
                "crabc-mimalloc/Cargo.toml: translated mimalloc package must remain MIT-only"
            )
        if "build" in package or (mimalloc_root / "build.rs").exists():
            errors.append("crabc-mimalloc: production allocator must not have a build script")

    native_allocator_sources = sorted(
        path.relative_to(ROOT)
        for path in mimalloc_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}
    )
    if native_allocator_sources:
        errors.append(
            "crabc-mimalloc: C/C++ production source is forbidden: "
            + ", ".join(map(str, native_allocator_sources))
        )

    mimalloc_source = mimalloc_root / "src"
    if mimalloc_source.is_dir():
        source_text = "\n".join(
            path.read_text(errors="replace") for path in sorted(mimalloc_source.rglob("*.rs"))
        )
        if re.search(r"(?m)^\s*extern\s+crate\s+alloc\s*;", source_text):
            errors.append("crabc-mimalloc: production allocator must not depend on alloc")
        if re.search(r"\b(?:crabc_libc|libmimalloc_sys|libc)::", source_text):
            errors.append("crabc-mimalloc: production allocator must not call libc or C mimalloc")
        lib_source = (mimalloc_source / "lib.rs").read_text(errors="replace")
        if "#![no_std]" not in lib_source:
            errors.append("crabc-mimalloc/src/lib.rs: production allocator must remain no_std")
        if any(
            target not in lib_source
            for target in (
                "target_os = \"linux\"",
                "target_arch = \"aarch64\"",
                "target_endian = \"little\"",
            )
        ):
            errors.append(
                "crabc-mimalloc/src/lib.rs: Linux/AArch64 little-endian target rejection is missing"
            )

    dev_script = (ROOT / "scripts" / "dev.sh").read_text()
    # Oracle checkouts are mounted for native evidence only.  They must stay
    # outside the worktree so Git provenance observes the repository rather
    # than Docker-injected untracked directories.
    if ":/workspace/rustix:ro" in dev_script:
        errors.append("scripts/dev.sh: Rustix oracle mount must remain outside /workspace")
    if ":/workspace/rustybench:ro" in dev_script:
        errors.append("scripts/dev.sh: Rustybench oracle mount must remain outside /workspace")

    files = text_files()
    report_matches(errors, r"TODO\.md", files, "deleted TODO authority must not return")
    report_matches(errors, REMOVED_ROOT_LOADER, files, "removed root loader reference")
    report_matches(
        errors,
        r"https://github\.com/mengzhuo/crabc",
        files,
        "stale repository URL",
    )
    evidence_files = [
        path
        for path in files
        if path.relative_to(ROOT).parts[0] in {"compat", "tests", "scripts", "docs"}
        and path.relative_to(ROOT) != Path("scripts/check_structure.py")
    ]
    report_matches(
        errors,
        r"crabc-core/src/lib\.rs",
        evidence_files,
        "machine-readable/source documentation must name the extracted core module",
    )
    check_root_c_link_boundaries(errors)
    check_x86_getcwd_boundary(errors)
    check_x86_readlinkat_boundary(errors)
    check_x86_memfd_boundary(errors)
    check_x86_rr_interval_boundary(errors)
    check_x86_sched_affinity_boundary(errors)
    check_x86_futex_boundary(errors)
    check_x86_clock_nanosleep_boundary(errors)
    check_x86_setitimer_boundary(errors)
    check_x86_access_boundary(errors)
    check_x86_fcntl_status_flags_boundary(errors)
    check_x86_flock_boundary(errors)
    check_x86_sendfile_boundary(errors)
    check_x86_copy_file_range_boundary(errors)
    check_x86_sync_file_range_boundary(errors)
    check_x86_syncfs_boundary(errors)
    check_x86_sync_boundary(errors)

    for source_root in PRODUCTION_SOURCE:
        for path in source_root.rglob("*.rs"):
            relative = path.relative_to(ROOT)
            for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
                if RISC_V_ARCH_BRANCH.search(line):
                    errors.append(f"{relative}:{line_number}: inactive RISC-V architecture branch")
                if X86_ARCH_BRANCH.search(line) and not is_authorized_x86_branch(
                    relative, line
                ):
                    errors.append(
                        f"{relative}:{line_number}: x86-64 branch is outside an explicit staged boundary"
                    )

    core_root = ROOT / "crabc-core" / "src" / "lib.rs"
    core_text = core_root.read_text()
    if len(core_text.splitlines()) > 300:
        errors.append("crabc-core/src/lib.rs: composition root exceeds 300 lines")
    if INLINE_CORE_MODULE.search(core_text):
        errors.append("crabc-core/src/lib.rs: inline domain modules are not allowed")

    rust_facade_root = ROOT / "crabc-rs" / "src" / "lib.rs"
    rust_facade_text = rust_facade_root.read_text()
    if any(
        target not in rust_facade_text
        for target in (
            'target_os = "linux"',
            'target_arch = "aarch64"',
            'target_arch = "x86_64"',
            'target_endian = "little"',
            'compile_error!("crabc-rs supports little-endian Linux/AArch64 and staged Linux/x86-64 only")',
        )
    ):
        errors.append(
            "crabc-rs/src/lib.rs: staged Linux/x86-64 facade target rejection is missing"
        )

    libc_root = ROOT / "libc" / "src" / "lib.rs"
    libc_text = libc_root.read_text()
    if len(libc_text.splitlines()) > 100:
        errors.append("libc/src/lib.rs: composition root exceeds 100 lines")
    if "include!(" in libc_text:
        errors.append("libc/src/lib.rs: root-level include chains are not allowed")

    c_abi_root = ROOT / "libc" / "src" / "c_abi.rs"
    c_abi_text = c_abi_root.read_text()
    # These isolated domains no longer depend on c_abi's lexical include
    # scope. Keep them as normal modules with named imports; a future change
    # must not restore their old include edges just because it is convenient.
    for module in LIBC_C_ABI_MODULES:
        declaration = rf'(?m)^\s*#\[path = "{re.escape(module)}\.rs"\]\s*\n\s*mod {module};'
        if re.search(declaration, c_abi_text) is None:
            errors.append(f"libc/src/c_abi.rs: {module} must remain a normal private module")
        if f'include!("{module}.rs")' in c_abi_text:
            errors.append(f"libc/src/c_abi.rs: {module} must not return to the lexical include graph")

    ldso_root = ROOT / "ldso" / "src" / "lib.rs"
    if len(ldso_root.read_text().splitlines()) > 100:
        errors.append("ldso/src/lib.rs: composition root exceeds 100 lines")

    if errors:
        print("structural check failed:", file=sys.stderr)
        print("\n".join(f"  {error}" for error in errors), file=sys.stderr)
        return 1
    print("structural check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
