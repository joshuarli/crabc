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
    Path("crabc-core/src/net.rs"),
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
# readiness with temporary signal masks. `fs_x86_64.rs` owns descriptor
# `fstat`, direct access/accessat permission observation, the separately
# proved pathname-lifecycle/namespace batch, caller-buffered and owned
# readlinkat path-core closure, file-access advice/readahead, and direct
# bounded anonymous memory-file/seal operations.
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
# `ipc.rs` owns the separately proved POSIX named-message-queue descriptor,
# attribute, priority, deadline, and unlink-lifetime boundary, while `shm.rs`
# separately owns validated POSIX shared-memory names and close-on-exec
# descriptor lifetime without mapping, SysV, semaphore, or other IPC families,
# `net.rs` owns the direct Linux LP64 socket/address transport boundary and
# separately evidenced bounded network-device ioctl/rtnetlink snapshots,
# `mm_x86_64.rs` owns the closed mmap/mprotect/munmap/memory-locking,
# mapping-synchronization, advice, and residency set,
# `system_x86_64.rs` owns uname/sysinfo records, `thread_x86_64.rs` owns
# three record-independent task observations, borrowed-atomic futex wait/wake,
# the direct read-only round-robin interval and bounded CPU-affinity
# observation/mutation operations,
# and `time_x86_64.rs` owns the separately proved clock-query/mutation,
# validated dynamic/process clock identifiers, owned non-callback POSIX timers,
# relative and direct clock-nanosleep seams, direct interval-timer
# query/control plus the bounded real-timer aliases, timerfd seams, and the
# direct gettimeofday bridge/reexports for the separately proved civil-time
# layer.
# `civil_time.rs` owns target-independent strict UTC conversion and one-way
# local projection, while alloc-gated `timezone.rs` owns only caller-supplied
# immutable POSIX-TZ/TZif rules. No other facade source inherits this
# exception.
X86_RUNTIME_FOUNDATION_FACADE_SOURCES = {
    Path("crabc-rs/src/civil_time.rs"),
    Path("crabc-rs/src/event_x86_64.rs"),
    Path("crabc-rs/src/eventfd.rs"),
    Path("crabc-rs/src/fs_x86_64.rs"),
    Path("crabc-rs/src/ipc.rs"),
    Path("crabc-rs/src/lib.rs"),
    Path("crabc-rs/src/mm_x86_64.rs"),
    Path("crabc-rs/src/net.rs"),
    Path("crabc-rs/src/pipe.rs"),
    Path("crabc-rs/src/process_x86_64.rs"),
    Path("crabc-rs/src/signal.rs"),
    Path("crabc-rs/src/shm.rs"),
   Path("crabc-rs/src/system_x86_64.rs"),
   Path("crabc-rs/src/time_x86_64.rs"),
   Path("crabc-rs/src/thread_x86_64.rs"),
    Path("crabc-rs/src/timezone.rs"),
}
# This source-only loader foundation has no `crabc-ldso` integration or public
# interpreter boundary. The image parser validates file-facing metadata before
# the relative-relocation leaf consumes it; both are listed independently so a
# later loader slice cannot inherit an artifact-wide x86 exception.
X86_RUNTIME_FOUNDATION_LDSO_SOURCES = {
    Path("ldso/src/x86_64_image.rs"),
    Path("ldso/src/x86_64_relocation.rs"),
}
# The selected x86 `crabc-libc` artifact admits independently evidenced static
# C ABI verticals for `sys/stat.h` metadata, credential setters/observation, bootstrap
# primitives, narrow simple signal control, bounded process-signal execution,
# one bounded pthread create/exit/
# join initial-TLS worker and its typed static C11 create/exit/join sibling,
# named termios control, selected
# process context, child reaping, C11 immediate termination, bounded static
# startup/ordinary exit, callback algorithms,
# selected descriptor entry, fcntl status control, bounded generic ioctl, and
# selected timestamp updates,
# selected descriptor I/O,
# selected process resources,
# selected readiness/signal waits, selected system observation, selected
# UTS-namespace identity, selected C-string copy/concatenation, fixed-C-
# locale ctype, scalar integer arithmetic, complete integer parsing, intmax
# arithmetic, and find-first-set, direct POSIX clock_gettime, nanosleep, and
# clock_nanosleep, descriptor entry, selected filesystem access, bounded fcntl
# status control, bounded generic ioctl, and the
# basic x87 classification/sign plus complex accessor/conjugation foundation.
# The older leaves remain source-only. Keeping exact file boundaries makes
# every later C-runtime admission deliberate rather than a directory-wide x86
# exception.
X86_RUNTIME_FOUNDATION_LIBC_SOURCES = {
    Path("libc/src/lib.rs"),
    Path("libc/src/c_abi/x86_64/atomic.rs"),
    Path("libc/src/c_abi/x86_64/clone.rs"),
    Path("libc/src/c_abi/x86_64/credentials.rs"),
    Path("libc/src/c_abi/x86_64/credential_observation.rs"),
    Path("libc/src/c_abi/x86_64/child_reaping.rs"),
    Path("libc/src/c_abi/x86_64/clock_gettime.rs"),
    Path("libc/src/c_abi/x86_64/clock_nanosleep.rs"),
    Path("libc/src/c_abi/x86_64/nanosleep.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_entry.rs"),
    Path("libc/src/c_abi/x86_64/filesystem_access.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_control.rs"),
    Path("libc/src/c_abi/x86_64/ioctl.rs"),
    Path("libc/src/c_abi/x86_64/immediate_termination.rs"),
    Path("libc/src/c_abi/x86_64/callback_algorithms.rs"),
    Path("libc/src/c_abi/x86_64/ctype.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_io.rs"),
    Path("libc/src/c_abi/x86_64/ffs.rs"),
    Path("libc/src/c_abi/x86_64/integer_arithmetic.rs"),
    Path("libc/src/c_abi/x86_64/integer_parse.rs"),
    Path("libc/src/c_abi/x86_64/intmax_arithmetic.rs"),
    Path("libc/src/c_abi/x86_64/math_complex.rs"),
    Path("libc/src/c_abi/x86_64/memory_search.rs"),
    Path("libc/src/c_abi/x86_64/fenv.rs"),
    Path("libc/src/c_abi/x86_64/foundation.rs"),
    Path("libc/src/c_abi/x86_64/memory.rs"),
    Path("libc/src/c_abi/x86_64/process_context.rs"),
    Path("libc/src/c_abi/x86_64/process_resources.rs"),
    Path("libc/src/c_abi/x86_64/c11_thread_lifecycle.rs"),
    Path("libc/src/c_abi/x86_64/pthread_create_join.rs"),
    Path("libc/src/c_abi/x86_64/pthread_identity.rs"),
    Path("libc/src/c_abi/x86_64/readiness_waits.rs"),
    Path("libc/src/c_abi/x86_64/setjmp.rs"),
    Path("libc/src/c_abi/x86_64/signal_control.rs"),
    Path("libc/src/c_abi/x86_64/signal_execution.rs"),
    Path("libc/src/c_abi/x86_64/signal_foundation.rs"),
    Path("libc/src/c_abi/x86_64/static_c_abi.rs"),
    Path("libc/src/c_abi/x86_64/static_startup.rs"),
    Path("libc/src/c_abi/x86_64/static_tls.rs"),
    Path("libc/src/c_abi/x86_64/stat_compat.rs"),
    Path("libc/src/c_abi/x86_64/timestamp_updates.rs"),
    Path("libc/src/c_abi/x86_64/string_copy.rs"),
    Path("libc/src/c_abi/x86_64/termios_control.rs"),
    Path("libc/src/c_abi/x86_64/thread_pointer.rs"),
    Path("libc/src/c_abi/x86_64/uts_identity.rs"),
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
        "path_configuration_exports.rs",
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
    """Keep direct x86 getcwd observations caller-buffered and alloc-gated."""

    process_source = ROOT / "crabc-rs" / "src" / "process_x86_64.rs"
    text = process_source.read_text(errors="replace")
    if "pub fn getcwd<" not in text:
        errors.append("crabc-rs/src/process_x86_64.rs: direct x86 getcwd slice is missing")
    if '#[cfg(feature = "alloc")]\n#[inline]\npub fn getcwd_alloc<' not in text:
        errors.append(
            "crabc-rs/src/process_x86_64.rs: direct x86 getcwd_alloc must remain alloc-gated"
        )


def check_x86_cwd_canonicalize_boundary(errors: list[str]) -> None:
    """Keep the private x86 filesystem-context slice direct and bounded."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub const CANONICAL_PATH_MAX: usize = 4096;",
        "const CANONICAL_PENDING_CAPACITY: usize = CANONICAL_PATH_MAX * 2;",
        "const CANONICAL_MAX_SYMLINKS: usize = 40;",
        "pub fn canonicalize_into<",
        "pub fn canonicalize<",
        "fn canonicalize_bytes<",
        "struct CanonicalWorkspace",
        "crate::process::getcwd(&mut self.cwd)?",
        "OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC",
        "crabc_core::fs::readlinkat_raw(",
        "Err(crate::Errno::LOOP)",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 canonicalization boundary is "
                f"missing {required}"
            )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', fs_text):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 canonicalization must not select a C pathname ABI"
        )
    if re.search(r"(?m)^pub\s+(?:unsafe\s+)?fn\s+openat2(?:<|\s*\()", fs_text):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 canonicalization must not select openat2"
        )

    process_source = ROOT / "crabc-rs" / "src" / "process_x86_64.rs"
    process_text = process_source.read_text(errors="replace")
    for required in (
        "use crate::fs::PathArg;",
        "pub fn chdir<P: PathArg>",
        "path.into_with_c_str(crabc_core::process::chdir)",
        "pub fn fchdir<Fd: AsFd>",
        "crabc_core::process::fchdir(fd.as_raw_fd())",
    ):
        if required not in process_text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: admitted x86 CWD-mutation boundary is "
                f"missing {required}"
            )
    core_process_source = ROOT / "crabc-core" / "src" / "process.rs"
    core_process_text = core_process_source.read_text(errors="replace")
    for required in ("pub fn chdir(path: &CStr)", "pub fn fchdir(fd: RawFd)"):
        if required not in core_process_text:
            errors.append(
                "crabc-core/src/process.rs: admitted x86 CWD seam is missing " f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("GETCWD", 79),
        ("CHDIR", 80),
        ("FCHDIR", 81),
        ("OPENAT", 257),
        ("READLINKAT", 267),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 CWD/canonical ABI proof is "
                f"missing SYS_{name}={value}"
        )


def check_x86_root_change_boundary(errors: list[str]) -> None:
    """Keep x86 process root-change direct, explicit, and non-sandboxing."""

    process_source = ROOT / "crabc-rs" / "src" / "process_x86_64.rs"
    process_text = process_source.read_text(errors="replace")
    for required in (
        "pub fn chroot<P: PathArg>(path: P) -> Result<()>",
        "path.into_with_c_str(crabc_core::process::chroot)",
        "does not change the current working",
        "preserve a route back to the old root",
        "provide a containment",
    ):
        if required not in process_text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: admitted x86 root-change boundary is "
                f"missing {required}"
            )

    for forbidden in (
        "pub fn pivot_root",
        "pub fn unshare",
        "pub fn setns",
        "pub fn mount",
        "pub fn umount",
    ):
        if forbidden in process_text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: x86 root-change must defer "
                f"{forbidden[4:]}"
            )

    core_process_source = ROOT / "crabc-core" / "src" / "process.rs"
    core_process_text = core_process_source.read_text(errors="replace")
    for required in (
        "pub fn chroot(path: &CStr) -> Result<()>",
        "syscall1(SYS_CHROOT, path.as_ptr() as usize)",
    ):
        if required not in core_process_text:
            errors.append(
                "crabc-core/src/process.rs: admitted x86 root-change seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    required = "pub(crate) const SYS_CHROOT: usize = 161"
    if required not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 root-change ABI proof is "
            "missing SYS_CHROOT=161"
        )


def check_x86_mount_boundary(errors: list[str]) -> None:
    """Keep x86 mount requests direct, unprivileged in evidence, and narrow.

    The selected `mount.basic` slice deliberately retains the existing Linux
    MS/MNT vocabulary, including its future-bit catch-all, but only proves
    checked missing-target failures. Flag availability must not be mistaken
    for successful bind/remount/propagation or namespace-policy evidence.
    """

    facade_root = (ROOT / "crabc-rs" / "src" / "lib.rs").read_text(errors="replace")
    required_module = (
        '#[cfg(target_arch = "x86_64")]\n'
        '#[path = "mount_x86_64.rs"]\npub mod mount;'
    )
    if required_module not in facade_root:
        errors.append(
            "crabc-rs/src/lib.rs: selected x86 mount requests are missing their "
            "explicit mount_x86_64 module boundary"
        )

    facade_source = ROOT / "crabc-rs" / "src" / "mount_x86_64.rs"
    facade_text = facade_source.read_text(errors="replace")
    for required in (
        "use crate::fs::PathArg;",
        "pub fn mount<'a, Source: PathArg, Target: PathArg, Fs: PathArg>(",
        "pub fn unmount<Target: PathArg>(target: Target, flags: UnmountFlags) -> Result<()>",
    ):
        if required not in facade_text:
            errors.append(
                "crabc-rs/src/mount_x86_64.rs: selected x86 mount request boundary is "
                f"missing {required}"
            )

    def bitflags_constants(name: str, representation: str, expected: tuple[tuple[str, str], ...]) -> None:
        match = re.search(
            rf"(?ms)pub struct {name}: {representation}\s*\{{(?P<body>.*?)^\}}",
            facade_text,
        )
        if match is None:
            errors.append(
                "crabc-rs/src/mount_x86_64.rs: selected x86 mount request boundary is "
                f"missing {name}"
            )
            return
        actual = tuple(
            (constant, re.sub(r"\s+", "", value))
            for constant, value in re.findall(
                r"(?m)^\s*const\s+([A-Z_][A-Z0-9_]*)\s*=\s*([^;]+);",
                match.group("body"),
            )
        )
        if actual != expected:
            errors.append(
                "crabc-rs/src/mount_x86_64.rs: selected x86 mount request boundary "
                f"must keep {name} to its copied Linux vocabulary plus the future-bit catch-all"
            )

    bitflags_constants(
        "MountFlags",
        "u64",
        (
            ("RDONLY", "1"),
            ("NOSUID", "2"),
            ("NODEV", "4"),
            ("NOEXEC", "8"),
            ("SYNCHRONOUS", "16"),
            ("REMOUNT", "32"),
            ("MANDLOCK", "64"),
            ("DIRSYNC", "128"),
            ("NOATIME", "1024"),
            ("NODIRATIME", "2048"),
            ("BIND", "4096"),
            ("MOVE", "8192"),
            ("REC", "16384"),
            ("SILENT", "32768"),
            ("POSIXACL", "1<<16"),
            ("UNBINDABLE", "1<<17"),
            ("PRIVATE", "1<<18"),
            ("SLAVE", "1<<19"),
            ("SHARED", "1<<20"),
            ("RELATIME", "1<<21"),
            ("KERNMOUNT", "1<<22"),
            ("I_VERSION", "1<<23"),
            ("STRICTATIME", "1<<24"),
            ("LAZYTIME", "1<<25"),
            ("_", "!0"),
        ),
    )
    bitflags_constants(
        "UnmountFlags",
        "i32",
        (
            ("FORCE", "1"),
            ("DETACH", "2"),
            ("EXPIRE", "4"),
            ("NOFOLLOW", "8"),
            ("_", "!0"),
        ),
    )

    def function_body(marker: str) -> str | None:
        start = facade_text.find(marker)
        if start < 0:
            errors.append(
                "crabc-rs/src/mount_x86_64.rs: selected x86 mount request boundary is "
                f"missing {marker}"
            )
            return None
        end = facade_text.find("\n}\n", start)
        if end < 0:
            errors.append(
                "crabc-rs/src/mount_x86_64.rs: selected x86 mount request boundary has "
                f"an unclosed {marker} body"
            )
            return None
        return facade_text[start:end]

    for marker, required in (
        (
            "pub fn mount<'a, Source: PathArg, Target: PathArg, Fs: PathArg>",
            (
                "source.into_with_c_str",
                "target.into_with_c_str",
                "file_system_type.into_with_c_str",
                "crabc_core::mount::mount(",
                "flags.bits(),",
            ),
        ),
        (
            "pub fn unmount<Target: PathArg>",
            ("target.into_with_c_str", "crabc_core::mount::umount2(target, flags.bits())"),
        ),
    ):
        body = function_body(marker)
        if body is None:
            continue
        for entry in required:
            if entry not in body:
                errors.append(
                    "crabc-rs/src/mount_x86_64.rs: selected x86 mount request boundary "
                    f"must directly retain {entry} in {marker}"
                )

    public_functions = tuple(
        re.findall(r"(?m)^pub\s+(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)", facade_text)
    )
    if public_functions != ("mount", "unmount"):
        errors.append(
            "crabc-rs/src/mount_x86_64.rs: x86 mount.basic must expose only mount and unmount"
        )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', facade_text):
        errors.append(
            "crabc-rs/src/mount_x86_64.rs: x86 mount.basic must not select a C ABI"
        )
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:"
        r"mount_raw|umount2(?:_raw)?|pivot_root|unshare|setns|"
        r"fsopen|fsconfig|fsmount|fspick|open_tree|move_mount|mount_setattr"
        r")(?:<|\s*\()",
        facade_text,
    ):
        errors.append(
            "crabc-rs/src/mount_x86_64.rs: x86 mount.basic must defer raw, namespace, "
            "and filesystem-descriptor mount APIs"
        )

    core_source = ROOT / "crabc-core" / "src" / "mount.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub fn mount(",
        "syscall5(\n            SYS_MOUNT,",
        "pub fn umount2(target: &CStr, flags: i32) -> Result<()>",
        "syscall2(SYS_UMOUNT2, target.as_ptr() as usize, flags as usize)",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/mount.rs: selected x86 mount request seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (("MOUNT", 165), ("UMOUNT2", 166)):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: selected x86 mount request ABI proof is "
                f"missing SYS_{name}={value}"
            )


def check_x86_thread_kill_boundary(errors: list[str]) -> None:
    """Keep x86 thread-targeted signaling direct and same-process only."""

    signal_source = ROOT / "crabc-rs" / "src" / "signal.rs"
    signal_text = signal_source.read_text(errors="replace")
    signature = (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\n'
        "#[inline]\n"
        "pub fn kill_thread(tid: Pid, signal: Signal) -> Result<()> {"
    )
    start = signal_text.find(signature)
    if start < 0:
        errors.append(
            "crabc-rs/src/signal.rs: admitted x86 thread-kill boundary must remain "
            "explicitly shared with AArch64"
        )
    else:
        end = signal_text.find("\n}\n", start)
        if end < 0:
            errors.append(
                "crabc-rs/src/signal.rs: admitted x86 thread-kill boundary has no "
                "closed function body"
            )
        else:
            body = signal_text[start:end]
            for required in (
                "crabc_core::process::tgkill(",
                "calling_pid_raw(),",
                "tid.as_raw_pid(),",
                "signal.as_raw(),",
            ):
                if required not in body:
                    errors.append(
                        "crabc-rs/src/signal.rs: admitted x86 thread-kill boundary must "
                        f"directly delegate through tgkill with {required}"
                    )

    generic_process_signal = re.compile(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:kill|killpg|kill_process|"
        r"kill_process_group|kill_current_process_group|test_kill_process|"
        r"test_kill_process_group|test_kill_current_process_group)(?:<|\s*\()"
    )
    for source in (signal_source, ROOT / "crabc-rs" / "src" / "process_x86_64.rs"):
        if generic_process_signal.search(source.read_text(errors="replace")):
            errors.append(
                f"{source.relative_to(ROOT)}: staged x86 thread-kill must defer generic "
                "process/group signaling"
            )

    core_process_source = ROOT / "crabc-core" / "src" / "process.rs"
    core_process_text = core_process_source.read_text(errors="replace")
    for required in (
        "pub fn tgkill(tgid: i32, tid: i32, signal: i32) -> Result<()>",
        "syscall3(SYS_TGKILL, tgid as usize, tid as usize, signal as usize)",
    ):
        if required not in core_process_text:
            errors.append(
                "crabc-core/src/process.rs: admitted x86 thread-kill seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    if "pub(crate) const SYS_TGKILL: usize = 234" not in syscall_source.read_text(
        errors="replace"
    ):
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 thread-kill ABI proof is "
            "missing SYS_TGKILL=234"
        )


def check_x86_ipc_boundary(errors: list[str]) -> None:
    """Keep the private x86 POSIX named-message-queue slice direct and typed."""

    facade_source = ROOT / "crabc-rs" / "src" / "lib.rs"
    facade_text = facade_source.read_text(errors="replace")
    required_module = (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\n'
        "pub mod ipc;"
    )
    if required_module not in facade_text:
        errors.append(
            "crabc-rs/src/lib.rs: admitted x86 POSIX message queues are missing "
            "their explicit shared module boundary"
        )

    ipc_source = ROOT / "crabc-rs" / "src" / "ipc.rs"
    ipc_text = ipc_source.read_text(errors="replace")
    for required in (
        "use crate::fs::PathArg as QueueNameArg;",
        "pub const MAX_MESSAGE_PRIORITY: u32 = 32_767;",
        "pub struct MessagePriority(u32);",
        "pub struct QueueAttributes",
        "pub struct MessageQueue",
        "pub fn open<P: QueueNameArg>",
        "pub fn create<P: QueueNameArg>",
        "pub fn unlink<P: QueueNameArg>",
        "pub fn set_nonblocking(&self, enabled: bool)",
        "pub fn send_until(",
        "pub fn receive_until(",
        "crabc_core::ipc::open(",
        "crabc_core::ipc::unlink",
        "crabc_core::ipc::timed_send",
        "crabc_core::ipc::timed_receive",
        "crabc_core::ipc::getsetattr",
    ):
        if required not in ipc_text:
            errors.append(
                "crabc-rs/src/ipc.rs: admitted x86 POSIX message-queue boundary is "
                f"missing {required}"
            )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', ipc_text):
        errors.append(
            "crabc-rs/src/ipc.rs: x86 POSIX message queues must not select a C ABI"
        )
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:mq_notify|shm_open|shm_unlink|"
        r"msgget|msgsnd|msgrcv|msgctl|semget|semop|semtimedop|semctl)(?:<|\s*\()",
        ipc_text,
    ):
        errors.append(
            "crabc-rs/src/ipc.rs: x86 named-message-queue slice must defer notification, "
            "shared-memory, and SysV/semaphore IPC"
        )

    core_source = ROOT / "crabc-core" / "src" / "ipc.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub struct KernelMqAttr",
        "pub struct KernelMqTimespec",
        "size_of::<KernelMqAttr>() == 64",
        "offset_of!(KernelMqAttr, reserved) == 32",
        "size_of::<KernelMqTimespec>() == 16",
        "pub fn open(name: &CStr, flags: i32, mode: u32, attr: Option<&KernelMqAttr>)",
        "pub fn unlink(name: &CStr)",
        "pub fn getsetattr(fd: RawFd, new_attr: Option<&KernelMqAttr>)",
        "pub fn timed_send(",
        "pub fn timed_receive(",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/ipc.rs: admitted x86 POSIX message-queue ABI seam is "
                f"missing {required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("MQ_OPEN", 240),
        ("MQ_UNLINK", 241),
        ("MQ_TIMEDSEND", 242),
        ("MQ_TIMEDRECEIVE", 243),
        ("MQ_GETSETATTR", 245),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 POSIX message-queue ABI "
                f"proof is missing SYS_{name}={value}"
        )


def check_x86_shm_boundary(errors: list[str]) -> None:
    """Keep the private x86 POSIX shared-memory slice direct and bounded."""

    facade_source = ROOT / "crabc-rs" / "src" / "lib.rs"
    facade_text = facade_source.read_text(errors="replace")
    required_module = (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\n'
        "pub mod shm;"
    )
    if required_module not in facade_text:
        errors.append(
            "crabc-rs/src/lib.rs: admitted x86 POSIX shared memory is missing "
            "its explicit shared module boundary"
        )

    shm_source = ROOT / "crabc-rs" / "src" / "shm.rs"
    shm_text = shm_source.read_text(errors="replace")
    for required in (
        "pub trait NameArg",
        "impl NameArg for &[u8]",
        "impl NameArg for &str",
        "pub fn open<P: NameArg>",
        "pub fn unlink<P: NameArg>",
        "fn with_shm_bytes<T, F>",
        "if name.contains(&0)",
        "let name = &name[first..];",
        "if name.len() > 255",
        "let mut path = [0_u8; 265];",
        'path[..9].copy_from_slice(b"/dev/shm/");',
        "fs::open(path, flags | OFlags::CLOEXEC, mode)",
        "fs::unlink(path)",
    ):
        if required not in shm_text:
            errors.append(
                "crabc-rs/src/shm.rs: admitted x86 POSIX shared-memory boundary is "
                f"missing {required}"
            )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', shm_text):
        errors.append("crabc-rs/src/shm.rs: x86 POSIX shared memory must not select a C ABI")
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:shm_open|shm_unlink|shmat|shmdt|shmget|shmctl|"
        r"sem_open|sem_unlink)(?:<|\s*\()",
        shm_text,
    ):
        errors.append(
            "crabc-rs/src/shm.rs: x86 POSIX shared-memory slice must defer C, SysV, and "
            "semaphore APIs"
        )

    core_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub fn openat(dirfd: RawFd, path: &CStr, flags: i32, mode: u32)",
        "pub fn unlinkat(dirfd: RawFd, path: &CStr, flags: u32)",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/fs.rs: admitted x86 POSIX shared-memory direct seam is "
                f"missing {required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (("OPENAT", 257), ("UNLINKAT", 263)):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 POSIX shared-memory ABI "
                f"proof is missing SYS_{name}={value}"
            )


def check_x86_inotify_boundary(errors: list[str]) -> None:
    """Keep the private x86 inotify slice owned, caller-buffered, and bounded."""

    system_source = ROOT / "crabc-rs" / "src" / "system_x86_64.rs"
    system_text = system_source.read_text(errors="replace")
    for required in (
        "pub mod inotify {",
        "use crate::fs::PathArg;",
        "const EVENT_HEADER_SIZE: usize = 16;",
        "pub struct CreateFlags: u32",
        "pub struct EventMask: u32",
        "pub struct WatchDescriptor(i32);",
        "pub struct Inotify",
        "pub fn new(flags: CreateFlags) -> Result<Self>",
        "CreateFlags::from_bits(flags.bits()).is_none()",
        "pub fn add_watch<P: PathArg>(",
        "crabc_core::inotify::add_watch",
        "pub fn remove_watch(&self, watch: WatchDescriptor)",
        "crabc_core::inotify::rm_watch",
        "pub fn read_events<'buffer>",
        "crabc_core::io::read(self.fd.as_raw_fd(), buffer)?",
        "pub struct Event<'buffer>",
        "pub struct Events<'buffer>",
        "EventMask::from_bits_retain(mask)",
        "event_batch_retains_unknown_bits_and_descriptor_wide_records",
    ):
        if required not in system_text:
            errors.append(
                "crabc-rs/src/system_x86_64.rs: admitted x86 inotify boundary is missing "
                f"{required}"
            )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', system_text):
        errors.append(
            "crabc-rs/src/system_x86_64.rs: x86 inotify must not select a C ABI"
        )
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:inotify_init|fanotify_init|fanotify_mark|"
        r"inotify_add_watch|inotify_rm_watch)(?:<|\s*\()",
        system_text,
    ):
        errors.append(
            "crabc-rs/src/system_x86_64.rs: x86 inotify must defer legacy/C and fanotify APIs"
        )

    core_source = ROOT / "crabc-core" / "src" / "inotify.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub fn init1(flags: u32) -> Result<RawFd>",
        "pub fn add_watch(fd: RawFd, path: &CStr, mask: u32) -> Result<i32>",
        "pub fn rm_watch(fd: RawFd, watch: i32) -> Result<()>",
        "SYS_INOTIFY_INIT1",
        "SYS_INOTIFY_ADD_WATCH",
        "SYS_INOTIFY_RM_WATCH",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/inotify.rs: admitted x86 inotify syscall seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("INOTIFY_INIT1", 294),
        ("INOTIFY_ADD_WATCH", 254),
        ("INOTIFY_RM_WATCH", 255),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 inotify ABI proof is "
                f"missing SYS_{name}={value}"
            )


def check_x86_calendar_time_boundary(errors: list[str]) -> None:
    """Keep the private x86 civil-time slice direct, pure, and one-way."""

    facade_text = (ROOT / "crabc-rs" / "src" / "lib.rs").read_text(errors="replace")
    for required in (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\nmod civil_time;',
        '#[cfg(all(\n    feature = "alloc",\n    any(target_arch = "aarch64", target_arch = "x86_64")\n))]\npub mod timezone;',
    ):
        if required not in facade_text:
            errors.append(
                "crabc-rs/src/lib.rs: admitted x86 civil-time layer is missing "
                f"its explicit module boundary {required!r}"
            )

    time_source = ROOT / "crabc-rs" / "src" / "time_x86_64.rs"
    time_text = time_source.read_text(errors="replace")
    for required in (
        "pub use crate::civil_time::{",
        "difftime, gmtime, timegm, CalendarTime, UnixTime, NANOS_PER_SECOND,",
        '#[cfg(feature = "alloc")]\npub use crate::civil_time::LocalCalendar;',
        "pub fn wall_clock() -> Result<UnixTime>",
        "crabc_core::time::gettimeofday()?",
        "UnixTime::from_wall_clock_parts(parts.seconds, parts.microseconds).ok_or(Errno::RANGE)",
    ):
        if required not in time_text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: admitted x86 civil-time boundary is "
                f"missing {required}"
            )

    civil_source = ROOT / "crabc-rs" / "src" / "civil_time.rs"
    civil_text = civil_source.read_text(errors="replace")
    for required in (
        "pub struct UnixTime",
        "pub struct CalendarTime",
        "pub fn gmtime(seconds: i64) -> Result<CalendarTime>",
        "pub fn timegm(calendar: &CalendarTime) -> Result<i64>",
        "pub fn difftime(t1: i64, t0: i64) -> f64",
        "pub struct LocalCalendar",
        "pub fn from_unix_time(instant: UnixTime, zone: &'zone TimeZone) -> Result<Self>",
    ):
        if required not in civil_text:
            errors.append(
                "crabc-rs/src/civil_time.rs: admitted x86 civil-time values are "
                f"missing {required}"
            )

    timezone_source = ROOT / "crabc-rs" / "src" / "timezone.rs"
    timezone_text = timezone_source.read_text(errors="replace")
    for required in (
        "pub struct TimeZone",
        "pub fn from_posix_tz(bytes: &[u8])",
        "pub fn from_tzif(bytes: &[u8])",
        "pub fn offset_at(&self, instant: UnixTime)",
    ):
        if required not in timezone_text:
            errors.append(
                "crabc-rs/src/timezone.rs: admitted x86 immutable-rule boundary is "
                f"missing {required}"
            )

    for relative, text in (
        ("crabc-rs/src/time_x86_64.rs", time_text),
        ("crabc-rs/src/civil_time.rs", civil_text),
        ("crabc-rs/src/timezone.rs", timezone_text),
    ):
        if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', text):
            errors.append(f"{relative}: x86 civil-time layer must not select a C ABI")
        if re.search(
            r"(?m)^\s*pub\s+(?:type|struct)\s+(?:Tm|TimeT|Timeval|Timezone)\b",
            text,
        ):
            errors.append(f"{relative}: x86 civil-time layer must not expose C time/tm records")
        if re.search(
            r"(?m)^\s*pub\s+(?:unsafe\s+)?fn\s+(?:ctime|asctime|gmtime_r|localtime(?:_r)?|mktime|strftime|strptime|tzset)\b",
            text,
        ):
            errors.append(f"{relative}: x86 civil-time layer must not expose C time APIs")

    timezone_code = "\n".join(
        line for line in timezone_text.splitlines() if not line.lstrip().startswith("//")
    )
    for forbidden in (
        r"\b(?:std|core)::env::",
        r"\b(?:getenv|setenv|unsetenv|putenv|tzset)\s*\(",
        r"(?m)^\s*(?:pub\s+)?static(?:\s+mut)?\s+(?:TZ|timezone|daylight|tzname)\b",
        r'"(?:/etc/localtime|/usr/share/zoneinfo|/usr/share/lib/zoneinfo)',
        r"\b(?:std::fs|crate::fs|File::open|read_to_end|read_to_string)\b",
    ):
        if re.search(forbidden, timezone_code):
            errors.append(
                "crabc-rs/src/timezone.rs: x86 civil-time rules must not read TZ globals "
                "or system zoneinfo"
            )
            break

    if re.search(
        r"(?m)^\s*pub\s+(?:unsafe\s+)?fn\s+(?:from_local(?:_time)?|to_unix(?:_time)?|to_instant|resolve_local|local_to_unix|mktime|localtime(?:_r)?)\b",
        civil_text,
    ):
        errors.append(
            "crabc-rs/src/civil_time.rs: x86 local-calendar projection must not "
            "admit inverse ambiguous-local conversion"
        )

    core_source = ROOT / "crabc-core" / "src" / "time_x86_64.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub struct KernelWallClockParts",
        "size_of::<KernelWallClockParts>() == 16",
        "align_of::<KernelWallClockParts>() == 8",
        "offset_of!(KernelWallClockParts, seconds) == 0",
        "offset_of!(KernelWallClockParts, microseconds) == 8",
        "pub fn gettimeofday() -> Result<KernelWallClockParts>",
        "pub unsafe fn gettimeofday_raw(parts: *mut KernelWallClockParts) -> Result<()>",
        "syscall2(SYS_GETTIMEOFDAY, parts as usize, 0)",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/time_x86_64.rs: admitted x86 gettimeofday seam is "
                f"missing {required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    required_syscall = "pub(crate) const SYS_GETTIMEOFDAY: usize = 96"
    if required_syscall not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 civil-time ABI proof is "
            "missing SYS_GETTIMEOFDAY=96"
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
    for forbidden in ("pub fn clock_adjtime",):
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
    # POSIX timers have their own separately-proved ownership boundary below;
    # do not let this older process-global interval-timer check govern it.


def check_x86_advanced_time_boundary(errors: list[str]) -> None:
    """Keep x86 advanced clocks and POSIX timers typed, owned, and bounded."""

    time_source = ROOT / "crabc-rs" / "src" / "time_x86_64.rs"
    time_text = time_source.read_text(errors="replace")
    for required in (
        "ThreadCPUTime = 3",
        "MonotonicRaw = 4",
        "Tai = 11",
        "pub struct ProcessClockId(i32);",
        "pub fn clock_getcpuclockid(pid: Option<Pid>) -> Result<ProcessClockId>",
        "pub enum DynamicClockId<'fd>",
        "Dynamic(BorrowedFd<'fd>)",
        "pub fn clock_gettime_dynamic(id: DynamicClockId<'_>) -> Result<Timespec>",
        "pub fn clock_settime(id: ClockId, timespec: Timespec) -> Result<()>",
        "pub struct TimerSpec",
        "pub struct TimerSetFlags: u32",
        "pub enum TimerNotification",
        "ThreadId {",
        "pub struct PosixTimer",
        "pub fn settime(",
        "pub fn gettime(&self)",
        "pub fn getoverrun(&self) -> Result<i32>",
        "pub fn delete(&mut self) -> Result<()>",
        "struct KernelSigevent",
        "size_of::<KernelSigevent>() == 64",
        "offset_of!(KernelSigevent, signal) == 8",
        "offset_of!(KernelSigevent, notify) == 12",
        "offset_of!(KernelSigevent, padding) == 16",
    ):
        if required not in time_text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: admitted x86 advanced-time boundary is "
                f"missing {required}"
            )

    notification = re.search(
        r"pub enum TimerNotification\s*\{(?P<body>.*?)^\}",
        time_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if notification is None:
        errors.append(
            "crabc-rs/src/time_x86_64.rs: advanced POSIX timers are missing "
            "their closed notification vocabulary"
        )
    elif re.search(r"(?m)^\s*Thread\s*(?:\{|,)", notification.group("body")):
        errors.append(
            "crabc-rs/src/time_x86_64.rs: advanced POSIX timers must defer "
            "SIGEV_THREAD callbacks"
        )

    for forbidden in (
        "pub fn clock_adjtime",
        "pub struct TimerT",
        "pub type TimerT",
        "pub struct Sigevent",
        "pub type Sigevent",
        'pub extern "C"',
        'pub unsafe extern "C"',
    ):
        if forbidden in time_text:
            errors.append(
                "crabc-rs/src/time_x86_64.rs: advanced-time boundary must defer "
                f"{forbidden}"
            )

    core_source = ROOT / "crabc-core" / "src" / "time_x86_64.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub unsafe fn clock_settime_raw",
        "pub unsafe fn clock_getres_raw",
        "pub unsafe fn timer_create_raw",
        "pub unsafe fn timer_settime_raw",
        "pub unsafe fn timer_gettime_raw",
        "pub fn timer_getoverrun_raw",
        "pub fn timer_delete_raw",
        "syscall4(\n            SYS_TIMER_SETTIME,",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/time_x86_64.rs: admitted x86 advanced-time seam is "
                f"missing {required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("SYS_TIMER_CREATE", 222),
        ("SYS_TIMER_SETTIME", 223),
        ("SYS_TIMER_GETTIME", 224),
        ("SYS_TIMER_GETOVERRUN", 225),
        ("SYS_TIMER_DELETE", 226),
        ("SYS_CLOCK_SETTIME", 227),
        ("SYS_CLOCK_GETRES", 229),
    ):
        required = f"pub(crate) const {name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 advanced-time ABI proof "
                f"is missing {name}={value}"
        )


def check_x86_users_databases_boundary(errors: list[str]) -> None:
    """Keep x86 local-account snapshots owned, alloc-gated, and direct."""

    facade_source = ROOT / "crabc-rs" / "src" / "lib.rs"
    facade_text = facade_source.read_text(errors="replace")
    required_module = (
        '#[cfg(all(\n'
        '    feature = "alloc",\n'
        '    any(target_arch = "aarch64", target_arch = "x86_64")\n'
        '))]\n'
        'pub mod users;'
    )
    if required_module not in facade_text or facade_text.count("pub mod users;") != 1:
        errors.append(
            "crabc-rs/src/lib.rs: admitted x86 local-account snapshots must expose exactly "
            "one alloc-gated shared users module"
        )

    users_source = ROOT / "crabc-rs" / "src" / "users.rs"
    users_text = users_source.read_text(errors="replace")
    for required in (
        "pub enum DatabaseError",
        "pub struct User",
        "name: String",
        "pub struct UserDatabase",
        "entries: Vec<User>",
        "pub struct Group",
        "members: Vec<String>",
        "pub struct GroupDatabase",
        "entries: Vec<Group>",
        "pub struct Database",
        "users: UserDatabase",
        "groups: GroupDatabase",
        "fn split_exact",
        "String::from_utf8(value.to_vec())",
        "if value.contains(&0)",
        'Self::from_bytes(&read_system_file(b"/etc/passwd")?)',
        'Self::from_bytes(&read_system_file(b"/etc/group")?)',
        "const MAX_SYSTEM_FILE_BYTES: usize = 1024 * 1024;",
        "crate::fs::open(path, crate::fs::OFlags::CLOEXEC, crate::fs::Mode::empty())",
        "crabc_core::io::read(descriptor.as_raw_fd(), &mut chunk)",
        "Err(crate::Errno::INTR) => continue",
        "if new_length > MAX_SYSTEM_FILE_BYTES",
    ):
        if required not in users_text:
            errors.append(
                "crabc-rs/src/users.rs: admitted x86 local-account snapshot boundary is "
                f"missing {required}"
            )

    x86_fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    x86_fs_text = x86_fs_source.read_text(errors="replace")
    for required in (
        "pub fn open<P: PathArg>(path: P, oflags: OFlags, create_mode: Mode) -> Result<OwnedFd>",
        "openat(CWD, path, oflags, create_mode)",
        "crabc_core::fs::openat(",
    ):
        if required not in x86_fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 local-account snapshots are "
                f"missing the direct file seam {required}"
            )

    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', users_text):
        errors.append(
            "crabc-rs/src/users.rs: x86 local-account snapshots must not select a C ABI"
        )

    c_or_provider_api = re.compile(
        r"(?im)^\s*pub\s+(?:unsafe\s+)?fn\s+(?:"
        r"getpwnam(?:_r)?|getpwuid(?:_r)?|getpwent|setpwent|endpwent|fgetpwent|putpwent|"
        r"getgrnam(?:_r)?|getgrgid(?:_r)?|getgrent|setgrent|endgrent|fgetgrent|putgrent|"
        r"getspnam(?:_r)?|getspent|setspent|endspent|fgetspent|putspent|"
        r"getutent|setutent|endutent|getutid|getutline|pututline|utmpname|"
        r"getutxent|setutxent|endutxent|getutxid|getutxline|pututxline|utmpxname|"
        r"setmntent|getmntent(?:_r)?|addmntent|endmntent|hasmntopt|"
        r"(?:set|add|remove|register|unregister|reload)_(?:nss_)?provider"
        r")(?:<|\s*\()"
    )
    if c_or_provider_api.search(users_text) or re.search(
        r"(?im)^\s*pub\s+(?:struct|enum|trait|type)\s+\w*(?:nss|shadow|utmp|mntent|provider)\w*",
        users_text,
    ):
        errors.append(
            "crabc-rs/src/users.rs: x86 local-account snapshots must defer C/NSS, "
            "shadow, utmp, mntent, and provider-mutation APIs"
        )


def check_x86_child_ownership_boundary(errors: list[str]) -> None:
    """Keep x86 prepared child ownership safe, one-shot, and non-generic."""

    process_source = ROOT / "crabc-rs" / "src" / "process_x86_64.rs"
    process_text = process_source.read_text(errors="replace")
    for required in (
        "pub struct WaitOptions: u32",
        "pub struct WaitStatus(i32);",
        "pub enum FdAction<'fd>",
        "pub struct SpawnOptions<'mask>",
        "pub struct PreparedExec<'fd>",
        "pub fn spawn(&self) -> Result<Child>",
        "pub struct Child",
        "pub fn wait(self, options: WaitOptions) -> Result<Option<WaitStatus>>",
        "crabc_core::pipe::pipe2(crabc_core::io::O_CLOEXEC)",
        "reserve_child_error_fd(initial_writer, &self.actions)",
        "crabc_core::process::fork_raw()",
        "crabc_core::process::execve_raw(",
        "fn wait_child(pid: Pid, options: WaitOptions)",
        "write_child_exec_error_and_exit(writer, error)",
    ):
        if required not in process_text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: admitted x86 child-ownership "
                f"boundary is missing {required}"
            )

    child_declaration = re.search(
        r"#\[cfg\(feature = \"alloc\"\)\]\n#\[derive\((?P<derives>[^)]*)\)\]\n"
        r"pub struct Child\s*\{",
        process_text,
    )
    if child_declaration is None:
        errors.append(
            "crabc-rs/src/process_x86_64.rs: x86 child ownership is missing "
            "the explicit Child declaration"
        )
    elif any(
        trait.strip() in {"Clone", "Copy"}
        for trait in child_declaration.group("derives").split(",")
    ):
        errors.append(
            "crabc-rs/src/process_x86_64.rs: x86 Child must remain a unique "
            "non-Clone, non-Copy wait owner"
        )

    # The selected safe boundary must not accidentally become the wider raw
    # process-control facade. Indented methods are deliberately not matched by
    # the first expression so `Child::wait(self, ...)` remains admitted.
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:fork(?:_raw)?|wait|waitpid|waitpgid|waitid)"
        r"(?:<|\s*\()",
        process_text,
    ):
        errors.append(
            "crabc-rs/src/process_x86_64.rs: x86 child ownership must not expose "
            "a generic fork or wait selector"
        )
    if re.search(r"(?m)^\s+pub\s+unsafe\s+fn\s+exec(?:<|\s*\()", process_text):
        errors.append(
            "crabc-rs/src/process_x86_64.rs: x86 child ownership must defer "
            "direct current-process exec"
        )
    for forbidden in ("pub enum ForkResult", "pub struct BorrowedExec", "pub struct WaitId"):
        if forbidden in process_text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: x86 child ownership must defer "
                f"{forbidden}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("CLONE", 56),
        ("EXECVE", 59),
        ("WAIT4", 61),
        ("WAITID", 247),
        ("EXIT_GROUP", 231),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 child-ownership ABI "
                f"proof is missing SYS_{name}={value}"
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


def check_x86_capacity_metadata_boundary(errors: list[str]) -> None:
    """Keep x86 filesystem-capacity metadata typed, direct, and Rust-only."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    for required in (
        "pub struct StatFs",
        "pub struct StatVfs",
        "pub struct StatVfsMountFlags",
        "pub fn statfs<",
        "pub fn fstatfs<",
        "pub fn statvfs<",
        "pub fn fstatvfs<",
        "crabc_core::fs::fstatfs_raw(",
        "crabc_core::fs::statfs(",
        "f_fsid: statfs.f_fsid[0] as u64,",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 capacity-metadata slice is missing "
                f"{required}"
            )
    for forbidden in (r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"',):
        if re.search(forbidden, text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: capacity-metadata slice must remain "
                "Rust-only"
            )


def check_x86_posix_fallocate_boundary(errors: list[str]) -> None:
    """Keep x86 POSIX range allocation typed and mode-zero."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    start = fs_text.find("pub fn posix_fallocate<")
    end = fs_text.find("\n/// Transfers", start)
    if start < 0 or end < 0:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 posix_fallocate slice is missing"
        )
        return
    posix_text = fs_text[start:end]
    if "fallocate(fd, FallocateFlags::empty(), offset, length)" not in posix_text:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 posix_fallocate delegation must "
            "fix the general mode to FallocateFlags::empty()"
        )
    if "crabc_core::fs::fallocate(" in posix_text:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 posix_fallocate must delegate "
            "through the closed general fallocate boundary"
        )


def check_x86_fallocate_boundary(errors: list[str]) -> None:
    """Keep the x86 general allocation facade closed and preflighted."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    flags_start = fs_text.find("pub struct FallocateFlags: u32")
    flags_end = fs_text.find("\n}\n\nbitflags!", flags_start)
    start = fs_text.find("pub fn fallocate<")
    end = fs_text.find("\n/// Allocates a non-negative", start)
    if flags_start < 0 or flags_end < 0 or start < 0 or end < 0:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 general fallocate slice is missing"
        )
        return
    flags_text = fs_text[flags_start:flags_end]
    general_text = fs_text[start:end]
    for required in (
        "pub struct FallocateFlags: u32",
        "const ALLOCATE = 0",
        "const KEEP_SIZE = 0x01",
        "const PUNCH_HOLE = 0x02",
        "const ZERO_RANGE = 0x10",
    ):
        if required not in flags_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: x86 fallocate flag set is missing "
                f"{required}"
            )
    for forbidden in (
        "NO_HIDE_STALE",
        "COLLAPSE_RANGE",
        "INSERT_RANGE",
        "UNSHARE_RANGE",
    ):
        if forbidden in flags_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: x86 fallocate flag set must not "
                f"expose {forbidden}"
            )
    for required in (
        "FallocateFlags::from_bits",
        "FallocateFlags::PUNCH_HOLE",
        "FallocateFlags::KEEP_SIZE",
        "FallocateFlags::ZERO_RANGE",
        ".checked_add",
        "i64::MAX",
        "crabc_core::fs::fallocate(",
        "flags.bits()",
        "fd.as_fd().as_raw_fd()",
    ):
        if required not in general_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: x86 fallocate boundary is missing "
                f"{required}"
            )

    core_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub fn fallocate(fd: RawFd, mode: u32, offset: i64, length: i64)",
        "SYS_FALLOCATE,",
        "syscall4(",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/fs.rs: x86 fallocate syscall seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    if "pub(crate) const SYS_FALLOCATE: usize = 285" not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: x86 POSIX allocation ABI proof is "
            "missing SYS_FALLOCATE=285"
        )


def check_x86_timestamp_boundary(errors: list[str]) -> None:
    """Keep the named x86 timestamp-mutation family layout-explicit and closed."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    start = fs_text.find("pub type Secs = i64")
    end = fs_text.find("\n/// Allocates, zeros, or punches", start)
    if start < 0 or end < 0:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: admitted x86 timestamp-mutation slice is missing"
        )
        return
    timestamp_text = fs_text[start:end]
    for required in (
        "pub struct TimestampAtFlags: u32",
        "const SYMLINK_NOFOLLOW = 0x0000_0100",
        "pub type Secs = i64",
        "pub type Nsecs = i64",
        "pub struct Timespec",
        "pub const UTIME_NOW: Nsecs = 0x3fff_ffff",
        "pub const UTIME_OMIT: Nsecs = 0x3fff_fffe",
        "pub struct Timestamps",
        "pub struct Timeval",
        "pub struct Utimbuf",
        "[(); 16] = [(); core::mem::size_of::<Timespec>()]",
        "[(); 8] = [(); core::mem::align_of::<Timespec>()]",
        "[(); 32] = [(); core::mem::size_of::<Timestamps>()]",
        "[(); 16] = [(); core::mem::size_of::<Timeval>()]",
        "[(); 8] = [(); core::mem::align_of::<Timeval>()]",
        "pub fn utimensat<",
        "pub fn futimens<",
        "pub fn futimes<",
        "pub fn futimesat<",
        "pub fn lutimes<",
        "pub fn utimes<",
        "pub fn utime<",
        "fn timeval_to_timespec",
        "time.tv_usec < 0 || time.tv_usec >= 1_000_000",
        "crabc_core::fs::utimensat_raw(",
        "fd.as_fd().as_raw_fd()",
        "core::ptr::null()",
        "crabc_core::AT_FDCWD",
        "TimestampAtFlags::SYMLINK_NOFOLLOW.bits()",
        "TimestampAtFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)?",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 timestamp-mutation "
                f"boundary is missing {required}"
            )
    if timestamp_text.count("crabc_core::fs::utimensat_raw(") < 7:
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: each named x86 timestamp-mutation "
            "form must remain on the direct utimensat seam"
        )
    for forbidden in (
        "pub fn utimensat_raw",
        "pub fn utimensat_all",
        "pub fn timestamp_path",
    ):
        if forbidden in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: x86 timestamp mutation must not "
                f"admit a broader pathname API {forbidden}"
            )

    core_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub unsafe fn utimensat_raw(",
        "SYS_UTIMENSAT,",
        "syscall4(",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/fs.rs: x86 timestamp syscall seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    if "pub(crate) const SYS_UTIMENSAT: usize = 280" not in syscall_text:
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: x86 timestamp ABI proof is "
            "missing SYS_UTIMENSAT=280"
        )


def check_x86_fcntl_status_flags_boundary(errors: list[str]) -> None:
    """Keep direct x86 status flags narrower than generic fcntl APIs."""

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
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+fcntl(?:<|\s*\()",
    ):
        if re.search(forbidden, text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 fcntl status-flag slice "
                "must defer generic fcntl"
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
    """Keep direct x86 sendfile separate from splice, openat2, and C APIs."""

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
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+openat2(?:<|\s*\()",
        r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"',
    ):
        if re.search(forbidden, fs_text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 sendfile slice must defer "
                "splice-family, openat2, and C ABI expansion"
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


def check_x86_path_lifecycle_boundary(errors: list[str]) -> None:
    """Keep the selected x86 path-core slice typed, direct, and bounded."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    for required in (
        "pub struct UnlinkAtFlags: u32",
        "pub struct LinkAtFlags: u32",
        "pub struct RenameFlags: u32",
        "pub struct ChownFlags: u32",
        "pub enum FileType",
        "pub type Dev = u64",
        "pub const FIFO_DEVICE: Dev = 0",
        "pub fn truncate<",
        "pub fn lstat<",
        "pub fn openat<",
        "pub fn open<",
        "pub fn create<",
        "pub fn mkdirat<",
        "pub fn mkdir<",
        "pub fn mknodat<",
        "pub fn mkfifoat<",
        "pub fn mkfifo<",
        "pub fn unlinkat<",
        "pub fn unlink<",
        "pub fn rmdir<",
        "pub fn linkat<",
        "pub fn link<",
        "pub fn symlinkat<",
        "pub fn symlink<",
        "pub fn renameat<",
        "pub fn renameat_with<",
        "pub fn rename<",
        "pub fn fchmod<",
        "pub fn chmodat<",
        "pub fn chmod<",
        "pub fn fchown<",
        "pub fn chownat<",
        "pub fn chown<",
        "pub fn lchown<",
        "FileType::Unknown || mode.bits() & !0o7777 != 0",
        "RenameFlags::NOREPLACE",
        "RenameFlags::EXCHANGE",
        "ownership_words(owner, group)?",
        "u32::MAX",
        "crabc_core::fs::openat(",
        "crabc_core::fs::truncate(",
        "crabc_core::fs::mkdirat(",
        "crabc_core::fs::mknodat(",
        "crabc_core::fs::unlinkat(",
        "crabc_core::fs::linkat(",
        "crabc_core::fs::symlinkat(",
        "crabc_core::fs::renameat2(",
        "crabc_core::fs::fchmod(",
        "crabc_core::fs::fchmodat(",
        "crabc_core::fs::fchown(",
        "crabc_core::fs::fchownat(",
        "pub fn readlinkat_raw<",
        "pub fn readlinkat<",
        "pub fn readlink<",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: selected x86 path-core slice is missing "
                f"{required}"
            )

    for forbidden in (
        r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"',
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+openat2(?:<|\s*\()",
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:opendir|fdopendir|readdir|closedir)(?:<|\s*\()",
    ):
        if re.search(forbidden, text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: selected x86 path-core slice must "
                "defer unselected path/runtime APIs"
            )


def check_x86_socket_transport_boundary(errors: list[str]) -> None:
    """Keep the staged x86 socket and interface-device boundaries typed/direct."""

    facade_text = (ROOT / "crabc-rs" / "src" / "lib.rs").read_text(errors="replace")
    net_text = (ROOT / "crabc-rs" / "src" / "net.rs").read_text(errors="replace")
    netdevice_text = (ROOT / "crabc-rs" / "src" / "netdevice.rs").read_text(
        errors="replace"
    )
    core_text = (ROOT / "crabc-core" / "src" / "net.rs").read_text(errors="replace")
    resolver_text = (ROOT / "crabc-core" / "src" / "resolver.rs").read_text(
        errors="replace"
    )

    for required in (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\npub mod net;',
        '#[cfg(all(feature = "alloc", any(target_arch = "aarch64", target_arch = "x86_64")))]\npub mod netdb;',
        '#[cfg(all(feature = "alloc", any(target_arch = "aarch64", target_arch = "x86_64")))]\npub mod resolver;',
    ):
        if required not in facade_text:
            errors.append(
                "crabc-rs/src/lib.rs: staged x86 network transport is missing "
                f"its explicit module boundary {required!r}"
            )

    netdb_text = (ROOT / "crabc-rs" / "src" / "netdb.rs").read_text(errors="replace")
    for required in (
        "pub enum ServiceProtocol",
        "pub struct ServiceDatabase",
        "pub struct ProtocolDatabase",
        "fn parse_service_spec(",
        "fn parse_u16(",
    ):
        if required not in netdb_text:
            errors.append(
                "crabc-rs/src/netdb.rs: staged x86 netdb support is missing "
                f"its admitted service/protocol parser boundary {required}"
            )
    if 'target_arch = "aarch64"' in netdb_text:
        errors.append(
            "crabc-rs/src/netdb.rs: x86 netdb evidence must not leave an "
            "AArch64-only service/protocol gate"
        )

    netdevice_boundary = (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\n'
        '#[path = "netdevice.rs"]\npub mod netdevice;'
    )
    if netdevice_boundary not in net_text:
        errors.append(
            "crabc-rs/src/net.rs: staged x86 network-device operations are missing "
            "their explicit admitted module boundary"
        )

    for required in (
        "fn receive_netlink_packet(",
        "crabc_core::net::recvmsg_raw(",
        "MSG_TRUNC",
    ):
        if required not in netdevice_text:
            errors.append(
                "crabc-rs/src/netdevice.rs: bounded netlink snapshots must reject "
                f"truncated datagrams through {required}"
            )
    if "crabc_core::net::recvfrom_raw(" in netdevice_text:
        errors.append(
            "crabc-rs/src/netdevice.rs: bounded netlink snapshots must not parse "
            "an undetectably truncated recvfrom datagram"
        )

    for required in (
        "const MSG_TRUNC: u32 = 0x20;",
        "fn receive_datagram(",
        "fn compression_target(",
        "net::recvmsg_raw(fd, &iovec, 1, MSG_TRUNC)",
        "fn matching_question_end(",
        "fn has_complete_records(",
        "Err(crate::Errno::OVERFLOW)",
    ):
        if required not in resolver_text:
            errors.append(
                "crabc-core/src/resolver.rs: bounded x86 DNS UDP transport must "
                f"reject partial datagrams and validate {required}"
            )

    for required in (
        "pub fn socketpair(",
        "pub fn socket(",
        "pub fn connect<",
        "pub fn bind<",
        "pub fn listen<",
        "pub fn accept<",
        "pub fn accept_with<",
        "pub fn acceptfrom<",
        "pub fn acceptfrom_with<",
        "pub fn getsockname<",
        "pub fn getpeername<",
        "pub fn shutdown<",
        "pub fn send<",
        "pub fn recv<",
        "pub fn sendmsg<",
        "pub fn recvmsg<",
        "pub fn sendmmsg<",
        "pub fn recvmmsg<",
        "pub fn sendto<",
        "pub fn recvfrom<",
        "pub fn sockatmark<",
        "pub fn socket_type<",
        "pub fn socket_protocol<",
        "pub fn socket_cookie<",
        "pub fn socket_domain<",
        "pub fn socket_acceptconn<",
        "pub fn set_socket_broadcast<",
        "pub fn socket_broadcast<",
        "pub fn set_socket_oobinline<",
        "pub fn socket_oobinline<",
        "size_of::<MMsgHeader>() == 64",
        "offset_of!(MMsgHeader, message_length) == 56",
        "size_of::<SockaddrIn>() == 16",
        "size_of::<SockaddrIn6>() == 28",
        "size_of::<SockaddrStorage>() == 128",
    ):
        if required not in net_text:
            errors.append(
                "crabc-rs/src/net.rs: staged x86 socket transport is missing "
                f"{required}"
            )

    for required in (
        "size_of::<MessageHeader>() == 56",
        "offset_of!(MessageHeader, flags) == 48",
        "SYS_SOCKET",
        "SYS_ACCEPT4",
        "SYS_SENDMMSG",
        "SYS_RECVMMSG",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/net.rs: staged x86 socket transport is missing "
                f"{required}"
            )

    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:setsockopt|getsockopt|ioctl)(?:<|\s*\()",
        net_text,
    ):
        errors.append(
            "crabc-rs/src/net.rs: staged x86 socket transport must not expose "
            "a generic socket-option or ioctl API"
        )


def check_x86_path_core_readlink_boundary(errors: list[str]) -> None:
    """Keep owned x86 readlink exact, byte-preserving, and direct."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    text = fs_source.read_text(errors="replace")
    for required in (
        "pub fn readlinkat_raw<",
        "pub fn readlinkat<",
        "pub fn readlink<",
        "buffer.reserve(SMALL_PATH_BUFFER_SIZE)",
        "if length < capacity",
        "CString::from_vec_unchecked(buffer)",
        "impl PathArg for String",
    ):
        if required not in text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: x86 owned readlink path-core boundary is missing "
                f"{required}"
            )
    for forbidden in (
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+openat2(?:<|\s*\()",
    ):
        if re.search(forbidden, text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: x86 owned readlink must not widen "
                "the selected path-core boundary"
            )


def check_x86_xattr_boundary(errors: list[str]) -> None:
    """Keep direct x86 xattrs caller-buffered, syscall-specific, and private."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub struct XattrFlags: u32",
        "const CREATE = 0x1",
        "const REPLACE = 0x2",
        "const _ = !0",
        "pub fn getxattr<",
        "pub fn lgetxattr<",
        "pub fn fgetxattr<",
        "pub fn setxattr<",
        "pub fn lsetxattr<",
        "pub fn fsetxattr<",
        "pub fn listxattr<",
        "pub fn llistxattr<",
        "pub fn flistxattr<",
        "pub fn removexattr<",
        "pub fn lremovexattr<",
        "pub fn fremovexattr<",
        "crabc_core::fs::getxattr_raw(",
        "crabc_core::fs::lgetxattr_raw(",
        "crabc_core::fs::fgetxattr_raw(",
        "crabc_core::fs::setxattr_raw(",
        "crabc_core::fs::lsetxattr_raw(",
        "crabc_core::fs::fsetxattr_raw(",
        "crabc_core::fs::listxattr_raw(",
        "crabc_core::fs::llistxattr_raw(",
        "crabc_core::fs::flistxattr_raw(",
        "crabc_core::fs::removexattr_raw(",
        "crabc_core::fs::lremovexattr_raw(",
        "crabc_core::fs::fremovexattr_raw(",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 xattr slice is missing "
                f"{required}"
            )

    for forbidden in (
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:name_to_handle_at|open_by_handle_at)(?:<|\s*\()",
        r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"',
    ):
        if re.search(forbidden, fs_text):
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 xattr slice must defer "
                "file-handle and C ABI expansion"
            )

    core_fs_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_fs_text = core_fs_source.read_text(errors="replace")
    for required in (
        "pub unsafe fn setxattr_raw(",
        "pub unsafe fn lsetxattr_raw(",
        "pub unsafe fn fsetxattr_raw(",
        "pub unsafe fn getxattr_raw(",
        "pub unsafe fn lgetxattr_raw(",
        "pub unsafe fn fgetxattr_raw(",
        "pub unsafe fn listxattr_raw(",
        "pub unsafe fn llistxattr_raw(",
        "pub unsafe fn flistxattr_raw(",
        "pub unsafe fn removexattr_raw(",
        "pub unsafe fn lremovexattr_raw(",
        "pub unsafe fn fremovexattr_raw(",
    ):
        if required not in core_fs_text:
            errors.append(
                "crabc-core/src/fs.rs: admitted x86 xattr syscall boundary is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("SETXATTR", 188),
        ("LSETXATTR", 189),
        ("FSETXATTR", 190),
        ("GETXATTR", 191),
        ("LGETXATTR", 192),
        ("FGETXATTR", 193),
        ("LISTXATTR", 194),
        ("LLISTXATTR", 195),
        ("FLISTXATTR", 196),
        ("REMOVEXATTR", 197),
        ("LREMOVEXATTR", 198),
        ("FREMOVEXATTR", 199),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 xattr ABI proof is missing "
                f"SYS_{name}={value}"
            )


def check_x86_directory_boundary(errors: list[str]) -> None:
    """Keep x86 directory records caller-buffered, typed, and outside C DIR."""

    facade_source = ROOT / "crabc-rs" / "src" / "lib.rs"
    facade_text = facade_source.read_text(errors="replace")
    for required in (
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\nmod raw_dir;',
        '#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]\npub use raw_dir::{RawDir, RawDirEntry};',
    ):
        if required not in facade_text:
            errors.append(
                "crabc-rs/src/lib.rs: admitted x86 directory records are missing "
                f"their explicit shared module boundary {required!r}"
            )

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub use crate::{RawDir, RawDirEntry};",
        "pub(crate) const fn from_dirent_d_type",
        "pub struct Dir<'buffer>",
        "pub type DirEntry<'entry> = RawDirEntry<'entry>;",
        "pub fn open<P: PathArg>",
        "pub fn openat<P: PathArg, Fd: AsFd>",
        "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC",
        "pub fn from_owned_fd",
        "RawDir::new(fd, buffer)",
        "pub fn rewind(&mut self)",
        "pub fn seek(&mut self, offset: i64)",
        "pub fn next(&mut self) -> Option<Result<DirEntry<'_>>>",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 directory slice is missing "
                f"{required}"
            )
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:opendir|fdopendir|readdir|readdir_r|"
        r"closedir|telldir|seekdir|rewinddir|scandir)(?:<|\s*\()",
        fs_text,
    ):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: admitted x86 directory slice must not expose "
            "a C DIR-style or bulk directory API"
        )

    raw_source = ROOT / "crabc-rs" / "src" / "raw_dir.rs"
    raw_text = raw_source.read_text(errors="replace")
    for required in (
        "const LINUX_DIRENT64_HEADER_SIZE: usize = 19;",
        "const LINUX_DIRENT64_ALIGNMENT: usize = align_of::<u64>();",
        "crabc_core::fs::getdents64_raw(",
        "crabc_core::fs::lseek(",
        "Err(Errno::INTR) => continue",
        "FileType::from_dirent_d_type(d_type)",
        "pub struct RawDir<'buffer, Fd: AsFd>",
        "pub struct RawDirEntry<'entry>",
    ):
        if required not in raw_text:
            errors.append(
                "crabc-rs/src/raw_dir.rs: admitted x86 getdents64 record boundary is missing "
                f"{required}"
            )

    core_fs_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_fs_text = core_fs_source.read_text(errors="replace")
    if "pub unsafe fn getdents64_raw(" not in core_fs_text:
        errors.append(
            "crabc-core/src/fs.rs: admitted x86 directory slice is missing getdents64_raw"
        )
    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (("GETDENTS64", 217), ("LSEEK", 8), ("OPENAT", 257)):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 directory ABI proof is "
                f"missing SYS_{name}={value}"
            )


def check_x86_temporary_object_boundary(errors: list[str]) -> None:
    """Keep x86 temporary ownership descriptor-relative and free of C fallbacks."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub const TEMP_FILE_RANDOM_BYTES: usize = 12;",
        "pub const TEMP_FILE_MAX_ATTEMPTS: usize = 128;",
        "pub struct NamedTempFile",
        "pub fn create_temp_file<P: PathArg, Prefix: PathArg>",
        "pub fn create_temp_file_at<Fd: AsFd, Prefix: PathArg>",
        "crate::io::fcntl_dupfd_cloexec(parent, 0)",
        "OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC",
        "pub struct TempFile",
        "OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC",
        "pub const TEMP_DIR_RANDOM_BYTES: usize = 12;",
        "pub const TEMP_DIR_MAX_ATTEMPTS: usize = 128;",
        "const TEMP_DIR_PATH_MAX: usize = 4096;",
        "pub fn create_temp_dir_into<P: PathArg, Prefix: PathArg, Buf: Buffer<u8>>",
        "pub fn create_temp_dir_at_into<Fd: AsFd, Prefix: PathArg, Buf: Buffer<u8>>",
        "create_temp_dir_at_bytes(&directory, prefix_bytes, &mut basename)",
        "crate::rand::getentropy(&mut entropy)?",
        "UnlinkAtFlags::empty()",
        "UnlinkAtFlags::REMOVEDIR",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 temporary-object slice is missing "
                f"{required}"
            )
    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:mkstemp|mkdtemp|tmpfile|tempnam|tmpnam|"
        r"chdir|fchdir|name_to_handle_at|open_by_handle_at)(?:<|\s*\()",
        fs_text,
    ):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: admitted x86 temporary-object slice must not expose "
            "C temporary, CWD-mutation, or file-handle APIs"
        )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("OPENAT", 257),
        ("MKDIRAT", 258),
        ("UNLINKAT", 263),
        ("GETRANDOM", 318),
        ("FCNTL", 72),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: admitted x86 temporary-object ABI proof is "
                f"missing SYS_{name}={value}"
            )

    io_source = ROOT / "crabc-core" / "src" / "io.rs"
    if "pub fn fcntl_dupfd_cloexec(" not in io_source.read_text(errors="replace"):
        errors.append(
            "crabc-core/src/io.rs: admitted x86 temporary named-file cleanup is missing "
            "F_DUPFD_CLOEXEC ownership support"
        )


def check_x86_statx_boundary(errors: list[str]) -> None:
    """Keep direct x86 statx typed, stateless, and operation-specific."""

    fs_source = ROOT / "crabc-rs" / "src" / "fs_x86_64.rs"
    fs_text = fs_source.read_text(errors="replace")
    for required in (
        "pub struct StatxAtFlags: u32",
        "const SYMLINK_NOFOLLOW = 0x0000_0100",
        "const NO_AUTOMOUNT = 0x0000_0800",
        "const EMPTY_PATH = 0x0000_1000",
        "const FORCE_SYNC = 0x0000_2000",
        "const DONT_SYNC = 0x0000_4000",
        "pub struct StatxFlags: u32",
        "pub const RESERVED_MASK: u32 = 0x8000_0000",
        "pub struct StatxAttributes: u64",
        "pub struct Statx",
        "pub struct StatxTimestamp",
        "pub fn statx<P: PathArg, Fd: AsFd>",
        "crabc_core::fs::statx_raw(",
        "flags.bits(),",
        "mask.bits(),",
        "const _: [(); 256] = [(); core::mem::size_of::<Statx>()];",
        "const _: [(); 156] = [(); core::mem::offset_of!(Statx, stx_dio_offset_align)];",
    ):
        if required not in fs_text:
            errors.append(
                "crabc-rs/src/fs_x86_64.rs: admitted x86 statx slice is missing "
                f"{required}"
            )

    at_flags = re.search(
        r"pub struct AtFlags: u32 \{(?P<body>.*?)^    \}",
        fs_text,
        re.MULTILINE | re.DOTALL,
    )
    if at_flags is None:
        errors.append("crabc-rs/src/fs_x86_64.rs: x86 fstatat flags are missing")
    elif re.search(
        r"const\s+(?:EMPTY_PATH|NO_AUTOMOUNT|FORCE_SYNC|DONT_SYNC)\b",
        at_flags.group("body"),
    ):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: statx flags must not widen the closed x86 AtFlags type"
        )

    if re.search(
        r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', fs_text
    ) or re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:__xstat|fstatat64)(?:<|\s*\()",
        fs_text,
    ):
        errors.append(
            "crabc-rs/src/fs_x86_64.rs: x86 statx slice must not select a C metadata ABI"
        )

    core_fs_source = ROOT / "crabc-core" / "src" / "fs.rs"
    core_fs_text = core_fs_source.read_text(errors="replace")
    for required in (
        "pub unsafe fn statx_raw(",
        "const STATX_RESERVED: u32 = 0x8000_0000;",
        "const STATX_KNOWN_MASK: u32 = 0x0000_3fff;",
        "if mask & STATX_RESERVED != 0",
        "let mask = mask & STATX_KNOWN_MASK;",
        "syscall5(",
        "SYS_STATX,",
    ):
        if required not in core_fs_text:
            errors.append(
                "crabc-core/src/fs.rs: admitted x86 statx seam is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    if "pub(crate) const SYS_STATX: usize = 332" not in syscall_source.read_text(
        errors="replace"
    ):
        errors.append(
            "crabc-core/src/syscall_x86_64.rs: admitted x86 statx ABI proof is missing SYS_STATX=332"
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


def check_x86_memory_mapping_boundary(errors: list[str]) -> None:
    """Ratchet the selected x86 mapping lifecycle without widening its siblings.

    This check deliberately covers only `mmap`, `mmap_anonymous`, `mprotect`,
    and `munmap`. The existing remap, locking, synchronization, advisory, and
    residency APIs are separately admitted x86 boundaries; their presence must
    not be mistaken for evidence that this `memory.mapping` slice owns them.
    """

    facade_source = ROOT / "crabc-rs" / "src" / "mm_x86_64.rs"
    facade_text = facade_source.read_text(errors="replace")
    facade_root = (ROOT / "crabc-rs" / "src" / "lib.rs").read_text(errors="replace")
    required_facade_module = (
        '#[cfg(target_arch = "x86_64")]\n'
        '#[path = "mm_x86_64.rs"]\npub mod mm;'
    )
    if required_facade_module not in facade_root:
        errors.append(
            "crabc-rs/src/lib.rs: selected x86 mapping lifecycle is missing its "
            "explicit mm_x86_64 module boundary"
        )

    def flag_body(name: str) -> str | None:
        match = re.search(
            rf"(?ms)pub struct {name}: u32\s*\{{(?P<body>.*?)^\}}",
            facade_text,
        )
        if match is None:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle is "
                f"missing closed {name}"
            )
            return None
        return match.group("body")

    for name, expected in (
        ("ProtFlags", ("READ", "WRITE", "EXEC")),
        ("MprotectFlags", ("READ", "WRITE", "EXEC")),
        ("MapFlags", ("SHARED", "PRIVATE")),
    ):
        body = flag_body(name)
        if body is None:
            continue
        actual = tuple(re.findall(r"(?m)^\s*const\s+([A-Z][A-Z0-9_]*)\s*=", body))
        if actual != expected or re.search(r"(?m)^\s*const\s+_\s*=", body):
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle must "
                f"keep {name} closed to {', '.join(expected)}"
            )

    for required in (
        "const MAP_ANONYMOUS: u32 = 0x20;",
        "const SUPPORTED_PROTECTION_BITS: u32 =",
        "ProtFlags::READ.bits() | ProtFlags::WRITE.bits() | ProtFlags::EXEC.bits();",
        "const SUPPORTED_MAP_BITS: u32 = MapFlags::SHARED.bits() | MapFlags::PRIVATE.bits();",
        "fn checked_protection_bits(bits: u32) -> Result<u32>",
        "if bits & !SUPPORTED_PROTECTION_BITS == 0",
        "fn checked_map_bits(flags: MapFlags) -> Result<u32>",
        "if bits & !SUPPORTED_MAP_BITS != 0 || kind == 0 || kind == SUPPORTED_MAP_BITS",
    ):
        if required not in facade_text:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle is "
                f"missing closed-flag proof {required}"
            )

    def function_body(marker: str) -> str | None:
        start = facade_text.find(marker)
        if start < 0:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle is "
                f"missing {marker}"
            )
            return None
        end = facade_text.find("\n}\n", start)
        if end < 0:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle has "
                f"an unclosed {marker} body"
            )
            return None
        return facade_text[start:end]

    selected_functions = (
        (
            "pub unsafe fn mmap<",
            (
                "let prot = checked_protection_bits(prot.bits())?;",
                "let flags = checked_map_bits(flags)?;",
                "crabc_core::mm::mmap_raw(",
                "fd.as_raw_fd(),",
                "offset,",
            ),
        ),
        (
            "pub unsafe fn mmap_anonymous(",
            (
                "let prot = checked_protection_bits(prot.bits())?;",
                "let flags = checked_map_bits(flags)?;",
                "crabc_core::mm::mmap_raw(",
                "flags | MAP_ANONYMOUS,",
                "-1,",
                "0,",
            ),
        ),
        (
            "pub unsafe fn mprotect(",
            (
                "let flags = checked_protection_bits(flags.bits())?;",
                "crabc_core::mm::mprotect_raw(ptr.cast(), len, flags)",
            ),
        ),
        (
            "pub unsafe fn munmap(",
            ("crabc_core::mm::munmap_raw(ptr.cast(), len)",),
        ),
    )
    for marker, required in selected_functions:
        body = function_body(marker)
        if body is None:
            continue
        for entry in required:
            if entry not in body:
                errors.append(
                    "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle "
                    f"must directly retain {entry} in {marker}"
                )
        for forbidden in (
            "mremap",
            "mlock",
            "munlock",
            "msync",
            "madvise",
            "mincore",
            "brk",
            "MAP_FIXED",
        ):
            if forbidden in body:
                errors.append(
                    "crabc-rs/src/mm_x86_64.rs: selected x86 mapping lifecycle "
                    f"must not widen {marker} through {forbidden}"
                )

    core_source = ROOT / "crabc-core" / "src" / "mm_x86_64.rs"
    core_text = core_source.read_text(errors="replace")
    core_root = (ROOT / "crabc-core" / "src" / "lib.rs").read_text(errors="replace")
    required_core_module = (
        '#[cfg(target_arch = "x86_64")]\n'
        '#[path = "mm_x86_64.rs"]\npub mod mm;'
    )
    if required_core_module not in core_root:
        errors.append(
            "crabc-core/src/lib.rs: selected x86 mapping lifecycle is missing its "
            "explicit mm_x86_64 module boundary"
        )
    for required in (
        "pub unsafe fn mmap_raw(",
        "syscall6(\n            SYS_MMAP,",
        "pub unsafe fn mprotect_raw(address: *mut u8, length: usize, flags: u32) -> Result<()>",
        "syscall3(SYS_MPROTECT, address as usize, length, flags as usize)",
        "pub unsafe fn munmap_raw(address: *mut u8, length: usize) -> Result<()>",
        "syscall2(SYS_MUNMAP, address as usize, length)",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/mm_x86_64.rs: selected x86 mapping lifecycle "
                f"is missing direct kernel seam {required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (("MMAP", 9), ("MPROTECT", 10), ("MUNMAP", 11)):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: selected x86 mapping lifecycle "
                f"is missing SYS_{name}={value}"
            )


def check_x86_memory_vm_boundary(errors: list[str]) -> None:
    """Keep the x86 raw-break and VM-policy slice distinct from mapping life.

    `memory.mapping` owns ordinary mapping/protection/unmap behavior. This
    check instead ratchets only raw-break query/replay, process-global
    lock-all policy, and legacy file-page remapping. It does not turn the
    separately admitted per-range locking, advice, residency, synchronization,
    or ordinary remapping APIs into evidence for this slice.
    """

    facade_root = (ROOT / "crabc-rs" / "src" / "lib.rs").read_text(errors="replace")
    for required in (
        '#[cfg(target_arch = "x86_64")]\n#[path = "mm_x86_64.rs"]\npub mod mm;',
        '#[cfg(target_arch = "x86_64")]\n#[path = "process_x86_64.rs"]\npub mod process;',
    ):
        if required not in facade_root:
            errors.append(
                "crabc-rs/src/lib.rs: selected x86 memory.vm is missing its explicit "
                f"module boundary {required!r}"
            )

    process_source = ROOT / "crabc-rs" / "src" / "process_x86_64.rs"
    process_text = process_source.read_text(errors="replace")
    for required in (
        "pub unsafe fn kernel_brk(address: *mut c_void) -> Result<*mut c_void>",
        "crabc_core::process::brk_raw(address.cast())",
        "This is the Rustix-style kernel primitive",
        "changes process-global heap state",
    ):
        if required not in process_text:
            errors.append(
                "crabc-rs/src/process_x86_64.rs: selected x86 memory.vm raw-break "
                f"boundary is missing {required}"
            )
    if re.search(r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:brk|sbrk)(?:<|\s*\()", process_text):
        errors.append(
            "crabc-rs/src/process_x86_64.rs: x86 memory.vm must expose only kernel_brk, "
            "not libc-style brk/sbrk adapters"
        )

    facade_source = ROOT / "crabc-rs" / "src" / "mm_x86_64.rs"
    facade_text = facade_source.read_text(errors="replace")
    match = re.search(
        r"(?ms)pub struct MlockAllFlags: u32\s*\{(?P<body>.*?)^\}", facade_text
    )
    if match is None:
        errors.append(
            "crabc-rs/src/mm_x86_64.rs: selected x86 memory.vm is missing MlockAllFlags"
        )
    else:
        actual = tuple(
            (constant, re.sub(r"\s+", "", value))
            for constant, value in re.findall(
                r"(?m)^\s*const\s+([A-Z_][A-Z0-9_]*)\s*=\s*([^;]+);",
                match.group("body"),
            )
        )
        expected = (("CURRENT", "0x1"), ("FUTURE", "0x2"), ("ONFAULT", "0x4"))
        if actual != expected:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 memory.vm must keep "
                "MlockAllFlags closed to CURRENT, FUTURE, and ONFAULT"
            )

    def function_body(marker: str) -> str | None:
        start = facade_text.find(marker)
        if start < 0:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 memory.vm is missing " + marker
            )
            return None
        end = facade_text.find("\n}\n", start)
        if end < 0:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 memory.vm has an unclosed " + marker
            )
            return None
        return facade_text[start:end]

    for marker, direct_call in (
        (
            "pub fn mlockall(flags: MlockAllFlags) -> Result<()>",
            "crabc_core::mm::mlockall_raw(flags.bits())",
        ),
        ("pub fn munlockall() -> Result<()>", "crabc_core::mm::munlockall_raw()"),
        (
            "pub unsafe fn remap_file_pages(",
            "crabc_core::mm::remap_file_pages_raw(ptr.cast(), len, page_offset)",
        ),
    ):
        body = function_body(marker)
        if body is not None and direct_call not in body:
            errors.append(
                "crabc-rs/src/mm_x86_64.rs: selected x86 memory.vm must directly retain "
                f"{direct_call} in {marker}"
            )

    if re.search(
        r"(?m)^pub\s+(?:unsafe\s+)?fn\s+(?:"
        r"mlockall_raw|munlockall_raw|remap_file_pages_raw|"
        r"brk|sbrk|process_madvise|userfaultfd|membarrier"
        r")(?:<|\s*\()",
        facade_text,
    ):
        errors.append(
            "crabc-rs/src/mm_x86_64.rs: x86 memory.vm must defer raw libc-shaped "
            "adapters and broader VM-control APIs"
        )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', facade_text):
        errors.append("crabc-rs/src/mm_x86_64.rs: x86 memory.vm must not select a C ABI")

    probe_source = ROOT / "crabc-rs" / "examples" / "memory_vm_direct_probe.rs"
    probe_text = probe_source.read_text(errors="replace")
    for required in (
        "use crabc_rs::process::kernel_brk;",
        "mm::remap_file_pages(mapping, PAGE_SIZE, 0)",
        "mm::mlockall(MlockAllFlags::CURRENT).map(|_| mm::munlockall())",
    ):
        if required not in probe_text:
            errors.append(
                "crabc-rs/examples/memory_vm_direct_probe.rs: selected x86 memory.vm "
                f"probe is missing its narrow boundary {required}"
            )
    for marker in (
        r'let advisory = unsafe \{ mm::posix_madvise\(',
        r'if let Err\(error\) = advisory',
    ):
        if not re.search(
            r'(?m)^\s*#\[cfg\(target_arch = "aarch64"\)\]\n\s*' + marker,
            probe_text,
        ):
            errors.append(
                "crabc-rs/examples/memory_vm_direct_probe.rs: selected x86 memory.vm "
                "must cfg-gate its inherited POSIX-advice probe step to AArch64"
            )

    core_process_source = ROOT / "crabc-core" / "src" / "process.rs"
    core_process_text = core_process_source.read_text(errors="replace")
    for required in (
        "pub unsafe fn brk_raw(address: *mut u8) -> *mut u8",
        "syscall1(SYS_BRK, address as usize)",
    ):
        if required not in core_process_text:
            errors.append(
                "crabc-core/src/process.rs: selected x86 memory.vm raw-break seam is "
                f"missing {required}"
            )

    core_source = ROOT / "crabc-core" / "src" / "mm_x86_64.rs"
    core_text = core_source.read_text(errors="replace")
    for required in (
        "pub fn mlockall_raw(flags: u32) -> Result<()>",
        "syscall1(SYS_MLOCKALL, flags as usize)",
        "pub fn munlockall_raw() -> Result<()>",
        "syscall0(SYS_MUNLOCKALL)",
        "pub unsafe fn remap_file_pages_raw(",
        "syscall5(\n            SYS_REMAP_FILE_PAGES,",
        "address as usize,\n            size,\n            0,\n            page_offset,\n            0,",
    ):
        if required not in core_text:
            errors.append(
                "crabc-core/src/mm_x86_64.rs: selected x86 memory.vm direct seam is "
                f"missing {required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (
        ("BRK", 12),
        ("MLOCKALL", 151),
        ("MUNLOCKALL", 152),
        ("REMAP_FILE_PAGES", 216),
    ):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: selected x86 memory.vm ABI proof is "
                f"missing SYS_{name}={value}"
            )


def check_x86_terminal_boundary(errors: list[str]) -> None:
    """Guard the private x86 PTY/session and typed terminal-control seam.

    PTY construction remains safe and forces O_NOCTTY. The only terminal
    transition is the explicit unsafe pair handoff; the x86 TCGETS record
    remains private to the named Rust termios operations.
    """

    facade_root = (ROOT / "crabc-rs" / "src" / "lib.rs").read_text(errors="replace")
    required_module = (
        '#[cfg(target_arch = "x86_64")]\n'
        '#[path = "pty_x86_64.rs"]\npub mod pty;'
    )
    if required_module not in facade_root:
        errors.append(
            "crabc-rs/src/lib.rs: selected x86 terminal.pty-basic is missing its "
            "explicit pty_x86_64 module boundary"
        )
    required_termios_module = (
        '#[cfg(target_arch = "x86_64")]\n'
        '#[path = "termios_x86_64.rs"]\npub mod termios;'
    )
    if required_termios_module not in facade_root:
        errors.append(
            "crabc-rs/src/lib.rs: selected x86 terminal boundary is missing its "
            "explicit termios_x86_64 module boundary"
        )

    facade_source = ROOT / "crabc-rs" / "src" / "pty_x86_64.rs"
    facade_text = facade_source.read_text(errors="replace")
    for required in (
        "pub struct OpenptFlags: u32",
        "pub struct PtyPair {",
        "pub fn open(flags: OpenptFlags) -> Result<Self>",
        "pub fn master(&self) -> BorrowedFd<'_>",
        "pub fn slave(&self) -> BorrowedFd<'_>",
        "pub fn into_parts(self) -> (OwnedFd, OwnedFd)",
        "pub unsafe fn set_controlling_terminal(&self, steal: bool) -> Result<()>",
        "pub unsafe fn establish_session_and_controlling_terminal(&self, steal: bool) -> Result<()>",
        "pub fn openpt(flags: OpenptFlags) -> Result<OwnedFd>",
        "pub fn grantpt<Fd: AsFd>(fd: Fd) -> Result<()>",
        "pub fn unlockpt<Fd: AsFd>(fd: Fd) -> Result<()>",
        "pub fn ptsname_into<'buffer, Fd: AsFd>(",
        "pub fn ptsname<Fd: AsFd, B: Into<Vec<u8>>>(fd: Fd, reuse: B) -> Result<CString>",
        'fs::open("/dev/ptmx", flags.into(), Mode::empty())',
        "let slave = open_peer_noctty(&master, flags | OpenptFlags::NOCTTY)?;",
        "crabc_core::io::ioctl_raw(",
        "const TIOCGPTN: u32 = 0x8004_5430;",
        "const TIOCSPTLCK: u32 = 0x4004_5431;",
        "const TIOCGPTPEER: u32 = 0x5441;",
        "const TIOCSCTTY: u32 = 0x540e;",
        "crabc_core::process::setsid()?",
        "# Safety",
    ):
        if required not in facade_text:
            errors.append(
                "crabc-rs/src/pty_x86_64.rs: selected x86 terminal.pty-basic boundary is "
                f"missing {required}"
            )

    public_functions = tuple(
        re.findall(r"(?m)^pub\s+(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)", facade_text)
    )
    if public_functions != ("openpt", "grantpt", "unlockpt", "ptsname_into", "ptsname"):
        errors.append(
            "crabc-rs/src/pty_x86_64.rs: x86 terminal boundary must keep its "
            "free functions to the bounded master/pair/name seam"
        )
    if re.search(r'(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"', facade_text):
        errors.append(
            "crabc-rs/src/pty_x86_64.rs: x86 terminal.pty-basic must not select a C ABI"
        )
    if re.search(
        r"(?m)^\s*pub\s+(?:unsafe\s+)?fn\s+(?:"
        r"ioctl_tiocgptpeer|posix_openpt|ptsname_r|openpty|forkpty|login_tty|vhangup"
        r")(?:<|\s*\()",
        facade_text,
    ):
        errors.append(
            "crabc-rs/src/pty_x86_64.rs: x86 terminal boundary must not expose "
            "generic peer-open or C-shaped PTY/session APIs"
        )
    for forbidden in ("crate::termios",):
        if forbidden in facade_text:
            errors.append(
                "crabc-rs/src/pty_x86_64.rs: x86 terminal boundary must defer "
                f"{forbidden}"
            )

    termios_source = ROOT / "crabc-rs" / "src" / "termios_x86_64.rs"
    termios_text = termios_source.read_text(errors="replace")
    for required in (
        "struct KernelTermios {",
        "const _: [(); 36] = [(); core::mem::size_of::<KernelTermios>()];",
        "const _: [(); 4] = [(); core::mem::align_of::<KernelTermios>()];",
        "offset_of!(KernelTermios, input_modes)",
        "offset_of!(KernelTermios, output_modes)",
        "offset_of!(KernelTermios, control_modes)",
        "offset_of!(KernelTermios, local_modes)",
        "offset_of!(KernelTermios, line_discipline)",
        "offset_of!(KernelTermios, special_codes)",
        "pub struct Termios {",
        "pub struct SpecialCodes(pub(crate) [u8; 19]);",
        "pub struct Winsize {",
        "pub fn tcgetattr<Fd: AsFd>(fd: Fd) -> Result<Termios>",
        "pub fn tcsetattr<Fd: AsFd>(fd: Fd, action: OptionalActions, termios: &Termios)",
        "pub fn tcgetwinsize<Fd: AsFd>(fd: Fd) -> Result<Winsize>",
        "pub fn tcsetwinsize<Fd: AsFd>(fd: Fd, size: Winsize) -> Result<()>",
        "pub fn ioctl_tiocexcl<Fd: AsFd>(fd: Fd) -> Result<()>",
        "pub fn ioctl_tiocnxcl<Fd: AsFd>(fd: Fd) -> Result<()>",
        "pub fn tcgetpgrp<Fd: AsFd>(fd: Fd) -> Result<Pid>",
        "pub fn tcsetpgrp<Fd: AsFd>(fd: Fd, pgrp: Pid) -> Result<()>",
        "pub fn tcgetsid<Fd: AsFd>(fd: Fd) -> Result<Pid>",
        "pub fn isatty<Fd: AsFd>(fd: Fd) -> bool",
        "pub fn ttyname_into<'buffer, Fd: AsFd>(",
        "pub fn ttyname<Fd: AsFd, B: Into<Vec<u8>>>(fd: Fd, reuse: B) -> Result<CString>",
        "pub fn tcdrain<Fd: AsFd>(fd: Fd) -> Result<()>",
        "pub fn tcflush<Fd: AsFd>(fd: Fd, queue: QueueSelector) -> Result<()>",
        "pub fn tcflow<Fd: AsFd>(fd: Fd, action: Action) -> Result<()>",
        "pub fn tcsendbreak<Fd: AsFd>(fd: Fd) -> Result<()>",
        "const TCGETS: u32 = 0x5401;",
        "const TCSETS: u32 = 0x5402;",
        "const TIOCEXCL: u32 = 0x540c;",
        "const TIOCGSID: u32 = 0x5429;",
        "const CBAUD: u32 = 0x100f;",
        "const CIBAUD: u32 = 0x100f_0000;",
        "CIBAUD's zero selector is the distinct B0 input setting on Linux",
        "buffer.reserve(fs::SMALL_PATH_BUFFER_SIZE);",
    ):
        if required not in termios_text:
            errors.append(
                "crabc-rs/src/termios_x86_64.rs: selected x86 terminal boundary is "
                f"missing {required}"
            )
    for forbidden in (
        "pub struct KernelTermios",
        'extern "C"',
        "crate::ioctl::ioctl",
        "pub unsafe fn",
    ):
        if forbidden in termios_text:
            errors.append(
                "crabc-rs/src/termios_x86_64.rs: x86 terminal boundary must not "
                f"expose or reuse {forbidden}"
            )

    probe_source = ROOT / "crabc-rs" / "examples" / "pty_basic_direct_probe.rs"
    probe_text = probe_source.read_text(errors="replace")
    for required in (
        "#![no_std]",
        "pub extern \"C\" fn crabc_rs_pty_basic_direct_probe() -> i32",
        "PtyPair::open(",
        "pty::ptsname_into(pair.master(), &mut storage)",
        "io::write(pair.slave(), b\"x\")",
        "io::read(pair.master(), &mut received)",
    ):
        if required not in probe_text:
            errors.append(
                "crabc-rs/examples/pty_basic_direct_probe.rs: selected x86 terminal.pty-basic "
                f"probe is missing {required}"
            )
    for forbidden in ("setsid", "TIOCSCTTY", "use crabc_rs::termios", "termios::"):
        if forbidden in probe_text:
            errors.append(
                "crabc-rs/examples/pty_basic_direct_probe.rs: x86 terminal.pty-basic probe "
                f"must defer {forbidden}"
            )

    test_source = ROOT / "crabc-rs" / "tests" / "x86_64_terminal.rs"
    test_text = test_source.read_text(errors="replace")
    for required in (
        '#![cfg(target_arch = "x86_64")]',
        "x86_64_terminal_attributes_queue_special_codes_and_window_size_round_trip",
        "x86_64_terminal_name_and_exclusive_mode_are_typed_and_bounded",
        "x86_64_explicit_session_handoff_is_confined_to_a_child",
        "raw_process::fork_raw()",
        "raw_process::wait4_raw",
        "pair.establish_session_and_controlling_terminal(false)",
        "termios::tcgetattr",
        "raw.make_raw()",
        "changed.set_input_speed(0)",
        "termios::ttyname_into",
    ):
        if required not in test_text:
            errors.append(
                "crabc-rs/tests/x86_64_terminal.rs: selected x86 terminal regression "
                f"is missing {required}"
            )

    terminal_probe = ROOT / "crabc-rs" / "examples" / "x86_64_terminal_direct_probe.rs"
    terminal_probe_text = terminal_probe.read_text(errors="replace")
    for required in (
        "#![no_std]",
        'pub extern "C" fn crabc_rs_x86_64_terminal_direct_probe() -> i32',
        "PtyPair::open(",
        "termios::tcgetattr",
        "termios::ttyname_into",
        "termios::ioctl_tiocexcl",
        "changed.make_raw()",
        "changed.set_input_speed(0)",
        "raw_process::fork_raw()",
        "pair.establish_session_and_controlling_terminal(false)",
    ):
        if required not in terminal_probe_text:
            errors.append(
                "crabc-rs/examples/x86_64_terminal_direct_probe.rs: selected x86 "
                f"terminal probe is missing {required}"
            )

    oracle_runner = ROOT / "compat" / "x86_64" / "run_x86_terminal_reference.sh"
    oracle_runner_text = oracle_runner.read_text(errors="replace")
    for required in (
        "crabc-x86_64-musl-gcc",
        "x86_terminal_reference_probe.c",
        "refuses emulation",
        "raw+musl=pty-rawmode-termios-queue-exclusive-ttyname-session",
    ):
        if required not in oracle_runner_text:
            errors.append(
                "compat/x86_64/run_x86_terminal_reference.sh: selected x86 terminal "
                f"oracle is missing {required}"
            )

    oracle_source = ROOT / "compat" / "x86_64" / "x86_terminal_reference_probe.c"
    oracle_text = oracle_source.read_text(errors="replace")
    for required in (
        "sizeof(struct kernel_termios_x86) == 36",
        "sizeof(struct termios) == 60",
        "NCCS == 32",
        "SYS_ioctl == 16",
        "SYS_setsid == 112",
        "TIOCSCTTY == 0x540eUL",
        "TIOCGSID == 0x5429UL",
        "terminal_session_child",
        "compare_kernel_and_public",
        "make_kernel_raw",
        "CIBAUD) == B0",
    ):
        if required not in oracle_text:
            errors.append(
                "compat/x86_64/x86_terminal_reference_probe.c: selected x86 terminal "
                f"oracle is missing {required}"
            )

    runner_text = (ROOT / "scripts" / "dev-x86_64.sh").read_text(errors="replace")
    for required in (
        "run_terminal_reference()",
        "--test x86_64_terminal",
        "--example x86_64_terminal_direct_probe",
        "run_x86_terminal_reference.sh",
    ):
        if required not in runner_text:
            errors.append(
                "scripts/dev-x86_64.sh: selected x86 terminal command is missing "
                f"{required}"
            )

    syscall_source = ROOT / "crabc-core" / "src" / "syscall_x86_64.rs"
    syscall_text = syscall_source.read_text(errors="replace")
    for name, value in (("IOCTL", 16), ("SETSID", 112), ("CLONE", 56), ("WAIT4", 61)):
        required = f"pub(crate) const SYS_{name}: usize = {value}"
        if required not in syscall_text:
            errors.append(
                "crabc-core/src/syscall_x86_64.rs: selected x86 terminal ABI proof "
                f"is missing SYS_{name}={value}"
        )


def check_x86_header_layouts_baseline(errors: list[str]) -> None:
    """Keep the C/C++ aggregate a consumer-only header/layout artifact.

    It may compose existing selected C archive APIs to prove real static C++
    linkage, but it must not become another implementation module, a new C
    export, or a hidden C++ runtime/constructor path.
    """

    c_probe_path = ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_probe.c"
    cxx_probe_path = ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_probe.cpp"
    start_path = ROOT / "compat" / "x86_64" / "libc_header_layouts_baseline_start.S"
    runner_path = ROOT / "compat" / "x86_64" / "run_libc_header_layouts_baseline.sh"
    for path in (c_probe_path, cxx_probe_path, start_path, runner_path):
        if not path.is_file():
            errors.append(f"x86 header-layout baseline is missing {path.relative_to(ROOT)}")
            return

    c_probe = c_probe_path.read_text(errors="replace")
    cxx_probe = cxx_probe_path.read_text(errors="replace")
    start = start_path.read_text(errors="replace")
    runner = runner_path.read_text(errors="replace")
    static_root = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
    ).read_text(errors="replace")
    exports = (
        ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
    ).read_text(errors="replace")

    headers = (
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
    )
    for header in headers:
        include = f"#include <{header}>"
        if include not in c_probe or include not in cxx_probe:
            errors.append(
                "compat/x86_64: static C/C++ header-layout baseline must use "
                f"the project {header} header in both fixtures"
            )
    for required in (
        "crabc_x86_64_header_layouts_baseline_cxx_probe",
        "check_observation_records",
        "check_mapping_records",
        "check_descriptor_records",
        "check_signal_and_termios_records",
        "CRABC_HEADER_LAYOUTS_BASELINE_FREESTANDING",
    ):
        if required not in c_probe:
            errors.append(
                "compat/x86_64/libc_header_layouts_baseline_probe.c: static "
                f"header-layout baseline is missing {required!r}"
            )
    for required in (
        'extern "C" int crabc_x86_64_header_layouts_baseline_cxx_probe',
        "check_cpp_observation",
        "check_cpp_mapping",
        "check_cpp_descriptor_and_signal",
    ):
        if required not in cxx_probe:
            errors.append(
                "compat/x86_64/libc_header_layouts_baseline_probe.cpp: "
                f"freestanding C++ companion is missing {required!r}"
            )
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
        if forbidden in cxx_probe:
            errors.append(
                "compat/x86_64/libc_header_layouts_baseline_probe.cpp: "
                f"freestanding C++ companion must not contain {forbidden!r}"
            )
    for required in (
        "ARCH_SET_FS",
        "mov %rsi, %fs:0",
        "crabc_x86_64_header_layouts_baseline_probe",
    ):
        if required not in start:
            errors.append(
                "compat/x86_64/libc_header_layouts_baseline_start.S: fixture "
                f"TLS shim is missing {required!r}"
            )
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
        if required not in runner:
            errors.append(
                "compat/x86_64/run_libc_header_layouts_baseline.sh: static "
                f"C/C++ boundary is missing {required!r}"
            )
    if "--whole-archive" in runner:
        errors.append(
            "compat/x86_64/run_libc_header_layouts_baseline.sh: static "
            "C/C++ boundary must not force-link the whole archive"
        )
    if "header_layouts_baseline" in static_root:
        errors.append(
            "libc/src/c_abi/x86_64/static_c_abi.rs: header-layout baseline "
            "must remain a fixture, not a selected implementation module"
        )
    if "header_layouts_baseline" in exports:
        errors.append(
            "compat/x86_64/static_c_abi_exports.txt: header-layout baseline "
            "must not introduce a C export"
        )


def check_x86_crt_libc_static_tls_handoff(errors: list[str]) -> None:
    """Keep first-thread TLS ownership in libc and the rcrt1 static-link edge."""

    crt_startup_source = ROOT / "crt" / "src" / "x86_64_startup.rs"
    crt_startup = crt_startup_source.read_text(errors="replace")
    bootstrap_call = "if unsafe { __crabc_x86_static_tls_bootstrap(initial_stack) } != 0"
    lifecycle_call = "unsafe {\n        __libc_start_main("
    for required in (
        "use core::ffi::c_int;",
        "type ApplicationMain = unsafe extern \"C\" fn",
        "type LifecycleHook = unsafe extern \"C\" fn();",
        "fn __crabc_x86_static_tls_bootstrap(initial_stack: *const usize) -> c_int;",
        'core::arch::global_asm!(".hidden __crabc_x86_static_tls_bootstrap");',
        bootstrap_call,
        "startup_reject();",
        lifecycle_call,
    ):
        if required not in crt_startup:
            errors.append(
                "crt/src/x86_64_startup.rs: rcrt1 must retain the hidden libc "
                "Static Initial TLS v1 handoff"
            )
    if bootstrap_call in crt_startup and lifecycle_call in crt_startup and (
        crt_startup.index(bootstrap_call) > crt_startup.index(lifecycle_call)
    ):
        errors.append(
            "crt/src/x86_64_startup.rs: libc TLS bootstrap must precede lifecycle startup"
        )
    for forbidden in (
        "x86_64_static_tls",
        "install_initial_static_tls",
        "ARCH_SET_FS",
        "SYS_ARCH_PRCTL",
    ):
        if forbidden in crt_startup:
            errors.append(
                "crt/src/x86_64_startup.rs: CRT must not retain a first-thread TLS "
                f"owner ({forbidden!r})"
            )
    if (ROOT / "crt" / "src" / "x86_64_static_tls.rs").exists():
        errors.append(
            "crt: first-thread x86 TLS must be libc-owned, not an rcrt1 module"
        )


def check_x86_libc_static_c_abi_boundary(errors: list[str]) -> None:
    """Keep the selected x86 static C archive to its named vertical slices."""

    libc_root = ROOT / "libc" / "src" / "lib.rs"
    root_text = libc_root.read_text(errors="replace")
    required_module = (
        '#[cfg(all(target_os = "linux", target_arch = "x86_64", target_endian = "little"))]\n'
        '#[path = "c_abi/x86_64/static_c_abi.rs"]\n'
        "mod x86_64_static_c_abi;"
    )
    if required_module not in root_text:
        errors.append(
            "libc/src/lib.rs: selected x86 static C ABI needs its explicit separate "
            "target root"
        )

    static_root_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
    static_root_text = static_root_source.read_text(errors="replace")
    for required in (
        '#[path = "errno.rs"]',
        '#[path = "syscall.rs"]',
        '#[path = "static_tls.rs"]',
        '#[path = "static_startup.rs"]',
        '#[path = "stat_compat.rs"]',
        '#[path = "timestamp_updates.rs"]',
        '#[path = "credentials.rs"]',
        '#[path = "credential_observation.rs"]',
        '#[path = "memory.rs"]',
        '#[path = "fenv.rs"]',
        '#[path = "setjmp.rs"]',
        '#[path = "signal_foundation.rs"]',
        '#[path = "signal_control.rs"]',
        '#[path = "signal_execution.rs"]',
        '#[path = "pthread_identity.rs"]',
        '#[path = "pthread_create_join.rs"]',
        '#[path = "c11_thread_lifecycle.rs"]',
        '#[path = "termios_control.rs"]',
        '#[path = "process_context.rs"]',
        '#[path = "child_reaping.rs"]',
        '#[path = "immediate_termination.rs"]',
        '#[path = "callback_algorithms.rs"]',
        '#[path = "clock_gettime.rs"]',
        '#[path = "clock_nanosleep.rs"]',
        '#[path = "nanosleep.rs"]',
        '#[path = "descriptor_entry.rs"]',
        '#[path = "filesystem_access.rs"]',
        '#[path = "descriptor_control.rs"]',
        '#[path = "ioctl.rs"]',
        '#[path = "descriptor_io.rs"]',
        '#[path = "process_resources.rs"]',
        '#[path = "memory_mapping.rs"]',
        '#[path = "readiness_waits.rs"]',
        '#[path = "socket_transport.rs"]',
        '#[path = "byte_strings.rs"]',
        '#[path = "random_entropy.rs"]',
        '#[path = "memory_search.rs"]',
        '#[path = "string_copy.rs"]',
        '#[path = "ctype.rs"]',
        '#[path = "integer_arithmetic.rs"]',
        '#[path = "integer_parse.rs"]',
        '#[path = "intmax_arithmetic.rs"]',
        '#[path = "ffs.rs"]',
        '#[path = "system_observation.rs"]',
        '#[path = "uts_identity.rs"]',
        "fn c_status",
        "fn c_pointer_status",
        "fn c_ssize_status",
        "fn c_off_status",
        "fn rust_eh_personality",
    ):
        if required not in static_root_text:
            errors.append(
                "libc/src/c_abi/x86_64/static_c_abi.rs: selected static C ABI root "
                f"is missing {required!r}"
            )

    static_startup_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_startup.rs"
    static_startup_text = static_startup_source.read_text(errors="replace")
    for required in (
        "Static Initial TLS v1",
        "const ATEXIT_CAPACITY: usize = 32;",
        "pub unsafe extern \"C\" fn __cxa_atexit(",
        "pub unsafe extern \"C\" fn atexit(",
        "pub unsafe extern \"C\" fn __funcs_on_exit()",
        "pub unsafe extern \"C\" fn __cxa_finalize(",
        "pub unsafe extern \"C\" fn _exit(",
        "pub unsafe extern \"C\" fn exit(",
        "pub unsafe extern \"C\" fn __libc_start_main(",
        "if rtld_fini.is_some() || !static_tls::is_ready()",
        "if fini.is_some() && unsafe { atexit(fini) } != 0",
        "immediate_termination::_Exit(127)",
    ):
        if required not in static_startup_text:
            errors.append(
                "libc/src/c_abi/x86_64/static_startup.rs: selected static "
                f"startup boundary is missing {required!r}"
            )
    static_startup_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            static_startup_text,
        )
    )
    expected_static_startup_exports = {
        "__cxa_atexit",
        "atexit",
        "__funcs_on_exit",
        "__cxa_finalize",
        "_exit",
        "exit",
        "__libc_start_main",
    }
    if static_startup_exports != expected_static_startup_exports:
        errors.append(
            "libc/src/c_abi/x86_64/static_startup.rs: selected static startup "
            "artifact must export only its bounded lifecycle symbols"
        )

    stat_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "stat_compat.rs"
    stat_text = stat_source.read_text(errors="replace")
    for required in (
        "struct Stat",
        "size_of::<Stat>() == 144",
        "align_of::<Stat>() == 8",
        "raw_syscall::SYS_FSTAT",
        "raw_syscall::SYS_NEWFSTATAT",
        "raw_syscall::syscall2(",
        "raw_syscall::syscall4(",
        "AT_FDCWD",
        "AT_SYMLINK_NOFOLLOW",
        "c_status(result)",
    ):
        if required not in stat_text:
            errors.append(
                "libc/src/c_abi/x86_64/stat_compat.rs: selected static stat boundary "
                f"is missing {required!r}"
            )

    credentials_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "credentials.rs"
    credentials_text = credentials_source.read_text(errors="replace")
    for required in (
        "fn setgroups(",
        "fn setuid(",
        "fn setgid(",
        "fn setresuid(",
        "fn setresgid(",
        "fn seteuid(",
        "fn setegid(",
        "fn setreuid(",
        "fn setregid(",
        "raw_syscall::SYS_SETGROUPS",
        "raw_syscall::SYS_SETUID",
        "raw_syscall::SYS_SETGID",
        "raw_syscall::SYS_SETRESUID",
        "raw_syscall::SYS_SETRESGID",
        "EOPNOTSUPP",
        "c_status(result)",
    ):
        if required not in credentials_text:
            errors.append(
                "libc/src/c_abi/x86_64/credentials.rs: selected static credential "
                f"boundary is missing {required!r}"
            )

    errno_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "errno.rs"
    errno_text = errno_source.read_text(errors="replace")
    if "#[thread_local]" not in errno_text or "fn __errno_location" not in errno_text:
        errors.append(
            "libc/src/c_abi/x86_64/errno.rs: selected static C ABI must retain its "
            "initial-TLS errno slot"
        )

    static_tls_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_tls.rs"
    static_tls_text = static_tls_source.read_text(errors="replace")
    for required in (
        "StaticInitialTlsPlan",
        "StaticInitialTlsBlock",
        "pub(super) struct StaticInitialTlsBlock",
        "AT_PHDR",
        "AT_PHENT",
        "AT_PHNUM",
        "PT_PHDR",
        "PT_TLS",
        "ET_EXEC",
        "ELF64_HEADER_SIZE",
        "from_initial_stack",
        "variant_ii_image_offset",
        "ARCH_SET_FS",
        "raw_syscall::SYS_ARCH_PRCTL",
        "raw_syscall::SYS_MMAP",
        "raw_syscall::SYS_MUNMAP",
        "bootstrap_initial_thread",
        "allocate_thread",
        "release_thread",
        "STATIC_INITIAL_TLS_STATE",
        "STATIC_INITIAL_TLS_PLAN",
        "TLS_STATE_READY",
        "__crabc_x86_static_tls_bootstrap",
        ".hidden __crabc_x86_static_tls_bootstrap",
    ):
        if required not in static_tls_text:
            errors.append(
                "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
                f"owner is missing {required!r}"
            )
    load_bias_marker = "let load_bias = match program_header_virtual_address"
    load_bias_end = "let (image, filesz, memsz, tls_alignment)"
    if load_bias_marker not in static_tls_text or load_bias_end not in static_tls_text:
        errors.append(
            "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
            "must select a validated PT_PHDR or ET_EXEC load-bias path"
        )
    else:
        load_bias_text = static_tls_text.split(load_bias_marker, 1)[1].split(
            load_bias_end, 1
        )[0]
        if (
            "Some(program_header_virtual_address)" not in load_bias_text
            or "static_executable_load_bias_without_pt_phdr" not in load_bias_text
        ):
            errors.append(
                "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
                "must retain both its PT_PHDR and controlled ET_EXEC load-bias branches"
            )
    et_exec_fallback_marker = "unsafe fn static_executable_load_bias_without_pt_phdr"
    et_exec_fallback_end = "/// Locate the auxiliary vector"
    if (
        et_exec_fallback_marker not in static_tls_text
        or et_exec_fallback_end not in static_tls_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
            "is missing its controlled no-PT_PHDR ET_EXEC fallback"
        )
    else:
        et_exec_fallback_text = static_tls_text.split(et_exec_fallback_marker, 1)[1].split(
            et_exec_fallback_end, 1
        )[0]
        for required in (
            "ET_EXEC",
            "ELF64_HEADER_SIZE",
            "ELF64_CLASS",
            "ELFDATA2LSB",
            "EV_CURRENT",
            "EM_X86_64",
            "virtual_range_within_readable_file_load",
            "Some(0)",
            "!= ET_EXEC",
        ):
            if required not in et_exec_fallback_text:
                errors.append(
                    "libc/src/c_abi/x86_64/static_tls.rs: controlled no-PT_PHDR "
                    f"ET_EXEC fallback is missing {required!r}"
                )
    static_tls_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            static_tls_text,
        )
    )
    if static_tls_exports != {"__crabc_x86_static_tls_bootstrap"}:
        errors.append(
            "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
            "must expose only its hidden freestanding bootstrap hook"
        )
    if not re.search(
        r'(?s)#\[no_mangle\]\s*pub\s+unsafe\s+extern\s+"C"\s+fn\s+'
        r"__crabc_x86_static_tls_bootstrap\s*\(",
        static_tls_text,
    ):
        errors.append(
            "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
            "bootstrap hook must retain its unmangled C link name"
        )
    for forbidden in (
        "__tls_get_addr",
        "TLSGD",
        "TLSLD",
        "TLSDESC",
        "dlopen",
        "initial_errno_offset",
        "INITIAL_TLS_REGION_SIZE",
        "child_errno",
        "child_thread_pointer",
    ):
        if forbidden in static_tls_text:
            errors.append(
                "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
                f"must not select {forbidden!r}"
            )

    memory_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory.rs"
    memory_text = memory_source.read_text(errors="replace")
    for required in (
        "src/string/x86_64/memcpy.s",
        "src/string/x86_64/memmove.s",
        "src/string/x86_64/memset.s",
        "src/string/memcmp.c",
        "src/string/bcmp.c",
        ".global memcpy",
        ".global memcmp",
        ".global bcmp",
        ".global memset",
        ".global memmove",
        "xor eax, eax",
        "std",
        "cld",
    ):
        if required not in memory_text:
            errors.append(
                "libc/src/c_abi/x86_64/memory.rs: selected static memory "
                f"boundary is missing {required!r}"
            )

    fenv_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "fenv.rs"
    fenv_text = fenv_source.read_text(errors="replace")
    for required in (
        "struct Fenv",
        "size_of::<Fenv>()",
        ".global feclearexcept",
        ".global fegetenv",
        ".global fesetenv",
        ".global fetestexcept",
        "fn fegetexceptflag",
        "fn feholdexcept",
        "fn fesetexceptflag",
        "fn fesetround",
        "fn feupdateenv",
        "fn __flt_rounds",
    ):
        if required not in fenv_text:
            errors.append(
                "libc/src/c_abi/x86_64/fenv.rs: selected static fenv boundary "
                f"is missing {required!r}"
            )

    setjmp_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "setjmp.rs"
    setjmp_text = setjmp_source.read_text(errors="replace")
    for required in (
        ".global setjmp",
        ".global longjmp",
        ".global sigsetjmp",
        ".global siglongjmp",
        "mov eax, 14",
        "mov r10d, 8",
    ):
        if required not in setjmp_text:
            errors.append(
                "libc/src/c_abi/x86_64/setjmp.rs: selected static continuation "
                f"boundary is missing {required!r}"
            )

    signal_foundation_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_foundation.rs"
    )
    signal_foundation_text = signal_foundation_source.read_text(errors="replace")
    for required in (
        "struct PublicSigAction",
        "struct KernelSigAction",
        "PUBLIC_SIGSET_WORDS: usize = 16",
        "SA_RESTORER: u64 = 0x0400_0000",
        ".hidden crabc_x86_64_signal_restorer",
        "mov rax, 15",
        "fn pack_public_action",
        "fn unpack_kernel_action",
    ):
        if required not in signal_foundation_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_foundation.rs: selected static signal "
                f"boundary is missing {required!r}"
            )
    if "#[no_mangle]" in signal_foundation_text:
        errors.append(
            "libc/src/c_abi/x86_64/signal_foundation.rs: frame packing must not "
            "export a public C bridge from the selected archive"
        )
    if "crabc_x86_64_signal_action_pack" in signal_foundation_text:
        errors.append(
            "libc/src/c_abi/x86_64/signal_foundation.rs: source-only bridge must "
            "stay outside the selected archive"
        )

    signal_control_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_control.rs"
    )
    signal_control_text = signal_control_source.read_text(errors="replace")
    for required in (
        "raw_syscall::SYS_RT_SIGACTION",
        "raw_syscall::SYS_RT_SIGPROCMASK",
        "raw_syscall::SYS_RT_SIGPENDING",
        "raw_syscall::syscall4(",
        "raw_syscall::syscall2(",
        "size_of::<u64>()",
        "RESERVED_SIGNAL_MASK",
        "pack_public_action",
        "unpack_kernel_action",
        "SIGRTMAX: c_int = 64",
    ):
        if required not in signal_control_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_control.rs: selected static signal "
                f"boundary is missing {required!r}"
            )
    signal_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_control_text,
        )
    )
    expected_signal_exports = {
        "sigaction",
        "signal",
        "sigemptyset",
        "sigfillset",
        "sigaddset",
        "sigdelset",
        "sigismember",
        "sigprocmask",
        "sigpending",
        "__libc_current_sigrtmax",
    }
    if signal_exports != expected_signal_exports:
        errors.append(
            "libc/src/c_abi/x86_64/signal_control.rs: selected static signal "
            "artifact must export only simple action/set/mask/pending symbols"
        )

    pthread_identity_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_identity.rs"
    )
    pthread_identity_text = pthread_identity_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "arch/x86_64/pthread_arch.h::__get_tp()",
        "src/internal/pthread_impl.h::__pthread_self()",
        "src/thread/pthread_self.c",
        "src/thread/pthread_equal.c",
        "pub(super) fn current_thread_pointer()",
        "mov {thread_pointer}, fs:[0]",
        "options(readonly, nostack, preserves_flags)",
        ".weak pthread_self",
        ".set thrd_current, pthread_self",
        ".weak pthread_equal",
        ".set thrd_equal, pthread_equal",
        "mov rax, qword ptr fs:[0]",
        "cmp rdi, rsi",
        "sete al",
    ):
        if required not in pthread_identity_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_identity.rs: bounded static "
                f"pthread identity leaf is missing {required!r}"
            )
    pthread_identity_exports = set(
        re.findall(r"(?m)^\s*\.weak\s+(\w+)\s*$", pthread_identity_text)
    )
    if pthread_identity_exports != {
        "pthread_self",
        "thrd_current",
        "pthread_equal",
        "thrd_equal",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_identity.rs: selected static identity "
            "leaf must emit exactly the four weak pthread/C11 identity symbols"
        )
    pthread_identity_aliases = dict(
        re.findall(r"(?m)^\s*\.set\s+(\w+)\s*,\s*(\w+)\s*$", pthread_identity_text)
    )
    if pthread_identity_aliases != {
        "thrd_current": "pthread_self",
        "thrd_equal": "pthread_equal",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_identity.rs: selected static identity "
            "leaf must retain musl's weak same-address C11 aliases"
        )
    if "#[no_mangle]" in pthread_identity_text:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_identity.rs: public identity symbols "
            "must remain weak assembler definitions rather than strong Rust exports"
        )

    pthread_create_join_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_create_join.rs"
    )
    pthread_create_join_text = pthread_create_join_source.read_text(errors="replace")
    c11_thread_lifecycle_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "c11_thread_lifecycle.rs"
    )
    c11_thread_lifecycle_text = c11_thread_lifecycle_source.read_text(errors="replace")
    for required in (
        "src/thread/pthread_create.c::__pthread_create",
        "src/thread/pthread_create.c::__pthread_exit",
        "src/thread/x86_64/clone.s::__clone",
        "src/thread/pthread_join.c",
        "src/thread/pthread_detach.c",
        "struct ThreadControl",
        "PTHREAD_CLONE_FLAGS",
        "CLONE_SETTLS",
        "CLONE_PARENT_SETTID",
        "CLONE_CHILD_CLEARTID",
        "FUTEX_WAIT",
        "raw_syscall::SYS_MMAP",
        "raw_syscall::SYS_MUNMAP",
        "raw_syscall::SYS_FUTEX",
        "static_tls::is_ready()",
        "static_tls::allocate_thread()",
        "static_tls::release_thread(tls_block)",
        "static_tls::StaticInitialTlsBlock",
        "start_ready",
        "tls_released",
        "tls_block.thread_pointer()",
        "SELECTED_WORKER_REGISTRY_SIZE",
        "SELECTED_WORKER_REGISTRY",
        "SELECTED_WORKER_REGISTRY_LOCK",
        "reserve_selected_worker",
        "claim_selected_worker_by_thread_pointer",
        "publish_current_selected_worker_result",
        "release_selected_worker",
        "release_selected_worker_locked",
        "reclaim_withdrawn_selected_worker",
        "reap_finished_detached_selected_workers",
        "SelectedWorkerLifecycleState",
        "DetachedReclaiming",
        "pthread_identity::current_thread_pointer",
        "current_linux_thread_id",
        "raw_syscall::SYS_GETTID",
        "registry_retired",
        "finished",
        ".hidden __crabc_x86_pthread_clone",
        "pthread_create",
        "pthread_exit",
        "pthread_join",
        "pthread_detach",
        "tls_block.thread_pointer().cast()",
        "ENOTSUP",
    ):
        if required not in pthread_create_join_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: bounded static "
                f"pthread worker is missing {required!r}"
            )
    for forbidden in (
        "initial_errno_offset",
        "INITIAL_TLS_REGION_SIZE",
        "child_errno",
        "child_thread_pointer",
        "SYS_ARCH_PRCTL",
        "ARCH_SET_FS",
    ):
        if forbidden in pthread_create_join_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: bounded static "
                f"pthread worker must not retain fixed errno-only TLS machinery {forbidden!r}"
            )
    pthread_create_join_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            pthread_create_join_text,
        )
    )
    if pthread_create_join_exports != {
        "pthread_create",
        "pthread_exit",
        "pthread_join",
        "pthread_detach",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: bounded static "
            "pthread worker must export only pthread_create, pthread_exit, pthread_join, and pthread_detach"
        )
    public_pthread_create_marker = 'pub unsafe extern "C" fn pthread_create'
    public_pthread_create_end = (
        "/// Create one selected default-attribute worker for the pthread or C11 leaf."
    )
    if (
        public_pthread_create_marker not in pthread_create_join_text
        or public_pthread_create_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: bounded static "
            "pthread worker is missing its public create validation boundary"
        )
    else:
        public_pthread_create_text = pthread_create_join_text.split(
            public_pthread_create_marker, 1
        )[1].split(public_pthread_create_end, 1)[0]
        invalid_inputs = "if thread.is_null() || start.is_none()"
        unsupported_attributes = "if !attributes.is_null()"
        if (
            invalid_inputs not in public_pthread_create_text
            or unsupported_attributes not in public_pthread_create_text
            or public_pthread_create_text.index(invalid_inputs)
            > public_pthread_create_text.index(unsupported_attributes)
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: pthread_create "
                "must retain invalid thread/start EINVAL precedence before "
                "unsupported-attribute ENOTSUP"
            )
    selected_join_marker = "pub(super) unsafe fn join_selected_worker"
    if selected_join_marker not in pthread_create_join_text:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: bounded static "
            "pthread worker is missing its join boundary"
        )
    else:
        pthread_join_text = pthread_create_join_text.split(selected_join_marker, 1)[1].split(
            "/// Join one normal-returning", 1
        )[0]
        join_claim_marker = "claim_selected_worker_by_thread_pointer("
        if (
            join_claim_marker not in pthread_join_text
            or "SelectedWorkerLifecycleState::JoinClaimed" not in pthread_join_text
            or "(*control)" not in pthread_join_text
            or pthread_join_text.index(join_claim_marker)
            > pthread_join_text.index("(*control)")
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: join must resolve "
                "the public TP handle under its registry lock before dereferencing "
                "the private control record"
            )
        if (
            "release_selected_worker" not in pthread_join_text
            or "reclaim_withdrawn_selected_worker(control)" not in pthread_join_text
            or pthread_join_text.index("release_selected_worker")
            > pthread_join_text.index("reclaim_withdrawn_selected_worker(control)")
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: join must withdraw "
                "the selected worker registry before shared completed-worker reclamation"
            )
    reclaim_marker = "unsafe fn reclaim_withdrawn_selected_worker"
    reclaim_end = "/// Reap every detached selected worker"
    if reclaim_marker not in pthread_create_join_text or reclaim_end not in pthread_create_join_text:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
            "is missing its shared completed-worker reclamation boundary"
        )
    else:
        tls_reclamation = pthread_create_join_text.split(reclaim_marker, 1)[1].split(
            reclaim_end, 1
        )[0]
        if (
            "tls_released.load(Ordering::Acquire)" not in tls_reclamation
            or "tls_released.store(1, Ordering::Release)" not in tls_reclamation
            or "static_tls::release_thread(tls_block)" not in tls_reclamation
            or "unmap_worker" not in tls_reclamation
            or tls_reclamation.index("static_tls::release_thread(tls_block)")
            > tls_reclamation.index("unmap_worker")
            or tls_reclamation.index("static_tls::release_thread(tls_block)")
            > tls_reclamation.index("tls_released.store(1, Ordering::Release)")
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: completed-worker "
                "reclamation must release full TLS once before control-map unmapping"
            )
    detach_marker = "pub(super) unsafe fn detach_selected_worker"
    detach_end = "/// Detach one selected static pthread/C11 worker"
    if detach_marker not in pthread_create_join_text or detach_end not in pthread_create_join_text:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
            "is missing its detach ownership boundary"
        )
    else:
        detach_text = pthread_create_join_text.split(detach_marker, 1)[1].split(detach_end, 1)[0]
        if (
            "SelectedWorkerLifecycleState::Detached" not in detach_text
            or "claim_selected_worker_by_thread_pointer" not in detach_text
            or "reap_finished_detached_selected_workers" in detach_text
            or "reclaim_withdrawn_selected_worker" in detach_text
            or "raw_syscall" in detach_text
            or "unmap_worker" in detach_text
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: detach must remain "
                "a prompt state-only ownership transition"
            )
    detached_claim_marker = "fn claim_finished_detached_selected_worker"
    detached_claim_end = "/// Release mappings for a registry-withdrawn"
    if (
        detached_claim_marker not in pthread_create_join_text
        or detached_claim_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
            "is missing its clear-child-tid detached reaper claim"
        )
    else:
        detached_claim_text = pthread_create_join_text.split(detached_claim_marker, 1)[1].split(
            detached_claim_end, 1
        )[0]
        required_detached_order = (
            "SelectedWorkerLifecycleState::Detached.encode()",
            "child_tid.load(Ordering::Acquire)",
            "SelectedWorkerLifecycleState::DetachedReclaiming.encode()",
            "release_selected_worker_locked",
        )
        if any(marker not in detached_claim_text for marker in required_detached_order) or any(
            detached_claim_text.index(left) > detached_claim_text.index(right)
            for left, right in zip(required_detached_order, required_detached_order[1:])
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: detached reaping must "
                "claim only a clear-child-tid detached worker before withdrawal"
            )
    explicit_exit_publish_marker = "fn publish_current_selected_worker_result"
    explicit_exit_publish_end = "/// Map one control/stack backing range"
    if (
        explicit_exit_publish_marker not in pthread_create_join_text
        or explicit_exit_publish_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread exit "
            "is missing its bounded registry publication helper"
        )
    else:
        explicit_exit_publish_text = pthread_create_join_text.split(
            explicit_exit_publish_marker, 1
        )[1].split(explicit_exit_publish_end, 1)[0]
        if (
            "worker_tid.load" not in explicit_exit_publish_text
            or "child_tid.load" not in explicit_exit_publish_text
            or explicit_exit_publish_text.index("lock_selected_worker_registry")
            > explicit_exit_publish_text.index("publish_worker_result")
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread exit "
                "must hold its registry lock through matching worker/gettid/child-TID publication"
            )

    worker_entry_marker = 'unsafe extern "C" fn worker_entry'
    worker_entry_end = "/// Create one default-attribute"
    if (
        worker_entry_marker not in pthread_create_join_text
        or worker_entry_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
            "is missing its start readiness boundary"
        )
    else:
        worker_entry_text = pthread_create_join_text.split(worker_entry_marker, 1)[1].split(
            worker_entry_end, 1
        )[0]
        if (
            "start_ready.load(Ordering::Acquire)" not in worker_entry_text
            or "current_linux_thread_id()" not in worker_entry_text
            or worker_entry_text.index("start_ready.load(Ordering::Acquire)")
            > worker_entry_text.index("current_linux_thread_id()")
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
                "must acquire its initialized control record before reading worker state"
            )

    pthread_create_marker = "pub(super) unsafe fn create_selected_worker"
    pthread_create_end = "/// Exit a selected worker"
    if (
        pthread_create_marker not in pthread_create_join_text
        or pthread_create_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
            "is missing its Static Initial TLS v1 create boundary"
        )
    else:
        pthread_create_text = pthread_create_join_text.split(pthread_create_marker, 1)[1].split(
            pthread_create_end, 1
        )[0]
        required_order = (
            "static_tls::is_ready()",
            "reap_finished_detached_selected_workers()",
            "static_tls::allocate_thread()",
            "start_ready.store(1, Ordering::Release)",
            "__crabc_x86_pthread_clone(",
        )
        if any(marker not in pthread_create_text for marker in required_order):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
                "must materialize and publish Static Initial TLS v1 before clone"
            )
        elif any(
            pthread_create_text.index(left) > pthread_create_text.index(right)
            for left, right in zip(required_order, required_order[1:])
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
                "must validate, allocate, release-publish, then clone in that order"
            )
        clone_failure_marker = "if is_linux_error(clone_result)"
        clone_failure_end = "// SAFETY: clone succeeded"
        if (
            clone_failure_marker not in pthread_create_text
            or clone_failure_end not in pthread_create_text
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread worker "
                "is missing its clone-failure cleanup boundary"
            )
        else:
            clone_failure_text = pthread_create_text.split(clone_failure_marker, 1)[1].split(
                clone_failure_end, 1
            )[0]
            if (
                "if !release_selected_worker" not in clone_failure_text
                or "return EAGAIN" not in clone_failure_text
                or "unmap_worker" not in clone_failure_text
                or clone_failure_text.index("if !release_selected_worker")
                > clone_failure_text.index("unmap_worker")
            ):
                errors.append(
                    "libc/src/c_abi/x86_64/pthread_create_join.rs: failed clone must "
                    "retain mappings when registry withdrawal cannot prove no dangling pointer"
                )

    # The C11 lifecycle is a typed static sibling of the selected pthread
    # worker, not a reason to reintroduce an ABI-unsafe callback cast or a
    # broad C11 synchronization/runtime surface.
    for required in (
        "pub(super) type C11StartRoutine",
        "enum SelectedWorkerStart",
        "C11(C11StartRoutine)",
        "SelectedWorkerResult::C11",
        "SelectedWorkerResultKind",
        "result_kind: AtomicU8",
        "exit_selected_pthread_worker",
        "exit_selected_c11_worker",
        "join_selected_worker",
        "SelectedWorkerResultKind::Invalid",
    ):
        if required not in pthread_create_join_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: typed C11 "
                f"selected-worker seam is missing {required!r}"
            )
    if re.search(
        r"C11StartRoutine[^\n]*as[^\n]*(?:PthreadStartRoutine|StartRoutine)",
        pthread_create_join_text,
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: C11 callbacks must not be "
            "cast to the pthread pointer-return callback type"
        )
    for required in (
        "musl 1.2.6 release commit",
        "src/thread/thrd_create.c",
        "src/thread/pthread_create.c::start_c11",
        "src/thread/thrd_join.c",
        "src/thread/thrd_exit.c",
        "src/thread/thrd_detach.c",
        "C11StartRoutine",
        "SelectedWorkerStart::C11",
        "THRD_SUCCESS",
        "THRD_ERROR",
        "THRD_NOMEM",
        "fn thrd_create(",
        "fn thrd_join(",
        "fn thrd_exit(",
        "fn thrd_detach(",
        "detach_selected_worker",
        "exit_selected_c11_worker",
        "SelectedWorkerResultKind::C11",
        "decode_c11_result",
        "INT_MIN",
        "INT_MAX",
        "dynamic/loader TLS",
        "public x86 support",
    ):
        if required not in c11_thread_lifecycle_text:
            errors.append(
                "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs: bounded static "
                f"C11 lifecycle leaf is missing {required!r}"
            )
    c11_thread_lifecycle_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            c11_thread_lifecycle_text,
        )
    )
    if c11_thread_lifecycle_exports != {
        "thrd_create",
        "thrd_join",
        "thrd_exit",
        "thrd_detach",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs: bounded static C11 "
            "leaf must export only thrd_create, thrd_join, thrd_exit, and thrd_detach"
        )
    for forbidden in (
        "fn thrd_sleep(",
        "fn thrd_yield(",
        "fn call_once(",
        "fn mtx_",
        "fn cnd_",
        "fn tss_",
        "pthread_mutex",
        "__tls_get_addr",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in c11_thread_lifecycle_text:
            errors.append(
                "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs: bounded static C11 "
                f"leaf must not select {forbidden!r}"
            )

    termios_control_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "termios_control.rs"
    )
    termios_control_text = termios_control_source.read_text(errors="replace")
    for required in (
        "struct PublicTermios",
        "struct KernelTermios",
        "struct Winsize",
        "size_of::<PublicTermios>()",
        "size_of::<KernelTermios>()",
        "size_of::<Winsize>()",
        "raw_syscall::SYS_IOCTL",
        "raw_syscall::syscall3(",
        "CBAUD",
        "CIBAUD",
        "TCSANOW",
        "TCSAFLUSH",
        "TCGETS",
        "TCSETS",
        "TCFLSH",
        "TCXONC",
        "TCSBRK",
        "TIOCGWINSZ",
        "TIOCSWINSZ",
        "TCSETS + i64::from(action)",
        "TCSBRK, 0",
    ):
        if required not in termios_control_text:
            errors.append(
                "libc/src/c_abi/x86_64/termios_control.rs: selected static termios "
                f"boundary is missing {required!r}"
            )
    termios_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            termios_control_text,
        )
    )
    expected_termios_exports = {
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
    }
    if termios_exports != expected_termios_exports:
        errors.append(
            "libc/src/c_abi/x86_64/termios_control.rs: selected static termios "
            "artifact must export only its named baud/raw/control symbols"
        )

    process_context_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_context.rs"
    )
    process_context_text = process_context_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/unistd/getpid.c",
        "src/unistd/setpgid.c",
        "src/stat/umask.c",
        "raw_syscall::SYS_GETPID",
        "raw_syscall::SYS_GETPPID",
        "raw_syscall::SYS_GETUID",
        "raw_syscall::SYS_GETGID",
        "raw_syscall::SYS_GETEUID",
        "raw_syscall::SYS_GETEGID",
        "raw_syscall::SYS_UMASK",
        "raw_syscall::SYS_SETSID",
        "raw_syscall::SYS_SETPGID",
        "raw_syscall::SYS_GETPGID",
        "raw_syscall::SYS_GETSID",
        "raw_syscall::syscall0(",
        "raw_syscall::syscall1(",
        "raw_syscall::syscall2(",
        "c_status(result)",
    ):
        if required not in process_context_text:
            errors.append(
                "libc/src/c_abi/x86_64/process_context.rs: selected static "
                f"process-context boundary is missing {required!r}"
            )
    process_context_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            process_context_text,
        )
    )
    expected_process_context_exports = {
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
    }
    if process_context_exports != expected_process_context_exports:
        errors.append(
            "libc/src/c_abi/x86_64/process_context.rs: selected static "
            "artifact must export only its named identity/group/session/mask symbols"
        )

    child_reaping_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "child_reaping.rs"
    )
    child_reaping_text = child_reaping_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/process/wait.c",
        "src/process/waitpid.c",
        "src/process/waitid.c",
        "SYS_WAIT4",
        "SYS_WAITID",
        "syscall4(",
        "syscall5(",
        "WNOWAIT",
        "cancellation",
        "c_status",
    ):
        if required not in child_reaping_text:
            errors.append(
                "libc/src/c_abi/x86_64/child_reaping.rs: selected static "
                f"child-reaping boundary is missing {required!r}"
            )
    child_reaping_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            child_reaping_text,
        )
    )
    expected_child_reaping_exports = {"wait", "waitpid", "waitid"}
    if child_reaping_exports != expected_child_reaping_exports:
        errors.append(
            "libc/src/c_abi/x86_64/child_reaping.rs: selected static "
            "artifact must export only wait, waitpid, and waitid"
        )

    immediate_termination_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "immediate_termination.rs"
    )
    immediate_termination_text = immediate_termination_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/exit/_Exit.c",
        "SYS_EXIT_GROUP",
        "SYS_EXIT",
        "exit_group",
        "quick-exit hook state",
        "raw_syscall::syscall1(",
    ):
        if required not in immediate_termination_text:
            errors.append(
                "libc/src/c_abi/x86_64/immediate_termination.rs: selected static "
                f"immediate-termination boundary is missing {required!r}"
            )
    immediate_termination_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            immediate_termination_text,
        )
    )
    if immediate_termination_exports != {"_Exit"}:
        errors.append(
            "libc/src/c_abi/x86_64/immediate_termination.rs: selected static "
            "artifact must export only _Exit"
        )

    callback_algorithms_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "callback_algorithms.rs"
    )
    callback_algorithms_text = callback_algorithms_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/stdlib/bsearch.c",
        "src/stdlib/qsort.c",
        "src/stdlib/qsort_nr.c",
        "smoothsort",
        "14 * core::mem::size_of::<usize>() + 1",
        "12 * core::mem::size_of::<usize>()",
        "qsort_copy_nonoverlapping",
        "global_asm!",
        ".weak qsort_r",
        ".set qsort_r, __qsort_r",
    ):
        if required not in callback_algorithms_text:
            errors.append(
                "libc/src/c_abi/x86_64/callback_algorithms.rs: selected static "
                f"callback-algorithms boundary is missing {required!r}"
            )
    callback_algorithms_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            callback_algorithms_text,
        )
    )
    if callback_algorithms_exports != {"bsearch", "__qsort_r", "qsort"}:
        errors.append(
            "libc/src/c_abi/x86_64/callback_algorithms.rs: selected static "
            "artifact must export bsearch, __qsort_r, and qsort only as Rust entries"
        )
    callback_algorithms_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*__qsort_r",\s*$',
            callback_algorithms_text,
        )
    )
    if callback_algorithms_aliases != {"qsort_r"}:
        errors.append(
            "libc/src/c_abi/x86_64/callback_algorithms.rs: selected static "
            "artifact must retain qsort_r as the musl same-address assembler alias"
        )

    clock_nanosleep_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_nanosleep.rs"
    )
    clock_nanosleep_text = clock_nanosleep_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/time/clock_nanosleep.c",
        "clock_nanosleep=230",
        "raw_syscall::SYS_CLOCK_NANOSLEEP",
        "raw_syscall::syscall4(",
        "LINUX_ERRNO_MAX",
        "wrapping_neg",
        "positive errno",
        "must not publish failures through `errno`",
        "__syscall_cp",
        "special-cases a relative realtime request",
        "CLOCK_THREAD_CPUTIME_ID",
        "independent of the",
    ):
        if required not in clock_nanosleep_text:
            errors.append(
                "libc/src/c_abi/x86_64/clock_nanosleep.rs: selected static "
                f"clock_nanosleep boundary is missing {required!r}"
            )
    clock_nanosleep_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            clock_nanosleep_text,
        )
    )
    if clock_nanosleep_exports != {"clock_nanosleep"}:
        errors.append(
            "libc/src/c_abi/x86_64/clock_nanosleep.rs: selected static "
            "artifact must export only clock_nanosleep"
        )

    clock_gettime_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "clock_gettime.rs"
    clock_gettime_text = clock_gettime_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/time/clock_gettime.c",
        "raw_syscall::SYS_CLOCK_GETTIME",
        "raw_syscall::syscall2(",
        "c_status(result)",
        "initial-TLS errno",
        "direct Linux syscall",
        "vDSO",
    ):
        if required not in clock_gettime_text:
            errors.append(
                "libc/src/c_abi/x86_64/clock_gettime.rs: selected static "
                f"clock_gettime boundary is missing {required!r}"
            )
    clock_gettime_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            clock_gettime_text,
        )
    )
    if clock_gettime_exports != {"clock_gettime"}:
        errors.append(
            "libc/src/c_abi/x86_64/clock_gettime.rs: selected static artifact "
            "must export only clock_gettime"
        )
    raw_syscall_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
    raw_syscall_text = raw_syscall_source.read_text(errors="replace")
    if "pub(crate) const SYS_CLOCK_GETTIME: i64 = 228;" not in raw_syscall_text:
        errors.append(
            "libc/src/c_abi/x86_64/syscall.rs: selected static clock_gettime "
            "boundary requires SYS_CLOCK_GETTIME=228"
        )

    memory_mapping_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_mapping.rs"
    )
    memory_mapping_text = memory_mapping_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
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
        "c_status(result)",
        "wrapping_neg",
        "msync",
        "mremap",
        "mlock*",
    ):
        if required not in memory_mapping_text:
            errors.append(
                "libc/src/c_abi/x86_64/memory_mapping.rs: selected static "
                f"mapping-core boundary is missing {required!r}"
            )
    memory_mapping_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            memory_mapping_text,
        )
    )
    expected_memory_mapping_exports = {
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        "posix_madvise",
        "mincore",
    }
    if memory_mapping_exports != expected_memory_mapping_exports:
        errors.append(
            "libc/src/c_abi/x86_64/memory_mapping.rs: selected static "
            "artifact must export only the named mapping-core symbols"
        )
    for required in (
        "pub(crate) const SYS_MMAP: i64 = 9;",
        "pub(crate) const SYS_MPROTECT: i64 = 10;",
        "pub(crate) const SYS_MUNMAP: i64 = 11;",
        "pub(crate) const SYS_MINCORE: i64 = 27;",
        "pub(crate) const SYS_MADVISE: i64 = 28;",
    ):
        if required not in raw_syscall_text:
            errors.append(
                "libc/src/c_abi/x86_64/syscall.rs: selected static mapping-core "
                f"boundary is missing {required!r}"
            )

    signal_execution_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_execution.rs"
    )
    signal_execution_text = signal_execution_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/signal/kill.c",
        "src/signal/killpg.c",
        "src/signal/raise.c",
        "src/signal/sigqueue.c",
        "src/signal/sigtimedwait.c",
        "src/signal/sigwaitinfo.c",
        "src/signal/sigwait.c",
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
        "sigaltstack",
        "signalfd",
    ):
        if required not in signal_execution_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_execution.rs: selected static "
                f"process-signal boundary is missing {required!r}"
            )
    signal_execution_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_execution_text,
        )
    )
    expected_signal_execution_exports = {
        "kill",
        "killpg",
        "raise",
        "sigqueue",
        "sigtimedwait",
        "sigwaitinfo",
        "sigwait",
    }
    if signal_execution_exports != expected_signal_execution_exports:
        errors.append(
            "libc/src/c_abi/x86_64/signal_execution.rs: selected static "
            "artifact must export only the named process-signal symbols"
        )
    for required in (
        "pub(crate) const SYS_KILL: i64 = 62;",
        "pub(crate) const SYS_RT_SIGPROCMASK: i64 = 14;",
        "pub(crate) const SYS_RT_SIGTIMEDWAIT: i64 = 128;",
        "pub(crate) const SYS_RT_SIGQUEUEINFO: i64 = 129;",
        "pub(crate) const SYS_GETTID: i64 = 186;",
        "pub(crate) const SYS_TKILL: i64 = 200;",
    ):
        if required not in raw_syscall_text:
            errors.append(
                "libc/src/c_abi/x86_64/syscall.rs: selected static process-signal "
                f"boundary is missing {required!r}"
            )

    nanosleep_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "nanosleep.rs"
    nanosleep_text = nanosleep_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/time/nanosleep.c",
        "src/time/clock_nanosleep.c",
        "nanosleep=35",
        "raw_syscall::SYS_NANOSLEEP",
        "raw_syscall::syscall2(",
        "c_status(result)",
        "initial-TLS errno",
        "__syscall_cp",
        "omits cancellation",
    ):
        if required not in nanosleep_text:
            errors.append(
                "libc/src/c_abi/x86_64/nanosleep.rs: selected static "
                f"nanosleep boundary is missing {required!r}"
            )
    nanosleep_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            nanosleep_text,
        )
    )
    if nanosleep_exports != {"nanosleep"}:
        errors.append(
            "libc/src/c_abi/x86_64/nanosleep.rs: selected static artifact "
            "must export only nanosleep"
        )

    descriptor_entry_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_entry.rs"
    )
    descriptor_entry_text = descriptor_entry_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/fcntl/open.c",
        "src/fcntl/openat.c",
        "src/fcntl/creat.c",
        "open=2",
        "openat=257",
        "raw_syscall::SYS_OPEN",
        "raw_syscall::SYS_OPENAT",
        "raw_syscall::SYS_FCNTL",
        "raw_syscall::syscall4(",
        "O_LARGEFILE",
        "O_TMPFILE",
        "(flags & O_TMPFILE) == O_TMPFILE",
        "F_SETFD",
        "FD_CLOEXEC",
        "__syscall_cp",
        "c_status(result)",
    ):
        if required not in descriptor_entry_text:
            errors.append(
                "libc/src/c_abi/x86_64/descriptor_entry.rs: selected static "
                f"descriptor-entry boundary is missing {required!r}"
            )
    descriptor_entry_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            descriptor_entry_text,
        )
    )
    if descriptor_entry_exports != {"open", "openat", "creat"}:
        errors.append(
            "libc/src/c_abi/x86_64/descriptor_entry.rs: selected static "
            "artifact must export only open, openat, and creat"
        )

    filesystem_access_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_access.rs"
    )
    filesystem_access_text = filesystem_access_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/unistd/access.c",
        "src/unistd/faccessat.c",
        "src/legacy/euidaccess.c",
        "access=21",
        "faccessat=269",
        "faccessat2=439",
        "Linux 5.10 includes `faccessat2`",
        "raw_syscall::SYS_ACCESS",
        "raw_syscall::SYS_FACCESSAT",
        "raw_syscall::SYS_FACCESSAT2",
        "raw_syscall::syscall2(",
        "raw_syscall::syscall3(",
        "raw_syscall::syscall4(",
        "AT_FDCWD",
        "AT_EACCESS",
        "c_status(result)",
        "__syscall_cp",
        ".weak eaccess",
        ".set eaccess, euidaccess",
    ):
        if required not in filesystem_access_text:
            errors.append(
                "libc/src/c_abi/x86_64/filesystem_access.rs: selected static "
                f"filesystem-access boundary is missing {required!r}"
            )
    filesystem_access_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            filesystem_access_text,
        )
    )
    if filesystem_access_exports != {"access", "faccessat", "euidaccess"}:
        errors.append(
            "libc/src/c_abi/x86_64/filesystem_access.rs: selected static "
            "artifact must export access, faccessat, and euidaccess only as Rust entries"
        )
    filesystem_access_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*euidaccess",\s*$',
            filesystem_access_text,
        )
    )
    if filesystem_access_aliases != {"eaccess"}:
        errors.append(
            "libc/src/c_abi/x86_64/filesystem_access.rs: selected static "
            "artifact must retain eaccess as the musl same-address assembler alias"
        )

    descriptor_control_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_control.rs"
    )
    descriptor_control_text = descriptor_control_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/fcntl/fcntl.c",
        "global_asm!",
        ".global fcntl",
        "fcntl_no_argument",
        "fcntl_scalar",
        "fcntl_unsupported",
        "F_GETFD",
        "F_SETFD",
        "F_GETFL",
        "F_SETFL",
        "O_LARGEFILE",
        "if command == F_SETFL",
        "raw_syscall::SYS_FCNTL",
        "raw_syscall::syscall3(",
        "errno::set_errno(EINVAL)",
        "must not read an absent vararg",
        "rdi/rsi/rdx",
    ):
        if required not in descriptor_control_text:
            errors.append(
                "libc/src/c_abi/x86_64/descriptor_control.rs: selected static "
                f"fcntl status-control boundary is missing {required!r}"
            )
    descriptor_control_exports = set(
        re.findall(r"(?m)^\s*\.global\s+(\w+)\s*$", descriptor_control_text)
    )
    if descriptor_control_exports != {"fcntl"}:
        errors.append(
            "libc/src/c_abi/x86_64/descriptor_control.rs: selected static "
            "artifact must export only the assembly-dispatched fcntl entry"
        )
    if re.search(
        r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+fcntl(?:<|\s*\()',
        descriptor_control_text,
    ):
        errors.append(
            "libc/src/c_abi/x86_64/descriptor_control.rs: variadic fcntl "
            "must remain assembly-dispatched rather than a fixed Rust C entry"
        )

    ioctl_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ioctl.rs"
    ioctl_text = ioctl_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/misc/ioctl.c",
        "global_asm!",
        ".global ioctl",
        "ioctl_no_argument",
        "ioctl_word",
        "FIONCLEX",
        "FIOCLEX",
        "raw_syscall::SYS_IOCTL",
        "i64::from(request)",
        "c_status(result)",
        "rdi/rsi/rdx",
        "must provide an explicit third word",
        "does not select a request vocabulary",
    ):
        if required not in ioctl_text:
            errors.append(
                "libc/src/c_abi/x86_64/ioctl.rs: selected static generic ioctl "
                f"boundary is missing {required!r}"
            )
    ioctl_exports = set(re.findall(r"(?m)^\s*\.global\s+(\w+)\s*$", ioctl_text))
    if ioctl_exports != {"ioctl"}:
        errors.append(
            "libc/src/c_abi/x86_64/ioctl.rs: selected static artifact must export "
            "only the assembly-dispatched ioctl entry"
        )
    if re.search(
        r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+ioctl(?:<|\s*\()',
        ioctl_text,
    ):
        errors.append(
            "libc/src/c_abi/x86_64/ioctl.rs: variadic ioctl must remain "
            "assembly-dispatched rather than a fixed Rust C entry"
        )

    timestamp_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "timestamp_updates.rs"
    )
    timestamp_text = timestamp_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/stat/utimensat.c",
        "src/stat/futimens.c",
        "src/stat/futimesat.c",
        "src/legacy/futimes.c",
        "src/legacy/lutimes.c",
        "src/linux/utimes.c",
        "src/time/utime.c",
        "UTIME_NOW",
        "AT_SYMLINK_NOFOLLOW",
        "raw_syscall::SYS_UTIMENSAT",
        "raw_syscall::syscall4(",
        "futimesat_timeval_pair",
        ".weak futimesat",
        ".set futimesat, __futimesat",
    ):
        if required not in timestamp_text:
            errors.append(
                "libc/src/c_abi/x86_64/timestamp_updates.rs: selected static "
                f"timestamp boundary is missing {required!r}"
            )
    timestamp_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            timestamp_text,
        )
    )
    expected_timestamp_exports = {
        "utimensat",
        "futimens",
        "__futimesat",
        "futimes",
        "lutimes",
        "utimes",
        "utime",
    }
    if timestamp_exports != expected_timestamp_exports:
        errors.append(
            "libc/src/c_abi/x86_64/timestamp_updates.rs: selected static artifact "
            "must export only the seven Rust timestamp entries; futimesat remains "
            "the musl same-address assembler alias"
        )

    descriptor_io_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "descriptor_io.rs"
    )
    descriptor_io_text = descriptor_io_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/unistd/pwrite.c",
        "struct IoVec",
        "size_of::<IoVec>()",
        "raw_syscall::SYS_READ",
        "raw_syscall::SYS_WRITE",
        "raw_syscall::SYS_CLOSE",
        "raw_syscall::SYS_LSEEK",
        "raw_syscall::SYS_PREAD64",
        "raw_syscall::SYS_PWRITE64",
        "raw_syscall::SYS_PWRITEV2",
        "raw_syscall::SYS_FTRUNCATE",
        "raw_syscall::SYS_FSYNC",
        "raw_syscall::SYS_FDATASYNC",
        "raw_syscall::SYS_DUP",
        "raw_syscall::SYS_DUP2",
        "raw_syscall::SYS_DUP3",
        "raw_syscall::SYS_PIPE",
        "raw_syscall::SYS_PIPE2",
        "raw_syscall::SYS_FCNTL",
        "raw_syscall::syscall6(",
        "RWF_NOAPPEND",
        "if offset == -1 { -2 } else { offset }",
        "if result == -EINTR",
        "if result != -EBUSY",
        "if old_descriptor == new_descriptor",
        "if flags == 0",
        "c_ssize_status(result)",
        "c_off_status(result)",
    ):
        if required not in descriptor_io_text:
            errors.append(
                "libc/src/c_abi/x86_64/descriptor_io.rs: selected static "
                f"descriptor-I/O boundary is missing {required!r}"
            )
    descriptor_io_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            descriptor_io_text,
        )
    )
    expected_descriptor_io_exports = {
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
    }
    if descriptor_io_exports != expected_descriptor_io_exports:
        errors.append(
            "libc/src/c_abi/x86_64/descriptor_io.rs: selected static descriptor-I/O "
            "artifact must export only its named transfer/lifecycle symbols"
        )

    process_resources_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_resources.rs"
    )
    process_resources_text = process_resources_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/misc/getrlimit.c",
        "src/misc/setrlimit.c",
        "src/linux/prlimit.c",
        "src/misc/getrusage.c",
        "src/misc/getpriority.c",
        "src/misc/setpriority.c",
        "src/unistd/nice.c",
        "struct Rlimit",
        "struct Rusage",
        "size_of::<Rlimit>() == 16",
        "size_of::<Rusage>() == 272",
        "offset_of!(Rusage, reserved) == 144",
        "raw_syscall::SYS_PRLIMIT64",
        "raw_syscall::SYS_GETRUSAGE",
        "raw_syscall::SYS_GETPRIORITY",
        "raw_syscall::SYS_SETPRIORITY",
        "raw_syscall::syscall4(",
        "errno::get_errno()",
        "EACCES",
        "EPERM",
        "c_status(result)",
    ):
        if required not in process_resources_text:
            errors.append(
                "libc/src/c_abi/x86_64/process_resources.rs: selected static "
                f"process-resources boundary is missing {required!r}"
            )
    process_resources_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            process_resources_text,
        )
    )
    expected_process_resources_exports = {
        "getrlimit",
        "setrlimit",
        "prlimit",
        "getrusage",
        "getpriority",
        "setpriority",
        "nice",
    }
    if process_resources_exports != expected_process_resources_exports:
        errors.append(
            "libc/src/c_abi/x86_64/process_resources.rs: selected static "
            "artifact must export only its named resource/priority symbols"
        )

    readiness_waits_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "readiness_waits.rs"
    )
    readiness_waits_text = readiness_waits_source.read_text(errors="replace")
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
        "raw_syscall::syscall6(",
        "KERNEL_SIGSET_SIZE",
        "requested.microseconds / MICROSECONDS_PER_SECOND",
        "c_status(result)",
    ):
        if required not in readiness_waits_text:
            errors.append(
                "libc/src/c_abi/x86_64/readiness_waits.rs: selected static "
                f"readiness/signal-waits boundary is missing {required!r}"
            )
    readiness_waits_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            readiness_waits_text,
        )
    )
    expected_readiness_waits_exports = {
        "poll",
        "ppoll",
        "select",
        "pselect",
        "pause",
        "sigsuspend",
    }
    if readiness_waits_exports != expected_readiness_waits_exports:
        errors.append(
            "libc/src/c_abi/x86_64/readiness_waits.rs: selected static "
            "artifact must export only its named readiness/signal-wait symbols"
        )

    socket_transport_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "socket_transport.rs"
    )
    socket_transport_text = socket_transport_source.read_text(errors="replace")
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
        "SOCK_CLOEXEC",
        "SOCK_NONBLOCK",
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
        "raw_syscall::syscall6(",
        "c_status(result)",
        "c_ssize_status(result)",
    ):
        if required not in socket_transport_text:
            errors.append(
                "libc/src/c_abi/x86_64/socket_transport.rs: selected static "
                f"socket-transport boundary is missing {required!r}"
            )
    socket_transport_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            socket_transport_text,
        )
    )
    expected_socket_transport_exports = {
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
    }
    if socket_transport_exports != expected_socket_transport_exports:
        errors.append(
            "libc/src/c_abi/x86_64/socket_transport.rs: selected static "
            "artifact must export only its named socket-transport symbols"
        )

    byte_strings_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "byte_strings.rs"
    )
    byte_strings_text = byte_strings_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/string/index.c",
        "src/string/rindex.c",
        "src/string/strchr.c",
        "src/string/strchrnul.c",
        "src/string/strcmp.c",
        "src/string/strcspn.c",
        "src/string/strlen.c",
        "src/string/strncmp.c",
        "src/string/strnlen.c",
        "src/string/strpbrk.c",
        "src/string/strrchr.c",
        "src/string/strspn.c",
        "src/string/strstr.c",
        "scalar fallback",
        "strchrnul",
    ):
        if required not in byte_strings_text:
            errors.append(
                "libc/src/c_abi/x86_64/byte_strings.rs: selected static byte-string "
                f"boundary is missing {required!r}"
            )
    byte_strings_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            byte_strings_text,
        )
    )
    expected_byte_strings_exports = {
        "index",
        "rindex",
        "strchr",
        "strchrnul",
        "strcmp",
        "strcspn",
        "strlen",
        "strncmp",
        "strnlen",
        "strpbrk",
        "strrchr",
        "strspn",
        "strstr",
    }
    if byte_strings_exports != expected_byte_strings_exports:
        errors.append(
            "libc/src/c_abi/x86_64/byte_strings.rs: selected static byte-string "
            "artifact must export only its named byte-string symbols"
        )

    memory_search_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_search.rs"
    )
    memory_search_text = memory_search_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/string/memchr.c",
        "src/string/memmem.c",
        "src/string/memrchr.c",
        "__memrchr",
        "stateless",
        "allocation-free",
        "memchr",
        "memmem",
        "memrchr",
    ):
        if required not in memory_search_text:
            errors.append(
                "libc/src/c_abi/x86_64/memory_search.rs: selected static memory-search "
                f"boundary is missing {required!r}"
            )
    memory_search_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            memory_search_text,
        )
    )
    expected_memory_search_exports = {"memchr", "memmem", "memrchr"}
    if memory_search_exports != expected_memory_search_exports:
        errors.append(
            "libc/src/c_abi/x86_64/memory_search.rs: selected static memory-search "
            "artifact must export only memchr, memmem, and memrchr"
        )

    string_copy_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "string_copy.rs"
    string_copy_text = string_copy_source.read_text(errors="replace")
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
    ):
        if required not in string_copy_text:
            errors.append(
                "libc/src/c_abi/x86_64/string_copy.rs: selected static C-string-copy "
                f"boundary is missing {required!r}"
            )
    string_copy_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            string_copy_text,
        )
    )
    expected_string_copy_exports = {
        "stpcpy",
        "stpncpy",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strlcpy",
        "strlcat",
    }
    if string_copy_exports != expected_string_copy_exports:
        errors.append(
            "libc/src/c_abi/x86_64/string_copy.rs: selected static C-string-copy "
            "artifact must export only its named copy and concatenation symbols"
        )

    ctype_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ctype.rs"
    ctype_text = ctype_source.read_text(errors="replace")
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
        if required not in ctype_text:
            errors.append(
                "libc/src/c_abi/x86_64/ctype.rs: selected static C ctype "
                f"boundary is missing {required!r}"
            )
    ctype_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            ctype_text,
        )
    )
    expected_ctype_exports = {
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
    }
    if ctype_exports != expected_ctype_exports:
        errors.append(
            "libc/src/c_abi/x86_64/ctype.rs: selected static C ctype artifact "
            "must export only its named fixed-C-locale symbols"
        )

    integer_arithmetic_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "integer_arithmetic.rs"
    )
    integer_arithmetic_text = integer_arithmetic_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/stdlib/abs.c",
        "src/stdlib/labs.c",
        "src/stdlib/llabs.c",
        "src/stdlib/div.c",
        "src/stdlib/ldiv.c",
        "src/stdlib/lldiv.c",
        "scalar",
        "stateless",
        "allocation-free",
        "idiv",
        "undefined",
        "wrapping_neg",
    ):
        if required not in integer_arithmetic_text:
            errors.append(
                "libc/src/c_abi/x86_64/integer_arithmetic.rs: selected static "
                f"integer-arithmetic boundary is missing {required!r}"
            )
    integer_arithmetic_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            integer_arithmetic_text,
        )
    )
    expected_integer_arithmetic_exports = {
        "abs",
        "labs",
        "llabs",
        "div",
        "ldiv",
        "lldiv",
    }
    if integer_arithmetic_exports != expected_integer_arithmetic_exports:
        errors.append(
            "libc/src/c_abi/x86_64/integer_arithmetic.rs: selected static "
            "artifact must export only its named integer-arithmetic symbols"
        )

    integer_parse_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "integer_parse.rs"
    )
    integer_parse_text = integer_parse_source.read_text(errors="replace")
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
        if required not in integer_parse_text:
            errors.append(
                "libc/src/c_abi/x86_64/integer_parse.rs: selected static "
                f"integer-parsing boundary is missing {required!r}"
            )
    integer_parse_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            integer_parse_text,
        )
    )
    expected_integer_parse_exports = {
        "atoi",
        "atol",
        "atoll",
        "strtol",
        "strtoul",
        "strtoll",
        "strtoull",
        "strtoimax",
        "strtoumax",
    }
    if integer_parse_exports != expected_integer_parse_exports:
        errors.append(
            "libc/src/c_abi/x86_64/integer_parse.rs: selected static "
            "artifact must export only its named integer-parsing symbols"
        )
    for forbidden in (
        "crabc_core",
        "crabc_mimalloc",
        "fn strtod(",
        "fn wcstol(",
        "fn malloc(",
        "raw_syscall::",
        "__tls_get_addr",
    ):
        if forbidden in integer_parse_text:
            errors.append(
                "libc/src/c_abi/x86_64/integer_parse.rs: selected static "
                f"integer-parsing boundary must not select {forbidden!r}"
            )

    intmax_arithmetic_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "intmax_arithmetic.rs"
    )
    intmax_arithmetic_text = intmax_arithmetic_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/stdlib/imaxabs.c",
        "src/stdlib/imaxdiv.c",
        "intmax_t",
        "imaxdiv_t",
        "stateless",
        "allocation-free",
        "idiv",
        "undefined",
        "wrapping_neg",
    ):
        if required not in intmax_arithmetic_text:
            errors.append(
                "libc/src/c_abi/x86_64/intmax_arithmetic.rs: selected static "
                f"intmax-arithmetic boundary is missing {required!r}"
            )
    intmax_arithmetic_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            intmax_arithmetic_text,
        )
    )
    expected_intmax_arithmetic_exports = {"imaxabs", "imaxdiv"}
    if intmax_arithmetic_exports != expected_intmax_arithmetic_exports:
        errors.append(
            "libc/src/c_abi/x86_64/intmax_arithmetic.rs: selected static "
            "artifact must export only imaxabs and imaxdiv"
        )

    credential_observation_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "credential_observation.rs"
    )
    credential_observation_text = credential_observation_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/unistd/getgroups.c",
        "src/misc/getresuid.c",
        "src/misc/getresgid.c",
        "SYS_GETGROUPS",
        "SYS_GETRESUID",
        "SYS_GETRESGID",
        "c_status",
        "EINVAL",
        "EFAULT",
    ):
        if required not in credential_observation_text:
            errors.append(
                "libc/src/c_abi/x86_64/credential_observation.rs: selected static "
                f"credential-observation boundary is missing {required!r}"
            )
    credential_observation_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            credential_observation_text,
        )
    )
    expected_credential_observation_exports = {
        "getgroups",
        "getresuid",
        "getresgid",
    }
    if credential_observation_exports != expected_credential_observation_exports:
        errors.append(
            "libc/src/c_abi/x86_64/credential_observation.rs: selected static "
            "artifact must export only getgroups, getresuid, and getresgid"
        )

    ffs_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ffs.rs"
    ffs_text = ffs_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/misc/ffs.c",
        "src/misc/ffsl.c",
        "src/misc/ffsll.c",
        "src/internal/atomic.h",
        "scalar",
        "stateless",
        "allocation-free",
        "trailing_zeros",
        "two's-complement",
    ):
        if required not in ffs_text:
            errors.append(
                "libc/src/c_abi/x86_64/ffs.rs: selected static find-first-set "
                f"boundary is missing {required!r}"
            )
    ffs_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            ffs_text,
        )
    )
    expected_ffs_exports = {"ffs", "ffsl", "ffsll"}
    if ffs_exports != expected_ffs_exports:
        errors.append(
            "libc/src/c_abi/x86_64/ffs.rs: selected static find-first-set "
            "artifact must export only ffs, ffsl, and ffsll"
        )

    random_entropy_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "random_entropy.rs"
    )
    random_entropy_text = random_entropy_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/linux/getrandom.c",
        "src/misc/getentropy.c",
        "SYS_GETRANDOM",
        "syscall3(",
        "syscall_cp",
        "c_ssize_status(result)",
        "errno::set_errno(EIO)",
        "256",
        "EIO",
        "EINTR",
        "cancellation",
    ):
        if required not in random_entropy_text:
            errors.append(
                "libc/src/c_abi/x86_64/random_entropy.rs: selected static "
                f"random-entropy boundary is missing {required!r}"
            )
    random_entropy_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            random_entropy_text,
        )
    )
    expected_random_entropy_exports = {"getrandom", "getentropy"}
    if random_entropy_exports != expected_random_entropy_exports:
        errors.append(
            "libc/src/c_abi/x86_64/random_entropy.rs: selected static "
            "random-entropy artifact must export only getrandom and getentropy"
        )

    system_observation_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_observation.rs"
    )
    system_observation_text = system_observation_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/misc/uname.c",
        "src/linux/sysinfo.c",
        "struct UtsName",
        "pub(super) const UTS_FIELD_BYTES: usize = 65",
        "pub(super) unsafe fn uname_raw",
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
        if required not in system_observation_text:
            errors.append(
                "libc/src/c_abi/x86_64/system_observation.rs: selected static "
                f"system-observation boundary is missing {required!r}"
            )
    system_observation_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            system_observation_text,
        )
    )
    expected_system_observation_exports = {"uname", "sysinfo"}
    if system_observation_exports != expected_system_observation_exports:
        errors.append(
            "libc/src/c_abi/x86_64/system_observation.rs: selected static "
            "artifact must export only uname and sysinfo"
        )

    uts_identity_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "uts_identity.rs"
    uts_identity_text = uts_identity_source.read_text(errors="replace")
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
        "fn read_utsname",
        "fn field_nul_length",
        "raw_syscall::SYS_SETHOSTNAME",
        "raw_syscall::SYS_SETDOMAINNAME",
        "raw_syscall::syscall2(",
        "errno::set_errno(EINVAL)",
        "c_status(result)",
    ):
        if required not in uts_identity_text:
            errors.append(
                "libc/src/c_abi/x86_64/uts_identity.rs: selected static "
                f"UTS-identity boundary is missing {required!r}"
            )
    uts_identity_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            uts_identity_text,
        )
    )
    expected_uts_identity_exports = {
        "gethostname",
        "sethostname",
        "getdomainname",
        "setdomainname",
    }
    if uts_identity_exports != expected_uts_identity_exports:
        errors.append(
            "libc/src/c_abi/x86_64/uts_identity.rs: selected static "
            "artifact must export only get/set hostname/domain-name symbols"
        )

    export_sources = (
        static_root_text,
        stat_text,
        credentials_text,
        errno_text,
        static_tls_text,
        static_startup_text,
        fenv_text,
        signal_control_text,
        signal_execution_text,
        pthread_identity_text,
        pthread_create_join_text,
        c11_thread_lifecycle_text,
        termios_control_text,
        process_context_text,
        child_reaping_text,
        immediate_termination_text,
        callback_algorithms_text,
        clock_gettime_text,
        clock_nanosleep_text,
        memory_mapping_text,
        nanosleep_text,
        descriptor_entry_text,
        filesystem_access_text,
        descriptor_control_text,
        descriptor_io_text,
        process_resources_text,
        readiness_waits_text,
        socket_transport_text,
        byte_strings_text,
        random_entropy_text,
        memory_search_text,
        string_copy_text,
        ctype_text,
        integer_arithmetic_text,
        integer_parse_text,
        intmax_arithmetic_text,
        credential_observation_text,
        ffs_text,
        system_observation_text,
        uts_identity_text,
        timestamp_text,
    )
    rust_exports = set().union(
        *(
            set(
                re.findall(
                    r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                    source,
                )
            )
            for source in export_sources
        )
    )
    assembly_exports = set().union(
        *(
            set(re.findall(r"(?m)^\s*\.global\s+(\w+)\s*$", source))
            for source in (memory_text, fenv_text, setjmp_text, descriptor_control_text)
        )
    )
    timestamp_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*__futimesat",\s*$',
            timestamp_text,
        )
    )
    if timestamp_aliases != {"futimesat"}:
        errors.append(
            "libc/src/c_abi/x86_64/timestamp_updates.rs: selected static artifact "
            "must retain futimesat as the musl same-address assembler alias"
        )
    exports = (
        rust_exports
        | assembly_exports
        | callback_algorithms_aliases
        | filesystem_access_aliases
        | timestamp_aliases
        | pthread_identity_exports
    )
    expected_exports = {
        "__errno_location",
        "__crabc_x86_static_tls_bootstrap",
        "stat",
        "lstat",
        "fstat",
        "fstatat",
        "utimensat",
        "futimens",
        "__futimesat",
        "futimes",
        "futimesat",
        "lutimes",
        "utimes",
        "utime",
        "__xstat",
        "__lxstat",
        "__fxstat",
        "__fxstatat",
        "setgroups",
        "setuid",
        "setgid",
        "setresuid",
        "setresgid",
        "seteuid",
        "setegid",
        "setreuid",
        "setregid",
        "memcpy",
        "__memcpy_fwd",
        "memcmp",
        "bcmp",
        "memset",
        "memmove",
        "feclearexcept",
        "feraiseexcept",
        "__fesetround",
        "fegetround",
        "fegetenv",
        "fesetenv",
        "fetestexcept",
        "fegetexceptflag",
        "feholdexcept",
        "fesetexceptflag",
        "fesetround",
        "feupdateenv",
        "ffs",
        "ffsl",
        "ffsll",
        "__flt_rounds",
        "setjmp",
        "__setjmp",
        "_setjmp",
        "longjmp",
        "_longjmp",
        "sigsetjmp",
        "__sigsetjmp",
        "siglongjmp",
        "sigaction",
        "signal",
        "sigemptyset",
        "sigfillset",
        "sigaddset",
        "sigdelset",
        "sigismember",
        "sigprocmask",
        "sigpending",
        "__libc_current_sigrtmax",
        "kill",
        "killpg",
        "raise",
        "sigqueue",
        "sigtimedwait",
        "sigwaitinfo",
        "sigwait",
        "pthread_create",
        "pthread_detach",
        "pthread_exit",
        "pthread_join",
        "thrd_create",
        "thrd_detach",
        "thrd_exit",
        "thrd_join",
        "pthread_self",
        "pthread_equal",
        "thrd_current",
        "thrd_equal",
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
        "wait",
        "waitpid",
        "waitid",
        "clock_gettime",
        "clock_nanosleep",
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        "posix_madvise",
        "mincore",
        "nanosleep",
        "open",
        "openat",
        "creat",
        "access",
        "faccessat",
        "euidaccess",
        "eaccess",
        "close",
        "read",
        "write",
        "pread",
        "pwrite",
        "lseek",
        "ftruncate",
        "fsync",
        "fdatasync",
        "fcntl",
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "getrlimit",
        "setrlimit",
        "prlimit",
        "getrusage",
        "getpriority",
        "setpriority",
        "nice",
        "poll",
        "ppoll",
        "select",
        "pselect",
        "pause",
        "sigsuspend",
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
        "uname",
        "sysinfo",
        "gethostname",
        "sethostname",
        "getdomainname",
        "setdomainname",
        "index",
        "rindex",
        "strchr",
        "strchrnul",
        "strcmp",
        "strcspn",
        "strlen",
        "strncmp",
        "strnlen",
        "strpbrk",
        "strrchr",
        "strspn",
        "strstr",
        "getrandom",
        "getentropy",
        "memchr",
        "memmem",
        "memrchr",
        "stpcpy",
        "stpncpy",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strlcpy",
        "strlcat",
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
        "abs",
        "labs",
        "llabs",
        "div",
        "ldiv",
        "lldiv",
        "atoi",
        "atol",
        "atoll",
        "strtol",
        "strtoul",
        "strtoll",
        "strtoull",
        "strtoimax",
        "strtoumax",
        "imaxabs",
        "imaxdiv",
        "getgroups",
        "getresuid",
        "getresgid",
        "_Exit",
        "__cxa_atexit",
        "atexit",
        "__funcs_on_exit",
        "__cxa_finalize",
        "_exit",
        "exit",
        "__libc_start_main",
        "bsearch",
        "__qsort_r",
        "qsort",
        "qsort_r",
        "rust_eh_personality",
    }
    if exports != expected_exports:
        errors.append(
            "libc/src/c_abi/x86_64: selected static archive must export only its "
            "stat, credential, errno, bootstrap-memory/fenv/continuation, simple "
            "signal-control and bounded process-signal execution, bounded pthread create/exit/join/detach initial-TLS worker, its typed C11 create/exit/join/detach sibling, and pthread/C11 identity aliases, named termios-control, selected process-context, child-reaping, C11 immediate termination, callback algorithms, direct clock_gettime, caller-owned mapping-core, nanosleep, and clock_nanosleep, selected "
            "descriptor-entry, selected filesystem-access, bounded descriptor-control, timestamp updates, and descriptor-I/O, selected process-resources, selected readiness/signal-waits, "
            "selected socket transport, selected system-observation, selected UTS-identity, "
            "selected byte-string, random-entropy, memory-search, C-string-copy, "
            "fixed-C-locale ctype, integer-arithmetic, integer-parsing, intmax-arithmetic, credential-observation, and "
            "find-first-set, "
            "and abort-personality surfaces"
        )
    for source_name, source_text in (
        ("static_c_abi.rs", static_root_text),
        ("stat_compat.rs", stat_text),
        ("credentials.rs", credentials_text),
        ("credential_observation.rs", credential_observation_text),
        ("errno.rs", errno_text),
        ("static_startup.rs", static_startup_text),
        ("memory.rs", memory_text),
        ("fenv.rs", fenv_text),
        ("setjmp.rs", setjmp_text),
        ("signal_foundation.rs", signal_foundation_text),
        ("signal_control.rs", signal_control_text),
        ("signal_execution.rs", signal_execution_text),
        ("pthread_identity.rs", pthread_identity_text),
        ("pthread_create_join.rs", pthread_create_join_text),
        ("c11_thread_lifecycle.rs", c11_thread_lifecycle_text),
        ("termios_control.rs", termios_control_text),
        ("process_context.rs", process_context_text),
        ("child_reaping.rs", child_reaping_text),
        ("immediate_termination.rs", immediate_termination_text),
        ("callback_algorithms.rs", callback_algorithms_text),
        ("clock_gettime.rs", clock_gettime_text),
        ("clock_nanosleep.rs", clock_nanosleep_text),
        ("memory_mapping.rs", memory_mapping_text),
        ("nanosleep.rs", nanosleep_text),
        ("descriptor_entry.rs", descriptor_entry_text),
        ("filesystem_access.rs", filesystem_access_text),
        ("descriptor_control.rs", descriptor_control_text),
        ("timestamp_updates.rs", timestamp_text),
        ("descriptor_io.rs", descriptor_io_text),
        ("process_resources.rs", process_resources_text),
        ("readiness_waits.rs", readiness_waits_text),
        ("socket_transport.rs", socket_transport_text),
        ("random_entropy.rs", random_entropy_text),
        ("memory_search.rs", memory_search_text),
        ("string_copy.rs", string_copy_text),
        ("ctype.rs", ctype_text),
        ("integer_arithmetic.rs", integer_arithmetic_text),
        ("integer_parse.rs", integer_parse_text),
        ("intmax_arithmetic.rs", intmax_arithmetic_text),
        ("ffs.rs", ffs_text),
        ("system_observation.rs", system_observation_text),
        ("uts_identity.rs", uts_identity_text),
    ):
        if re.search(
            r"\b(?:crabc_core|crabc_mimalloc|libmimalloc|sha_crypt|base64ct)\b",
            source_text,
        ):
            errors.append(
                "libc/src/c_abi/x86_64/"
                f"{source_name}: selected static C ABI must not import an allocator, "
                "shared core, or third-party runtime"
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
    check_x86_cwd_canonicalize_boundary(errors)
    check_x86_root_change_boundary(errors)
    check_x86_mount_boundary(errors)
    check_x86_thread_kill_boundary(errors)
    check_x86_ipc_boundary(errors)
    check_x86_shm_boundary(errors)
    check_x86_inotify_boundary(errors)
    check_x86_calendar_time_boundary(errors)
    check_x86_advanced_time_boundary(errors)
    check_x86_users_databases_boundary(errors)
    check_x86_child_ownership_boundary(errors)
    check_x86_path_lifecycle_boundary(errors)
    check_x86_socket_transport_boundary(errors)
    check_x86_path_core_readlink_boundary(errors)
    check_x86_xattr_boundary(errors)
    check_x86_directory_boundary(errors)
    check_x86_temporary_object_boundary(errors)
    check_x86_statx_boundary(errors)
    check_x86_memfd_boundary(errors)
    check_x86_memory_mapping_boundary(errors)
    check_x86_memory_vm_boundary(errors)
    check_x86_terminal_boundary(errors)
    check_x86_header_layouts_baseline(errors)
    check_x86_crt_libc_static_tls_handoff(errors)
    check_x86_libc_static_c_abi_boundary(errors)
    check_x86_rr_interval_boundary(errors)
    check_x86_sched_affinity_boundary(errors)
    check_x86_futex_boundary(errors)
    check_x86_clock_nanosleep_boundary(errors)
    check_x86_setitimer_boundary(errors)
    check_x86_access_boundary(errors)
    check_x86_capacity_metadata_boundary(errors)
    check_x86_posix_fallocate_boundary(errors)
    check_x86_fallocate_boundary(errors)
    check_x86_timestamp_boundary(errors)
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
