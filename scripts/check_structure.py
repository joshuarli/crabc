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
# The source-only loader foundations have no `crabc-ldso` integration or public
# interpreter boundary. The image parser validates file-facing metadata before
# the relative-relocation leaf consumes it; both are listed independently so a
# later loader slice cannot inherit an artifact-wide exception. `lib.rs` is
# additionally admitted for exactly one feature-gated private x86 ET_DYN
# target root; its runner proves a fixed graph through PT_INTERP and does not
# make x86 a public loader target.
X86_RUNTIME_FOUNDATION_LDSO_SOURCES = {
    Path("ldso/src/lib.rs"),
    Path("ldso/src/x86_64_image.rs"),
    Path("ldso/src/x86_64_relocation.rs"),
}
# The selected x86 `crabc-libc` artifact admits independently evidenced static
# C ABI verticals for `sys/stat.h` metadata, credential setters/observation, bootstrap
# primitives, narrow simple signal control, bounded process-signal execution,
# one bounded pthread create/exit/
# join initial-TLS worker, its private selected-main/worker pthread-key/C11-TSS
# sibling, selected process-private normal mutex and condition siblings, their
# distinct C11 plain-sync adapter, and its typed static C11 create/exit/join
# sibling,
# named termios control, selected
# process context, bounded process environment, child reaping, C11 immediate
# termination, POSIX _exit forwarding, bounded static
# startup/ordinary exit, callback algorithms,
# selected descriptor entry, fcntl status control, bounded generic ioctl, and
# selected timestamp updates,
# selected descriptor I/O,
# selected process resources,
# selected readiness/signal waits, selected system observation, selected
# UTS-namespace identity, selected legacy bcopy/bzero adapters, selected
# source-backed memccpy copy-until-target and mempcpy return-after-copy adapters,
# one caller-buffer `strsep` token-mutation leaf, selected C-string
# copy/concatenation, fixed-C-
# locale ctype and the separately bounded named-locale/multibyte conversion
# artifact, scalar integer arithmetic, complete integer parsing, intmax
# arithmetic, and find-first-set, direct POSIX clock_gettime, bounded clock
# observation, no-cancellation mapping synchronization, direct anonymous-memory
# descriptor creation, nanosleep, and clock_nanosleep, descriptor entry, selected
# filesystem access, bounded fcntl
# status control, bounded generic ioctl, and the basic x87 classification/sign,
# complex accessor/conjugation plus the complete private math.complex
# capability, hardware square root, binary32/binary64 extrema, fixed-direction
# ceiling/floor, half-away rounding, truncation, remainder, and cube root,
# selected fenv-sensitive rounding, and binary80
# elementary/remainder/conversion foundations.
# The older leaves remain source-only. Keeping exact file boundaries makes
# every later C-runtime admission deliberate rather than a directory-wide x86
# exception.
X86_RUNTIME_FOUNDATION_LIBC_SOURCES = {
    Path("libc/src/lib.rs"),
    Path("libc/src/getopt_exports.rs"),
    Path("libc/src/c_abi/x86_64/atomic.rs"),
    Path("libc/src/c_abi/x86_64/clone.rs"),
    Path("libc/src/c_abi/x86_64/credentials.rs"),
    Path("libc/src/c_abi/x86_64/credential_observation.rs"),
    Path("libc/src/c_abi/x86_64/child_reaping.rs"),
    Path("libc/src/c_abi/x86_64/clock_gettime.rs"),
    Path("libc/src/c_abi/x86_64/difftime.rs"),
    Path("libc/src/c_abi/x86_64/gmtime_r.rs"),
    Path("libc/src/c_abi/x86_64/timegm.rs"),
    Path("libc/src/c_abi/x86_64/time_observation.rs"),
    Path("libc/src/c_abi/x86_64/clock_nanosleep.rs"),
    Path("libc/src/c_abi/x86_64/nanosleep.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_entry.rs"),
    Path("libc/src/c_abi/x86_64/filesystem_access.rs"),
    Path("libc/src/c_abi/x86_64/mktemp.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_control.rs"),
    Path("libc/src/c_abi/x86_64/ioctl.rs"),
    Path("libc/src/c_abi/x86_64/immediate_termination.rs"),
    Path("libc/src/c_abi/x86_64/posix_exit.rs"),
    Path("libc/src/c_abi/x86_64/bsearch.rs"),
    Path("libc/src/c_abi/x86_64/linear_search.rs"),
    Path("libc/src/c_abi/x86_64/qsort.rs"),
    Path("libc/src/c_abi/x86_64/callback_algorithms.rs"),
    Path("libc/src/c_abi/x86_64/search_tree_intrusive.rs"),
    Path("libc/src/c_abi/x86_64/search_hash_table.rs"),
    Path("libc/src/c_abi/x86_64/gettext_catalog.rs"),
    Path("libc/src/c_abi/x86_64/ctype.rs"),
    Path("libc/src/c_abi/x86_64/locale_ctype.rs"),
    Path("libc/src/c_abi/x86_64/locale_multibyte.rs"),
    Path("libc/src/c_abi/x86_64/locale_objects.rs"),
    Path("libc/src/c_abi/x86_64/locale_narrow.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_io.rs"),
    Path("libc/src/c_abi/x86_64/ffs.rs"),
    Path("libc/src/c_abi/x86_64/integer_arithmetic.rs"),
    Path("libc/src/c_abi/x86_64/integer_parse.rs"),
    Path("libc/src/c_abi/x86_64/intmax_arithmetic.rs"),
    Path("libc/src/c_abi/x86_64/math_complex.rs"),
    Path("libc/src/c_abi/x86_64/complex_projection.rs"),
    Path("libc/src/c_abi/x86_64/math_complex_complete.rs"),
    Path("libc/src/c_abi/x86_64/elementary_sqrt.rs"),
    Path("libc/src/c_abi/x86_64/fenv_rounding.rs"),
    Path("libc/src/c_abi/x86_64/math_bit_sign.rs"),
    Path("libc/src/c_abi/x86_64/math_trunc.rs"),
    Path("libc/src/c_abi/x86_64/math_fmod.rs"),
    Path("libc/src/c_abi/x86_64/math_cbrt.rs"),
    Path("libc/src/c_abi/x86_64/math_ceil.rs"),
    Path("libc/src/c_abi/x86_64/math_floor.rs"),
    Path("libc/src/c_abi/x86_64/math_round.rs"),
    Path("libc/src/c_abi/x86_64/math_minmax.rs"),
    Path("libc/src/c_abi/x86_64/math_special.rs"),
    Path("libc/src/c_abi/x86_64/math_x87_extended.rs"),
    Path("libc/src/c_abi/x86_64/memory_search.rs"),
    Path("libc/src/c_abi/x86_64/memory_sync.rs"),
    Path("libc/src/c_abi/x86_64/memfd_create.rs"),
    Path("libc/src/c_abi/x86_64/fenv.rs"),
    Path("libc/src/c_abi/x86_64/foundation.rs"),
    Path("libc/src/c_abi/x86_64/memory.rs"),
    Path("libc/src/c_abi/x86_64/memccpy.rs"),
    Path("libc/src/c_abi/x86_64/mempcpy.rs"),
    Path("libc/src/c_abi/x86_64/strsep.rs"),
    Path("libc/src/c_abi/x86_64/legacy_memory.rs"),
    Path("libc/src/c_abi/x86_64/process_context.rs"),
    Path("libc/src/c_abi/x86_64/environment.rs"),
    Path("libc/src/c_abi/x86_64/startup_security.rs"),
    Path("libc/src/c_abi/x86_64/secure_environment.rs"),
    Path("libc/src/c_abi/x86_64/login_name.rs"),
    Path("libc/src/c_abi/x86_64/auxv_observation.rs"),
    Path("libc/src/c_abi/x86_64/process_globals.rs"),
    Path("libc/src/c_abi/x86_64/process_resources.rs"),
    Path("libc/src/c_abi/x86_64/sched_getcpu.rs"),
    Path("libc/src/c_abi/x86_64/sched_yield.rs"),
    Path("libc/src/c_abi/x86_64/posix_semaphore.rs"),
    Path("libc/src/c_abi/x86_64/c11_thread_lifecycle.rs"),
    Path("libc/src/c_abi/x86_64/c11_sync.rs"),
    Path("libc/src/c_abi/x86_64/pthread_once.rs"),
    Path("libc/src/c_abi/x86_64/pthread_create_join.rs"),
    Path("libc/src/c_abi/x86_64/pthread_tsd.rs"),
    Path("libc/src/c_abi/x86_64/pthread_identity.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutex.rs"),
    Path("libc/src/c_abi/x86_64/pthread_cond.rs"),
    Path("libc/src/c_abi/x86_64/pthread_rwlock.rs"),
    Path("libc/src/c_abi/x86_64/readiness_waits.rs"),
    Path("libc/src/c_abi/x86_64/setjmp.rs"),
    Path("libc/src/c_abi/x86_64/signal_control.rs"),
    Path("libc/src/c_abi/x86_64/signal_realtime_max.rs"),
    Path("libc/src/c_abi/x86_64/signal_realtime_min.rs"),
    Path("libc/src/c_abi/x86_64/sched_getscheduler.rs"),
    Path("libc/src/c_abi/x86_64/signal_alarm.rs"),
    Path("libc/src/c_abi/x86_64/signal_pending.rs"),
    Path("libc/src/c_abi/x86_64/signal_set_mutation.rs"),
    Path("libc/src/c_abi/x86_64/signal_execution.rs"),
    Path("libc/src/c_abi/x86_64/signal_set_isempty.rs"),
    Path("libc/src/c_abi/x86_64/signal_set_binary.rs"),
    Path("libc/src/c_abi/x86_64/signal_pause.rs"),
    Path("libc/src/c_abi/x86_64/signal_foundation.rs"),
    Path("libc/src/c_abi/x86_64/static_c_abi.rs"),
    Path("libc/src/c_abi/x86_64/static_startup.rs"),
    Path("libc/src/c_abi/x86_64/static_tls.rs"),
    Path("libc/src/c_abi/x86_64/stat_compat.rs"),
    Path("libc/src/c_abi/x86_64/signal_fd.rs"),
    Path("libc/src/c_abi/x86_64/timer_fd.rs"),
    Path("libc/src/c_abi/x86_64/timestamp_updates.rs"),
    Path("libc/src/c_abi/x86_64/string_copy.rs"),
    Path("libc/src/c_abi/x86_64/error_strings.rs"),
    Path("libc/src/c_abi/x86_64/strsignal.rs"),
    Path("libc/src/c_abi/x86_64/termios_control.rs"),
    Path("libc/src/c_abi/x86_64/isatty.rs"),
    Path("libc/src/c_abi/x86_64/tcgetpgrp.rs"),
    Path("libc/src/c_abi/x86_64/tcsetpgrp.rs"),
    Path("libc/src/c_abi/x86_64/getpass.rs"),
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


def check_x86_installed_header_tree_closure(errors: list[str]) -> None:
    """Keep materialized header closure separate from an owned sysroot claim."""

    runner_path = (
        ROOT / "compat" / "x86_64" / "run_installed_header_tree_closure.sh"
    )
    test_path = (
        ROOT / "compat" / "x86_64" / "tests" / "test_installed_header_tree_closure.py"
    )
    for path in (runner_path, test_path):
        if not path.is_file():
            errors.append(
                "x86 installed-header-tree closure is missing "
                f"{path.relative_to(ROOT)}"
            )
            return

    runner = runner_path.read_text(errors="replace")
    for required in (
        "readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183",
        "readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191",
        "readonly EXPECTED_PROFILE_COUNT=7",
        "readonly EXPECTED_RECORD_COUNT=1337",
        "readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)",
        "materialize_header_tree",
        "validate_regular_header_tree",
        "write_manifest",
        "installed_include=\"$materialized_project/usr/include\"",
        "readonly PROJECT_INCLUDE=\"$ROOT_DIR/usr/include\"",
        "# pinned_public_header_count=$EXPECTED_PINNED_PUBLIC_HEADER_COUNT",
        "# candidate_public_header_count=$EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT",
        "# status.reference-not-applicable=2",
        "candidate include trace reached source include tree",
        "candidate include trace escaped installed-tree/builtin/Linux-5.10 roots",
        "# schema=crabc.x86_64-installed-header-tree-closure/v1",
        "# scope=header-tree closure only; not ABI/layout/linkage/sysroot/promotion/public-support parity",
    ):
        if required not in runner:
            errors.append(
                "compat/x86_64/run_installed_header_tree_closure.sh: "
                f"materialized closure contract is missing {required!r}"
            )
    for forbidden in (
        "scripts/crabc_sysroot.py",
        "--report-only",
        "installed-header completion",
    ):
        if forbidden in runner:
            errors.append(
                "compat/x86_64/run_installed_header_tree_closure.sh: private "
                f"header closure must not contain {forbidden!r}"
            )


def check_x86_dirent_header_abi(errors: list[str]) -> None:
    """Keep the dirent C++ fence and feature matrix below runtime selection."""

    header_path = ROOT / "include" / "dirent.h"
    c_probe_path = ROOT / "compat" / "x86_64" / "dirent_header_abi_probe.c"
    cxx_probe_path = ROOT / "compat" / "x86_64" / "dirent_header_abi_probe.cpp"
    runner_path = ROOT / "compat" / "x86_64" / "run_dirent_header_abi.sh"
    test_path = ROOT / "compat" / "x86_64" / "tests" / "test_dirent_header_abi.py"
    for path in (header_path, c_probe_path, cxx_probe_path, runner_path, test_path):
        if not path.is_file():
            errors.append(f"x86 dirent header ABI is missing {path.relative_to(ROOT)}")
            return

    header = header_path.read_text(errors="replace")
    for required in (
        "#ifdef __cplusplus\nextern \"C\" {\n#endif",
        "#define d_fileno d_ino",
        "#ifdef _GNU_SOURCE\nint versionsort",
        "#if defined(_LARGEFILE64_SOURCE)",
        "#define dirent64 dirent",
        "#define readdir64 readdir",
        "#define versionsort64 versionsort",
        "#define getdents64 getdents",
        "#ifdef __cplusplus\n}\n#endif",
    ):
        if required not in header:
            errors.append(
                "include/dirent.h: x86 dirent header ABI contract is missing "
                f"{required!r}"
            )
    if "defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\nint versionsort" in header:
        errors.append(
            "include/dirent.h: versionsort must remain GNU-only in the pinned-musl contract"
        )

    runner = runner_path.read_text(errors="replace")
    for required in (
        "readonly EXPECTED_BASE_PROFILE_COUNT=7",
        "readonly EXPECTED_LARGEFILE64_PROFILE_COUNT=4",
        "SEEK_TELL_VISIBLE_PROFILES=(c11-gnu cxx17-gnu c11-xopen-700 c11-bsd)",
        "GETDENTS_VISIBLE_PROFILES=(c11-gnu cxx17-gnu c11-bsd)",
        "VERSIONSORT_VISIBLE_PROFILES=(c11-gnu cxx17-gnu)",
        "c11-gnu-largefile64 cxx17-gnu-largefile64 c11-strict-largefile64 cxx17-strict-largefile64",
        "-nostdinc",
        "-nostdinc++",
        "nm --undefined-only",
        "retained a mangled dirent reference",
        "header-requested C spellings",
        "does not claim x86 directory-stream runtime or archive linkage support",
    ):
        if required not in runner:
            errors.append(
                "compat/x86_64/run_dirent_header_abi.sh: x86 dirent profile "
                f"matrix is missing {required!r}"
            )
    for forbidden in ("-nostdlib", "libc-directory-streams", "--report-only"):
        if forbidden in runner:
            errors.append(
                "compat/x86_64/run_dirent_header_abi.sh: compile-only header "
                f"matrix must not contain {forbidden!r}"
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
        '#[path = "atomic.rs"]',
        '#[path = "syscall.rs"]',
        '#[path = "static_tls.rs"]',
        '#[path = "static_startup.rs"]',
        '#[path = "auxv_observation.rs"]',
        '#[path = "startup_security.rs"]',
        '#[path = "secure_environment.rs"]',
        '#[path = "process_globals.rs"]',
        '#[path = "stat_compat.rs"]',
        '#[path = "timestamp_updates.rs"]',
        '#[path = "credentials.rs"]',
        '#[path = "credential_observation.rs"]',
        '#[path = "memory.rs"]',
        '#[path = "memccpy.rs"]',
        '#[path = "mempcpy.rs"]',
        '#[path = "strsep.rs"]',
        '#[path = "legacy_memory.rs"]',
        '#[path = "fenv.rs"]',
        '#[path = "setjmp.rs"]',
        '#[path = "signal_foundation.rs"]',
        '#[path = "signal_control.rs"]',
        '#[path = "signal_realtime_max.rs"]',
        '#[path = "signal_realtime_min.rs"]',
        '#[path = "sched_getscheduler.rs"]',
        '#[path = "signal_alarm.rs"]',
        '#[path = "signal_pending.rs"]',
        '#[path = "signal_set_mutation.rs"]',
        '#[path = "signal_execution.rs"]',
        '#[path = "signal_set_isempty.rs"]',
        '#[path = "signal_set_binary.rs"]',
        '#[path = "signal_pause.rs"]',
        '#[path = "signal_fd.rs"]',
        '#[path = "timer_fd.rs"]',
        '#[path = "pthread_identity.rs"]',
        '#[path = "pthread_create_join.rs"]',
        '#[path = "pthread_tsd.rs"]',
        '#[path = "pthread_mutex.rs"]',
        '#[path = "pthread_cond.rs"]',
        '#[path = "pthread_rwlock.rs"]',
        '#[path = "c11_thread_lifecycle.rs"]',
        '#[path = "c11_sync.rs"]',
        '#[path = "pthread_once.rs"]',
        '#[path = "termios_control.rs"]',
        '#[path = "isatty.rs"]',
        '#[path = "tcgetpgrp.rs"]',
        '#[path = "tcsetpgrp.rs"]',
        '#[path = "getpass.rs"]',
        '#[path = "process_context.rs"]',
        '#[path = "login_name.rs"]',
        '#[path = "child_reaping.rs"]',
        '#[path = "immediate_termination.rs"]',
        '#[path = "posix_exit.rs"]',
        '#[path = "bsearch.rs"]',
        '#[path = "linear_search.rs"]',
        '#[path = "qsort.rs"]',
        '#[path = "callback_algorithms.rs"]',
        '#[path = "search_tree_intrusive.rs"]',
        '#[path = "search_hash_table.rs"]',
        '#[path = "gettext_catalog.rs"]',
        '#[path = "clock_gettime.rs"]',
        '#[path = "difftime.rs"]',
        '#[path = "gmtime_r.rs"]',
        '#[path = "timegm.rs"]',
        '#[path = "sched_getcpu.rs"]',
        '#[path = "sched_yield.rs"]',
        '#[path = "clock_nanosleep.rs"]',
        '#[path = "nanosleep.rs"]',
        '#[path = "descriptor_entry.rs"]',
        '#[path = "filesystem_access.rs"]',
        '#[path = "mktemp.rs"]',
        '#[path = "descriptor_control.rs"]',
        '#[path = "ioctl.rs"]',
        '#[path = "descriptor_io.rs"]',
        '#[path = "process_resources.rs"]',
        '#[path = "memory_mapping.rs"]',
        '#[path = "memory_sync.rs"]',
        '#[path = "memory_locking.rs"]',
        '#[path = "memfd_create.rs"]',
        '#[path = "readiness_waits.rs"]',
        '#[path = "socket_transport.rs"]',
        '#[path = "in6addr_any.rs"]',
        '#[path = "in6addr_loopback.rs"]',
        '#[path = "inet_address.rs"]',
        '#[path = "inet_ntoa.rs"]',
        '#[path = "inet_classful.rs"]',
        '#[path = "hstrerror.rs"]',
        '#[path = "socket_messages.rs"]',
        '#[path = "posix_semaphore.rs"]',
        '#[path = "byte_strings.rs"]',
        '#[path = "random_entropy.rs"]',
        '#[path = "memory_search.rs"]',
        '#[path = "string_copy.rs"]',
        '#[path = "error_strings.rs"]',
        '#[path = "strsignal.rs"]',
        '#[path = "ctype.rs"]',
        '#[path = "locale_ctype.rs"]',
        '#[path = "locale_multibyte.rs"]',
        '#[path = "locale_objects.rs"]',
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

    getpagesize_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "system_configuration.rs"
    )
    getpagesize_probe_source = ROOT / "compat" / "x86_64" / "libc_getpagesize_probe.c"
    getpagesize_start_source = ROOT / "compat" / "x86_64" / "libc_getpagesize_start.S"
    getpagesize_runner_source = ROOT / "compat" / "x86_64" / "run_libc_getpagesize.sh"
    getpagesize_header_c_source = (
        ROOT / "compat" / "x86_64" / "getpagesize_header_abi_probe.c"
    )
    getpagesize_header_cxx_source = (
        ROOT / "compat" / "x86_64" / "getpagesize_header_abi_probe.cpp"
    )
    getpagesize_header_runner_source = (
        ROOT / "compat" / "x86_64" / "run_getpagesize_header_abi.sh"
    )
    for path in (
        getpagesize_source,
        getpagesize_probe_source,
        getpagesize_start_source,
        getpagesize_runner_source,
        getpagesize_header_c_source,
        getpagesize_header_cxx_source,
        getpagesize_header_runner_source,
    ):
        if not path.is_file():
            errors.append(
                "x86 static getpagesize artifact is missing "
                f"{path.relative_to(ROOT)}"
            )
            return

    getpagesize_text = getpagesize_source.read_text(errors="replace")
    getpagesize_probe = getpagesize_probe_source.read_text(errors="replace")
    getpagesize_start = getpagesize_start_source.read_text(errors="replace")
    getpagesize_runner = getpagesize_runner_source.read_text(errors="replace")
    getpagesize_header_c = getpagesize_header_c_source.read_text(errors="replace")
    getpagesize_header_cxx = getpagesize_header_cxx_source.read_text(errors="replace")
    getpagesize_header_runner = getpagesize_header_runner_source.read_text(
        errors="replace"
    )
    for required in (
        "src/legacy/getpagesize.c",
        "X86_64_LINUX_PAGE_SIZE",
        'pub extern "C" fn getpagesize() -> c_int',
        "x86-64 Linux ABI has a 4096-byte base page size",
    ):
        if required not in getpagesize_text:
            errors.append(
                "libc/src/c_abi/x86_64/system_configuration.rs: selected "
                f"getpagesize source is missing {required!r}"
            )
    getpagesize_marker = "/// Return Linux/x86-64's fixed base page size."
    getdtablesize_marker = "/// Return the calling process's soft descriptor limit"
    if getpagesize_marker not in getpagesize_text or getdtablesize_marker not in getpagesize_text:
        errors.append(
            "libc/src/c_abi/x86_64/system_configuration.rs: selected "
            "getpagesize source boundary is missing"
        )
    else:
        getpagesize_body = getpagesize_text[
            getpagesize_text.index(getpagesize_marker) : getpagesize_text.index(
                getdtablesize_marker
            )
        ]
        for forbidden in ("raw_syscall", "errno", "getauxval", "sysconf", "pathconf"):
            if forbidden in getpagesize_body:
                errors.append(
                    "libc/src/c_abi/x86_64/system_configuration.rs: selected "
                    f"getpagesize leaf must not select {forbidden!r}"
                )
    for required in (
        "#include <unistd.h>",
        "getpagesize_signature",
        "check_fixed_x86_page_size",
        "indirect = getpagesize",
        "CRABC_GETPAGESIZE_FREESTANDING",
    ):
        if required not in getpagesize_probe:
            errors.append(
                "compat/x86_64/libc_getpagesize_probe.c: static getpagesize "
                f"regression is missing {required!r}"
            )
    for required in ("crabc_x86_64_getpagesize_probe", "mov $60, %eax"):
        if required not in getpagesize_start:
            errors.append(
                "compat/x86_64/libc_getpagesize_start.S: static getpagesize "
                f"entry shim is missing {required!r}"
            )
    for required in (
        "run_musl_oracle.sh",
        "run_getpagesize_header_abi.sh",
        "getpagesize.lo",
        "archive_member_for_symbol",
        "-nostdlib -static",
        "--no-undefined",
        "--gc-sections",
        "candidate retained broad system-configuration C ABI symbols",
        "candidate getpagesize unexpectedly performs a call or syscall",
    ):
        if required not in getpagesize_runner:
            errors.append(
                "compat/x86_64/run_libc_getpagesize.sh: static getpagesize "
                f"evidence is missing {required!r}"
            )
    if "--whole-archive" in getpagesize_runner:
        errors.append(
            "compat/x86_64/run_libc_getpagesize.sh: static getpagesize "
            "evidence must not force-link the archive"
        )
    for header_probe in (getpagesize_header_c, getpagesize_header_cxx):
        for required in (
            "getpagesize_signature",
            "CRABC_EXPECT_GETPAGESIZE",
            "CRABC_REQUIRE_GETPAGESIZE_HIDDEN",
        ):
            if required not in header_probe:
                errors.append(
                    "compat/x86_64 getpagesize header probe is missing "
                    f"{required!r}"
                )
    for required in (
        "getpagesize_header_abi_probe.c",
        "getpagesize_header_abi_probe.cpp",
        "bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_GETPAGESIZE)",
        "gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_GETPAGESIZE)",
        "outside GNU/BSD C selectors",
        "retained a mangled getpagesize reference",
    ):
        if required not in getpagesize_header_runner:
            errors.append(
                "compat/x86_64/run_getpagesize_header_abi.sh: getpagesize "
                f"declaration evidence is missing {required!r}"
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
        "pub unsafe extern \"C\" fn exit(",
        "pub unsafe extern \"C\" fn __libc_start_main(",
        "if rtld_fini.is_some() || !static_tls::is_ready()",
        "MAX_AUXV_ENTRIES",
        "auxv_observation::install_initial(vectors.auxv)",
        "startup_security::install_initial(vectors.auxv)",
        "if fini.is_some() && unsafe { atexit(fini) } != 0",
        "posix_exit::_exit(status)",
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
        "exit",
        "__libc_start_main",
    }
    if static_startup_exports != expected_static_startup_exports:
        errors.append(
            "libc/src/c_abi/x86_64/static_startup.rs: selected static startup "
            "artifact must export only its bounded lifecycle symbols"
        )

    auxv_observation_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "auxv_observation.rs"
    )
    auxv_observation_text = auxv_observation_source.read_text(errors="replace")
    startup_security_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "startup_security.rs"
    )
    startup_security_text = startup_security_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/env/__libc_start_main.c",
        "AT_UID",
        "AT_EUID",
        "AT_GID",
        "AT_EGID",
        "AT_SECURE",
        "MAX_AUXV_ENTRIES",
        "last matching auxiliary-vector value",
        "AtomicBool",
        "Ordering::Release",
        "Ordering::Acquire",
        "pub(super) unsafe fn install_initial",
        "pub(super) fn is_secure",
    ):
        if required not in startup_security_text:
            errors.append(
                "libc/src/c_abi/x86_64/startup_security.rs: selected static "
                f"secure-startup boundary is missing {required!r}"
            )

    secure_environment_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "secure_environment.rs"
    )
    secure_environment_text = secure_environment_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/env/secure_getenv.c",
        'pub unsafe extern "C" fn secure_getenv',
        "environment::getenv",
        "startup_security::is_secure",
        "auxv_observation",
    ):
        if required not in secure_environment_text:
            errors.append(
                "libc/src/c_abi/x86_64/secure_environment.rs: selected static "
                f"secure-environment boundary is missing {required!r}"
            )
    secure_environment_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            secure_environment_text,
        )
    )
    if secure_environment_exports != {"secure_getenv"}:
        errors.append(
            "libc/src/c_abi/x86_64/secure_environment.rs: selected static "
            "artifact must export only secure_getenv"
        )
    for forbidden in (
        "alloc::",
        "crabc_core",
        "crabc_mimalloc",
        "raw_syscall",
        "fn __getauxval",
        ".weak getauxval",
        "global_asm!",
        "fn fork(",
        "fn execve(",
        "fn setuid(",
        "fn sigaction(",
    ):
        if forbidden in secure_environment_text:
            errors.append(
                "libc/src/c_abi/x86_64/secure_environment.rs: selected static "
                f"secure-environment boundary must not select {forbidden!r}"
            )

    process_globals_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_globals.rs"
    )
    process_globals_text = process_globals_source.read_text(errors="replace")
    shared_getopt_source = ROOT / "libc" / "src" / "getopt_exports.rs"
    shared_getopt_text = shared_getopt_source.read_text(errors="replace")
    for required in (
        '".set optreset, __optreset"',
        '".set program_invocation_name, __progname_full"',
        '".set program_invocation_short_name, __progname"',
        '".set __posix_getopt, getopt"',
        'include!("../../getopt_exports.rs");',
        "EMPTY_PROGRAM_NAME",
        "pub(super) unsafe fn install(",
    ):
        if required not in process_globals_text:
            errors.append(
                "libc/src/c_abi/x86_64/process_globals.rs: selected program-name/"
                f"getopt boundary is missing {required!r}"
            )
    for overlap in (
        "__environ",
        "___environ",
        "_environ",
        "getenv(",
        "setenv(",
        "unsetenv(",
        "putenv(",
        "clearenv(",
    ):
        if overlap in process_globals_text:
            errors.append(
                "libc/src/c_abi/x86_64/process_globals.rs: selected program-name/"
                f"getopt boundary overlaps environment ownership through {overlap!r}"
            )
    for required in (
        'target_arch = "aarch64"',
        'target_arch = "x86_64"',
        "unsafe fn cabi_getopt_set_errno",
        "unsafe fn cabi_getopt_apply_reset",
        "pub unsafe extern \"C\" fn getopt(",
        "pub unsafe extern \"C\" fn getopt_long(",
        "pub unsafe extern \"C\" fn getopt_long_only(",
        "pub unsafe fn cabi_set_program_names",
    ):
        if required not in shared_getopt_text:
            errors.append(
                "libc/src/getopt_exports.rs: shared AArch64/x86 getopt boundary "
                f"is missing {required!r}"
            )
    install_call = "unsafe { process_globals::install(argc, argv) };"
    init_call = "if let Some(init) = init {"
    if (
        install_call not in static_startup_text
        or init_call not in static_startup_text
        or static_startup_text.index(install_call)
        >= static_startup_text.index(init_call)
    ):
        errors.append(
            "libc/src/c_abi/x86_64/static_startup.rs: program names must be "
            "published before the bounded init callback"
        )
    auxv_install_call = "unsafe { auxv_observation::install_initial(vectors.auxv) };"
    security_install_call = "unsafe { startup_security::install_initial(vectors.auxv) };"
    environment_install_call = "unsafe { environment::install_initial(vectors.envp) };"
    if (
        auxv_install_call not in static_startup_text
        or security_install_call not in static_startup_text
        or environment_install_call not in static_startup_text
        or init_call not in static_startup_text
        or static_startup_text.index(auxv_install_call)
        >= static_startup_text.index(security_install_call)
        or static_startup_text.index(security_install_call)
        >= static_startup_text.index(environment_install_call)
        or static_startup_text.index(environment_install_call)
        >= static_startup_text.index(init_call)
    ):
        errors.append(
            "libc/src/c_abi/x86_64/static_startup.rs: raw auxv observation, "
            "validated auxv security, and envp must publish before the bounded init callback"
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
        "STATIC_INITIAL_TLS_MAIN_THREAD_POINTER",
        "STATIC_INITIAL_TLS_MAIN_THREAD_ID",
        "TLS_STATE_READY",
        "is_initial_thread_pointer",
        "raw_syscall::SYS_GETTID",
        "__crabc_x86_static_tls_bootstrap",
        ".hidden __crabc_x86_static_tls_bootstrap",
    ):
        if required not in static_tls_text:
            errors.append(
                "libc/src/c_abi/x86_64/static_tls.rs: Static Initial TLS v1 "
                f"owner is missing {required!r}"
            )
    identity_bootstrap_marker = "pub(super) unsafe fn bootstrap_initial_thread"
    identity_bootstrap_end = "/// Private freestanding entry hook"
    if (
        identity_bootstrap_marker not in static_tls_text
        or identity_bootstrap_end not in static_tls_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/static_tls.rs: selected-main identity "
            "bootstrap boundary is missing"
        )
    else:
        identity_bootstrap_text = static_tls_text.split(
            identity_bootstrap_marker, 1
        )[1].split(identity_bootstrap_end, 1)[0]
        ready_store = "STATIC_INITIAL_TLS_STATE.store(TLS_STATE_READY"
        for identity_store in (
            "STATIC_INITIAL_TLS_MAIN_THREAD_POINTER.store",
            "STATIC_INITIAL_TLS_MAIN_THREAD_ID.store",
        ):
            if (
                identity_store not in identity_bootstrap_text
                or ready_store not in identity_bootstrap_text
                or identity_bootstrap_text.index(identity_store)
                >= identity_bootstrap_text.index(ready_store)
            ):
                errors.append(
                    "libc/src/c_abi/x86_64/static_tls.rs: selected-main "
                    "TP/TID identity must publish before TLS readiness"
                )
                break
    identity_check_marker = "pub(super) fn is_initial_thread_pointer"
    identity_check_end = "/// Materialize one independent child"
    if (
        identity_check_marker not in static_tls_text
        or identity_check_end not in static_tls_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/static_tls.rs: selected-main identity "
            "check is missing"
        )
    else:
        identity_check_text = static_tls_text.split(identity_check_marker, 1)[1].split(
            identity_check_end, 1
        )[0]
        for required in (
            "STATIC_INITIAL_TLS_MAIN_THREAD_POINTER.load",
            "raw_syscall::SYS_GETTID",
            "STATIC_INITIAL_TLS_MAIN_THREAD_ID.load",
        ):
            if required not in identity_check_text:
                errors.append(
                    "libc/src/c_abi/x86_64/static_tls.rs: selected-main "
                    f"TP/TID identity check is missing {required!r}"
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

    legacy_memory_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "legacy_memory.rs"
    )
    legacy_memory_text = legacy_memory_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/string/bcopy.c",
        "src/string/bzero.c",
        ".global bcopy",
        ".global bzero",
        "xchg rdi, rsi",
        "mov rdx, rsi",
        "xor esi, esi",
        "jmp memmove",
        "jmp memset",
    ):
        if required not in legacy_memory_text:
            errors.append(
                "libc/src/c_abi/x86_64/legacy_memory.rs: selected static legacy "
                f"memory adapter is missing {required!r}"
            )
    legacy_memory_exports = set(
        re.findall(r"(?m)^\s*\.global\s+(\w+)\s*$", legacy_memory_text)
    )
    if legacy_memory_exports != {"bcopy", "bzero"}:
        errors.append(
            "libc/src/c_abi/x86_64/legacy_memory.rs: selected static legacy "
            "memory adapter must export only bcopy and bzero"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
        "memccpy",
        "mempcpy",
        "explicit_bzero",
    ):
        if forbidden in legacy_memory_text:
            errors.append(
                "libc/src/c_abi/x86_64/legacy_memory.rs: selected static legacy "
                f"memory adapter must not select {forbidden!r}"
            )

    memccpy_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memccpy.rs"
    memccpy_text = memccpy_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/string/memccpy.c",
        "const WORD_SIZE",
        "const ALIGN",
        "const ONES",
        "const HIGHS",
        "const fn has_zero_byte",
        "wrapping_mul",
        "pub unsafe extern \"C\" fn memccpy",
        "restrict contract",
    ):
        if required not in memccpy_text:
            errors.append(
                "libc/src/c_abi/x86_64/memccpy.rs: selected static memccpy "
                f"boundary is missing {required!r}"
            )
    memccpy_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            memccpy_text,
        )
    )
    if memccpy_exports != {"memccpy"}:
        errors.append(
            "libc/src/c_abi/x86_64/memccpy.rs: selected static memccpy "
            "artifact must export only memccpy"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
        "malloc",
        "use super::memory",
        "memory::",
    ):
        if forbidden in memccpy_text:
            errors.append(
                "libc/src/c_abi/x86_64/memccpy.rs: selected static memccpy "
                f"leaf must not select {forbidden!r}"
            )

    mempcpy_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "mempcpy.rs"
    mempcpy_text = mempcpy_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/string/mempcpy.c",
        "restrict",
        ".global mempcpy",
        "push rbx",
        "lea rbx, [rdi + rdx]",
        "call memcpy",
        "mov rax, rbx",
        "pop rbx",
    ):
        if required not in mempcpy_text:
            errors.append(
                "libc/src/c_abi/x86_64/mempcpy.rs: selected static mempcpy "
                f"boundary is missing {required!r}"
            )
    mempcpy_exports = set(
        re.findall(r"(?m)^\s*\.global\s+(\w+)\s*$", mempcpy_text)
    )
    if mempcpy_exports != {"mempcpy"}:
        errors.append(
            "libc/src/c_abi/x86_64/mempcpy.rs: selected static mempcpy "
            "artifact must export only mempcpy"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
        "malloc",
        "memccpy",
        "explicit_bzero",
    ):
        if forbidden in mempcpy_text:
            errors.append(
                "libc/src/c_abi/x86_64/mempcpy.rs: selected static mempcpy "
                f"leaf must not select {forbidden!r}"
            )
    mempcpy_runner = ROOT / "compat" / "x86_64" / "run_libc_mempcpy.sh"
    mempcpy_runner_text = mempcpy_runner.read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_mempcpy_header_abi.sh",
        "mempcpy.lo",
        "archive_member_for_symbol",
        "mempcpy adapter dependency closure drifted",
        "mempcpy adapter lacks direct memcpy relocation",
        "SysV return preservation",
        "-nostdlib -static",
        "--no-undefined",
    ):
        if required not in mempcpy_runner_text:
            errors.append(
                "compat/x86_64/run_libc_mempcpy.sh: selected static mempcpy "
                f"evidence is missing {required!r}"
            )
    if "--whole-archive" in mempcpy_runner_text:
        errors.append(
            "compat/x86_64/run_libc_mempcpy.sh: selected static mempcpy "
            "evidence must not force-link the archive"
        )

    strsep_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "strsep.rs"
    strsep_text = strsep_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/string/strsep.c",
        "caller-owned `char **` state slot",
        "pub unsafe extern \"C\" fn strsep",
        "stringp.write(null_mut())",
        "current.write(0)",
    ):
        if required not in strsep_text:
            errors.append(
                "libc/src/c_abi/x86_64/strsep.rs: selected static strsep "
                f"boundary is missing {required!r}"
            )
    strsep_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            strsep_text,
        )
    )
    if strsep_exports != {"strsep"}:
        errors.append(
            "libc/src/c_abi/x86_64/strsep.rs: selected static strsep "
            "artifact must export only strsep"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
        "malloc",
        "strcspn",
        "strtok",
        "strtok_r",
        "use super::",
    ):
        if forbidden in strsep_text:
            errors.append(
                "libc/src/c_abi/x86_64/strsep.rs: selected static strsep "
                f"leaf must not select {forbidden!r}"
            )
    strsep_runner = ROOT / "compat" / "x86_64" / "run_libc_strsep.sh"
    strsep_runner_text = strsep_runner.read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_strsep_header_abi.sh",
        "strsep.lo",
        "archive_member_for_symbol",
        "strsep object export surface drifted",
        "strsep object unexpectedly depends on another symbol",
        "strsep object unexpectedly performs a syscall",
        "-nostdlib -static",
        "--no-undefined",
        "candidate retains a PLT",
    ):
        if required not in strsep_runner_text:
            errors.append(
                "compat/x86_64/run_libc_strsep.sh: selected static strsep "
                f"evidence is missing {required!r}"
            )
    if "--whole-archive" in strsep_runner_text:
        errors.append(
            "compat/x86_64/run_libc_strsep.sh: selected static strsep "
            "evidence must not force-link the archive"
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

    elementary_sqrt_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "elementary_sqrt.rs"
    )
    elementary_sqrt_text = elementary_sqrt_source.read_text(errors="replace")
    for required in (
        "src/math/x86_64/sqrt.c",
        "src/math/x86_64/sqrtf.c",
        "src/math/x86_64/sqrtl.c",
        ".global sqrt",
        ".global sqrtf",
        ".global sqrtl",
        "sqrtsd xmm0, xmm0",
        "sqrtss xmm0, xmm0",
        "fld tbyte ptr [rsp + 8]",
        "fsqrt",
        "public x86 support",
    ):
        if required not in elementary_sqrt_text:
            errors.append(
                "libc/src/c_abi/x86_64/elementary_sqrt.rs: selected static "
                f"square-root boundary is missing {required!r}"
            )

    fenv_rounding_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "fenv_rounding.rs"
    )
    fenv_rounding_text = fenv_rounding_source.read_text(errors="replace")
    for required in (
        "src/math/rint.c",
        "src/math/nearbyint.c",
        "math_lrint.rs",
        "math_compat.rs",
        ".global rint",
        ".global rintf",
        ".global rintl",
        ".global nearbyint",
        ".global nearbyintf",
        ".global nearbyintl",
        "addsd",
        "subsd",
        "addss",
        "subss",
        "faddp",
        "fsubp",
        "call fetestexcept",
        "call feclearexcept",
        "public x86 support",
    ):
        if required not in fenv_rounding_text:
            errors.append(
                "libc/src/c_abi/x86_64/fenv_rounding.rs: selected static "
                f"fenv-sensitive rounding boundary is missing {required!r}"
            )

    complex_projection_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "complex_projection.rs"
    )
    complex_projection_text = complex_projection_source.read_text(errors="replace")
    for required in (
        "src/complex/{cproj,cprojf,cprojl}.c",
        "complex_basic_exports.rs",
        ".global cproj",
        ".global cprojf",
        ".global cprojl",
        "fldz",
        "fld tbyte ptr",
        "public x86 support",
    ):
        if required not in complex_projection_text:
            errors.append(
                "libc/src/c_abi/x86_64/complex_projection.rs: selected static "
                f"complex projection boundary is missing {required!r}"
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
        "raw_syscall::syscall4(",
        "RESERVED_SIGNAL_MASK",
        "pack_public_action",
        "unpack_kernel_action",
        "APPLICATION_SIGNAL_MAX: c_int = 64",
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
        "sigismember",
        "sigprocmask",
    }
    if signal_exports != expected_signal_exports:
        errors.append(
            "libc/src/c_abi/x86_64/signal_control.rs: selected static signal "
            "artifact must export only simple action/set/mask symbols"
        )

    signal_realtime_max_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_realtime_max.rs"
    )
    signal_realtime_max_text = signal_realtime_max_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 realtime signal maximum C ABI boundary",
        "src/signal/sigrtmax.c",
        "_NSIG-1",
        "X86_NSIG: c_int = 65",
        "X86_SIGRTMAX: c_int = X86_NSIG - 1",
    ):
        if required not in signal_realtime_max_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_realtime_max.rs: selected static "
                f"realtime-maximum bridge is missing {required!r}"
            )
    signal_realtime_max_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_realtime_max_text,
        )
    )
    if signal_realtime_max_exports != {"__libc_current_sigrtmax"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_realtime_max.rs: selected static "
            "artifact must export only __libc_current_sigrtmax"
        )
    for forbidden in (
        "raw_syscall",
        "errno",
        "sigaction",
        "sigprocmask",
        "sigpending",
        "sigwait",
        "signalfd",
        "timerfd",
        "pthread_",
    ):
        if forbidden in signal_realtime_max_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_realtime_max.rs: selected static "
                f"realtime-maximum bridge must not select {forbidden!r}"
            )

    signal_realtime_min_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_realtime_min.rs"
    )
    signal_realtime_min_text = signal_realtime_min_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 realtime signal minimum C ABI boundary",
        "src/signal/sigrtmin.c",
        "X86_SIGRTMIN: c_int = 35",
    ):
        if required not in signal_realtime_min_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_realtime_min.rs: selected static "
                f"realtime-minimum bridge is missing {required!r}"
            )
    signal_realtime_min_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_realtime_min_text,
        )
    )
    if signal_realtime_min_exports != {"__libc_current_sigrtmin"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_realtime_min.rs: selected static "
            "artifact must export only __libc_current_sigrtmin"
        )
    for forbidden in (
        "raw_syscall",
        "errno",
        "sigaction",
        "sigprocmask",
        "sigpending",
        "sigwait",
        "signalfd",
        "timerfd",
        "pthread_",
    ):
        if forbidden in signal_realtime_min_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_realtime_min.rs: selected static "
                f"realtime-minimum bridge must not select {forbidden!r}"
            )

    sched_getscheduler_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_getscheduler.rs"
    )
    sched_getscheduler_text = sched_getscheduler_source.read_text(errors="replace")
    for required in (
        "Bounded Linux/x86-64 static POSIX scheduler-policy observation boundary",
        "src/sched/sched_getscheduler.c::sched_getscheduler",
        "__syscall_ret(-ENOSYS)",
        "raw syscall `sched_getscheduler=145`",
        "c_status(-ENOSYS)",
    ):
        if required not in sched_getscheduler_text:
            errors.append(
                "libc/src/c_abi/x86_64/sched_getscheduler.rs: selected static "
                f"musl-ENOSYS scheduler boundary is missing {required!r}"
            )
    sched_getscheduler_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            sched_getscheduler_text,
        )
    )
    if sched_getscheduler_exports != {"sched_getscheduler"}:
        errors.append(
            "libc/src/c_abi/x86_64/sched_getscheduler.rs: selected static "
            "artifact must export only sched_getscheduler"
        )
    for forbidden in (
        "raw_syscall::",
        "SYS_SCHED_GETSCHEDULER",
        "pthread_",
    ):
        if forbidden in sched_getscheduler_text:
            errors.append(
                "libc/src/c_abi/x86_64/sched_getscheduler.rs: selected static "
                f"musl-ENOSYS scheduler boundary must not select {forbidden!r}"
            )

    signal_alarm_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_alarm.rs"
    )
    signal_alarm_text = signal_alarm_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 alarm C boundary",
        "src/unistd/alarm.c",
        "src/signal/setitimer.c",
        "raw_syscall::SYS_SETITIMER",
        "raw_syscall::syscall3(",
        "c_status(result)",
        "ITIMER_REAL",
        "old.value.seconds",
        "old.value.microseconds",
    ):
        if required not in signal_alarm_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_alarm.rs: selected static "
                f"historical alarm boundary is missing {required!r}"
            )
    signal_alarm_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_alarm_text,
        )
    )
    if signal_alarm_exports != {"alarm"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_alarm.rs: selected static artifact "
            "must export only alarm"
        )
    for forbidden in (
        'pub extern "C" fn setitimer',
        'pub extern "C" fn ualarm',
        "sigaction",
        "sigprocmask",
        "sigtimedwait",
        "timerfd",
        "pthread_",
    ):
        if forbidden in signal_alarm_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_alarm.rs: selected static "
                f"historical alarm boundary must not select {forbidden!r}"
            )

    signal_pending_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_pending.rs"
    )
    signal_pending_text = signal_pending_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 `sigpending` C boundary",
        "src/signal/sigpending.c",
        "raw_syscall::SYS_RT_SIGPENDING",
        "raw_syscall::syscall2(",
        "size_of::<u64>()",
        "c_status(result)",
    ):
        if required not in signal_pending_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_pending.rs: selected static "
                f"sigpending boundary is missing {required!r}"
            )
    signal_pending_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_pending_text,
        )
    )
    if signal_pending_exports != {"sigpending"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_pending.rs: selected static artifact "
            "must export only sigpending"
        )
    for forbidden in (
        "sigaction(",
        "signal(",
        "sigprocmask(",
        "sigsuspend(",
        "sigwait",
        "signalfd",
        "timerfd",
        "pthread_",
    ):
        if forbidden in signal_pending_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_pending.rs: selected static "
                f"sigpending boundary must not select {forbidden!r}"
            )

    signal_set_mutation_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_mutation.rs"
    )
    signal_set_mutation_text = signal_set_mutation_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 POSIX signal-set mutation C boundary",
        "src/signal/sigaddset.c",
        "src/signal/sigdelset.c",
        "src/signal/sigfillset.c",
        "SST_SIZE",
        "SIGFILLSET_FIRST_WORD",
        "errno::set_errno",
        "core::ptr::read_unaligned",
        "core::ptr::write_unaligned",
    ):
        if required not in signal_set_mutation_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_set_mutation.rs: selected static "
                f"signal-set mutation boundary is missing {required!r}"
            )
    signal_set_mutation_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_set_mutation_text,
        )
    )
    if signal_set_mutation_exports != {"sigaddset", "sigdelset", "sigfillset"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_set_mutation.rs: selected static artifact "
            "must export only sigaddset, sigdelset, and sigfillset"
        )
    for forbidden in (
        "raw_syscall",
        "sigaction(",
        "sigprocmask(",
        "sigpending(",
        "sigsuspend(",
        "sigwait",
        "signalfd",
        "timerfd",
        "pthread_",
        "signal_control",
    ):
        if forbidden in signal_set_mutation_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_set_mutation.rs: selected static "
                f"signal-set mutation boundary must not select {forbidden!r}"
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
        "current_selected_worker_control",
        "publish_selected_worker_result",
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
        "tsd: pthread_tsd::SelectedTsdValues",
        "pthread_tsd::SelectedTsdValues::empty()",
        "current_selected_worker_tsd_values",
        "clear_selected_worker_tsd_key",
        "pthread_tsd::run_selected_worker_tsd_destructors",
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
    explicit_exit_publish_marker = "fn current_selected_worker_control"
    explicit_exit_publish_end = "/// Return the current selected worker's bounded TSD table"
    if (
        explicit_exit_publish_marker not in pthread_create_join_text
        or explicit_exit_publish_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread exit "
            "is missing its bounded current-worker resolution helper"
        )
    else:
        explicit_exit_publish_text = pthread_create_join_text.split(
            explicit_exit_publish_marker, 1
        )[1].split(explicit_exit_publish_end, 1)[0]
        required_resolution_order = (
            "lock_selected_worker_registry",
            "worker_tid.load",
            "child_tid.load",
            "current = Some(control)",
            "unlock_selected_worker_registry",
        )
        if any(
            marker not in explicit_exit_publish_text
            for marker in required_resolution_order
        ) or any(
            explicit_exit_publish_text.index(left)
            > explicit_exit_publish_text.index(right)
            for left, right in zip(
                required_resolution_order, required_resolution_order[1:]
            )
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: current selected-worker "
                "resolution must validate worker/gettid/child-TID under its registry lock"
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
        normal_exit_order = (
            "(*control).start.invoke",
            "pthread_tsd::run_selected_worker_tsd_destructors",
            "publish_selected_worker_result",
        )
        if any(marker not in worker_entry_text for marker in normal_exit_order) or any(
            worker_entry_text.index(left) > worker_entry_text.index(right)
            for left, right in zip(normal_exit_order, normal_exit_order[1:])
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: normal selected-worker "
                "exit must run private TSD destructors before result publication"
            )

    explicit_exit_marker = "unsafe fn exit_selected_worker"
    explicit_exit_end = "/// End one selected pthread-mode worker"
    if (
        explicit_exit_marker not in pthread_create_join_text
        or explicit_exit_end not in pthread_create_join_text
    ):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_create_join.rs: selected pthread exit "
            "is missing its private TSD destructor boundary"
        )
    else:
        explicit_exit_text = pthread_create_join_text.split(explicit_exit_marker, 1)[1].split(
            explicit_exit_end, 1
        )[0]
        explicit_exit_order = (
            "current_selected_worker_control()",
            "pthread_tsd::run_selected_worker_tsd_destructors",
            "publish_selected_worker_result",
        )
        if any(marker not in explicit_exit_text for marker in explicit_exit_order) or any(
            explicit_exit_text.index(left) > explicit_exit_text.index(right)
            for left, right in zip(explicit_exit_order, explicit_exit_order[1:])
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_create_join.rs: explicit selected-worker "
                "exit must run private TSD destructors before result publication"
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
        "src/thread/thrd_sleep.c",
        "C11StartRoutine",
        "SelectedWorkerStart::C11",
        "THRD_SUCCESS",
        "THRD_ERROR",
        "THRD_NOMEM",
        "THRD_SLEEP_INTR",
        "THRD_SLEEP_ERROR",
        "fn thrd_create(",
        "fn thrd_join(",
        "fn thrd_exit(",
        "fn thrd_detach(",
        "fn thrd_sleep(",
        "detach_selected_worker",
        "super::clock_nanosleep::clock_nanosleep",
        "super::clock_nanosleep::CLOCK_REALTIME",
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
        "thrd_sleep",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/c11_thread_lifecycle.rs: bounded static C11 "
            "leaf must export only thrd_create, thrd_join, thrd_exit, thrd_detach, and thrd_sleep"
        )
    for forbidden in (
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

    atomic_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "atomic.rs"
    atomic_text = atomic_source.read_text(errors="replace")
    for required in (
        "AtomicI32::from_ptr",
        "x86_64_load_acquire_i32",
        "x86_64_load_relaxed_i32",
        "x86_64_compare_exchange_acqrel_i32",
        "x86_64_swap_acqrel_i32",
        "x86_64_fetch_add_acqrel_i32",
        "x86_64_fetch_sub_acqrel_i32",
        "private normal-mutex and its private condition-variable handoff artifacts",
    ):
        if required not in atomic_text:
            errors.append(
                "libc/src/c_abi/x86_64/atomic.rs: selected static mutex/condition "
                f"helper is missing {required!r}"
            )
    if "#[no_mangle]" in atomic_text:
        errors.append(
            "libc/src/c_abi/x86_64/atomic.rs: mutex/condition atomic helpers must "
            "remain private Rust helpers rather than public C exports"
        )

    pthread_mutex_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_mutex.rs"
    )
    pthread_mutex_text = pthread_mutex_source.read_text(errors="replace")
    for required in (
        "1.2.6 release commit",
        "src/thread/pthread_mutex_init.c",
        "src/thread/pthread_mutex_trylock.c::__pthread_mutex_trylock",
        "src/thread/pthread_mutex_lock.c::__pthread_mutex_lock",
        "src/thread/pthread_mutex_timedlock.c::__pthread_mutex_timedlock",
        "src/thread/pthread_mutex_unlock.c::__pthread_mutex_unlock",
        "src/thread/pthread_mutex_destroy.c",
        "process-private `PTHREAD_MUTEX_NORMAL`",
        "struct PublicPthreadMutex",
        "#[repr(C, align(8))]",
        "MUTEX_TYPE_WORD: usize = 0",
        "MUTEX_LOCK_WORD: usize = 1",
        "MUTEX_WAITERS_WORD: usize = 2",
        "MUTEX_WORD_COUNT: usize = 10",
        "MUTEX_WAITER_BIT: c_int = c_int::MIN",
        "size_of::<PublicPthreadMutex>() == 40",
        "align_of::<PublicPthreadMutex>() == 8",
        "FUTEX_WAIT_PRIVATE",
        "FUTEX_WAKE_PRIVATE",
        "raw_syscall::SYS_FUTEX",
        "raw_syscall::syscall4(",
        "x86_64_compare_exchange_acqrel_i32",
        "x86_64_swap_acqrel_i32",
        "x86_64_fetch_add_acqrel_i32",
        "x86_64_fetch_sub_acqrel_i32",
        "public pthread boundary never writes C `errno`",
        "public x86 support",
    ):
        if required not in pthread_mutex_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_mutex.rs: selected private normal "
                f"mutex leaf is missing {required!r}"
            )
    pthread_mutex_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            pthread_mutex_text,
        )
    )
    if pthread_mutex_exports != {
        "pthread_mutex_init",
        "pthread_mutex_destroy",
        "pthread_mutex_trylock",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_mutex.rs: selected private normal "
            "mutex leaf must export only init, destroy, lock, trylock, and unlock"
        )
    for forbidden in (
        'pub unsafe extern "C" fn pthread_mutexattr_',
        'pub unsafe extern "C" fn pthread_mutex_timedlock',
        'pub unsafe extern "C" fn pthread_cond_',
        'pub unsafe extern "C" fn pthread_rwlock_',
        'pub unsafe extern "C" fn pthread_once',
        'pub unsafe extern "C" fn mtx_',
        "pthread_self",
        "SYS_GETTID",
        "__tls_get_addr",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in pthread_mutex_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_mutex.rs: selected private normal "
                f"mutex leaf must not select {forbidden!r}"
            )

    pthread_cond_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_cond.rs"
    )
    pthread_cond_text = pthread_cond_source.read_text(errors="replace")
    for required in (
        "1.2.6 release commit",
        "src/thread/pthread_cond_init.c::pthread_cond_init",
        "src/thread/pthread_cond_destroy.c::pthread_cond_destroy",
        "src/thread/pthread_cond_wait.c::pthread_cond_wait",
        "src/thread/pthread_cond_timedwait.c::__pthread_cond_timedwait",
        "src/thread/pthread_cond_signal.c::pthread_cond_signal",
        "src/thread/pthread_cond_broadcast.c::pthread_cond_broadcast",
        "src/thread/pthread_cond_timedwait.c::__private_cond_signal",
        "src/thread/__wait.c::__wait",
        "src/thread/pthread_cond_timedwait.c::{lock,unlock,unlock_requeue}",
        "process-private condition-variable handoff",
        "struct PublicPthreadCond",
        "#[repr(C, align(8))]",
        "COND_WORD_COUNT: usize = 12",
        "COND_LOCK_WORD: usize = 8",
        "size_of::<PublicPthreadCond>() == 48",
        "align_of::<PublicPthreadCond>() == 8",
        "cond_head_slot",
        "cond_tail_slot",
        "struct Waiter",
        "barrier: c_int",
        "notify: *mut c_int",
        "let mut node = Waiter {",
        "WAITER_LEAVING: c_int = 2",
        "private_cond_signal",
        "private_unlock_requeue",
        "const FUTEX_WAIT: i64 = 0;",
        "const FUTEX_WAKE: i64 = 1;",
        "const FUTEX_REQUEUE: i64 = 3;",
        "const FUTEX_PRIVATE_FLAG: i64 = 128;",
        "const FUTEX_WAIT_PRIVATE: i64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;",
        "const FUTEX_WAKE_PRIVATE: i64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;",
        "const FUTEX_REQUEUE_PRIVATE: i64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;",
        "raw_syscall::SYS_FUTEX",
        "raw_syscall::syscall4(",
        "raw_syscall::syscall5(",
        "val2=1` in r10",
        "mutex_lock` in r8",
        "pthread_mutex::selected_normal_mutex_words",
        "pthread_mutex::unlock_selected_normal_mutex",
        "pthread_mutex::lock_selected_normal_mutex",
        "public x86 support",
    ):
        if required not in pthread_cond_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_cond.rs: selected private condition "
                f"leaf is missing {required!r}"
            )
    pthread_cond_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            pthread_cond_text,
        )
    )
    expected_pthread_cond_exports = {
        "pthread_cond_init",
        "pthread_cond_destroy",
        "pthread_cond_wait",
        "pthread_cond_signal",
        "pthread_cond_broadcast",
    }
    if pthread_cond_exports != expected_pthread_cond_exports:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_cond.rs: selected private condition "
            "leaf must export only init, destroy, wait, signal, and broadcast"
        )
    for forbidden in (
        'pub unsafe extern "C" fn pthread_cond_timedwait',
        'pub unsafe extern "C" fn pthread_condattr_',
        'pub unsafe extern "C" fn cnd_',
        'pub unsafe extern "C" fn mtx_',
        'pub unsafe extern "C" fn pthread_mutexattr_',
        'pub unsafe extern "C" fn pthread_rwlock_',
        'pub unsafe extern "C" fn pthread_once',
        "__tls_get_addr",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in pthread_cond_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_cond.rs: selected private condition "
                f"leaf must not select {forbidden!r}"
            )

    pthread_rwlock_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_rwlock.rs"
    )
    pthread_rwlock_text = pthread_rwlock_source.read_text(errors="replace")
    for required in (
        "1.2.6 release commit",
        "src/thread/pthread_rwlock_init.c",
        "src/thread/pthread_rwlock_destroy.c",
        "src/thread/pthread_rwlock_{tryrdlock,timedrdlock,rdlock}.c",
        "src/thread/pthread_rwlock_{trywrlock,timedwrlock,wrlock}.c",
        "src/thread/pthread_rwlock_unlock.c",
        "src/thread/pthread_rwlockattr_{init,destroy,setpshared}.c",
        "src/thread/pthread_attr_get.c::pthread_rwlockattr_getpshared",
        "src/thread/__timedwait.c",
        "struct PublicPthreadRwlock",
        "struct PublicPthreadRwlockAttr",
        "RWLOCK_LOCK_WORD: usize = 0",
        "RWLOCK_WAITERS_WORD: usize = 1",
        "RWLOCK_SHARED_WORD: usize = 2",
        "RWLOCK_WORD_COUNT: usize = 14",
        "RWLOCK_WRITER: c_int = 0x7fff_ffff",
        "RWLOCK_READER_MAX: c_int = 0x7fff_fffe",
        "RWLOCK_WAITER_BIT: c_int = c_int::MIN",
        "size_of::<PublicPthreadRwlock>() == 56",
        "align_of::<PublicPthreadRwlock>() == 8",
        "size_of::<PublicPthreadRwlockAttr>() == 8",
        "align_of::<PublicPthreadRwlockAttr>() == 4",
        "timed_futex_wait",
        "futex_private_flag",
        "FUTEX_PRIVATE_FLAG",
        "raw_syscall::SYS_CLOCK_GETTIME",
        "raw_syscall::SYS_FUTEX",
        "raw_syscall::syscall2(",
        "raw_syscall::syscall4(",
        "x86_64_compare_exchange_acqrel_i32",
        "x86_64_fetch_add_acqrel_i32",
        "x86_64_fetch_sub_acqrel_i32",
        "public x86 support",
    ):
        if required not in pthread_rwlock_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_rwlock.rs: selected static rwlock "
                f"artifact is missing {required!r}"
            )
    pthread_rwlock_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            pthread_rwlock_text,
        )
    )
    expected_pthread_rwlock_exports = {
        "pthread_rwlockattr_init",
        "pthread_rwlockattr_destroy",
        "pthread_rwlockattr_setpshared",
        "pthread_rwlockattr_getpshared",
        "pthread_rwlock_init",
        "pthread_rwlock_destroy",
        "__pthread_rwlock_rdlock",
        "__pthread_rwlock_tryrdlock",
        "__pthread_rwlock_timedrdlock",
        "__pthread_rwlock_wrlock",
        "__pthread_rwlock_trywrlock",
        "__pthread_rwlock_timedwrlock",
        "__pthread_rwlock_unlock",
    }
    if pthread_rwlock_exports != expected_pthread_rwlock_exports:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_rwlock.rs: selected static rwlock "
            "artifact must export its six direct APIs and seven hidden lock aliases"
        )
    pthread_rwlock_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(pthread_rwlock_\w+)\s*,\s*(__pthread_rwlock_\w+)",\s*$',
            pthread_rwlock_text,
        )
    )
    expected_pthread_rwlock_aliases = {
        ("pthread_rwlock_rdlock", "__pthread_rwlock_rdlock"),
        ("pthread_rwlock_tryrdlock", "__pthread_rwlock_tryrdlock"),
        ("pthread_rwlock_timedrdlock", "__pthread_rwlock_timedrdlock"),
        ("pthread_rwlock_wrlock", "__pthread_rwlock_wrlock"),
        ("pthread_rwlock_trywrlock", "__pthread_rwlock_trywrlock"),
        ("pthread_rwlock_timedwrlock", "__pthread_rwlock_timedwrlock"),
        ("pthread_rwlock_unlock", "__pthread_rwlock_unlock"),
    }
    if pthread_rwlock_aliases != expected_pthread_rwlock_aliases:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_rwlock.rs: selected static rwlock "
            "artifact must retain all seven musl same-address assembler aliases"
        )
    for forbidden in (
        "errno::",
        "c_status(",
        "pthread_mutex::",
        "pthread_cond::",
        "crabc_core",
        "crabc_mimalloc",
        "__tls_get_addr",
    ):
        if forbidden in pthread_rwlock_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_rwlock.rs: selected static rwlock "
                f"artifact must not select {forbidden!r}"
            )

    c11_sync_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "c11_sync.rs"
    c11_sync_text = c11_sync_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/thread/mtx_init.c",
        "mtx_destroy.c",
        "mtx_lock.c",
        "mtx_trylock.c",
        "mtx_unlock.c",
        "src/thread/cnd_init.c",
        "cnd_destroy.c",
        "cnd_wait.c",
        "cnd_signal.c",
        "cnd_broadcast.c",
        "mtx_timedlock.c",
        "cnd_timedwait.c",
        "struct PublicC11Mutex",
        "struct PublicC11Condition",
        "size_of::<PublicC11Mutex>() == 40",
        "align_of::<PublicC11Mutex>() == 8",
        "size_of::<PublicC11Condition>() == 48",
        "align_of::<PublicC11Condition>() == 8",
        "MTX_PLAIN: c_int = 0",
        "THRD_SUCCESS: c_int = 0",
        "THRD_BUSY: c_int = 1",
        "THRD_ERROR: c_int = 2",
        "pthread_mutex::init_selected_normal_mutex",
        "pthread_mutex::destroy_selected_normal_mutex",
        "pthread_mutex::lock_selected_normal_mutex",
        "pthread_mutex::try_lock_selected_normal_mutex",
        "pthread_mutex::unlock_selected_normal_mutex",
        "pthread_cond::init_selected_private_cond",
        "pthread_cond::destroy_selected_private_cond",
        "pthread_cond::wait_selected_private_cond",
        "pthread_cond::signal_selected_private_cond",
        "pthread_cond::broadcast_selected_private_cond",
        "interposable pthread C symbol",
        "dynamic/loader TLS",
        "general C11",
        "pthread parity",
        "public x86 support",
    ):
        if required not in c11_sync_text:
            errors.append(
                "libc/src/c_abi/x86_64/c11_sync.rs: selected private C11 plain "
                f"synchronization leaf is missing {required!r}"
            )
    c11_sync_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            c11_sync_text,
        )
    )
    expected_c11_sync_exports = {
        "mtx_init",
        "mtx_destroy",
        "mtx_lock",
        "mtx_trylock",
        "mtx_unlock",
        "cnd_init",
        "cnd_destroy",
        "cnd_wait",
        "cnd_signal",
        "cnd_broadcast",
    }
    if c11_sync_exports != expected_c11_sync_exports:
        errors.append(
            "libc/src/c_abi/x86_64/c11_sync.rs: selected private C11 plain "
            "synchronization leaf must export only its five mtx and five cnd symbols"
        )
    for forbidden in (
        'pub unsafe extern "C" fn mtx_timedlock',
        'pub unsafe extern "C" fn cnd_timedwait',
        'pub unsafe extern "C" fn call_once',
        'pub unsafe extern "C" fn tss_',
        'pub unsafe extern "C" fn thrd_yield',
        'pub unsafe extern "C" fn pthread_',
        "__tls_get_addr",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in c11_sync_text:
            errors.append(
                "libc/src/c_abi/x86_64/c11_sync.rs: selected private C11 plain "
                f"synchronization leaf must not select {forbidden!r}"
            )

    pthread_once_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_once.rs"
    )
    pthread_once_text = pthread_once_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/thread/pthread_once.c::{__pthread_once,__pthread_once_full}",
        "src/thread/call_once.c",
        "src/thread/__wait.c::__wait",
        "src/internal/pthread_impl.h::__wake",
        "ONCE_INITIAL: c_int = 0",
        "ONCE_INITIALIZING: c_int = 1",
        "ONCE_COMPLETE: c_int = 2",
        "ONCE_WAITERS: c_int = 3",
        "FUTEX_WAIT_PRIVATE",
        "FUTEX_WAKE_PRIVATE",
        "raw_syscall::SYS_FUTEX",
        "raw_syscall::syscall4(",
        "raw_syscall::syscall3(",
        "c_int::MAX as i64",
        "x86_64_load_acquire_i32",
        "x86_64_compare_exchange_acqrel_i32",
        "x86_64_swap_acqrel_i32",
        "run_selected_once",
        "non-cancellation",
        "recursive same-control",
        "dynamic/loader TLS",
        "weak `pthread_once` ELF-alias binding",
        "public x86 support",
    ):
        if required not in pthread_once_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_once.rs: selected private pthread/C11 "
                f"once leaf is missing {required!r}"
            )
    pthread_once_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            pthread_once_text,
        )
    )
    if pthread_once_exports != {"pthread_once", "call_once"}:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_once.rs: selected private pthread/C11 "
            "once leaf must export only pthread_once and call_once"
        )
    for forbidden in (
        'pub unsafe extern "C" fn pthread_cancel',
        'pub unsafe extern "C" fn pthread_exit',
        'pub unsafe extern "C" fn thrd_exit',
        'pub unsafe extern "C" fn tss_',
        "__tls_get_addr",
        "errno::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in pthread_once_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_once.rs: selected private pthread/C11 "
                f"once leaf must not select {forbidden!r}"
            )
    call_once_text = pthread_once_text.split(
        'pub unsafe extern "C" fn call_once', 1
    )[-1]
    if "run_selected_once(flag, function)" not in call_once_text:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_once.rs: call_once must use the "
            "private shared once state machine"
        )
    if re.search(r"\bpthread_once\s*\(", call_once_text):
        errors.append(
            "libc/src/c_abi/x86_64/pthread_once.rs: call_once must not cross "
            "the interposable pthread_once C ABI"
        )

    # TSS remains a separate private leaf: the prior C11 lifecycle, plain-sync,
    # and once-leaf exclusions must not be relaxed into a broader C11 runtime.
    pthread_tsd_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "pthread_tsd.rs"
    )
    pthread_tsd_text = pthread_tsd_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/thread/pthread_key_create.c::{__pthread_key_create,",
        "__pthread_key_delete,__pthread_tsd_run_dtors}",
        "src/thread/pthread_getspecific.c::__pthread_getspecific",
        "src/thread/pthread_setspecific.c::pthread_setspecific",
        "src/thread/tss_create.c",
        "src/thread/tss_delete.c",
        "src/thread/tss_set.c",
        "src/thread/pthread_create.c::{start,start_c11,__pthread_exit}",
        "PTHREAD_KEYS_MAX: usize = 128",
        "PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4",
        "KEY_FREE: u8 = 0",
        "KEY_ALLOCATED: u8 = 1",
        "struct SelectedTsdValues",
        "static SELECTED_TSD_KEYS",
        "static MAIN_SELECTED_TSD_VALUES",
        "static_tls::is_initial_thread_pointer",
        "current_selected_values().is_none()",
        "pthread_create_join::current_selected_worker_tsd_values",
        "pthread_create_join::clear_selected_worker_tsd_key",
        "run_selected_worker_tsd_destructors",
        "for _ in 0..PTHREAD_DESTRUCTOR_ITERATIONS",
        "values.values[index].swap(0, Ordering::AcqRel)",
        "foreign threads",
        "main-thread process-exit destructors",
        "dynamic or loader TLS/DTV",
        "weak/same-address TSD ELF aliases",
        "This is deliberately not musl's general thread-list/TSD implementation.",
    ):
        if required not in pthread_tsd_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private pthread-key/C11 "
                f"TSS leaf is missing {required!r}"
            )
    pthread_tsd_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            pthread_tsd_text,
        )
    )
    expected_pthread_tsd_exports = {
        "pthread_key_create",
        "pthread_key_delete",
        "pthread_getspecific",
        "pthread_setspecific",
        "tss_create",
        "tss_delete",
        "tss_get",
        "tss_set",
    }
    if pthread_tsd_exports != expected_pthread_tsd_exports:
        errors.append(
            "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private pthread-key/C11 "
            "TSS leaf must export only pthread key and C11 TSS entry points"
        )
    selected_tsd_entry_boundaries = (
        (
            "pthread_key_create",
            'pub unsafe extern "C" fn pthread_key_create',
            "/// Delete one selected key",
        ),
        (
            "pthread_key_delete",
            'pub unsafe extern "C" fn pthread_key_delete',
            "/// Read one selected current-thread value",
        ),
        (
            "pthread_getspecific",
            'pub unsafe extern "C" fn pthread_getspecific',
            "/// Store one selected current-thread value",
        ),
        (
            "pthread_setspecific",
            'pub unsafe extern "C" fn pthread_setspecific',
            "/// Run the selected worker's private TSD destructor phase",
        ),
    )
    for entry_name, entry_marker, entry_end in selected_tsd_entry_boundaries:
        if entry_marker not in pthread_tsd_text or entry_end not in pthread_tsd_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private "
                f"pthread-key/C11 TSS {entry_name} boundary is missing"
            )
            continue
        entry_text = pthread_tsd_text.split(entry_marker, 1)[1].split(entry_end, 1)[0]
        admission = "current_selected_values()"
        metadata_lock = "lock_selected_tsd()"
        if (
            admission not in entry_text
            or metadata_lock not in entry_text
            or entry_text.index(admission) >= entry_text.index(metadata_lock)
        ):
            errors.append(
                "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private "
                f"pthread-key/C11 TSS {entry_name} must admit only a selected "
                "caller before the metadata lock"
            )
    for wrapper_name, pthread_entry in (
        ("tss_create", "pthread_key_create(key, destructor)"),
        ("tss_delete", "pthread_key_delete(key)"),
        ("tss_get", "pthread_getspecific(key)"),
        ("tss_set", "pthread_setspecific(key, value)"),
    ):
        wrapper_marker = f'pub unsafe extern "C" fn {wrapper_name}'
        if wrapper_marker not in pthread_tsd_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private "
                f"pthread-key/C11 TSS {wrapper_name} wrapper is missing"
            )
        elif pthread_entry not in pthread_tsd_text.split(wrapper_marker, 1)[1]:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private "
                f"pthread-key/C11 TSS {wrapper_name} must delegate through the "
                "selected pthread admission boundary"
            )
    for forbidden in (
        'pub unsafe extern "C" fn pthread_create',
        'pub unsafe extern "C" fn pthread_join',
        'pub unsafe extern "C" fn pthread_detach',
        'pub unsafe extern "C" fn pthread_exit',
        'pub unsafe extern "C" fn pthread_cancel',
        'pub unsafe extern "C" fn pthread_once',
        'pub unsafe extern "C" fn pthread_mutex_',
        'pub unsafe extern "C" fn pthread_cond_',
        'pub unsafe extern "C" fn thrd_',
        'pub unsafe extern "C" fn mtx_',
        'pub unsafe extern "C" fn cnd_',
        'pub unsafe extern "C" fn call_once',
        "__tls_get_addr",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in pthread_tsd_text:
            errors.append(
                "libc/src/c_abi/x86_64/pthread_tsd.rs: selected private pthread-key/C11 "
                f"TSS leaf must not select {forbidden!r}"
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

    ctermid_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "ctermid.rs"
    ctermid_text = ctermid_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/unistd/ctermid.c",
        "CTERMID_PATH: [u8; 9]",
        "does not open",
        "# Safety",
        "destination.add(index).write(CTERMID_PATH[index])",
        "immutable literal pointer",
    ):
        if required not in ctermid_text:
            errors.append(
                "libc/src/c_abi/x86_64/ctermid.rs: selected static historical "
                f"ctermid boundary is missing {required!r}"
            )
    ctermid_exports = set(
        re.findall(
            r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
            ctermid_text,
        )
    )
    if ctermid_exports != {"ctermid"}:
        errors.append(
            "libc/src/c_abi/x86_64/ctermid.rs: selected static historical "
            "ctermid artifact must export only ctermid"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "termios_control::",
        "getpass::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in ctermid_text:
            errors.append(
                "libc/src/c_abi/x86_64/ctermid.rs: selected static historical "
                f"ctermid boundary must not select {forbidden!r}"
            )

    gethostid_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gethostid.rs"
    gethostid_text = gethostid_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/misc/gethostid.c::gethostid",
        "deterministic zero host identifier",
        "System V AMD64 ABI",
        'pub extern \"C\" fn gethostid() -> c_long',
    ):
        if required not in gethostid_text:
            errors.append(
                "libc/src/c_abi/x86_64/gethostid.rs: selected static historical "
                f"gethostid boundary is missing {required!r}"
            )
    gethostid_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            gethostid_text,
        )
    )
    if gethostid_exports != {"gethostid"}:
        errors.append(
            "libc/src/c_abi/x86_64/gethostid.rs: selected static historical "
            "gethostid artifact must export only gethostid"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "uts_identity::",
        "static_startup::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in gethostid_text:
            errors.append(
                "libc/src/c_abi/x86_64/gethostid.rs: selected static historical "
                f"gethostid boundary must not select {forbidden!r}"
            )

    gettid_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gettid.rs"
    gettid_text = gettid_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/linux/gettid.c::gettid",
        "__pthread_self()->tid",
        "direct Linux 5.10 x86-64 `gettid=186` syscall",
        "seccomp-injected raw",
        "System V AMD64 ABI",
        'pub extern \"C\" fn gettid() -> c_int',
        "raw_syscall::syscall0(raw_syscall::SYS_GETTID)",
    ):
        if required not in gettid_text:
            errors.append(
                "libc/src/c_abi/x86_64/gettid.rs: selected static GNU "
                f"gettid boundary is missing {required!r}"
            )
    gettid_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            gettid_text,
        )
    )
    if gettid_exports != {"gettid"}:
        errors.append(
            "libc/src/c_abi/x86_64/gettid.rs: selected static GNU gettid "
            "artifact must export only gettid"
        )
    for forbidden in (
        "errno::",
        "static_tls::",
        "process_context::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in gettid_text:
            errors.append(
                "libc/src/c_abi/x86_64/gettid.rs: selected static GNU gettid "
                f"boundary must not select {forbidden!r}"
            )

    isatty_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "isatty.rs"
    isatty_text = isatty_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/unistd/isatty.c::isatty",
        "TIOCGWINSZ: i64 = 0x5413",
        "struct KernelWinsize",
        "MaybeUninit::<KernelWinsize>::uninit()",
        "raw_syscall::SYS_IOCTL",
        "c_status(result) + 1",
        "terminal-path or",
    ):
        if required not in isatty_text:
            errors.append(
                "libc/src/c_abi/x86_64/isatty.rs: selected static descriptor "
                f"observation boundary is missing {required!r}"
            )
    isatty_exports = set(
        re.findall(
            r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
            isatty_text,
        )
    )
    if isatty_exports != {"isatty"}:
        errors.append(
            "libc/src/c_abi/x86_64/isatty.rs: selected static descriptor "
            "observation artifact must export only isatty"
        )
    for forbidden in (
        "termios_control::",
        "raw_syscall::SYS_OPEN",
        "raw_syscall::SYS_OPENAT",
        "TCGETS",
        "TIOCSPTLCK",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in isatty_text:
            errors.append(
                "libc/src/c_abi/x86_64/isatty.rs: selected static descriptor "
                f"observation boundary must not select {forbidden!r}"
            )

    isatty_runner = (
        ROOT / "compat" / "x86_64" / "run_libc_isatty.sh"
    ).read_text(errors="replace")
    isatty_header_runner = (
        ROOT / "compat" / "x86_64" / "run_isatty_header_abi.sh"
    ).read_text(errors="replace")
    isatty_header_c = (
        ROOT / "compat" / "x86_64" / "isatty_header_abi_probe.c"
    ).read_text(errors="replace")
    isatty_header_cxx = (
        ROOT / "compat" / "x86_64" / "isatty_header_abi_probe.cpp"
    ).read_text(errors="replace")
    isatty_probe = (
        ROOT / "compat" / "x86_64" / "libc_isatty_probe.c"
    ).read_text(errors="replace")
    isatty_start = (
        ROOT / "compat" / "x86_64" / "libc_isatty_start.S"
    ).read_text(errors="replace")
    x86_runner = (ROOT / "scripts" / "dev-x86_64.sh").read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_isatty_header_abi.sh",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "--no-undefined",
        "for symbol in __errno_location isatty",
        "--disassemble=isatty",
        "project-header isatty fixture contract drifted",
        "fixture did not use the project",
        "fixed TIOCGWINSZ request",
        "termios-control request",
        "candidate selects an excluded terminal helper",
        'timeout "$EXECUTION_TIMEOUT"',
        "candidate retains a dynamic TLS model",
    ):
        if required not in isatty_runner:
            errors.append(
                "compat/x86_64/run_libc_isatty.sh: selected static descriptor "
                f"observation evidence is missing {required!r}"
            )
    for required in (
        "isatty_header_abi_probe.c",
        "isatty_header_abi_probe.cpp",
        "Pinned musl 1.2.6",
        "unconditional <unistd.h> declaration",
        "retained a mangled isatty reference",
    ):
        if required not in isatty_header_runner:
            errors.append(
                "compat/x86_64/run_isatty_header_abi.sh: selected descriptor "
                f"observation declaration evidence is missing {required!r}"
            )
    for required in ("isatty declaration", "isatty_function = isatty"):
        if required not in isatty_header_c or required not in isatty_header_cxx:
            errors.append(
                "compat/x86_64/isatty_header_abi_probe: selected descriptor "
                f"observation declaration evidence is missing {required!r}"
            )
    for required in (
        "FIXTURE_EBADF",
        "FIXTURE_ENOTTY",
        "FIXTURE_TIOCGWINSZ",
        "FIXTURE_TIOCSPTLCK",
        "FIXTURE_TIOCGPTPEER",
        "open_pty_pair",
        "isatty(pair.slave) != 1 || errno != 313",
        "isatty(-1) != 0 || errno != FIXTURE_EBADF",
        "isatty(null_fd) != 0 || errno != FIXTURE_ENOTTY",
    ):
        if required not in isatty_probe:
            errors.append(
                "compat/x86_64/libc_isatty_probe.c: selected descriptor "
                f"observation regression is missing {required!r}"
            )
    for forbidden in ("tcgetattr(", "tcsetattr(", "ttyname(", "getpass("):
        if forbidden in isatty_probe:
            errors.append(
                "compat/x86_64/libc_isatty_probe.c: selected descriptor "
                f"observation fixture must not select {forbidden!r}"
            )
    for required in (
        "ARCH_SET_FS",
        "mov %rsi, %fs:0",
        "crabc_x86_64_isatty_probe",
    ):
        if required not in isatty_start:
            errors.append(
                "compat/x86_64/libc_isatty_start.S: selected descriptor "
                f"observation TLS fixture is missing {required!r}"
            )
    for required in (
        "isatty-header-abi)",
        "run_isatty_header_abi",
        "libc-isatty)",
        "run_libc_isatty_probe",
    ):
        if required not in x86_runner:
            errors.append(
                "scripts/dev-x86_64.sh: selected static isatty dispatcher is "
                f"missing {required!r}"
            )

    tcgetpgrp_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "tcgetpgrp.rs"
    )
    tcgetpgrp_text = tcgetpgrp_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/unistd/tcgetpgrp.c::tcgetpgrp",
        "TIOCGPGRP: i64 = 0x540f",
        "MaybeUninit::<c_int>::uninit()",
        "raw_syscall::SYS_IOCTL",
        "if c_status(result) < 0",
        "neither creates a session",
    ):
        if required not in tcgetpgrp_text:
            errors.append(
                "libc/src/c_abi/x86_64/tcgetpgrp.rs: selected static foreground "
                f"group observation boundary is missing {required!r}"
            )
    tcgetpgrp_exports = set(
        re.findall(
            r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
            tcgetpgrp_text,
        )
    )
    if tcgetpgrp_exports != {"tcgetpgrp"}:
        errors.append(
            "libc/src/c_abi/x86_64/tcgetpgrp.rs: selected static foreground "
            "group observation artifact must export only tcgetpgrp"
        )
    for forbidden in (
        "termios_control::",
        "raw_syscall::SYS_SETSID",
        "raw_syscall::SYS_FORK",
        "raw_syscall::SYS_OPEN",
        "raw_syscall::SYS_OPENAT",
        "TIOCSCTTY",
        "TIOCSPGRP",
        "TIOCGSID",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in tcgetpgrp_text:
            errors.append(
                "libc/src/c_abi/x86_64/tcgetpgrp.rs: selected static foreground "
                f"group observation boundary must not select {forbidden!r}"
            )

    tcgetpgrp_runner = (
        ROOT / "compat" / "x86_64" / "run_libc_tcgetpgrp.sh"
    ).read_text(errors="replace")
    tcgetpgrp_header_runner = (
        ROOT / "compat" / "x86_64" / "run_tcgetpgrp_header_abi.sh"
    ).read_text(errors="replace")
    tcgetpgrp_header_c = (
        ROOT / "compat" / "x86_64" / "tcgetpgrp_header_abi_probe.c"
    ).read_text(errors="replace")
    tcgetpgrp_header_cxx = (
        ROOT / "compat" / "x86_64" / "tcgetpgrp_header_abi_probe.cpp"
    ).read_text(errors="replace")
    tcgetpgrp_probe = (
        ROOT / "compat" / "x86_64" / "libc_tcgetpgrp_probe.c"
    ).read_text(errors="replace")
    tcgetpgrp_start = (
        ROOT / "compat" / "x86_64" / "libc_tcgetpgrp_start.S"
    ).read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_tcgetpgrp_header_abi.sh",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "--no-undefined",
        "for symbol in __errno_location tcgetpgrp",
        "--disassemble=tcgetpgrp",
        "project-header tcgetpgrp fixture contract drifted",
        "fixture did not use the project",
        "fixed TIOCGPGRP request",
        "terminal-control request",
        "candidate selects an excluded session or terminal helper",
        'timeout "$EXECUTION_TIMEOUT"',
        "candidate retains a dynamic TLS model",
    ):
        if required not in tcgetpgrp_runner:
            errors.append(
                "compat/x86_64/run_libc_tcgetpgrp.sh: selected static foreground "
                f"group observation evidence is missing {required!r}"
            )
    for required in (
        "tcgetpgrp_header_abi_probe.c",
        "tcgetpgrp_header_abi_probe.cpp",
        "Pinned musl 1.2.6",
        "unconditional <unistd.h> declaration",
        "retained a mangled tcgetpgrp reference",
    ):
        if required not in tcgetpgrp_header_runner:
            errors.append(
                "compat/x86_64/run_tcgetpgrp_header_abi.sh: selected foreground "
                f"group observation declaration evidence is missing {required!r}"
            )
    for required in ("tcgetpgrp declaration", "tcgetpgrp_function = tcgetpgrp"):
        if required not in tcgetpgrp_header_c or required not in tcgetpgrp_header_cxx:
            errors.append(
                "compat/x86_64/tcgetpgrp_header_abi_probe: selected foreground "
                f"group observation declaration evidence is missing {required!r}"
            )
    for required in (
        "FIXTURE_EBADF",
        "FIXTURE_ENOTTY",
        "FIXTURE_TIOCSCTTY",
        "FIXTURE_TIOCGPGRP",
        "FIXTURE_TIOCSPTLCK",
        "FIXTURE_TIOCGPTPEER",
        "__builtin_types_compatible_p(pid_t, int)",
        "open_pty_pair",
        "child_reads_foreground_group",
        "check_foreground_group",
        "tcgetpgrp(slave) != (pid_t)pid || errno != 313",
        "tcgetpgrp(-1) != -1 || errno != FIXTURE_EBADF",
        "tcgetpgrp(null_fd) != -1 || errno != FIXTURE_ENOTTY",
    ):
        if required not in tcgetpgrp_probe:
            errors.append(
                "compat/x86_64/libc_tcgetpgrp_probe.c: selected foreground "
                f"group observation regression is missing {required!r}"
            )
    for forbidden in (
        "tcsetpgrp(",
        "tcgetsid(",
        "tcgetattr(",
        "tcsetattr(",
        "ttyname(",
        "getpass(",
    ):
        if forbidden in tcgetpgrp_probe:
            errors.append(
                "compat/x86_64/libc_tcgetpgrp_probe.c: selected foreground "
                f"group observation fixture must not select {forbidden!r}"
            )
    for required in (
        "ARCH_SET_FS",
        "mov %rsi, %fs:0",
        "crabc_x86_64_tcgetpgrp_probe",
    ):
        if required not in tcgetpgrp_start:
            errors.append(
                "compat/x86_64/libc_tcgetpgrp_start.S: selected foreground "
                f"group observation TLS fixture is missing {required!r}"
            )
    for required in (
        "tcgetpgrp-header-abi)",
        "run_tcgetpgrp_header_abi",
        "libc-tcgetpgrp)",
        "run_libc_tcgetpgrp_probe",
    ):
        if required not in x86_runner:
            errors.append(
                "scripts/dev-x86_64.sh: selected static tcgetpgrp dispatcher is "
                f"missing {required!r}"
            )

    tcsetpgrp_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "tcsetpgrp.rs"
    )
    tcsetpgrp_text = tcsetpgrp_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/unistd/tcsetpgrp.c::tcsetpgrp",
        "TIOCSPGRP: i64 = 0x5410",
        "let mut pgrp_int = pgrp;",
        "raw_syscall::SYS_IOCTL",
        "c_status(result)",
        "neither creates a session",
    ):
        if required not in tcsetpgrp_text:
            errors.append(
                "libc/src/c_abi/x86_64/tcsetpgrp.rs: selected static foreground "
                f"group assignment boundary is missing {required!r}"
            )
    tcsetpgrp_exports = set(
        re.findall(
            r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
            tcsetpgrp_text,
        )
    )
    if tcsetpgrp_exports != {"tcsetpgrp"}:
        errors.append(
            "libc/src/c_abi/x86_64/tcsetpgrp.rs: selected static foreground "
            "group assignment artifact must export only tcsetpgrp"
        )
    for forbidden in (
        "termios_control::",
        "raw_syscall::SYS_SETSID",
        "raw_syscall::SYS_FORK",
        "raw_syscall::SYS_SETPGID",
        "raw_syscall::SYS_OPEN",
        "raw_syscall::SYS_OPENAT",
        "TIOCSCTTY",
        "TIOCGPGRP",
        "TIOCGSID",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in tcsetpgrp_text:
            errors.append(
                "libc/src/c_abi/x86_64/tcsetpgrp.rs: selected static foreground "
                f"group assignment boundary must not select {forbidden!r}"
            )

    tcsetpgrp_runner = (
        ROOT / "compat" / "x86_64" / "run_libc_tcsetpgrp.sh"
    ).read_text(errors="replace")
    tcsetpgrp_header_runner = (
        ROOT / "compat" / "x86_64" / "run_tcsetpgrp_header_abi.sh"
    ).read_text(errors="replace")
    tcsetpgrp_header_c = (
        ROOT / "compat" / "x86_64" / "tcsetpgrp_header_abi_probe.c"
    ).read_text(errors="replace")
    tcsetpgrp_header_cxx = (
        ROOT / "compat" / "x86_64" / "tcsetpgrp_header_abi_probe.cpp"
    ).read_text(errors="replace")
    tcsetpgrp_probe = (
        ROOT / "compat" / "x86_64" / "libc_tcsetpgrp_probe.c"
    ).read_text(errors="replace")
    tcsetpgrp_start = (
        ROOT / "compat" / "x86_64" / "libc_tcsetpgrp_start.S"
    ).read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_tcsetpgrp_header_abi.sh",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "--no-undefined",
        "for symbol in __errno_location tcsetpgrp",
        "--disassemble=tcsetpgrp",
        "project-header tcsetpgrp fixture contract drifted",
        "fixture did not use the project",
        "fixed TIOCSPGRP request",
        "terminal-control request",
        "candidate selects an excluded session or terminal helper",
        'timeout "$EXECUTION_TIMEOUT"',
        "candidate retains a dynamic TLS model",
    ):
        if required not in tcsetpgrp_runner:
            errors.append(
                "compat/x86_64/run_libc_tcsetpgrp.sh: selected static foreground "
                f"group assignment evidence is missing {required!r}"
            )
    for required in (
        "tcsetpgrp_header_abi_probe.c",
        "tcsetpgrp_header_abi_probe.cpp",
        "Pinned musl 1.2.6",
        "unconditional <unistd.h> declaration",
        "retained a mangled tcsetpgrp reference",
    ):
        if required not in tcsetpgrp_header_runner:
            errors.append(
                "compat/x86_64/run_tcsetpgrp_header_abi.sh: selected foreground "
                f"group assignment declaration evidence is missing {required!r}"
            )
    for required in ("tcsetpgrp declaration", "tcsetpgrp_function = tcsetpgrp"):
        if required not in tcsetpgrp_header_c or required not in tcsetpgrp_header_cxx:
            errors.append(
                "compat/x86_64/tcsetpgrp_header_abi_probe: selected foreground "
                f"group assignment declaration evidence is missing {required!r}"
            )
    for required in (
        "FIXTURE_EBADF",
        "FIXTURE_ENOTTY",
        "FIXTURE_TIOCSCTTY",
        "FIXTURE_TIOCGPGRP",
        "FIXTURE_TIOCSPGRP",
        "FIXTURE_TIOCSPTLCK",
        "FIXTURE_TIOCGPTPEER",
        "__builtin_types_compatible_p(pid_t, int)",
        "open_pty_pair",
        "child_assigns_foreground_group",
        "check_foreground_group_assignment",
        "raw_syscall2(SYS_setpgid, member, member)",
        "tcsetpgrp(slave, (pid_t)member) != 0 || errno != 313",
        "foreground_group != (int)member",
        "tcsetpgrp(-1, 0) != -1 || errno != FIXTURE_EBADF",
        "tcsetpgrp(null_fd, 0) != -1 || errno != FIXTURE_ENOTTY",
    ):
        if required not in tcsetpgrp_probe:
            errors.append(
                "compat/x86_64/libc_tcsetpgrp_probe.c: selected foreground "
                f"group assignment regression is missing {required!r}"
            )
    for forbidden in (
        "tcgetpgrp(",
        "tcgetsid(",
        "tcgetattr(",
        "tcsetattr(",
        "ttyname(",
        "getpass(",
    ):
        if forbidden in tcsetpgrp_probe:
            errors.append(
                "compat/x86_64/libc_tcsetpgrp_probe.c: selected foreground "
                f"group assignment fixture must not select {forbidden!r}"
            )
    for required in (
        "ARCH_SET_FS",
        "mov %rsi, %fs:0",
        "crabc_x86_64_tcsetpgrp_probe",
    ):
        if required not in tcsetpgrp_start:
            errors.append(
                "compat/x86_64/libc_tcsetpgrp_start.S: selected foreground "
                f"group assignment TLS fixture is missing {required!r}"
            )
    for required in (
        "tcsetpgrp-header-abi)",
        "run_tcsetpgrp_header_abi",
        "libc-tcsetpgrp)",
        "run_libc_tcsetpgrp_probe",
    ):
        if required not in x86_runner:
            errors.append(
                "scripts/dev-x86_64.sh: selected static tcsetpgrp dispatcher is "
                f"missing {required!r}"
            )

    getpass_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "getpass.rs"
    getpass_text = getpass_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/legacy/getpass.c",
        "Source-function mapping: musl `getpass` -> `getpass.rs::getpass`",
        "struct PublicTermios",
        "PASSWORD_CAPACITY: usize = 128",
        "O_RDWR",
        "O_NOCTTY",
        "O_CLOEXEC",
        "TCSAFLUSH",
        "TCSBRK",
        "drain_terminal_output",
        "termios_control::tcgetattr",
        "termios_control::tcsetattr",
        "raw_syscall::SYS_OPEN",
        "raw_syscall::SYS_READ",
        "raw_syscall::SYS_WRITE",
        "raw_syscall::SYS_CLOSE",
        "create a Rust secret type",
        "secret-memory ownership",
        "initial `tcgetattr` failure returns null",
        "a null prompt writes no bytes",
        "cleanup preserves a raw read error",
    ):
        if required not in getpass_text:
            errors.append(
                "libc/src/c_abi/x86_64/getpass.rs: selected static historical "
                f"getpass boundary is missing {required!r}"
            )
    getpass_exports = set(
        re.findall(
            r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
            getpass_text,
        )
    )
    if getpass_exports != {"getpass"}:
        errors.append(
            "libc/src/c_abi/x86_64/getpass.rs: selected static historical "
            "getpass artifact must export only getpass"
        )
    for forbidden in (
        'pub unsafe extern "C" fn getlogin',
        'pub unsafe extern "C" fn cuserid',
        'pub unsafe extern "C" fn tcdrain',
        "fn ioctl(",
        "forkpty(",
        "openpty(",
        "login_tty(",
        "vhangup(",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in getpass_text:
            errors.append(
                "libc/src/c_abi/x86_64/getpass.rs: selected static historical "
                f"getpass boundary must not select {forbidden!r}"
            )

    getpass_runner = (
        ROOT / "compat" / "x86_64" / "run_libc_getpass.sh"
    ).read_text(errors="replace")
    getpass_header_runner = (
        ROOT / "compat" / "x86_64" / "run_getpass_header_abi.sh"
    ).read_text(errors="replace")
    getpass_header_c = (
        ROOT / "compat" / "x86_64" / "getpass_header_abi_probe.c"
    ).read_text(errors="replace")
    getpass_header_cxx = (
        ROOT / "compat" / "x86_64" / "getpass_header_abi_probe.cpp"
    ).read_text(errors="replace")
    getpass_probe = (
        ROOT / "compat" / "x86_64" / "libc_getpass_probe.c"
    ).read_text(errors="replace")
    getpass_start = (
        ROOT / "compat" / "x86_64" / "libc_getpass_start.S"
    ).read_text(errors="replace")
    x86_runner = (ROOT / "scripts" / "dev-x86_64.sh").read_text(errors="replace")
    ctermid_runner = (
        ROOT / "compat" / "x86_64" / "run_libc_ctermid.sh"
    ).read_text(errors="replace")
    ctermid_header_runner = (
        ROOT / "compat" / "x86_64" / "run_ctermid_header_abi.sh"
    ).read_text(errors="replace")
    ctermid_header_c = (
        ROOT / "compat" / "x86_64" / "ctermid_header_abi_probe.c"
    ).read_text(errors="replace")
    ctermid_header_cxx = (
        ROOT / "compat" / "x86_64" / "ctermid_header_abi_probe.cpp"
    ).read_text(errors="replace")
    ctermid_probe = (
        ROOT / "compat" / "x86_64" / "libc_ctermid_probe.c"
    ).read_text(errors="replace")
    ctermid_start = (
        ROOT / "compat" / "x86_64" / "libc_ctermid_start.S"
    ).read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_ctermid_header_abi.sh",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "--no-undefined",
        "archive does not define ctermid",
        "--disassemble=ctermid",
        "ctermid candidate unexpectedly retains TLS",
        "ctermid unexpectedly performs a syscall",
        "candidate selects terminal, filesystem, or string helper behavior",
    ):
        if required not in ctermid_runner:
            errors.append(
                "compat/x86_64/run_libc_ctermid.sh: selected static historical "
                f"ctermid evidence is missing {required!r}"
            )
    for required in (
        "ctermid_header_abi_probe.c",
        "ctermid_header_abi_probe.cpp",
        "Pinned musl 1.2.6",
        "strict ${language}",
        "retained a mangled ctermid reference",
    ):
        if required not in ctermid_header_runner:
            errors.append(
                "compat/x86_64/run_ctermid_header_abi.sh: selected static historical "
                f"ctermid declaration evidence is missing {required!r}"
            )
    for required in (
        "ctermid declaration",
        "ctermid_must_be_hidden",
        "CRABC_REQUIRE_L_CTERMID_HIDDEN",
        "L_ctermid",
    ):
        if required not in ctermid_header_c or required not in ctermid_header_cxx:
            errors.append(
                "compat/x86_64/ctermid_header_abi_probe: selected static historical "
                f"ctermid declaration evidence is missing {required!r}"
            )
    for required in (
        "L_ctermid == 20",
        "expected_ctermid",
        "ctermid((char *)0)",
        "result != buffer",
        "sizeof(expected_ctermid)",
        "0x5aU",
    ):
        if required not in ctermid_probe:
            errors.append(
                "compat/x86_64/libc_ctermid_probe.c: selected static historical "
                f"ctermid regression is missing {required!r}"
            )
    for required in ("crabc_x86_64_ctermid_probe", "mov $60, %eax"):
        if required not in ctermid_start:
            errors.append(
                "compat/x86_64/libc_ctermid_start.S: selected static historical "
                f"ctermid fixture is missing {required!r}"
            )
    for required in (
        "ctermid-header-abi)",
        "run_ctermid_header_abi",
        "libc-ctermid)",
        "run_libc_ctermid_probe",
    ):
        if required not in x86_runner:
            errors.append(
                "scripts/dev-x86_64.sh: selected historical ctermid dispatcher is "
                f"missing {required!r}"
            )
    for required in (
        "run_musl_oracle.sh",
        "run_getpass_header_abi.sh",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "--no-undefined",
        "for symbol in __errno_location getpass",
        "for unselected in cuserid getusershell",
        "--disassemble=getpass",
        "Linux x86-64 open syscall 2",
        "fixed private TCSBRK drain request",
        "candidate selects an account or login helper",
        "forkpty|openpty|login_tty|vhangup|TIOCGPTPEER",
        'timeout "$EXECUTION_TIMEOUT"',
        "candidate retains a dynamic TLS model",
    ):
        if required not in getpass_runner:
            errors.append(
                "compat/x86_64/run_libc_getpass.sh: selected static historical "
                f"getpass evidence is missing {required!r}"
            )
    for required in (
        "getpass_header_abi_probe.c",
        "getpass_header_abi_probe.cpp",
        "Pinned musl 1.2.6",
        "getpass outside GNU/BSD selection",
        "retained a mangled getpass reference",
    ):
        if required not in getpass_header_runner:
            errors.append(
                "compat/x86_64/run_getpass_header_abi.sh: selected historical "
                f"getpass declaration evidence is missing {required!r}"
            )
    for required in ("getpass declaration", "getpass_must_be_hidden"):
        if required not in getpass_header_c or required not in getpass_header_cxx:
            errors.append(
                "compat/x86_64/getpass_header_abi_probe: selected historical "
                f"getpass declaration evidence is missing {required!r}"
            )
    for required in (
        "check_no_controlling_tty",
        "FIXTURE_ENXIO",
        "check_interactive_tty",
        "FIXTURE_TIOCSCTTY",
        "FIXTURE_TIOCGPTPEER",
        "c_string_equals",
        "FIXTURE_PASSWORD_BYTES",
        "bytes_contain",
        "raw_syscall4(SYS_openat",
        "getpass(NULL) != NULL || errno != FIXTURE_ENXIO",
        "second != first",
        "FIXTURE_PASSWORD_BYTES - 1",
        "!bytes_equal(&before, &after, sizeof(before))",
    ):
        if required not in getpass_probe:
            errors.append(
                "compat/x86_64/libc_getpass_probe.c: selected historical "
                f"getpass regression is missing {required!r}"
            )
    for forbidden in ("openpty(", "forkpty(", "login_tty(", "vhangup("):
        if forbidden in getpass_probe:
            errors.append(
                "compat/x86_64/libc_getpass_probe.c: selected historical "
                f"getpass fixture must not select {forbidden!r}"
            )
    for required in (
        "ARCH_SET_FS",
        "mov %rsi, %fs:0",
        "crabc_x86_64_getpass_probe",
    ):
        if required not in getpass_start:
            errors.append(
                "compat/x86_64/libc_getpass_start.S: selected historical "
                f"getpass TLS fixture is missing {required!r}"
            )
    for required in (
        "getpass-header-abi)",
        "run_getpass_header_abi",
        "libc-getpass)",
        "run_libc_getpass_probe",
    ):
        if required not in x86_runner:
            errors.append(
                "scripts/dev-x86_64.sh: selected historical getpass dispatcher is "
                f"missing {required!r}"
            )

    mktemp_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "mktemp.rs"
    mktemp_text = mktemp_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/temp/mktemp.c::mktemp",
        "src/temp/__randname.c::__randname",
        "TEMPLATE_SUFFIX_BYTES: usize = 6",
        "MAX_ATTEMPTS: usize = 100",
        "CLOCK_REALTIME",
        "struct Timespec",
        "struct KernelStatScratch",
        "size_of::<KernelStatScratch>() == 144",
        "raw_syscall::SYS_CLOCK_GETTIME",
        "raw_syscall::SYS_GETTID",
        "raw_syscall::SYS_NEWFSTATAT",
        "wrapping_mul(65_537)",
        "random >>= 5",
        "if error != ENOENT",
        "errno::set_errno(EEXIST)",
        "inherently racy",
        "does not create, open, reserve, unlink",
    ):
        if required not in mktemp_text:
            errors.append(
                "libc/src/c_abi/x86_64/mktemp.rs: selected static historical "
                f"mktemp boundary is missing {required!r}"
            )
    mktemp_exports = set(
        re.findall(
            r'(?m)^pub\s+unsafe\s+extern\s+"C"\s+fn\s+(\w+)\s*\(',
            mktemp_text,
        )
    )
    if mktemp_exports != {"mktemp"}:
        errors.append(
            "libc/src/c_abi/x86_64/mktemp.rs: selected static historical "
            "mktemp artifact must export only mktemp"
        )
    for forbidden in (
        "raw_syscall::SYS_OPEN",
        "raw_syscall::SYS_OPENAT",
        "raw_syscall::SYS_GETRANDOM",
        "raw_syscall::SYS_UNLINK",
        "raw_syscall::SYS_UNLINKAT",
        'pub unsafe extern "C" fn tmpnam',
        'pub unsafe extern "C" fn tempnam',
        'pub unsafe extern "C" fn mkstemp',
        'pub unsafe extern "C" fn mkdtemp',
        'pub unsafe extern "C" fn name_to_handle_at',
        'pub unsafe extern "C" fn open_by_handle_at',
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in mktemp_text:
            errors.append(
                "libc/src/c_abi/x86_64/mktemp.rs: selected static historical "
                f"mktemp boundary must not select {forbidden!r}"
            )

    mktemp_runner = (
        ROOT / "compat" / "x86_64" / "run_libc_mktemp.sh"
    ).read_text(errors="replace")
    mktemp_header_runner = (
        ROOT / "compat" / "x86_64" / "run_mktemp_header_abi.sh"
    ).read_text(errors="replace")
    mktemp_header_c = (
        ROOT / "compat" / "x86_64" / "mktemp_header_abi_probe.c"
    ).read_text(errors="replace")
    mktemp_header_cxx = (
        ROOT / "compat" / "x86_64" / "mktemp_header_abi_probe.cpp"
    ).read_text(errors="replace")
    mktemp_probe = (
        ROOT / "compat" / "x86_64" / "libc_mktemp_probe.c"
    ).read_text(errors="replace")
    mktemp_start = (
        ROOT / "compat" / "x86_64" / "libc_mktemp_start.S"
    ).read_text(errors="replace")
    for required in (
        "run_musl_oracle.sh",
        "run_mktemp_header_abi.sh",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "--no-undefined",
        "for symbol in __errno_location mktemp",
        "--disassemble=mktemp",
        "for word in 0xe4 0xba 0x106",
        "excluded temporary or handle API",
        "excluded entropy or authority API",
        'timeout "$EXECUTION_TIMEOUT"',
        "candidate retains a dynamic TLS model",
    ):
        if required not in mktemp_runner:
            errors.append(
                "compat/x86_64/run_libc_mktemp.sh: selected static historical "
                f"mktemp evidence is missing {required!r}"
            )
    for required in (
        "mktemp_header_abi_probe.c",
        "mktemp_header_abi_probe.cpp",
        "Pinned musl 1.2.6",
        "mktemp outside GNU/BSD selection",
        "retained a mangled mktemp reference",
    ):
        if required not in mktemp_header_runner:
            errors.append(
                "compat/x86_64/run_mktemp_header_abi.sh: selected historical "
                f"mktemp declaration evidence is missing {required!r}"
            )
    for required in ("mktemp declaration", "mktemp_must_be_hidden"):
        if required not in mktemp_header_c or required not in mktemp_header_cxx:
            errors.append(
                "compat/x86_64/mktemp_header_abi_probe: selected historical "
                f"mktemp declaration evidence is missing {required!r}"
            )
    for required in (
        "FIXTURE_ENOENT",
        "FIXTURE_EINVAL",
        "FIXTURE_ELOOP",
        "FIXTURE_STAT_BYTES = 144",
        "has_musl_randname_alphabet",
        "path_is_absent",
        "mktemp(invalid) != invalid || invalid[0] != '\\0' || errno != EINVAL",
        "mktemp(valid) != valid || errno != ENOENT",
        "SYS_symlinkat",
        "mktemp(loop_template) != loop_template || loop_template[0] != '\\0'",
        "errno != ELOOP",
    ):
        if required not in mktemp_probe:
            errors.append(
                "compat/x86_64/libc_mktemp_probe.c: selected historical "
                f"mktemp regression is missing {required!r}"
            )
    for required in (
        "ARCH_SET_FS",
        "mov %rsi, %fs:0",
        "crabc_x86_64_mktemp_probe",
    ):
        if required not in mktemp_start:
            errors.append(
                "compat/x86_64/libc_mktemp_start.S: selected historical "
                f"mktemp TLS fixture is missing {required!r}"
            )
    for required in (
        "mktemp-header-abi)",
        "run_mktemp_header_abi",
        "libc-mktemp)",
        "run_libc_mktemp_probe",
    ):
        if required not in x86_runner:
            errors.append(
                "scripts/dev-x86_64.sh: selected historical mktemp dispatcher is "
                f"missing {required!r}"
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

    login_name_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "login_name.rs"
    )
    login_name_text = login_name_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/unistd/getlogin.c",
        "src/unistd/getlogin_r.c",
        "LOGNAME\\0",
        "environment::getenv",
        "ENXIO",
        "ERANGE",
        "copy_nonoverlapping",
        "borrowed pointer",
        "Caller-coordinated environment writers",
        "does not set `errno`",
        "public x86 support",
    ):
        if required not in login_name_text:
            errors.append(
                "libc/src/c_abi/x86_64/login_name.rs: selected static "
                f"login-name boundary is missing {required!r}"
            )
    login_name_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            login_name_text,
        )
    )
    expected_login_name_exports = {"getlogin", "getlogin_r"}
    if login_name_exports != expected_login_name_exports:
        errors.append(
            "libc/src/c_abi/x86_64/login_name.rs: selected static artifact "
            "must export only getlogin and getlogin_r"
        )
    for forbidden in (
        "alloc::",
        "crabc_core",
        "crabc_mimalloc",
        "getpwnam",
        "getpwuid",
        "getutent",
        "getutxent",
        "ttyname",
        "fn fork(",
        "fn execve(",
    ):
        if forbidden in login_name_text:
            errors.append(
                "libc/src/c_abi/x86_64/login_name.rs: selected static "
                f"login-name boundary must not select {forbidden!r}"
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

    posix_exit_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "posix_exit.rs"
    posix_exit_text = posix_exit_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/unistd/_exit.c",
        "directly to `_Exit(status)`",
        "immediate_termination::_Exit(status)",
        "no raw syscall",
        "no errno",
        "ordinary `exit`",
    ):
        if required not in posix_exit_text:
            errors.append(
                "libc/src/c_abi/x86_64/posix_exit.rs: selected static "
                f"POSIX _exit boundary is missing {required!r}"
            )
    posix_exit_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            posix_exit_text,
        )
    )
    if posix_exit_exports != {"_exit"}:
        errors.append(
            "libc/src/c_abi/x86_64/posix_exit.rs: selected static artifact "
            "must export only POSIX _exit"
        )
    for forbidden in (
        "raw_syscall::",
        "errno::",
        "fn exit(",
        "fn atexit(",
        "fn abort(",
        "fn quick_exit(",
    ):
        if forbidden in posix_exit_text:
            errors.append(
                "libc/src/c_abi/x86_64/posix_exit.rs: selected static POSIX "
                f"_exit boundary must not select {forbidden!r}"
            )
    bsearch_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "bsearch.rs"
    bsearch_text = bsearch_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/stdlib/bsearch.c::bsearch",
        "checked multiplication return",
        "caller-owned C array domain",
        "pub unsafe extern \"C\" fn bsearch",
    ):
        if required not in bsearch_text:
            errors.append(
                "libc/src/c_abi/x86_64/bsearch.rs: selected static bsearch "
                f"boundary is missing {required!r}"
            )
    bsearch_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            bsearch_text,
        )
    )
    if bsearch_exports != {"bsearch"}:
        errors.append(
            "libc/src/c_abi/x86_64/bsearch.rs: selected static artifact must "
            "export bsearch only as a Rust entry"
        )
    for forbidden in ("__qsort_r", "qsort_r", "qsort", "raw_syscall::", "errno::"):
        if forbidden in bsearch_text:
            errors.append(
                "libc/src/c_abi/x86_64/bsearch.rs: selected static bsearch "
                f"boundary widens into {forbidden!r}"
            )

    linear_search_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "linear_search.rs"
    )
    linear_search_text = linear_search_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 C linear-search ABI boundary",
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/search/lsearch.c::{lsearch,lfind}",
        "first-match scan",
        "n + 1",
        'pub unsafe extern "C" fn lfind',
        'pub unsafe extern "C" fn lsearch',
    ):
        if required not in linear_search_text:
            errors.append(
                "libc/src/c_abi/x86_64/linear_search.rs: selected static "
                f"linear-search boundary is missing {required!r}"
            )
    linear_search_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            linear_search_text,
        )
    )
    if linear_search_exports != {"lfind", "lsearch"}:
        errors.append(
            "libc/src/c_abi/x86_64/linear_search.rs: selected static artifact "
            "must export lfind and lsearch only as Rust entries"
        )
    for forbidden in ("raw_syscall::", "errno::", "crabc_core", "crabc_mimalloc", "global_asm!"):
        if forbidden in linear_search_text:
            errors.append(
                "libc/src/c_abi/x86_64/linear_search.rs: selected static "
                f"linear-search boundary widens into {forbidden!r}"
            )

    qsort_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "qsort.rs"
    qsort_text = qsort_source.read_text(errors="replace")
    for required in (
        "pinned musl 1.2.6 release commit",
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/stdlib/qsort.c::__qsort_r",
        "src/stdlib/qsort_nr.c::qsort",
        "qsort_with_context",
        "14 * core::mem::size_of::<usize>() + 1",
        "12 * core::mem::size_of::<usize>()",
        "qsort_copy_nonoverlapping",
        "pub unsafe extern \"C\" fn qsort",
    ):
        if required not in qsort_text:
            errors.append(
                "libc/src/c_abi/x86_64/qsort.rs: selected static qsort "
                f"boundary is missing {required!r}"
            )
    qsort_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            qsort_text,
        )
    )
    if qsort_exports != {"qsort"}:
        errors.append(
            "libc/src/c_abi/x86_64/qsort.rs: selected static artifact must "
            "export qsort only as a Rust entry"
        )
    for forbidden in ("global_asm!", ".weak qsort_r", ".set qsort_r", "raw_syscall::", "errno::"):
        if forbidden in qsort_text:
            errors.append(
                "libc/src/c_abi/x86_64/qsort.rs: selected static qsort "
                f"boundary widens into {forbidden!r}"
            )

    callback_algorithms_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "callback_algorithms.rs"
    )
    callback_algorithms_text = callback_algorithms_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/stdlib/qsort.c::__qsort_r",
        "qsort_with_context",
        "smoothsort",
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
    if callback_algorithms_exports != {"__qsort_r"}:
        errors.append(
            "libc/src/c_abi/x86_64/callback_algorithms.rs: selected static "
            "artifact must export __qsort_r only as a Rust entry"
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

    search_tree_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "search_tree_intrusive.rs"
    )
    search_tree_text = search_tree_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/search/tsearch.c",
        "MAX_HEIGHT",
        "size_of::<Node>() == 32",
        'global_asm!(".hidden __tsearch_balance")',
        "selected_mmap",
        "selected_munmap",
        "allocation failure rollback",
        "parent-return deletion",
    ):
        if required not in search_tree_text:
            errors.append(
                "libc/src/c_abi/x86_64/search_tree_intrusive.rs: selected "
                f"tree boundary is missing {required!r}"
            )
    search_tree_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            search_tree_text,
        )
    )
    if search_tree_exports != {
        "__tsearch_balance",
        "tdelete",
        "tdestroy",
        "tfind",
        "tsearch",
        "twalk",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/search_tree_intrusive.rs: selected static "
            "tree leaf must export five public functions plus its hidden helper"
        )
    if '#[linkage = "weak"]' in search_tree_text:
        errors.append(
            "libc/src/c_abi/x86_64/search_tree_intrusive.rs: musl tree "
            "functions and hidden helper must not be weak"
        )
    for forbidden in (
        "libmimalloc",
        'extern "C" fn malloc',
        'extern "C" fn calloc',
        'extern "C" fn realloc',
        'extern "C" fn free',
    ):
        if forbidden in search_tree_text:
            errors.append(
                "libc/src/c_abi/x86_64/search_tree_intrusive.rs: selected "
                f"tree boundary selects forbidden allocator seam {forbidden!r}"
            )

    search_hash_table_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "search_hash_table.rs"
    )
    search_hash_table_text = search_hash_table_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/search/hsearch.c",
        "unsigned-byte hash",
        "quadratic probing",
        "resize rollback",
        "overwrite-and-leak",
        "selected_mmap",
        "selected_munmap",
        "MAXIMUM_SIZE",
        "wrapping_mul(31)",
        '#[linkage = "weak"]',
    ):
        if required not in search_hash_table_text:
            errors.append(
                "libc/src/c_abi/x86_64/search_hash_table.rs: selected static "
                f"hash-table boundary is missing {required!r}"
            )
    search_hash_table_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            search_hash_table_text,
        )
    )
    if search_hash_table_exports != {
        "hcreate",
        "hcreate_r",
        "hdestroy",
        "hdestroy_r",
        "hsearch",
        "hsearch_r",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/search_hash_table.rs: selected static "
            "artifact must export only the six named hash-table symbols"
        )
    for forbidden in (
        "libmimalloc",
        'extern "C" fn malloc',
        'extern "C" fn calloc',
        'extern "C" fn realloc',
        'extern "C" fn free',
    ):
        if forbidden in search_hash_table_text:
            errors.append(
                "libc/src/c_abi/x86_64/search_hash_table.rs: selected static "
                f"hash-table boundary selects forbidden allocator seam {forbidden!r}"
            )

    gettext_catalog_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gettext_catalog.rs"
    )
    gettext_catalog_text = gettext_catalog_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/locale/dcngettext.c",
        "src/locale/textdomain.c",
        "src/locale/bind_textdomain_codeset.c",
        "src/locale/{catopen,catgets,catclose}.c",
        "BINDING_CAPACITY: usize = 4",
        "MAX_DIRECTORY_LENGTH",
        "no-catalog",
        "catopen` always reports `ENOENT`",
        "catalog-file/NLSPATH/LANG lookup",
        "ENOMEM",
    ):
        if required not in gettext_catalog_text:
            errors.append(
                "libc/src/c_abi/x86_64/gettext_catalog.rs: selected static "
                f"gettext/catalog boundary is missing {required!r}"
            )
    gettext_catalog_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            gettext_catalog_text,
        )
    )
    if gettext_catalog_exports != {
        "bind_textdomain_codeset",
        "bindtextdomain",
        "catclose",
        "catgets",
        "catopen",
        "dcgettext",
        "dcngettext",
        "dgettext",
        "dngettext",
        "gettext",
        "ngettext",
        "textdomain",
    }:
        errors.append(
            "libc/src/c_abi/x86_64/gettext_catalog.rs: selected static "
            "artifact must export only the twelve named gettext/catalog symbols"
        )
    for forbidden in (
        "crabc_core",
        "crabc_mimalloc",
        "libmimalloc",
        "sha_crypt",
        "base64ct",
        "alloc::",
    ):
        if forbidden in gettext_catalog_text:
            errors.append(
                "libc/src/c_abi/x86_64/gettext_catalog.rs: selected static "
                f"gettext/catalog boundary selects forbidden runtime seam {forbidden!r}"
            )

    search_header_text = (ROOT / "include" / "search.h").read_text(errors="replace")
    if "#ifdef _GNU_SOURCE\nstruct qelem" not in search_header_text:
        errors.append("include/search.h: tdestroy/qelem must retain exact GNU-only visibility")
    if (
        "#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\nstruct qelem"
        in search_header_text
    ):
        errors.append("include/search.h: BSD must not expose musl GNU tdestroy/qelem")
    if "#ifdef _GNU_SOURCE\nstruct hsearch_data" not in search_header_text:
        errors.append("include/search.h: GNU hsearch_data must retain exact GNU-only visibility")
    if (
        "#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)\nstruct hsearch_data"
        in search_header_text
    ):
        errors.append("include/search.h: BSD must not expose musl GNU hsearch_data")

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

    difftime_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "difftime.rs"
    difftime_text = difftime_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/time/difftime.c",
        "wrapping_sub",
        "binary64",
        "xmm0",
        'pub extern "C" fn difftime',
    ):
        if required not in difftime_text:
            errors.append(
                "libc/src/c_abi/x86_64/difftime.rs: selected binary64 "
                f"difftime boundary is missing {required!r}"
            )
    difftime_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            difftime_text,
        )
    )
    if difftime_exports != {"difftime"}:
        errors.append(
            "libc/src/c_abi/x86_64/difftime.rs: selected binary64 artifact "
            "must export only difftime"
        )
    for forbidden in (
        "crabc_core",
        "crabc_mimalloc",
        "raw_syscall",
        "set_errno",
        "getenv",
        "tzset",
        "__tls_get_addr",
    ):
        if forbidden in difftime_text:
            errors.append(
                "libc/src/c_abi/x86_64/difftime.rs: selected binary64 difftime "
                f"boundary must not select {forbidden!r}"
            )

    sched_yield_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_yield.rs"
    sched_yield_text = sched_yield_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/sched/sched_yield.c::sched_yield",
        "sched_yield=24",
        "raw_syscall::SYS_SCHED_YIELD",
        "raw_syscall::syscall0",
        "c_status(result)",
        "initial-TLS",
        "scheduler policy",
        "process lifecycle",
    ):
        if required not in sched_yield_text:
            errors.append(
                "libc/src/c_abi/x86_64/sched_yield.rs: selected static POSIX "
                f"scheduler-yield boundary is missing {required!r}"
            )
    sched_yield_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            sched_yield_text,
        )
    )
    if sched_yield_exports != {"sched_yield"}:
        errors.append(
            "libc/src/c_abi/x86_64/sched_yield.rs: selected static artifact "
            "must export only sched_yield"
        )

    sched_getcpu_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_getcpu.rs"
    sched_getcpu_text = sched_getcpu_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/sched/sched_getcpu.c::sched_getcpu",
        "VDSO_GETCPU_SYM",
        "raw syscall fallback",
        "getcpu=309",
        "raw_syscall::SYS_GETCPU",
        "raw_syscall::syscall3",
        "c_status(result)",
        "scheduler policy",
        "clock/timer/calendar/timezone",
        "public x86 support",
    ):
        if required not in sched_getcpu_text:
            errors.append(
                "libc/src/c_abi/x86_64/sched_getcpu.rs: selected static GNU "
                f"current-CPU boundary is missing {required!r}"
            )
    sched_getcpu_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            sched_getcpu_text,
        )
    )
    if sched_getcpu_exports != {"sched_getcpu"}:
        errors.append(
            "libc/src/c_abi/x86_64/sched_getcpu.rs: selected static artifact "
            "must export only sched_getcpu"
        )
    for forbidden in (
        "crabc_core",
        "crabc_mimalloc",
        "sched_getaffinity(",
        "sched_setaffinity(",
        "sched_getparam(",
        "sched_getscheduler(",
        "sched_yield(",
        "__tls_get_addr",
    ):
        if forbidden in sched_getcpu_text:
            errors.append(
                "libc/src/c_abi/x86_64/sched_getcpu.rs: selected static GNU "
                f"current-CPU boundary must not select {forbidden!r}"
            )

    timegm_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "timegm.rs"
    timegm_text = timegm_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/time/timegm.c",
        "src/time/__tm_to_secs.c",
        "src/time/__secs_to_tm.c",
        "src/time/__year_to_secs.c",
        "src/time/__month_to_secs.c",
        "pub(super) fn secs_to_utc_tm",
        "month < 0",
        "EOVERFLOW",
        "UTC",
        "initial-TLS errno",
        'pub unsafe extern "C" fn timegm',
    ):
        if required not in timegm_text:
            errors.append(
                "libc/src/c_abi/x86_64/timegm.rs: selected fixed-UTC timegm "
                f"boundary is missing {required!r}"
            )
    timegm_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            timegm_text,
        )
    )
    if timegm_exports != {"timegm"}:
        errors.append(
            "libc/src/c_abi/x86_64/timegm.rs: selected fixed-UTC artifact "
            "must export only timegm"
        )
    for forbidden in (
        "crabc_core",
        "crabc_mimalloc",
        "raw_syscall",
        "getenv",
        "tzset",
        "localtime",
        "mktime",
        "strftime",
        "strptime",
        "__tls_get_addr",
    ):
        if forbidden in timegm_text:
            errors.append(
                "libc/src/c_abi/x86_64/timegm.rs: selected fixed-UTC timegm "
                f"boundary must not select {forbidden!r}"
            )

    gmtime_r_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "gmtime_r.rs"
    gmtime_r_text = gmtime_r_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/time/gmtime_r.c",
        "src/time/__secs_to_tm.c",
        "secs_to_utc_tm, Tm",
        "EOVERFLOW",
        "UTC",
        "initial-TLS errno",
        "__gmtime_r",
        'pub unsafe extern "C" fn gmtime_r',
    ):
        if required not in gmtime_r_text:
            errors.append(
                "libc/src/c_abi/x86_64/gmtime_r.rs: selected caller-buffered "
                f"fixed-UTC boundary is missing {required!r}"
            )
    gmtime_r_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            gmtime_r_text,
        )
    )
    if gmtime_r_exports != {"gmtime_r"}:
        errors.append(
            "libc/src/c_abi/x86_64/gmtime_r.rs: selected caller-buffered "
            "fixed-UTC artifact must export only gmtime_r"
        )
    for forbidden in (
        "crabc_core",
        "crabc_mimalloc",
        "raw_syscall",
        "getenv",
        "tzset",
        "localtime",
        "mktime",
        "strftime",
        "strptime",
        "__tls_get_addr",
    ):
        if forbidden in gmtime_r_text:
            errors.append(
                "libc/src/c_abi/x86_64/gmtime_r.rs: selected caller-buffered "
                f"fixed-UTC boundary must not select {forbidden!r}"
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

    memory_sync_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_sync.rs"
    memory_sync_text = memory_sync_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/mman/msync.c",
        "src/thread/x86_64/syscall_cp.s",
        "syscall_cp(SYS_msync",
        "raw_syscall::SYS_MSYNC",
        "raw_syscall::syscall3(",
        "c_status(result)",
        "no-cancellation direct",
        "full musl `msync` parity",
        "file-backed shared-map writeback",
    ):
        if required not in memory_sync_text:
            errors.append(
                "libc/src/c_abi/x86_64/memory_sync.rs: selected static "
                f"mapping-synchronization boundary is missing {required!r}"
            )
    memory_sync_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            memory_sync_text,
        )
    )
    if memory_sync_exports != {"msync"}:
        errors.append(
            "libc/src/c_abi/x86_64/memory_sync.rs: selected static artifact "
            "must export only msync"
        )
    if "pub(crate) const SYS_MSYNC: i64 = 26;" not in raw_syscall_text:
        errors.append(
            "libc/src/c_abi/x86_64/syscall.rs: selected static mapping "
            "synchronization boundary requires SYS_MSYNC=26"
        )

    memory_locking_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memory_locking.rs"
    )
    memory_locking_text = memory_locking_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/mman/mlock.c",
        "src/mman/munlock.c",
        "src/linux/mlock2.c",
        "raw_syscall::SYS_MLOCK",
        "raw_syscall::SYS_MUNLOCK",
        "raw_syscall::SYS_MLOCK2",
        "if flags == 0",
        "return unsafe { mlock(address, length) }",
        "c_status(result)",
        "initial-TLS",
        "cancellation-point syscall path",
        "mlockall",
        "munlockall",
        "msync",
        "mremap",
    ):
        if required not in memory_locking_text:
            errors.append(
                "libc/src/c_abi/x86_64/memory_locking.rs: selected static "
                f"per-range locking boundary is missing {required!r}"
            )
    memory_locking_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            memory_locking_text,
        )
    )
    if memory_locking_exports != {"mlock", "munlock", "mlock2"}:
        errors.append(
            "libc/src/c_abi/x86_64/memory_locking.rs: selected static artifact "
            "must export only mlock, munlock, and mlock2"
        )
    for required in (
        "pub(crate) const SYS_MLOCK: i64 = 149;",
        "pub(crate) const SYS_MUNLOCK: i64 = 150;",
        "pub(crate) const SYS_MLOCK2: i64 = 325;",
    ):
        if required not in raw_syscall_text:
            errors.append(
                "libc/src/c_abi/x86_64/syscall.rs: selected static per-range "
                f"locking boundary is missing {required!r}"
            )

    memfd_create_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "memfd_create.rs"
    memfd_create_text = memfd_create_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/linux/memfd_create.c",
        "memfd_create=319",
        "raw_syscall::SYS_MEMFD_CREATE",
        "raw_syscall::syscall2(",
        "c_status(result)",
        "initial-TLS C `errno`",
        "MFD_HUGETLB",
        "memfd_secret",
        "fcntl",
    ):
        if required not in memfd_create_text:
            errors.append(
                "libc/src/c_abi/x86_64/memfd_create.rs: selected static "
                f"anonymous-memory-descriptor boundary is missing {required!r}"
            )
    memfd_create_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            memfd_create_text,
        )
    )
    if memfd_create_exports != {"memfd_create"}:
        errors.append(
            "libc/src/c_abi/x86_64/memfd_create.rs: selected static artifact "
            "must export only memfd_create"
        )
    if "pub(crate) const SYS_MEMFD_CREATE: i64 = 319;" not in raw_syscall_text:
        errors.append(
            "libc/src/c_abi/x86_64/syscall.rs: selected static anonymous-memory "
            "descriptor boundary requires SYS_MEMFD_CREATE=319"
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

    signal_pause_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_pause.rs"
    )
    signal_pause_text = signal_pause_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 sigpause C boundary",
        "src/signal/sigpause.c",
        "KERNEL_SIGSET_SIZE",
        "SYS_RT_SIGPROCMASK",
        "SYS_RT_SIGSUSPEND",
        "raw_syscall::syscall4(",
        "raw_syscall::syscall2(",
        "errno::set_errno(EINVAL)",
        "c_status(result)",
    ):
        if required not in signal_pause_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_pause.rs: selected static "
                f"single-signal wait boundary is missing {required!r}"
            )
    signal_pause_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_pause_text,
        )
    )
    if signal_pause_exports != {"sigpause"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_pause.rs: selected static artifact "
            "must export only sigpause"
        )
    for forbidden in (
        "sigprocmask(",
        "sigdelset(",
        "sigsuspend(",
        "sigtimedwait(",
        "signalfd",
        "timerfd",
        "pthread_",
        "process_context",
    ):
        if forbidden in signal_pause_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_pause.rs: selected static "
                f"single-signal wait boundary must not select {forbidden!r}"
            )

    signal_set_isempty_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_isempty.rs"
    )
    signal_set_isempty_text = signal_set_isempty_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 GNU `sigisemptyset` C boundary",
        "src/signal/sigisemptyset.c",
        "SST_SIZE",
        "const _: [(); 1] = [(); SST_SIZE]",
        "core::ptr::read_unaligned",
    ):
        if required not in signal_set_isempty_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_set_isempty.rs: selected static "
                f"GNU predicate is missing {required!r}"
            )
    signal_set_isempty_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_set_isempty_text,
        )
    )
    if signal_set_isempty_exports != {"sigisemptyset"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_set_isempty.rs: selected static "
            "artifact must export only sigisemptyset"
        )
    for forbidden in (
        "raw_syscall",
        "errno::",
        "sigaction(",
        "sigprocmask(",
        "pthread_",
        "signalfd",
        "timerfd",
    ):
        if forbidden in signal_set_isempty_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_set_isempty.rs: selected static "
                f"GNU predicate must not select {forbidden!r}"
            )

    signal_set_binary_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_set_binary.rs"
    )
    signal_set_binary_text = signal_set_binary_source.read_text(errors="replace")
    for required in (
        "Selected static Linux/x86-64 GNU `sigandset`/`sigorset` C boundary",
        "src/signal/sigandset.c",
        "src/signal/sigorset.c",
        "SST_SIZE",
        "const _: [(); 1] = [(); SST_SIZE]",
        "core::ptr::read_unaligned",
        "core::ptr::write_unaligned",
    ):
        if required not in signal_set_binary_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_set_binary.rs: selected static "
                f"GNU binary operation is missing {required!r}"
            )
    signal_set_binary_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            signal_set_binary_text,
        )
    )
    if signal_set_binary_exports != {"sigandset", "sigorset"}:
        errors.append(
            "libc/src/c_abi/x86_64/signal_set_binary.rs: selected static "
            "artifact must export only sigandset and sigorset"
        )
    for forbidden in (
        "raw_syscall",
        "errno::",
        "sigaction(",
        "sigprocmask(",
        "pthread_",
        "signalfd",
        "timerfd",
    ):
        if forbidden in signal_set_binary_text:
            errors.append(
                "libc/src/c_abi/x86_64/signal_set_binary.rs: selected static "
                f"GNU binary operation must not select {forbidden!r}"
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

    socket_messages_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "socket_messages.rs"
    )
    socket_messages_text = socket_messages_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/network/setsockopt.c",
        "src/network/getsockopt.c",
        "src/network/sendmsg.c",
        "src/network/recvmsg.c",
        "src/network/sendmmsg.c",
        "src/network/recvmmsg.c",
        "src/network/sockatmark.c",
        "MUSL_SEND_CONTROL_BYTES",
        "zero_cmsg_padding",
        "raw_syscall::SYS_SETSOCKOPT",
        "raw_syscall::SYS_GETSOCKOPT",
        "raw_syscall::SYS_SENDMSG",
        "raw_syscall::SYS_RECVMSG",
        "raw_syscall::SYS_RECVMMSG",
        "raw_syscall::SYS_IOCTL",
        "SIOCATMARK",
        "cancellation",
    ):
        if required not in socket_messages_text:
            errors.append(
                "libc/src/c_abi/x86_64/socket_messages.rs: selected static "
                f"socket-message boundary is missing {required!r}"
            )
    socket_messages_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            socket_messages_text,
        )
    )
    expected_socket_messages_exports = {
        "setsockopt",
        "getsockopt",
        "sendmsg",
        "recvmsg",
        "sendmmsg",
        "recvmmsg",
        "sockatmark",
    }
    if socket_messages_exports != expected_socket_messages_exports:
        errors.append(
            "libc/src/c_abi/x86_64/socket_messages.rs: selected static "
            "artifact must export only its named socket-message/options symbols"
        )

    in6addr_any_probe_source = (
        ROOT / "compat" / "x86_64" / "libc_in6addr_any_probe.c"
    )
    in6addr_any_start_source = (
        ROOT / "compat" / "x86_64" / "libc_in6addr_any_start.S"
    )
    in6addr_any_runner_source = (
        ROOT / "compat" / "x86_64" / "run_libc_in6addr_any.sh"
    )
    for path in (
        in6addr_any_probe_source,
        in6addr_any_start_source,
        in6addr_any_runner_source,
    ):
        if not path.is_file():
            errors.append(
                "x86 static immutable IPv6 unspecified-address artifact is missing "
                f"{path.relative_to(ROOT)}"
            )
            return

    in6addr_any_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "in6addr_any.rs"
    )
    in6addr_any_text = in6addr_any_source.read_text(errors="replace")
    in6addr_any_probe = in6addr_any_probe_source.read_text(errors="replace")
    in6addr_any_start = in6addr_any_start_source.read_text(errors="replace")
    in6addr_any_runner = in6addr_any_runner_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/network/in6addr_any.c",
        "src/network/in6addr_loopback.c",
        "pub struct In6Addr",
        "pub union In6AddrUnion",
        "[u8; 16]",
        "[u16; 8]",
        "[u32; 4]",
        "#[no_mangle]",
        "pub static in6addr_any",
        "[0; 16]",
    ):
        if required not in in6addr_any_text:
            errors.append(
                "libc/src/c_abi/x86_64/in6addr_any.rs: selected static "
                f"immutable IPv6 object boundary is missing {required!r}"
            )
    for forbidden in (
        "static mut",
        "raw_syscall",
        "__errno_location",
        "getaddrinfo",
        "gethostby",
        "if_nameindex",
        "socket(",
        "std::",
        "alloc::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in in6addr_any_text:
            errors.append(
                "libc/src/c_abi/x86_64/in6addr_any.rs: selected static "
                f"immutable IPv6 object must not select {forbidden!r}"
            )
    in6addr_any_exports = set(
        re.findall(r"(?m)^pub\s+static\s+(\w+)\s*:", in6addr_any_text)
    )
    if in6addr_any_exports != {"in6addr_any"}:
        errors.append(
            "libc/src/c_abi/x86_64/in6addr_any.rs: selected static artifact "
            "must export only in6addr_any"
        )
    netinet_header = (ROOT / "include" / "netinet" / "in.h").read_text(
        errors="replace"
    )
    for required in (
        'extern "C" {',
        "uint8_t __s6_addr[16]",
        "uint16_t __s6_addr16[8]",
        "uint32_t __s6_addr32[4]",
        "__in6_union",
        "#define s6_addr __in6_union.__s6_addr",
        "extern const struct in6_addr in6addr_any",
        "extern const struct in6_addr in6addr_loopback",
    ):
        if required not in netinet_header:
            errors.append(
                "include/netinet/in.h: immutable IPv6 C/C++ data-object ABI "
                f"is missing {required!r}"
            )
    for required in (
        "sizeof(struct in6_addr) == 16",
        "_Alignof(struct in6_addr) == 4",
        "offsetof(struct in6_addr, s6_addr) == 0",
        "in6addr_any_pointer",
        "all_zero",
        "IN6_IS_ADDR_UNSPECIFIED",
        "IN6_IS_ADDR_LOOPBACK",
        "CRABC_IN6ADDR_ANY_FREESTANDING",
    ):
        if required not in in6addr_any_probe:
            errors.append(
                "compat/x86_64/libc_in6addr_any_probe.c: immutable IPv6 "
                f"regression is missing {required!r}"
            )
    for required in (
        "crabc_x86_64_in6addr_any_probe",
        "mov $60, %eax",
    ):
        if required not in in6addr_any_start:
            errors.append(
                "compat/x86_64/libc_in6addr_any_start.S: immutable IPv6 "
                f"entry is missing {required!r}"
            )
    if "ARCH_SET_FS" in in6addr_any_start:
        errors.append(
            "compat/x86_64/libc_in6addr_any_start.S: immutable IPv6 entry "
            "must not bootstrap TLS"
        )
    for required in (
        "in6addr_any.lo",
        "in6addr_loopback.lo",
        "in6addr_any.c",
        "in6addr_loopback.c",
        "assert_selected_c_abi_surface",
        "extract_selected_member",
        "in6addr_any archive member also defines in6addr_loopback",
        "-nostdlib -static",
        '"$selected_member" -o "$candidate"',
        "candidate unexpectedly selects TLS",
        "in6addr_loopback htonl htons ntohl ntohs",
        "getaddrinfo",
        "if_indextoname",
        "if_nameindex",
        "if_nametoindex",
        "socket bind connect send recv",
        "__tls_get_addr",
    ):
        if required not in in6addr_any_runner:
            errors.append(
                "compat/x86_64/run_libc_in6addr_any.sh: archive-free static "
                f"immutable IPv6 evidence is missing {required!r}"
            )
    if '"$archive" -o "$candidate"' in in6addr_any_runner:
        errors.append(
            "compat/x86_64/run_libc_in6addr_any.sh: final immutable IPv6 "
            "candidate must not link libc.a"
        )
    socket_header_runner = (
        ROOT / "compat" / "x86_64" / "run_socket_header_abi.sh"
    ).read_text(errors="replace")
    if (
        "check_cxx_in6addr_any_linkage" not in socket_header_runner
        or "check_cxx_in6addr_loopback_linkage" not in socket_header_runner
    ):
        errors.append(
            "compat/x86_64/run_socket_header_abi.sh: IPv6 data-object C++ "
            "linkage proof is missing"
        )

    in6addr_loopback_probe_source = (
        ROOT / "compat" / "x86_64" / "libc_in6addr_loopback_probe.c"
    )
    in6addr_loopback_start_source = (
        ROOT / "compat" / "x86_64" / "libc_in6addr_loopback_start.S"
    )
    in6addr_loopback_runner_source = (
        ROOT / "compat" / "x86_64" / "run_libc_in6addr_loopback.sh"
    )
    for path in (
        in6addr_loopback_probe_source,
        in6addr_loopback_start_source,
        in6addr_loopback_runner_source,
    ):
        if not path.is_file():
            errors.append(
                "x86 static immutable IPv6 loopback-address artifact is missing "
                f"{path.relative_to(ROOT)}"
            )
            return

    in6addr_loopback_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "in6addr_loopback.rs"
    )
    in6addr_loopback_text = in6addr_loopback_source.read_text(errors="replace")
    in6addr_loopback_probe = in6addr_loopback_probe_source.read_text(
        errors="replace"
    )
    in6addr_loopback_start = in6addr_loopback_start_source.read_text(
        errors="replace"
    )
    in6addr_loopback_runner = in6addr_loopback_runner_source.read_text(
        errors="replace"
    )
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/network/in6addr_loopback.c",
        "src/network/in6addr_any.c",
        "pub struct In6Addr",
        "pub union In6AddrUnion",
        "[u8; 16]",
        "[u16; 8]",
        "[u32; 4]",
        "#[no_mangle]",
        "pub static in6addr_loopback",
        "0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1",
    ):
        if required not in in6addr_loopback_text:
            errors.append(
                "libc/src/c_abi/x86_64/in6addr_loopback.rs: selected static "
                f"immutable IPv6 object boundary is missing {required!r}"
            )
    for forbidden in (
        "static mut",
        "raw_syscall",
        "__errno_location",
        "getaddrinfo",
        "gethostby",
        "if_nameindex",
        "socket(",
        "std::",
        "alloc::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in in6addr_loopback_text:
            errors.append(
                "libc/src/c_abi/x86_64/in6addr_loopback.rs: selected static "
                f"immutable IPv6 object must not select {forbidden!r}"
            )
    in6addr_loopback_exports = set(
        re.findall(r"(?m)^pub\s+static\s+(\w+)\s*:", in6addr_loopback_text)
    )
    if in6addr_loopback_exports != {"in6addr_loopback"}:
        errors.append(
            "libc/src/c_abi/x86_64/in6addr_loopback.rs: selected static artifact "
            "must export only in6addr_loopback"
        )
    for required in (
        "sizeof(struct in6_addr) == 16",
        "_Alignof(struct in6_addr) == 4",
        "offsetof(struct in6_addr, s6_addr) == 0",
        "in6addr_loopback_pointer",
        "is_loopback",
        "IN6_IS_ADDR_LOOPBACK",
        "IN6_IS_ADDR_UNSPECIFIED",
        "CRABC_IN6ADDR_LOOPBACK_FREESTANDING",
    ):
        if required not in in6addr_loopback_probe:
            errors.append(
                "compat/x86_64/libc_in6addr_loopback_probe.c: immutable IPv6 "
                f"regression is missing {required!r}"
            )
    for required in (
        "crabc_x86_64_in6addr_loopback_probe",
        "mov $60, %eax",
    ):
        if required not in in6addr_loopback_start:
            errors.append(
                "compat/x86_64/libc_in6addr_loopback_start.S: immutable IPv6 "
                f"entry is missing {required!r}"
            )
    if "ARCH_SET_FS" in in6addr_loopback_start:
        errors.append(
            "compat/x86_64/libc_in6addr_loopback_start.S: immutable IPv6 entry "
            "must not bootstrap TLS"
        )
    for required in (
        "in6addr_loopback.lo",
        "in6addr_any.lo",
        "in6addr_loopback.c",
        "in6addr_any.c",
        "assert_selected_c_abi_surface",
        "extract_selected_member",
        "in6addr_loopback archive member also defines in6addr_any",
        "-nostdlib -static",
        '"$selected_member" -o "$candidate"',
        "candidate unexpectedly selects TLS",
        "in6addr_any htonl htons ntohl ntohs",
        "getaddrinfo",
        "if_indextoname",
        "if_nameindex",
        "if_nametoindex",
        "socket bind connect send recv",
        "__tls_get_addr",
    ):
        if required not in in6addr_loopback_runner:
            errors.append(
                "compat/x86_64/run_libc_in6addr_loopback.sh: archive-free static "
                f"immutable IPv6 evidence is missing {required!r}"
            )
    if '"$archive" -o "$candidate"' in in6addr_loopback_runner:
        errors.append(
            "compat/x86_64/run_libc_in6addr_loopback.sh: final immutable IPv6 "
            "candidate must not link libc.a"
        )

    inet_address_probe_source = (
        ROOT / "compat" / "x86_64" / "libc_inet_address_probe.c"
    )
    inet_address_start_source = (
        ROOT / "compat" / "x86_64" / "libc_inet_address_start.S"
    )
    inet_address_runner_source = (
        ROOT / "compat" / "x86_64" / "run_libc_inet_address.sh"
    )
    for path in (
        inet_address_probe_source,
        inet_address_start_source,
        inet_address_runner_source,
    ):
        if not path.is_file():
            errors.append(
                "x86 static numeric address-codec artifact is missing "
                f"{path.relative_to(ROOT)}"
            )
            return

    inet_address_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "inet_address.rs"
    )
    inet_address_text = inet_address_source.read_text(errors="replace")
    inet_address_probe = inet_address_probe_source.read_text(errors="replace")
    inet_address_start = inet_address_start_source.read_text(errors="replace")
    inet_address_runner = inet_address_runner_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/network/inet_pton.c",
        "src/network/inet_ntop.c",
        "src/network/inet_aton.c",
        "src/network/inet_addr.c",
        "partial output writes",
        "partial IPv4 output",
        "integer_parse::strtoul",
        "errno::set_errno(EAFNOSUPPORT)",
        "errno::set_errno(ENOSPC)",
        ".hidden __inet_aton",
        ".weak inet_aton",
        ".set inet_aton, __inet_aton",
        "pub unsafe extern \"C\" fn inet_pton",
        "pub unsafe extern \"C\" fn inet_ntop",
        "pub unsafe extern \"C\" fn __inet_aton",
        "pub unsafe extern \"C\" fn inet_addr",
    ):
        if required not in inet_address_text:
            errors.append(
                "libc/src/c_abi/x86_64/inet_address.rs: selected static "
                f"numeric address-codec boundary is missing {required!r}"
            )
    for forbidden in ("std::", "alloc::", "raw_syscall::", "crabc_core"):
        if forbidden in inet_address_text:
            errors.append(
                "libc/src/c_abi/x86_64/inet_address.rs: selected static "
                f"numeric address-codec boundary must not select {forbidden!r}"
            )
    inet_address_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            inet_address_text,
        )
    )
    expected_inet_address_exports = {
        "inet_pton",
        "inet_ntop",
        "__inet_aton",
        "inet_addr",
    }
    if inet_address_exports != expected_inet_address_exports:
        errors.append(
            "libc/src/c_abi/x86_64/inet_address.rs: selected static "
            "artifact must export only its named numeric address-codec symbols"
        )
    inet_address_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*__inet_aton",\s*$',
            inet_address_text,
        )
    )
    if inet_address_aliases != {"inet_aton"}:
        errors.append(
            "libc/src/c_abi/x86_64/inet_address.rs: selected static artifact "
            "must retain inet_aton as musl's same-address assembler alias"
        )
    for required in (
        "#include <arpa/inet.h>",
        '"01.2.3.4"',
        '"1.2.3.4x"',
        '"::192.0.2.1"',
        '"::ffff:192.0.2.999"',
        '"::c000:280"',
        '"::1:0:0:1:1:1"',
        '"0177.1"',
        '"18446744073709551616"',
        "AF_INET6, ipv6, output, 12",
        "AF_INET6, ipv6, output, 11",
        "CRABC_INET_ADDRESS_FREESTANDING",
    ):
        if required not in inet_address_probe:
            errors.append(
                "compat/x86_64/libc_inet_address_probe.c: static numeric "
                f"address-codec regression is missing {required!r}"
            )
    for required in (
        "__crabc_x86_static_tls_bootstrap",
        "crabc_x86_64_inet_address_probe",
        "mov $231, %eax",
    ):
        if required not in inet_address_start:
            errors.append(
                "compat/x86_64/libc_inet_address_start.S: static numeric "
                f"address-codec TLS shim is missing {required!r}"
            )
    for required in (
        "assert_selected_c_abi_surface",
        "assert_musl_inet_aton_alias",
        "-print-file-name=libc.a",
        "inet_aton.lo",
        "pinned-musl static archive",
        "R_X86_64_TPOFF",
        "-nostdlib -static",
        "-Wl,-e,_start",
        "static_c_abi_exports.txt",
        "inet_ntoa",
        "gethostbyname",
        "__tls_get_addr",
    ):
        if required not in inet_address_runner:
            errors.append(
                "compat/x86_64/run_libc_inet_address.sh: static numeric "
                f"address-codec evidence is missing {required!r}"
            )
    if "--whole-archive" in inet_address_runner:
        errors.append(
            "compat/x86_64/run_libc_inet_address.sh: static numeric "
            "address-codec evidence must not force-link the whole archive"
        )

    inet_ntoa_probe_source = ROOT / "compat" / "x86_64" / "libc_inet_ntoa_probe.c"
    inet_ntoa_start_source = ROOT / "compat" / "x86_64" / "libc_inet_ntoa_start.S"
    inet_ntoa_runner_source = ROOT / "compat" / "x86_64" / "run_libc_inet_ntoa.sh"
    for path in (
        inet_ntoa_probe_source,
        inet_ntoa_start_source,
        inet_ntoa_runner_source,
    ):
        if not path.is_file():
            errors.append(
                f"x86 static inet_ntoa artifact is missing {path.relative_to(ROOT)}"
            )
            return

    inet_ntoa_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "inet_ntoa.rs"
    inet_ntoa_text = inet_ntoa_source.read_text(errors="replace")
    inet_ntoa_probe = inet_ntoa_probe_source.read_text(errors="replace")
    inet_ntoa_start = inet_ntoa_start_source.read_text(errors="replace")
    inet_ntoa_runner = inet_ntoa_runner_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/network/inet_ntoa.c",
        "snprintf",
        "INET_NTOA_BUFFER",
        "[c_char; 16]",
        "write_decimal_octet",
        "to_ne_bytes",
        'pub unsafe extern "C" fn inet_ntoa',
        "Concurrent callers must externally synchronize",
    ):
        if required not in inet_ntoa_text:
            errors.append(
                "libc/src/c_abi/x86_64/inet_ntoa.rs: selected static "
                f"scratch-buffer boundary is missing {required!r}"
            )
    if re.findall(r"(?m)^static mut (\w+)", inet_ntoa_text) != ["INET_NTOA_BUFFER"]:
        errors.append(
            "libc/src/c_abi/x86_64/inet_ntoa.rs: selected static artifact "
            "must own exactly one shared mutable buffer"
        )
    for forbidden in (
        "raw_syscall",
        "errno::",
        "__h_errno_location",
        "getaddrinfo",
        "gethostby",
        "if_nameindex",
        "socket(",
        "std::",
        "alloc::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in inet_ntoa_text:
            errors.append(
                "libc/src/c_abi/x86_64/inet_ntoa.rs: selected static "
                f"scratch-buffer boundary must not select {forbidden!r}"
            )
    inet_ntoa_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            inet_ntoa_text,
        )
    )
    if inet_ntoa_exports != {"inet_ntoa"}:
        errors.append(
            "libc/src/c_abi/x86_64/inet_ntoa.rs: selected static artifact "
            "must export only inet_ntoa"
        )
    for required in (
        "inet_ntoa_signature",
        "sizeof(struct in_addr) == 4",
        "offsetof(struct in_addr, s_addr) == 0",
        '"0.9.10.99"',
        '"100.255.0.1"',
        '"255.255.255.255"',
        '"0.0.0.0"',
        "second != first",
        "CRABC_INET_NTOA_FREESTANDING",
    ):
        if required not in inet_ntoa_probe:
            errors.append(
                "compat/x86_64/libc_inet_ntoa_probe.c: static scratch-buffer "
                f"regression is missing {required!r}"
            )
    for required in (
        "crabc_x86_64_inet_ntoa_probe",
        "mov $60, %eax",
    ):
        if required not in inet_ntoa_start:
            errors.append(
                "compat/x86_64/libc_inet_ntoa_start.S: static scratch-buffer "
                f"entry is missing {required!r}"
            )
    if "ARCH_SET_FS" in inet_ntoa_start:
        errors.append(
            "compat/x86_64/libc_inet_ntoa_start.S: scratch-buffer entry "
            "must not bootstrap TLS"
        )
    for required in (
        "inet_ntoa.lo",
        "snprintf",
        "%d.%d.%d.%d",
        "assert_selected_c_abi_surface",
        "extract_selected_member",
        "exactly one selected archive member",
        "-nostdlib -static",
        '"$selected_member" -o "$candidate"',
        "archive-free candidate",
        "candidate unexpectedly selects TLS",
        "__h_errno_location",
        "getaddrinfo",
        "if_nameindex",
        "socket bind connect send recv",
        "malloc free calloc realloc snprintf",
        "call|syscall",
    ):
        if required not in inet_ntoa_runner:
            errors.append(
                "compat/x86_64/run_libc_inet_ntoa.sh: archive-free static "
                f"scratch-buffer evidence is missing {required!r}"
            )
    if '"$archive" -o "$candidate"' in inet_ntoa_runner:
        errors.append(
            "compat/x86_64/run_libc_inet_ntoa.sh: final scratch-buffer "
            "candidate must not link libc.a"
        )
    if "candidate accidentally selects separate inet_ntoa scratch storage" not in inet_address_runner:
        errors.append(
            "compat/x86_64/run_libc_inet_address.sh: numeric candidate must "
            "continue excluding the separate inet_ntoa scratch buffer"
        )

    inet_classful_probe_source = (
        ROOT / "compat" / "x86_64" / "libc_inet_classful_probe.c"
    )
    inet_classful_start_source = (
        ROOT / "compat" / "x86_64" / "libc_inet_classful_start.S"
    )
    inet_classful_runner_source = (
        ROOT / "compat" / "x86_64" / "run_libc_inet_classful.sh"
    )
    for path in (
        inet_classful_probe_source,
        inet_classful_start_source,
        inet_classful_runner_source,
    ):
        if not path.is_file():
            errors.append(
                f"x86 static classful IPv4 artifact is missing {path.relative_to(ROOT)}"
            )
            return

    inet_classful_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "inet_classful.rs"
    )
    inet_classful_text = inet_classful_source.read_text(errors="replace")
    inet_classful_probe = inet_classful_probe_source.read_text(errors="replace")
    inet_classful_start = inet_classful_start_source.read_text(errors="replace")
    inet_classful_runner = inet_classful_runner_source.read_text(errors="replace")
    for required in (
        "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "src/network/inet_legacy.c",
        "`inet_network` (and its `inet_addr` call)",
        "`inet_netof`",
        "network << 24",
        "network << 16",
        "network << 8",
        "host >> 24 < 128",
        "host >> 24 < 192",
        "0x00ff_ffff",
        "0x0000_ffff",
        "0x0000_00ff",
        "#[repr(C)]",
        "pub struct InAddr",
        'pub extern "C" fn inet_makeaddr',
        'pub extern "C" fn inet_lnaof',
    ):
        if required not in inet_classful_text:
            errors.append(
                "libc/src/c_abi/x86_64/inet_classful.rs: selected static "
                f"classful boundary is missing {required!r}"
            )
    for forbidden in (
        "raw_syscall",
        "errno::",
        "__h_errno_location",
        "getaddrinfo",
        "gethostby",
        "if_nameindex",
        "socket(",
        "std::",
        "alloc::",
        "crabc_core",
        "crabc_mimalloc",
    ):
        if forbidden in inet_classful_text:
            errors.append(
                "libc/src/c_abi/x86_64/inet_classful.rs: selected static "
                f"classful boundary must not select {forbidden!r}"
            )
    inet_classful_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            inet_classful_text,
        )
    )
    if inet_classful_exports != {"inet_makeaddr", "inet_lnaof"}:
        errors.append(
            "libc/src/c_abi/x86_64/inet_classful.rs: selected static artifact "
            "must export only inet_makeaddr and inet_lnaof"
        )
    for required in (
        "inet_makeaddr_signature",
        "inet_lnaof_signature",
        "sizeof(in_addr_t) == 4",
        "offsetof(struct in_addr, s_addr) == 0",
        "0x7f123456",
        "0x80003456",
        "0x01003456",
        "0xffff00aa",
        "0x010000bb",
        "0xff000001",
        "0x0000cdef",
        "CRABC_INET_CLASSFUL_FREESTANDING",
    ):
        if required not in inet_classful_probe:
            errors.append(
                "compat/x86_64/libc_inet_classful_probe.c: static classful "
                f"regression is missing {required!r}"
            )
    for required in (
        "crabc_x86_64_inet_classful_probe",
        "mov $60, %eax",
    ):
        if required not in inet_classful_start:
            errors.append(
                "compat/x86_64/libc_inet_classful_start.S: static classful "
                f"entry is missing {required!r}"
            )
    if "ARCH_SET_FS" in inet_classful_start:
        errors.append(
            "compat/x86_64/libc_inet_classful_start.S: classful entry must not "
            "bootstrap TLS"
        )
    for required in (
        "inet_legacy.lo",
        "inet_network inet_makeaddr inet_lnaof inet_netof",
        "inet_network no longer carries its unselected inet_addr dependency",
        "assert_selected_c_abi_surface",
        "extract_selected_member",
        "inet_makeaddr archive member does not also define inet_lnaof",
        "-nostdlib -static",
        '"$selected_member" -o "$candidate"',
        "candidate unexpectedly selects TLS",
        "htonl htons ntohl ntohs",
        "inet_ntoa inet_ntop inet_pton inet_network inet_netof",
        "call|syscall",
    ):
        if required not in inet_classful_runner:
            errors.append(
                "compat/x86_64/run_libc_inet_classful.sh: archive-free static "
                f"classful evidence is missing {required!r}"
            )
    if '"$archive" -o "$candidate"' in inet_classful_runner:
        errors.append(
            "compat/x86_64/run_libc_inet_classful.sh: final classful candidate "
            "must not link libc.a"
        )
    if "candidate accidentally selects separate classful IPv4 leaf" not in inet_address_runner:
        errors.append(
            "compat/x86_64/run_libc_inet_address.sh: numeric candidate must "
            "continue excluding the separate classful IPv4 leaf"
        )

    hstrerror_probe_source = ROOT / "compat" / "x86_64" / "libc_hstrerror_probe.c"
    hstrerror_start_source = ROOT / "compat" / "x86_64" / "libc_hstrerror_start.S"
    hstrerror_runner_source = ROOT / "compat" / "x86_64" / "run_libc_hstrerror.sh"
    for path in (
        hstrerror_probe_source,
        hstrerror_start_source,
        hstrerror_runner_source,
    ):
        if not path.is_file():
            errors.append(
                f"x86 static hstrerror artifact is missing {path.relative_to(ROOT)}"
            )
            return

    hstrerror_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "hstrerror.rs"
    hstrerror_text = hstrerror_source.read_text(errors="replace")
    hstrerror_probe = hstrerror_probe_source.read_text(errors="replace")
    hstrerror_start = hstrerror_start_source.read_text(errors="replace")
    hstrerror_runner = hstrerror_runner_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/network/hstrerror.c",
        "LCTRANS_CUR",
        "static MESSAGES",
        "UNKNOWN_OFFSET",
        "read_volatile",
        'pub extern "C" fn hstrerror',
    ):
        if required not in hstrerror_text:
            errors.append(
                "libc/src/c_abi/x86_64/hstrerror.rs: selected static "
                f"fixed-profile message boundary is missing {required!r}"
            )
    for forbidden in (
        "static mut",
        "raw_syscall",
        "errno::",
        "gethostby",
        "getaddrinfo",
        "getnameinfo",
        "crabc_core",
        "crabc_mimalloc",
        "fn herror",
    ):
        if forbidden in hstrerror_text:
            errors.append(
                "libc/src/c_abi/x86_64/hstrerror.rs: selected static "
                f"fixed-profile message boundary must not select {forbidden!r}"
            )
    hstrerror_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            hstrerror_text,
        )
    )
    if hstrerror_exports != {"hstrerror"}:
        errors.append(
            "libc/src/c_abi/x86_64/hstrerror.rs: selected static artifact "
            "must export only hstrerror"
        )
    for required in (
        "#include <netdb.h>",
        "hstrerror_signature",
        "HOST_NOT_FOUND == 1",
        'check_message(-1, "Unknown error")',
        'check_message(NO_DATA, "Address not available")',
        "errno = E2BIG",
        "CRABC_HSTRERROR_FREESTANDING",
    ):
        if required not in hstrerror_probe:
            errors.append(
                "compat/x86_64/libc_hstrerror_probe.c: static fixed-profile "
                f"message regression is missing {required!r}"
            )
    for required in (
        "crabc_x86_64_hstrerror_probe",
        "mov $231, %eax",
    ):
        if required not in hstrerror_start:
            errors.append(
                "compat/x86_64/libc_hstrerror_start.S: static fixed-profile "
                f"message entry is missing {required!r}"
            )
    if "ARCH_SET_FS" in hstrerror_start:
        errors.append(
            "compat/x86_64/libc_hstrerror_start.S: fixed-profile message entry "
            "must not bootstrap TLS"
        )
    for required in (
        "hstrerror.lo",
        "static_c_abi_exports.txt",
        "-nostdlib -static",
        "-Wl,--no-undefined",
        "candidate unexpectedly selects TLS",
        "__h_errno_location",
        "gethostbyname",
        "getaddrinfo",
        "call|syscall",
        "for locale_name in C POSIX C.UTF-8",
    ):
        if required not in hstrerror_runner:
            errors.append(
                "compat/x86_64/run_libc_hstrerror.sh: static fixed-profile "
                f"message evidence is missing {required!r}"
            )
    if "--whole-archive" in hstrerror_runner:
        errors.append(
            "compat/x86_64/run_libc_hstrerror.sh: static fixed-profile "
            "message evidence must not force-link the whole archive"
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
        "src/string/strverscmp.c",
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
        "strverscmp",
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
        "strverscmp",
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

    error_strings_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "error_strings.rs"
    error_strings_text = error_strings_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/errno/__strerror.h",
        "src/errno/strerror.c",
        "src/string/strerror_r.c",
        "No error information",
        "weak_alias(strerror_r, __xpg_strerror_r)",
        ".weak __xpg_strerror_r",
        ".set __xpg_strerror_r, strerror_r",
        "immutable",
        "allocation-free",
        "negative indices",
    ):
        if required not in error_strings_text:
            errors.append(
                "libc/src/c_abi/x86_64/error_strings.rs: selected static error-string "
                f"boundary is missing {required!r}"
            )
    error_string_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            error_strings_text,
        )
    )
    if error_string_exports != {"strerror", "strerror_r"}:
        errors.append(
            "libc/src/c_abi/x86_64/error_strings.rs: selected static error-string "
            "artifact must export only strong strerror and strerror_r functions"
        )
    error_string_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*strerror_r",\s*$',
            error_strings_text,
        )
    )
    if error_string_aliases != {"__xpg_strerror_r"}:
        errors.append(
            "libc/src/c_abi/x86_64/error_strings.rs: selected static error-string "
            "artifact must retain only the weak same-address __xpg_strerror_r alias"
        )

    locale_error_strings_source = (
        ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_error_strings.rs"
    )
    locale_error_strings_text = locale_error_strings_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/errno/strerror.c::__strerror_l",
        "weak_alias(__strerror_l, strerror_l)",
        ".weak strerror_l",
        ".set strerror_l, __strerror_l",
        "C/POSIX/C.UTF-8",
        "LC_GLOBAL_LOCALE",
        "message catalogs",
        "locale database",
        "public x86 support",
    ):
        if required not in locale_error_strings_text:
            errors.append(
                "libc/src/c_abi/x86_64/locale_error_strings.rs: fixed-profile "
                f"locale-error-string boundary is missing {required!r}"
            )
    locale_error_string_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            locale_error_strings_text,
        )
    )
    if locale_error_string_exports != {"__strerror_l"}:
        errors.append(
            "libc/src/c_abi/x86_64/locale_error_strings.rs: fixed-profile "
            "artifact must export only strong __strerror_l"
        )
    locale_error_string_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*__strerror_l",\s*$',
            locale_error_strings_text,
        )
    )
    if locale_error_string_aliases != {"strerror_l"}:
        errors.append(
            "libc/src/c_abi/x86_64/locale_error_strings.rs: fixed-profile "
            "artifact must retain strerror_l as the weak same-address alias"
        )

    strsignal_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "strsignal.rs"
    strsignal_text = strsignal_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/string/strsignal.c",
        "SIGHUP..SIGSYS == 1..31",
        "MAX_SIGNAL_NUMBER: c_int = 64",
        "RT32",
        "RT64",
        "LCTRANS_CUR",
        "general diagnostics",
    ):
        if required not in strsignal_text:
            errors.append(
                "libc/src/c_abi/x86_64/strsignal.rs: selected static strsignal "
                f"boundary is missing {required!r}"
            )
    strsignal_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            strsignal_text,
        )
    )
    if strsignal_exports != {"strsignal"}:
        errors.append(
            "libc/src/c_abi/x86_64/strsignal.rs: selected static strsignal "
            "artifact must export only strsignal"
        )
    for forbidden in ("crabc_core", "crabc_mimalloc", "alloc::", "static mut", "use super"):
        if forbidden in strsignal_text:
            errors.append(
                "libc/src/c_abi/x86_64/strsignal.rs: selected static strsignal "
                f"boundary selects forbidden runtime seam {forbidden!r}"
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

    locale_ctype_source = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "locale_ctype.rs"
    locale_ctype_text = locale_ctype_source.read_text(errors="replace")
    for required in (
        "musl 1.2.6 release commit",
        "src/ctype/__ctype_b_loc.c",
        "src/ctype/__ctype_tolower_loc.c",
        "src/ctype/__ctype_toupper_loc.c",
        "384-entry table",
        "network-byte-order",
        "-128..=255",
        "not public `<ctype.h>`",
        "locale database",
        "public x86 support",
    ):
        if required not in locale_ctype_text:
            errors.append(
                "libc/src/c_abi/x86_64/locale_ctype.rs: musl-compatible ctype "
                f"locator boundary is missing {required!r}"
            )
    locale_ctype_exports = set(
        re.findall(
            r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
            locale_ctype_text,
        )
    )
    expected_locale_ctype_exports = {
        "__ctype_b_loc",
        "__ctype_tolower_loc",
        "__ctype_toupper_loc",
    }
    if locale_ctype_exports != expected_locale_ctype_exports:
        errors.append(
            "libc/src/c_abi/x86_64/locale_ctype.rs: musl-compatible ctype "
            "locator artifact must export only its named ABI locators"
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
        auxv_observation_text,
        startup_security_text,
        secure_environment_text,
        shared_getopt_text,
        fenv_text,
        signal_control_text,
        signal_realtime_max_text,
        sched_getscheduler_text,
        signal_alarm_text,
        signal_pending_text,
        signal_set_mutation_text,
        signal_execution_text,
        signal_set_isempty_text,
        signal_set_binary_text,
        signal_pause_text,
        pthread_identity_text,
        pthread_create_join_text,
        pthread_mutex_text,
        pthread_cond_text,
        pthread_rwlock_text,
        c11_thread_lifecycle_text,
        c11_sync_text,
        pthread_once_text,
        pthread_tsd_text,
        termios_control_text,
        ctermid_text,
        gethostid_text,
        gettid_text,
        isatty_text,
        tcgetpgrp_text,
        tcsetpgrp_text,
        process_context_text,
        login_name_text,
        child_reaping_text,
        immediate_termination_text,
        posix_exit_text,
        bsearch_text,
        linear_search_text,
        qsort_text,
        callback_algorithms_text,
        search_tree_text,
        search_hash_table_text,
        gettext_catalog_text,
        clock_gettime_text,
        difftime_text,
        gmtime_r_text,
        timegm_text,
        sched_getcpu_text,
        sched_yield_text,
        clock_nanosleep_text,
        memory_mapping_text,
        memory_sync_text,
        memory_locking_text,
        memfd_create_text,
        nanosleep_text,
        descriptor_entry_text,
        filesystem_access_text,
        mktemp_text,
        descriptor_control_text,
        descriptor_io_text,
        process_resources_text,
        readiness_waits_text,
        socket_transport_text,
        socket_messages_text,
        inet_address_text,
        inet_ntoa_text,
        inet_classful_text,
        hstrerror_text,
        byte_strings_text,
        memccpy_text,
        strsep_text,
        random_entropy_text,
        memory_search_text,
        string_copy_text,
        error_strings_text,
        locale_error_strings_text,
        strsignal_text,
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
            for source in (
                memory_text,
                legacy_memory_text,
                mempcpy_text,
                fenv_text,
                setjmp_text,
                descriptor_control_text,
            )
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
    auxv_observation_aliases = set(
        re.findall(
            r'(?m)^\s*"\.set\s+(\w+)\s*,\s*__getauxval",\s*$',
            auxv_observation_text,
        )
    )
    if auxv_observation_aliases != {"getauxval"}:
        errors.append(
            "libc/src/c_abi/x86_64/auxv_observation.rs: selected static "
            "artifact must retain getauxval as the musl same-address assembler alias"
        )
    pthread_rwlock_public_aliases = {public for public, _hidden in pthread_rwlock_aliases}
    process_global_data_exports = set(
        re.findall(
            r"(?m)^pub\s+static\s+mut\s+(\w+)\s*:",
            shared_getopt_text,
        )
    )
    expected_process_global_data_exports = {
        "optarg",
        "optind",
        "opterr",
        "optopt",
        "__optpos",
        "__optreset",
        "optreset",
        "__progname",
        "__progname_full",
        "program_invocation_name",
        "program_invocation_short_name",
    }
    if process_global_data_exports != expected_process_global_data_exports:
        errors.append(
            "libc/src/getopt_exports.rs: selected program-name/getopt data "
            "exports drifted"
        )
    exports = (
        rust_exports
        | assembly_exports
        | callback_algorithms_aliases
        | filesystem_access_aliases
        | inet_address_aliases
        | error_string_aliases
        | locale_error_string_aliases
        | timestamp_aliases
        | auxv_observation_aliases
        | pthread_rwlock_public_aliases
        | pthread_identity_exports
        | process_global_data_exports
        | in6addr_any_exports
        | in6addr_loopback_exports
    )
    expected_exports = {
        "__errno_location",
        "__crabc_x86_static_tls_bootstrap",
        "__getauxval",
        "getauxval",
        "secure_getenv",
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
        "bcopy",
        "bzero",
        "memccpy",
        "mempcpy",
        "strsep",
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
        "sigisemptyset",
        "sigandset",
        "sigorset",
        "sigprocmask",
        "sigpending",
        "__libc_current_sigrtmin",
        "__libc_current_sigrtmax",
        "sched_getscheduler",
        "alarm",
        "kill",
        "killpg",
        "raise",
        "sigqueue",
        "sigtimedwait",
        "sigwaitinfo",
        "sigwait",
        "sigpause",
        "pthread_create",
        "pthread_detach",
        "pthread_exit",
        "pthread_join",
        "pthread_key_create",
        "pthread_key_delete",
        "pthread_getspecific",
        "pthread_setspecific",
        "pthread_mutex_destroy",
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_trylock",
        "pthread_mutex_unlock",
        "pthread_rwlockattr_init",
        "pthread_rwlockattr_destroy",
        "pthread_rwlockattr_setpshared",
        "pthread_rwlockattr_getpshared",
        "pthread_rwlock_init",
        "pthread_rwlock_destroy",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_tryrdlock",
        "pthread_rwlock_timedrdlock",
        "pthread_rwlock_wrlock",
        "pthread_rwlock_trywrlock",
        "pthread_rwlock_timedwrlock",
        "pthread_rwlock_unlock",
        "__pthread_rwlock_rdlock",
        "__pthread_rwlock_tryrdlock",
        "__pthread_rwlock_timedrdlock",
        "__pthread_rwlock_wrlock",
        "__pthread_rwlock_trywrlock",
        "__pthread_rwlock_timedwrlock",
        "__pthread_rwlock_unlock",
        "pthread_once",
        "pthread_cond_broadcast",
        "pthread_cond_destroy",
        "pthread_cond_init",
        "pthread_cond_signal",
        "pthread_cond_wait",
        "thrd_create",
        "thrd_detach",
        "thrd_exit",
        "thrd_join",
        "thrd_sleep",
        "tss_create",
        "tss_delete",
        "tss_get",
        "tss_set",
        "mtx_init",
        "mtx_destroy",
        "mtx_lock",
        "mtx_trylock",
        "mtx_unlock",
        "cnd_init",
        "cnd_destroy",
        "cnd_wait",
        "cnd_signal",
        "cnd_broadcast",
        "call_once",
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
        "ctermid",
        "gethostid",
        "gettid",
        "isatty",
        "tcgetpgrp",
        "tcsetpgrp",
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
        "difftime",
        "gmtime_r",
        "timegm",
        "sched_getcpu",
        "sched_yield",
        "clock_nanosleep",
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        "posix_madvise",
        "mincore",
        "msync",
        "mlock",
        "munlock",
        "mlock2",
        "memfd_create",
        "nanosleep",
        "open",
        "openat",
        "creat",
        "access",
        "faccessat",
        "euidaccess",
        "eaccess",
        "mktemp",
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
        "setsockopt",
        "getsockopt",
        "sendmsg",
        "recvmsg",
        "sendmmsg",
        "recvmmsg",
        "sockatmark",
        "in6addr_any",
        "in6addr_loopback",
        "inet_pton",
        "inet_ntop",
        "__inet_aton",
        "inet_aton",
        "inet_addr",
        "inet_ntoa",
        "inet_lnaof",
        "inet_makeaddr",
        "hstrerror",
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
        "strverscmp",
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
        "strerror",
        "strerror_r",
        "__xpg_strerror_r",
        "__strerror_l",
        "strerror_l",
        "strsignal",
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
        "getlogin",
        "getlogin_r",
        "_Exit",
        "__cxa_atexit",
        "atexit",
        "__funcs_on_exit",
        "__cxa_finalize",
        "_exit",
        "exit",
        "__libc_start_main",
        "__optpos",
        "__optreset",
        "__posix_getopt",
        "__progname",
        "__progname_full",
        "getopt",
        "getopt_long",
        "getopt_long_only",
        "optarg",
        "opterr",
        "optind",
        "optopt",
        "optreset",
        "program_invocation_name",
        "program_invocation_short_name",
        "bsearch",
        "lfind",
        "lsearch",
        "__qsort_r",
        "qsort",
        "qsort_r",
        "__tsearch_balance",
        "tdelete",
        "tdestroy",
        "tfind",
        "tsearch",
        "twalk",
        "hcreate",
        "hcreate_r",
        "hdestroy",
        "hdestroy_r",
        "hsearch",
        "hsearch_r",
        "bind_textdomain_codeset",
        "bindtextdomain",
        "catclose",
        "catgets",
        "catopen",
        "dcgettext",
        "dcngettext",
        "dgettext",
        "dngettext",
        "gettext",
        "ngettext",
        "textdomain",
        "rust_eh_personality",
    }
    if exports != expected_exports:
        errors.append(
            "libc/src/c_abi/x86_64: selected static archive must export only its "
            "stat, credential, errno, bootstrap-memory/fenv/continuation, simple "
            "signal-control, separate realtime-minimum/realtime-maximum bridges, one pure GNU signal-set predicate, paired GNU binary set-operation leaf, and a three-symbol POSIX signal-set mutation leaf, bounded process-signal execution, and one legacy single-signal pause wait, bounded pthread create/exit/join/detach initial-TLS worker, its private selected-main/worker pthread-key/C11-TSS lifecycle, private process-normal pthread mutexes and their musl private condition-variable handoff, the complete selected rwlock/attribute family with private-or-shared futex operation, plus the distinct C11 plain-sync adapter and normal-return pthread/C11 once state machine, its typed C11 create/exit/join/detach sibling, and pthread/C11 identity aliases, named termios-control, direct terminal-descriptor and foreground-group observations plus one named foreground-group assignment, historical ctermid pathname spelling, constant historical gethostid compatibility, direct GNU gettid observation, selected process-context, child-reaping, C11 immediate termination, callback algorithms, direct clock_gettime, binary64 difftime, caller-buffered fixed-UTC gmtime_r, fixed-UTC timegm, a GNU current-CPU raw-fallback observation leaf, a status-returning POSIX scheduler-yield leaf, caller-owned mapping-core, no-cancellation mapping synchronization, direct anonymous-memory descriptor creation, nanosleep, and clock_nanosleep, selected "
            "signal-control, separate realtime-minimum/realtime-maximum bridges, one historical SIGALRM interval-timer adapter leaf, one pure GNU signal-set predicate, paired GNU binary set-operation leaf, and a three-symbol POSIX signal-set mutation leaf, bounded process-signal execution, and one legacy single-signal pause wait, bounded pthread create/exit/join/detach initial-TLS worker, its private selected-main/worker pthread-key/C11-TSS lifecycle, private process-normal pthread mutexes and their musl private condition-variable handoff, the complete selected rwlock/attribute family with private-or-shared futex operation, plus the distinct C11 plain-sync adapter and normal-return pthread/C11 once state machine, its typed C11 create/exit/join/detach sibling, and pthread/C11 identity aliases, named termios-control, direct terminal-descriptor and foreground-group observations plus one named foreground-group assignment, historical ctermid pathname spelling, constant historical gethostid compatibility, selected process-context, child-reaping, C11 immediate termination, callback algorithms, direct clock_gettime, binary64 difftime, caller-buffered fixed-UTC gmtime_r, fixed-UTC timegm, a status-returning POSIX scheduler-yield leaf, caller-owned mapping-core, no-cancellation mapping synchronization, direct anonymous-memory descriptor creation, nanosleep, and clock_nanosleep, selected "
            "POSIX _exit forwarding, descriptor-entry, selected filesystem-access, bounded descriptor-control, timestamp updates, and descriptor-I/O, selected process-resources, selected readiness/signal-waits, "
            "selected socket transport and selected socket-message/options, selected system-observation, selected UTS-identity, "
            "selected numeric-address codecs, immutable IPv6 unspecified/loopback address data objects, and legacy classful IPv4 arithmetic, fixed-profile h_errno message text, byte-string, legacy-memory adapters, source-backed memccpy/mempcpy, caller-buffer strsep, random-entropy, memory-search, C-string-copy, immutable error-string, "
            "fixed-C-locale ctype, integer-arithmetic, integer-parsing, intmax-arithmetic, credential-observation, and "
            "raw auxiliary-vector observation, startup-derived secure-environment, and environment-backed login-name observation, find-first-set, startup-published program names, short/GNU-long "
            "getopt state and aliases, standalone linear search, callback-tree/hash-table search, and the "
            "bounded no-catalog gettext/message-catalog ABI, "
            "and abort-personality surfaces"
        )
    for source_name, source_text in (
        ("static_c_abi.rs", static_root_text),
        ("stat_compat.rs", stat_text),
        ("credentials.rs", credentials_text),
        ("credential_observation.rs", credential_observation_text),
        ("auxv_observation.rs", auxv_observation_text),
        ("startup_security.rs", startup_security_text),
        ("secure_environment.rs", secure_environment_text),
        ("login_name.rs", login_name_text),
        ("errno.rs", errno_text),
        ("static_startup.rs", static_startup_text),
        ("process_globals.rs", process_globals_text),
        ("getopt_exports.rs", shared_getopt_text),
        ("memory.rs", memory_text),
        ("legacy_memory.rs", legacy_memory_text),
        ("memccpy.rs", memccpy_text),
        ("mempcpy.rs", mempcpy_text),
        ("strsep.rs", strsep_text),
        ("fenv.rs", fenv_text),
        ("setjmp.rs", setjmp_text),
        ("signal_foundation.rs", signal_foundation_text),
        ("signal_control.rs", signal_control_text),
        ("signal_realtime_max.rs", signal_realtime_max_text),
        ("signal_realtime_min.rs", signal_realtime_min_text),
        ("sched_getscheduler.rs", sched_getscheduler_text),
        ("signal_alarm.rs", signal_alarm_text),
        ("signal_pending.rs", signal_pending_text),
        ("signal_set_mutation.rs", signal_set_mutation_text),
        ("signal_execution.rs", signal_execution_text),
        ("signal_set_isempty.rs", signal_set_isempty_text),
        ("signal_set_binary.rs", signal_set_binary_text),
        ("signal_pause.rs", signal_pause_text),
        ("atomic.rs", atomic_text),
        ("pthread_identity.rs", pthread_identity_text),
        ("pthread_create_join.rs", pthread_create_join_text),
        ("pthread_mutex.rs", pthread_mutex_text),
        ("pthread_cond.rs", pthread_cond_text),
        ("pthread_rwlock.rs", pthread_rwlock_text),
        ("c11_thread_lifecycle.rs", c11_thread_lifecycle_text),
        ("c11_sync.rs", c11_sync_text),
        ("pthread_once.rs", pthread_once_text),
        ("pthread_tsd.rs", pthread_tsd_text),
        ("termios_control.rs", termios_control_text),
        ("ctermid.rs", ctermid_text),
        ("gettid.rs", gettid_text),
        ("isatty.rs", isatty_text),
        ("tcgetpgrp.rs", tcgetpgrp_text),
        ("tcsetpgrp.rs", tcsetpgrp_text),
        ("mktemp.rs", mktemp_text),
        ("process_context.rs", process_context_text),
        ("child_reaping.rs", child_reaping_text),
        ("immediate_termination.rs", immediate_termination_text),
        ("posix_exit.rs", posix_exit_text),
        ("bsearch.rs", bsearch_text),
        ("linear_search.rs", linear_search_text),
        ("qsort.rs", qsort_text),
        ("callback_algorithms.rs", callback_algorithms_text),
        ("search_tree_intrusive.rs", search_tree_text),
        ("search_hash_table.rs", search_hash_table_text),
        ("gettext_catalog.rs", gettext_catalog_text),
        ("clock_gettime.rs", clock_gettime_text),
        ("sched_getcpu.rs", sched_getcpu_text),
        ("sched_yield.rs", sched_yield_text),
        ("clock_nanosleep.rs", clock_nanosleep_text),
        ("memory_mapping.rs", memory_mapping_text),
        ("memory_sync.rs", memory_sync_text),
        ("memory_locking.rs", memory_locking_text),
        ("memfd_create.rs", memfd_create_text),
        ("nanosleep.rs", nanosleep_text),
        ("descriptor_entry.rs", descriptor_entry_text),
        ("filesystem_access.rs", filesystem_access_text),
        ("descriptor_control.rs", descriptor_control_text),
        ("timestamp_updates.rs", timestamp_text),
        ("descriptor_io.rs", descriptor_io_text),
        ("process_resources.rs", process_resources_text),
        ("readiness_waits.rs", readiness_waits_text),
        ("socket_transport.rs", socket_transport_text),
        ("socket_messages.rs", socket_messages_text),
        ("in6addr_any.rs", in6addr_any_text),
        ("in6addr_loopback.rs", in6addr_loopback_text),
        ("inet_address.rs", inet_address_text),
        ("inet_ntoa.rs", inet_ntoa_text),
        ("inet_classful.rs", inet_classful_text),
        ("hstrerror.rs", hstrerror_text),
        ("random_entropy.rs", random_entropy_text),
        ("memory_search.rs", memory_search_text),
        ("string_copy.rs", string_copy_text),
        ("error_strings.rs", error_strings_text),
        ("locale_error_strings.rs", locale_error_strings_text),
        ("strsignal.rs", strsignal_text),
        ("ctype.rs", ctype_text),
        ("locale_ctype.rs", locale_ctype_text),
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
    check_x86_installed_header_tree_closure(errors)
    check_x86_dirent_header_abi(errors)
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
