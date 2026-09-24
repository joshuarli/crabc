#!/usr/bin/env python3
"""Reject repository-shape regressions that normal compilation cannot see."""

from __future__ import annotations

import os
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
# one caller-buffer `strsep` token-mutation leaf, one caller-owned `rand_r`
# PRNG-state transform, stateless `pthread_setconcurrency`, fixed
# `pthread_getconcurrency`, and raw-record `pthread_mutexattr_settype` leaves, selected C-string
# copy/concatenation, fixed-C-
# locale ctype and the separately bounded named-locale/multibyte conversion
# artifact, scalar integer arithmetic, complete integer parsing, intmax
# arithmetic, and find-first-set, direct POSIX clock_gettime, bounded clock
# observation, no-cancellation mapping synchronization, direct anonymous-memory
# descriptor creation, nanosleep, one microsecond usleep adapter, sleep, and
# clock_nanosleep, descriptor entry, selected
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
    Path("libc/src/c_abi/x86_64/personality.rs"),
    Path("libc/src/c_abi/x86_64/setfsgid.rs"),
    Path("libc/src/c_abi/x86_64/setfsuid.rs"),
    Path("libc/src/c_abi/x86_64/child_reaping.rs"),
    Path("libc/src/c_abi/x86_64/wait_extensions.rs"),
    Path("libc/src/c_abi/x86_64/clock_gettime.rs"),
    Path("libc/src/c_abi/x86_64/clock_adjtime.rs"),
    Path("libc/src/c_abi/x86_64/clock_settime.rs"),
    Path("libc/src/c_abi/x86_64/timer_getoverrun.rs"),
    Path("libc/src/c_abi/x86_64/timer_delete.rs"),
    Path("libc/src/c_abi/x86_64/timer_gettime.rs"),
    Path("libc/src/c_abi/x86_64/timer_settime.rs"),
    Path("libc/src/c_abi/x86_64/difftime.rs"),
    Path("libc/src/c_abi/x86_64/gmtime_r.rs"),
    Path("libc/src/c_abi/x86_64/timegm.rs"),
    Path("libc/src/c_abi/x86_64/time_observation.rs"),
    Path("libc/src/c_abi/x86_64/clock_nanosleep.rs"),
    Path("libc/src/c_abi/x86_64/nanosleep.rs"),
    Path("libc/src/c_abi/x86_64/usleep.rs"),
    Path("libc/src/c_abi/x86_64/sleep.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_entry.rs"),
    Path("libc/src/c_abi/x86_64/filesystem_access.rs"),
    Path("libc/src/c_abi/x86_64/mktemp.rs"),
    # The common musl __randname translation remains private, while the
    # allocator-backed tmpnam/tempnam pair is an independently evidenced
    # feature. Neither exact admission widens the default static archive or
    # turns racy pathname generation into a general filesystem runtime.
    Path("libc/src/c_abi/x86_64/temp_name_random.rs"),
    Path("libc/src/c_abi/x86_64/temporary_names.rs"),
    Path("libc/src/c_abi/x86_64/descriptor_control.rs"),
    Path("libc/src/c_abi/x86_64/ioctl.rs"),
    Path("libc/src/c_abi/x86_64/immediate_termination.rs"),
    Path("libc/src/c_abi/x86_64/posix_exit.rs"),
    Path("libc/src/c_abi/x86_64/posix_spawnattr_init.rs"),
    Path("libc/src/c_abi/x86_64/posix_spawnattr_getpgroup.rs"),
    Path("libc/src/c_abi/x86_64/posix_spawnattr_getschedparam.rs"),
    Path("libc/src/c_abi/x86_64/posix_spawnattr_getschedpolicy.rs"),
    # These exact spawn-attribute signal-field entries are separately
    # evidenced; admitting the leaf does not select spawn execution or a
    # directory-wide process-runtime boundary.
    Path("libc/src/c_abi/x86_64/posix_spawnattr_signal_fields.rs"),
    Path("libc/src/c_abi/x86_64/posix_spawnattr_setschedparam.rs"),
    # This opt-in provider owns only the six allocating file-action records;
    # initialization remains the separately evidenced dependency-free leaf.
    Path("libc/src/c_abi/x86_64/posix_spawn_file_actions.rs"),
    Path("libc/src/c_abi/x86_64/bsearch.rs"),
    Path("libc/src/c_abi/x86_64/linear_search.rs"),
    Path("libc/src/c_abi/x86_64/intrusive_queue.rs"),
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
    Path("libc/src/c_abi/x86_64/l64a.rs"),
    # The decoder half of musl's shared a64l.c source is independently
    # feature-gated and evidenced; admitting this exact file does not widen
    # the frozen default l64a source split or create a directory exception.
    Path("libc/src/c_abi/x86_64/a64l.rs"),
    # The stateless legacy netdb setter pair is independently feature-gated.
    # This exact source admission preserves the default resolver-free archive.
    Path("libc/src/c_abi/x86_64/sethostent.rs"),
    # The frozen legacy.misc capability is separately feature-gated and
    # independently evidenced.  This exact admission is not a default-root
    # or directory-wide legacy-runtime exception.
    Path("libc/src/c_abi/x86_64/legacy_misc.rs"),
    # The inert historical DES ABI names are shared by the legacy.misc feature
    # and the owned-static product without admitting fmtmsg or a cipher.
    Path("libc/src/c_abi/x86_64/legacy_des_compat.rs"),
    Path("libc/src/c_abi/x86_64/math_complex.rs"),
    Path("libc/src/c_abi/x86_64/complex_projection.rs"),
    Path("libc/src/c_abi/x86_64/math_complex_complete.rs"),
    Path("libc/src/c_abi/x86_64/elementary_sqrt.rs"),
    Path("libc/src/c_abi/x86_64/fenv_rounding.rs"),
    Path("libc/src/c_abi/x86_64/math_bit_sign.rs"),
    Path("libc/src/c_abi/x86_64/math_trunc.rs"),
    Path("libc/src/c_abi/x86_64/math_fmod.rs"),
    Path("libc/src/c_abi/x86_64/math_cbrt.rs"),
    Path("libc/src/c_abi/x86_64/math_exp2.rs"),
    Path("libc/src/c_abi/x86_64/math_expm1.rs"),
    Path("libc/src/c_abi/x86_64/math_log10.rs"),
    Path("libc/src/c_abi/x86_64/math_ceil.rs"),
    Path("libc/src/c_abi/x86_64/math_floor.rs"),
    Path("libc/src/c_abi/x86_64/math_round.rs"),
    Path("libc/src/c_abi/x86_64/math_log2.rs"),
    Path("libc/src/c_abi/x86_64/math_minmax.rs"),
    Path("libc/src/c_abi/x86_64/math_special.rs"),
    Path("libc/src/c_abi/x86_64/math_x87_extended.rs"),
    Path("libc/src/c_abi/x86_64/memccpy.rs"),
    Path("libc/src/c_abi/x86_64/aio_error.rs"),
    Path("libc/src/c_abi/x86_64/memory_search.rs"),
    Path("libc/src/c_abi/x86_64/memory_sync.rs"),
    Path("libc/src/c_abi/x86_64/memfd_create.rs"),
    Path("libc/src/c_abi/x86_64/fenv.rs"),
    Path("libc/src/c_abi/x86_64/foundation.rs"),
    Path("libc/src/c_abi/x86_64/memory.rs"),
    Path("libc/src/c_abi/x86_64/memccpy.rs"),
    Path("libc/src/c_abi/x86_64/mempcpy.rs"),
    Path("libc/src/c_abi/x86_64/strsep.rs"),
    Path("libc/src/c_abi/x86_64/wcswcs.rs"),
    Path("libc/src/c_abi/x86_64/legacy_memory.rs"),
    Path("libc/src/c_abi/x86_64/process_context.rs"),
    Path("libc/src/c_abi/x86_64/environment.rs"),
    Path("libc/src/c_abi/x86_64/environment_runtime.rs"),
    # The private x86-process-exec feature admits only its direct syscall,
    # selected-environment, PATH-search, and variadic-vector leaves. This
    # exact list does not select the wider process-control runtime.
    Path("libc/src/c_abi/x86_64/process_exec.rs"),
    Path("libc/src/c_abi/x86_64/process_exec_env.rs"),
    Path("libc/src/c_abi/x86_64/process_exec_path.rs"),
    Path("libc/src/c_abi/x86_64/process_exec_variadic.rs"),
    Path("libc/src/c_abi/x86_64/startup_security.rs"),
    Path("libc/src/c_abi/x86_64/issetugid.rs"),
    Path("libc/src/c_abi/x86_64/secure_environment.rs"),
    Path("libc/src/c_abi/x86_64/login_name.rs"),
    Path("libc/src/c_abi/x86_64/auxv_observation.rs"),
    Path("libc/src/c_abi/x86_64/process_globals.rs"),
    Path("libc/src/c_abi/x86_64/process_resources.rs"),
    Path("libc/src/c_abi/x86_64/sched_cpucount.rs"),
    Path("libc/src/c_abi/x86_64/sched_getcpu.rs"),
    Path("libc/src/c_abi/x86_64/sched_priority_bounds.rs"),
    Path("libc/src/c_abi/x86_64/sched_yield.rs"),
    Path("libc/src/c_abi/x86_64/posix_semaphore.rs"),
    Path("libc/src/c_abi/x86_64/mq_setattr.rs"),
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
    # The frozen process.signal reporting pair is a separate opt-in closure
    # over existing permanent stderr/errno/strsignal owners, not a default
    # static-archive or general diagnostics admission.
    Path("libc/src/c_abi/x86_64/signal_reporting.rs"),
    Path("libc/src/c_abi/x86_64/signal_sysv_helpers.rs"),
    Path("libc/src/c_abi/x86_64/signal_realtime_max.rs"),
    Path("libc/src/c_abi/x86_64/signal_realtime_min.rs"),
    Path("libc/src/c_abi/x86_64/sched_getscheduler.rs"),
    Path("libc/src/c_abi/x86_64/sched_setaffinity.rs"),
    Path("libc/src/c_abi/x86_64/signal_alarm.rs"),
    # This exact timer adapter is feature-gated; admitting its source path
    # preserves the frozen default static archive rather than widening it.
    Path("libc/src/c_abi/x86_64/signal_ualarm.rs"),
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
    Path("libc/src/c_abi/x86_64/tee.rs"),
    Path("libc/src/c_abi/x86_64/copy_file_range.rs"),
    Path("libc/src/c_abi/x86_64/splice.rs"),
    Path("libc/src/c_abi/x86_64/sync_file_range.rs"),
    Path("libc/src/c_abi/x86_64/grantpt.rs"),
    Path("libc/src/c_abi/x86_64/unlockpt.rs"),
    Path("libc/src/c_abi/x86_64/isatty.rs"),
    Path("libc/src/c_abi/x86_64/ttyname_r.rs"),
    Path("libc/src/c_abi/x86_64/tcgetpgrp.rs"),
    Path("libc/src/c_abi/x86_64/tcsetpgrp.rs"),
    Path("libc/src/c_abi/x86_64/getpass.rs"),
    Path("libc/src/c_abi/x86_64/thread_pointer.rs"),
    Path("libc/src/c_abi/x86_64/uts_identity.rs"),
    Path("libc/src/c_abi/x86_64/getloadavg.rs"),
    # Each later leaf below is separately admitted by a named static C ABI
    # boundary and native runner. Keep the exact paths explicit: this is not
    # a directory-wide exemption or a family-completion claim.
    Path("libc/src/c_abi/x86_64/basename.rs"),
    Path("libc/src/c_abi/x86_64/c32rtomb.rs"),
    Path("libc/src/c_abi/x86_64/uchar_stateful.rs"),
    Path("libc/src/c_abi/x86_64/fdim.rs"),
    Path("libc/src/c_abi/x86_64/float_parse.rs"),
    Path("libc/src/c_abi/x86_64/iconv.rs"),
    Path("libc/src/c_abi/x86_64/math_acosh.rs"),
    # This eight-entry musl assembly component is gated by the owned static
    # profile; admitting its exact source does not widen the default archive.
    Path("libc/src/c_abi/x86_64/owned_inverse_trig.rs"),
    # This six-entry musl scalar component is likewise selected only by the
    # owned static profile; its local scalbn closure cannot widen default ABI.
    Path("libc/src/c_abi/x86_64/math_scalar_completion.rs"),
    Path("libc/src/c_abi/x86_64/math_asinh.rs"),
    Path("libc/src/c_abi/x86_64/math_atanh.rs"),
    Path("libc/src/c_abi/x86_64/math_cos.rs"),
    Path("libc/src/c_abi/x86_64/math_cosh.rs"),
    Path("libc/src/c_abi/x86_64/math_elementary_long_double.rs"),
    Path("libc/src/c_abi/x86_64/math_exp.rs"),
    Path("libc/src/c_abi/x86_64/math_exp10.rs"),
    Path("libc/src/c_abi/x86_64/math_exp10f.rs"),
    # This fixed musl binary80 closure is feature-gated and evidenced as one
    # private capability slice; admitting its exact source does not widen the
    # default static C ABI root or the surrounding math family.
    Path("libc/src/c_abi/x86_64/math_long_double_completion.rs"),
    Path("libc/src/c_abi/x86_64/math_log.rs"),
    Path("libc/src/c_abi/x86_64/math_pow.rs"),
    Path("libc/src/c_abi/x86_64/math_sin.rs"),
    Path("libc/src/c_abi/x86_64/math_sincos.rs"),
    Path("libc/src/c_abi/x86_64/math_sinh.rs"),
    Path("libc/src/c_abi/x86_64/math_tan.rs"),
    Path("libc/src/c_abi/x86_64/math_tanh.rs"),
    Path("libc/src/c_abi/x86_64/pthread_affinity.rs"),
    Path("libc/src/c_abi/x86_64/pthread_attr.rs"),
    Path("libc/src/c_abi/x86_64/pthread_attr_lifecycle.rs"),
    Path("libc/src/c_abi/x86_64/pthread_atfork.rs"),
    Path("libc/src/c_abi/x86_64/pthread_barrierattr_pshared.rs"),
    # This exact complete barrier port remains a separately evidenced static
    # C-ABI slice; it does not admit general pthread or x86 runtime support.
    Path("libc/src/c_abi/x86_64/pthread_barrier.rs"),
    Path("libc/src/c_abi/x86_64/pthread_cancel.rs"),
    Path("libc/src/c_abi/x86_64/pthread_condattr_clock.rs"),
    Path("libc/src/c_abi/x86_64/pthread_condattr_pshared.rs"),
    Path("libc/src/c_abi/x86_64/pthread_cpuclock.rs"),
    Path("libc/src/c_abi/x86_64/pthread_getconcurrency.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutex_prioceiling_query.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutexattr_protocol_query.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutexattr_pshared_query.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutexattr_robust_query.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutexattr_type_query.rs"),
    Path("libc/src/c_abi/x86_64/pthread_mutexattr_type_setter.rs"),
    Path("libc/src/c_abi/x86_64/pthread_name.rs"),
    Path("libc/src/c_abi/x86_64/pthread_setconcurrency.rs"),
    Path("libc/src/c_abi/x86_64/pthread_spin_init.rs"),
    # The feature-gated lock/trylock/unlock port is separately evidenced and
    # retains the frozen default spinlock archive boundary.
    Path("libc/src/c_abi/x86_64/pthread_spin_operations.rs"),
    Path("libc/src/c_abi/x86_64/rand_r.rs"),
    Path("libc/src/c_abi/x86_64/lrand48.rs"),
    Path("libc/src/c_abi/x86_64/stack_chk_fail.rs"),
    Path("libc/src/c_abi/x86_64/stdio_format_scan.rs"),
    Path("libc/src/c_abi/x86_64/stdio_standard.rs"),
    Path("libc/src/c_abi/x86_64/stateful_byte_strings.rs"),
    Path("libc/src/c_abi/x86_64/strtok.rs"),
    Path("libc/src/c_abi/x86_64/wide_character.rs"),
}
# These private loader/libc TLS foundations are compiled only through their
# isolated freestanding consumer root plus fixed and bounded-general
# initial-TLS producers. They are deliberately not admitted by
# `static_c_abi.rs`, whose no-PT_INTERP Initial TLS v1 contract has no loader
# record or dynamic registry to consume. Keeping this separate from the
# selected static C ABI allowlist prevents the structural ratchet from implying
# static-artifact admission or an x86 dynamic-runtime promotion.
X86_RUNTIME_FOUNDATION_LOADER_LIBC_SOURCES = {
    Path("ldso/src/x86_64_initial_tls_registry.rs"),
    Path("ldso/src/x86_64_general_initial_tls_runtime_v1_source_root.rs"),
    Path("ldso/src/x86_64_dynamic_main_thread_runtime_v1_source_root.rs"),
    Path("libc/src/c_abi/x86_64/loader_tls_runtime_v1.rs"),
    Path("libc/src/c_abi/x86_64/loader_tls_runtime_v1_source_root.rs"),
    Path("libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1.rs"),
    Path("libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_source_root.rs"),
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
REMOVED_ROOT_LOADER = re.compile(r"src/loader_core\.rs|(?<![-\w])root[- ]loader|loader helper", re.IGNORECASE)
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


# Ignored build, scratch, and lane-worktree trees are not source; `.work` holds
# whole lane checkouts and container-owned output.
PRUNED_DIRECTORIES = frozenset({".git", ".work", "target"})


def text_files() -> list[Path]:
    files: list[Path] = []
    for directory, subdirectories, names in os.walk(ROOT):
        relative_directory = Path(directory).relative_to(ROOT)
        subdirectories[:] = [
            name for name in subdirectories
            if name not in PRUNED_DIRECTORIES and relative_directory / name != Path("compat/reports")
        ]
        for name in names:
            path = Path(directory) / name
            if path.suffix in TEXT_SUFFIXES and path.is_file():
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
        # A test that also builds through crabc_cc() uses musl-gcc only for its
        # oracle side; only musl-only tests need an explicit oracle listing.
        uses_candidate_driver = "test_support::crabc_cc()" in text
        if uses_musl_driver and not uses_candidate_driver and path.name not in MUSL_ORACLE_C_TESTS:
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


    # POSIX timers have their own separately-proved ownership boundary below;
    # do not let this older process-global interval-timer check govern it.


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
        if set(dependencies) != {"chacha20", "crabc-core", "loom", "zeroize"}:
            errors.append(
                "crabc-mimalloc/Cargo.toml: dependencies must be exactly "
                "chacha20, crabc-core, optional loom, and zeroize"
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
        loom = dependencies.get("loom", {})
        if (
            not isinstance(loom, dict)
            or loom.get("version") != "=0.7.2"
            or loom.get("default-features") is not False
            or loom.get("features", [])
            or loom.get("optional") is not True
        ):
            errors.append(
                "crabc-mimalloc/Cargo.toml: loom must remain optional, pinned to =0.7.2, "
                "with defaults disabled and no features"
            )
        if mimalloc_manifest.get("dev-dependencies", {}):
            errors.append(
                "crabc-mimalloc/Cargo.toml: Loom must not be an unconditional dev-dependency"
            )
        features = mimalloc_manifest.get("features", {})
        if features.get("loom") != ["dep:loom"]:
            errors.append(
                "crabc-mimalloc/Cargo.toml: the loom feature must activate only dep:loom"
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
    check_root_c_link_boundaries(errors)

    for source_root in PRODUCTION_SOURCE:
        for path in source_root.rglob("*.rs"):
            relative = path.relative_to(ROOT)
            for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
                if RISC_V_ARCH_BRANCH.search(line):
                    errors.append(f"{relative}:{line_number}: inactive RISC-V architecture branch")

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
