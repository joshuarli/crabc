//! Selected static Linux/x86-64 C ABI composition.
//!
//! This target root owns one dependency-free `libc.a` artifact containing the
//! independently evidenced metadata and credential verticals alongside the x86
//! bulk-memory, floating-environment, continuation, binary32/binary64/x87
//! classification/sign, complex accessor/conjugation/projection, hardware
//! square root, selected fenv-sensitive rounding, and one selected x87 binary80
//! extended-math block as real C bootstrap leaves, plus the complete private
//! `math.special` error/Bessel/gamma/decomposition/stepping/scaling/conversion
//! block with binary80 preserved end to end, plus deliberately narrow simple
//! signal action/mask, bounded process-signal execution, and fixed-minimum
//! alternate signal-stack behavior, one default-attribute
//! create/explicit-exit/join/detach worker and its typed C11
//! `thrd_create`/`thrd_exit`/`thrd_join`/`thrd_detach`/`thrd_sleep` sibling, a
//! process-private normal `pthread_mutex_*` block and its paired private
//! process-private condition-variable handoff, a complete selected
//! `pthread_rwlock_*`/`pthread_rwlockattr_*` block with private and
//! process-shared futex operation, plus a distinct C11 plain mutex/condition
//! adapter, a private 128-key pthread/C11 TSD lifecycle for
//! the selected main and worker paths, and normal-return `pthread_once`/C11
//! `call_once` state machine over those private engines, all backed by the
//! private Static Initial TLS v1 final-executable template, plus bounded weak `pthread_self`/
//! `pthread_equal` and `thrd_current`/`thrd_equal` identity aliases,
//! one single-threaded fixed-capacity `pthread_atfork`/`fork` transition that
//! can compose the existing bounded ordinary-exit callback block in its child,
//! termios-control, selected process-context, bounded process-environment,
//! child-reaping, selected
//! descriptor-entry, selected filesystem-access, fixed Linux `lchmod`
//! unsupported compatibility, bounded fcntl status-control
//! and nonblocking record-lock boundaries, advisory whole-file flock, bounded
//! regular-file sendfile transfer, mode-zero POSIX range allocation,
//! descriptor advice, timestamp updates, descriptor-I/O, vector-I/O, and
//! selected process-resources, selected readiness/signal-waits, and selected
//! system-configuration, caller-owned mapping-core, per-range memory locking,
//! direct no-cancellation mapping synchronization, direct anonymous-memory
//! descriptor creation, system-observation,
//! processor/page-count system-information, UTS-namespace identity, basic socket-transport,
//! padded socket messages/options,
//! deterministic numeric `netdb.h` address/service translation and result
//! ownership without resolver configuration, hosts, or DNS,
//! credential-observation, integer-arithmetic, integer-parsing, selected
//! C-locale binary32/binary64/x87-binary80 floating parsing plus complete
//! fixed-C/POSIX/C.UTF-8 narrow/wide numeric parsing, legacy decimal
//! conversion, and suboption parsing, named
//! C/POSIX/C.UTF-8 multibyte state, fixed UTF/ASCII `iconv` conversion, and
//! allocation-free wide strings/memory, Unicode classification/simple case,
//! code-point collation, and terminal-column width,
//! bounded permanent stdin/stdout/stderr byte/block I/O with explicit flushing, selected
//! allocation-free byte-buffer formatting and NUL-string scanning,
//! plus one fixed
//! regular-file pathname stream/position-buffering slot, intmax-arithmetic,
//! find-first-set, C11 immediate-termination, a bounded private static
//! startup/ordinary-exit lifecycle, startup-published program-name globals
//! and option parsing, callback-algorithms, POSIX `nanosleep`
//! and `clock_nanosleep`, and direct clock-observation artifacts, plus one
//! bounded System V
//! message-queue/shared-memory artifact and one bounded event-descriptor
//! artifact, one bounded pathname-mutation/lifecycle artifact, and one
//! bounded directory-stream/raw-directory artifact.
//! The independently selected extended-attribute leaf owns the complete
//! direct Linux path, no-follow-path, and descriptor xattr syscall family;
//! it keeps values and lists caller-owned and does not select ACL policy.
//! It deliberately shares only the raw
//! Linux syscall register boundary, one initial-TLS C `errno` slot, and the
//! private Static Initial TLS v1 owner. The
//! archive is not `libc.so`,
//! a general C runtime, a CRT, a general pthread/TLS lifecycle, a dynamic-TLS
//! implementation, a loader, or a sysroot. Its private static startup owns
//! only bounded no-allocation `atexit` callbacks. Its permanent-standard-stream
//! leaf owns explicit `fflush` only; neither that leaf nor this lifecycle owns
//! input flushing, ordinary-exit stdio flushing, C++/DSO destruction, or a
//! concurrent process-exit protocol. Its pathname sibling owns only one
//! externally serialized `fopen("r")`/`fopen("w+")` slot with caller-buffered
//! full buffering and logical positions; it is not stream allocation or
//! general stdio. The pthread artifacts are
//! intentionally bounded to null-attribute workers that return normally or
//! use their selected explicit-exit path, plus prompt detach with later
//! clear-child-tid reaping and opaque current/equality identity. The mutex
//! block is limited to all-zero/NULL-attribute process-private normal mutexes
//! and private futex contention. Its condition sibling retains musl's private
//! waiter-list/barrier/requeue protocol only for all-zero/NULL-attribute
//! process-private conditions paired with those normal mutexes. The C11 plain
//! synchronization sibling maps only distinct `mtx_t`/`cnd_t` storage through
//! those same private engines. The independent rwlock block owns the complete
//! selected 56-byte rwlock/8-byte attribute surface, including realtime timed
//! waits, musl-shaped hidden/weak aliases, and process-shared futex wakeups,
//! but does not complete general pthread synchronization. Its TSD sibling
//! stores only selected-main and
//! selected-worker values in a bounded private table and runs worker
//! destructors for at most four clear-before-callback passes; the selected
//! deferred pthread-cancellation leaf invokes that phase after its owned LIFO
//! cleanup handlers. It excludes main process exit, foreign callers, fork, dynamic/loader
//! TLS, and general TCB/thread-list semantics. Its once sibling maps only
//! four-byte zero-initialized controls through a private 0/1/2/3 futex state
//! machine; the C11 lifecycle/sleep siblings likewise
//! remain static-only typed-worker and direct non-cancellation realtime-sleep
//! slices. None is a claim for broader pthread/C11 header support.
//! The atfork leaf is narrower still: it owns no all-thread quiescence,
//! signal masking, allocator/loader/TSD reset, or general process lifecycle;
//! it admits only a caller with no live selected worker and no other concurrent
//! runtime state, and registered hooks must not recurse into the atfork/fork or
//! ordinary-exit registry while its fixed lock is held.
//!
//! Each child leaf owns its named C surface and must retain its own native
//! artifact evidence. The shared result translator is intentionally smaller
//! than C's variadic `syscall(long, ...)`: a complete variadic wrapper needs a
//! separately specified argument-count and cancellation contract.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the selected static C ABI requires little-endian Linux/x86-64");

#[path = "errno.rs"]
mod errno;
#[path = "atomic.rs"]
mod atomic;
#[allow(dead_code)]
#[path = "syscall.rs"]
mod raw_syscall;
#[path = "static_tls.rs"]
mod static_tls;
#[path = "stat_compat.rs"]
mod stat_compat;
#[path = "filesystem_capacity.rs"]
mod filesystem_capacity;
#[path = "timestamp_updates.rs"]
mod timestamp_updates;
#[path = "credentials.rs"]
mod credentials;
#[path = "credential_observation.rs"]
mod credential_observation;
#[path = "memory.rs"]
mod memory;
#[path = "memory_search.rs"]
mod memory_search;
#[path = "byte_strings.rs"]
mod byte_strings;
#[path = "string_copy.rs"]
mod string_copy;
#[path = "ctype.rs"]
mod ctype;
#[path = "locale_multibyte.rs"]
mod locale_multibyte;
#[path = "wide_character_tables.rs"]
mod wide_character_tables;
#[path = "wide_character.rs"]
mod wide_character;
#[path = "regex.rs"]
mod regex;
#[path = "iconv.rs"]
mod iconv;
#[path = "integer_arithmetic.rs"]
mod integer_arithmetic;
#[path = "integer_parse.rs"]
mod integer_parse;
#[path = "float_parse.rs"]
mod float_parse;
#[path = "float_parse_locale.rs"]
mod float_parse_locale;
#[path = "intmax_arithmetic.rs"]
mod intmax_arithmetic;
#[path = "ffs.rs"]
mod ffs;
#[path = "random_entropy.rs"]
mod random_entropy;
#[path = "fenv.rs"]
mod fenv;
#[path = "math_complex.rs"]
mod math_complex;
#[path = "complex_projection.rs"]
mod complex_projection;
#[path = "elementary_sqrt.rs"]
mod elementary_sqrt;
#[path = "fenv_rounding.rs"]
mod fenv_rounding;
#[path = "math_x87_extended.rs"]
mod math_x87_extended;
#[path = "math_special.rs"]
mod math_special;
#[path = "setjmp.rs"]
mod setjmp;
#[path = "signal_foundation.rs"]
mod signal_foundation;
#[path = "signal_control.rs"]
mod signal_control;
#[path = "signal_execution.rs"]
mod signal_execution;
#[path = "signal_altstack.rs"]
mod signal_altstack;
#[path = "pthread_identity.rs"]
mod pthread_identity;
#[path = "pthread_create_join.rs"]
mod pthread_create_join;
#[path = "pthread_cancel.rs"]
mod pthread_cancel;
#[path = "pthread_atfork.rs"]
mod pthread_atfork;
#[path = "pthread_tsd.rs"]
mod pthread_tsd;
#[path = "pthread_mutex.rs"]
mod pthread_mutex;
#[path = "pthread_cond.rs"]
mod pthread_cond;
#[path = "pthread_rwlock.rs"]
mod pthread_rwlock;
#[path = "c11_thread_lifecycle.rs"]
mod c11_thread_lifecycle;
#[path = "c11_sync.rs"]
mod c11_sync;
#[path = "pthread_once.rs"]
mod pthread_once;
#[path = "termios_control.rs"]
mod termios_control;
#[path = "process_context.rs"]
mod process_context;
#[path = "environment.rs"]
mod environment;
#[path = "child_reaping.rs"]
mod child_reaping;
#[path = "immediate_termination.rs"]
mod immediate_termination;
#[path = "static_startup.rs"]
mod static_startup;
#[path = "process_globals.rs"]
mod process_globals;
#[path = "stdio_standard.rs"]
mod stdio_standard;
#[path = "stdio_format_scan.rs"]
mod stdio_format_scan;
#[path = "callback_algorithms.rs"]
mod callback_algorithms;
#[path = "clock_nanosleep.rs"]
mod clock_nanosleep;
#[path = "clock_gettime.rs"]
mod clock_gettime;
#[path = "time_observation.rs"]
mod time_observation;
#[path = "nanosleep.rs"]
mod nanosleep;
#[path = "descriptor_entry.rs"]
mod descriptor_entry;
#[path = "filesystem_access.rs"]
mod filesystem_access;
#[path = "lchmod_unsupported.rs"]
mod lchmod_unsupported;
#[path = "extended_attributes.rs"]
mod extended_attributes;
#[path = "descriptor_control.rs"]
mod descriptor_control;
#[path = "record_locks.rs"]
mod record_locks;
#[path = "flock.rs"]
mod flock;
#[path = "sendfile.rs"]
mod sendfile;
#[path = "posix_fallocate.rs"]
mod posix_fallocate;
#[path = "descriptor_advice.rs"]
mod descriptor_advice;
#[path = "ioctl.rs"]
mod ioctl;
#[path = "descriptor_io.rs"]
mod descriptor_io;
#[path = "vector_io.rs"]
mod vector_io;
#[path = "process_resources.rs"]
mod process_resources;
#[path = "system_configuration.rs"]
mod system_configuration;
#[path = "memory_mapping.rs"]
mod memory_mapping;
#[path = "memory_locking.rs"]
mod memory_locking;
#[path = "memory_sync.rs"]
mod memory_sync;
#[path = "memfd_create.rs"]
mod memfd_create;
#[path = "readiness_waits.rs"]
mod readiness_waits;
#[path = "event_descriptors.rs"]
mod event_descriptors;
#[path = "pathname_lifecycle.rs"]
mod pathname_lifecycle;
#[path = "directory_streams.rs"]
mod directory_streams;
#[path = "system_observation.rs"]
mod system_observation;
#[path = "system_information.rs"]
mod system_information;
#[path = "uts_identity.rs"]
mod uts_identity;
#[path = "socket_transport.rs"]
mod socket_transport;
#[path = "inet_address.rs"]
mod inet_address;
#[path = "numeric_netdb.rs"]
mod numeric_netdb;
#[path = "socket_messages.rs"]
mod socket_messages;
#[path = "sysv_semaphore.rs"]
mod sysv_semaphore;
#[path = "sysv_message_shared_memory.rs"]
mod sysv_message_shared_memory;

use core::ffi::{c_int, c_void};

const LINUX_ERRNO_MAX: i64 = 4_095;

/// Translate one raw Linux result into C's `-1`/`errno` convention.
///
/// The only recognized Linux error encoding is `-4095..=-1`; every other
/// result is returned unchanged. Typed callers below narrow a successful
/// result only after this common error boundary, so the selected descriptor
/// leaf can preserve signed `ssize_t` and `off_t` values.
#[inline]
fn c_result(result: i64) -> i64 {
    if result < 0 && result >= -LINUX_ERRNO_MAX {
        // SAFETY: the checked Linux range encodes exactly one positive errno
        // value for the calling initial TLS block.
        unsafe { errno::set_errno(result.wrapping_neg() as c_int) };
        -1
    } else {
        result
    }
}

/// Translate one raw Linux status result into C's `int` result convention.
#[inline]
pub(super) fn c_status(result: i64) -> c_int {
    c_result(result) as c_int
}

/// Translate one raw Linux mapping result into C's pointer/`errno` convention.
///
/// A successful Linux mapping address may have its sign bit set, so pointer
/// callers must pass through the shared raw-result boundary before narrowing
/// it to an address. Only Linux's reserved `-4095..=-1` range represents an
/// error and therefore becomes `MAP_FAILED` after the C ABI cast.
#[inline]
pub(super) fn c_pointer_status(result: i64) -> *mut c_void {
    c_result(result) as usize as *mut c_void
}

/// Translate one raw Linux byte-count result into C's signed `ssize_t` ABI.
#[inline]
pub(super) fn c_ssize_status(result: i64) -> isize {
    c_result(result) as isize
}

/// Translate one raw Linux signed file-offset result into C's `off_t` ABI.
#[inline]
pub(super) fn c_off_status(result: i64) -> i64 {
    c_result(result)
}

// The selected archive builds with panic=abort and its C entry points avoid
// normal Rust panic paths. Keep this terminal fallback local to the static
// target root so linking a selected leaf cannot acquire an ambient runtime.
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// Linker personality stub for the abort-only static archive. No unwinding ABI
// or dynamic C++ runtime is selected by the currently admitted C leaves.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
