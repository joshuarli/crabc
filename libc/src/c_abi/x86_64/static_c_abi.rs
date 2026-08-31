//! Selected static Linux/x86-64 C ABI composition.
//!
//! This target root owns one dependency-free `libc.a` artifact containing the
//! independently evidenced metadata and credential verticals alongside the x86
//! bulk-memory, floating-environment, continuation, binary32/binary64/x87
//! classification/sign, complex accessor/conjugation/projection, hardware
//! square root, binary32/binary64 bit-sign masks, binary32/binary64 extrema,
//! binary32/binary64 truncation, selected fenv-sensitive rounding,
//! and one selected x87 binary80 extended-math block as real C bootstrap
//! leaves, plus the complete private
//! `math.special` error/Bessel/gamma/decomposition/stepping/scaling/conversion
//! block with binary80 preserved end to end, plus deliberately narrow simple
//! signal action/mask, bounded process-signal execution, a direct legacy
//! single-signal pause wait, and fixed-minimum alternate signal-stack behavior,
//! plus direct timer-descriptor
//! creation/query/control and direct signal-descriptor creation/update, one default-attribute
//! create/explicit-exit/join/detach worker and its typed C11
//! `thrd_create`/`thrd_exit`/`thrd_join`/`thrd_detach`/`thrd_sleep` sibling, a
//! direct C11 `thrd_yield` leaf, a
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
//! termios-control, one historical `/dev/tty` password-input compatibility
//! leaf, selected process-context, bounded process-environment,
//! environment-backed login-name observation, child-reaping, selected
//! descriptor-entry, selected filesystem-access, one historical `mktemp`
//! pathname-selection leaf, fixed Linux `lchmod`
//! unsupported compatibility, bounded fcntl status-control
//! and nonblocking record-lock boundaries, advisory whole-file flock, bounded
//! regular-file sendfile transfer, mode-zero POSIX range allocation,
//! descriptor advice, timestamp updates, descriptor-I/O, vector-I/O, and
//! selected process-resources, selected readiness/signal-waits, and selected
//! system-configuration, caller-owned mapping-core, per-range memory locking,
//! direct no-cancellation mapping synchronization, direct anonymous-memory
//! descriptor creation, system-observation,
//! processor/page-count system-information, UTS-namespace identity, basic socket-transport,
//! scalar network byte-order conversion, one immutable IPv6 unspecified-address
//! data object and one immutable IPv6 loopback-address data object, one
//! caller-owned nameserver 16-bit wire-read codec, one caller-owned DNS
//! wire-name span codec,
//! isolated shared static IPv4 presentation buffer with no resolver state, and
//! selected classful raw-word
//! IPv4 arithmetic/network-part extraction with no resolver state, padded
//! socket messages/options,
//! deterministic numeric `netdb.h` address/service translation and result
//! ownership without resolver configuration, hosts, or DNS,
//! Linux interface name/index and address snapshots with private output
//! storage, isolated from numeric netdb, resolver configuration, DNS, and
//! conventional network databases,
//! credential-observation, integer-arithmetic, integer-parsing, selected
//! C-locale binary32/binary64/x87-binary80 floating parsing plus complete
//! fixed-C/POSIX/C.UTF-8 narrow/wide numeric parsing, legacy decimal
//! conversion, and suboption parsing, named
//! C/POSIX/C.UTF-8 multibyte state, fixed UTF/ASCII `iconv` conversion, and
//! allocation-free wide strings/memory, Unicode classification/simple case,
//! code-point collation, and terminal-column width,
//! bounded permanent stdin/stdout/stderr byte/block I/O with explicit flushing, selected
//! allocation-free byte-buffer formatting and NUL-string scanning,
//! plus one fixed regular-file pathname stream/position-buffering slot and
//! one bounded immediately-unlinked `tmpfile` route over that same slot,
//! intmax-arithmetic,
//! fixed-locale narrow ctype/case/collation, musl-compatible immutable ctype
//! table locators, immutable built-in locale objects, fixed langinfo,
//! selected-thread locale overrides, and localized wide
//! classification/case/collation wrappers,
//! find-first-set, immutable C-locale error strings and their fixed-profile
//! locale-message aliases, bounded fixed-profile signal descriptions, C11
//! immediate-termination,
//! a bounded private static
//! startup/ordinary-exit lifecycle, startup-published program-name globals,
//! raw initial auxiliary-vector observation, and option parsing,
//! callback-algorithms, allocator-export-free AVL callback-tree search, and
//! allocator-export-free hash-table search, a bounded no-catalog
//! gettext/message-catalog ABI profile, and POSIX `nanosleep`
//! and `clock_nanosleep`, and direct clock-observation artifacts, plus one
//! bounded System V message-queue/shared-memory artifact, one bounded
//! unnamed POSIX semaphore artifact, and one bounded event-descriptor
//! artifact, one bounded pathname-mutation/lifecycle artifact, and one
//! bounded directory-stream/raw-directory artifact.
//! The fixed-graph dlfcn bridge is a separate public-C spelling over the
//! loader-owned immutable RuntimeV1-prefix record. It owns only bounded
//! per-thread diagnostics and borrowed C views of copied loader metadata; it
//! cannot find, map, promote, finalize, or unmap an object.
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
//! full buffering and logical positions, plus an inactive-slot-only
//! immediately-unlinked `tmpfile` lifecycle; it is not stream allocation or
//! general stdio. The pthread artifacts are
//! intentionally bounded to null-attribute workers that return normally or
//! use their selected explicit-exit path, plus prompt detach with later
//! clear-child-tid reaping and opaque current/equality identity. GNU affinity
//! selects only bootstrapped-main self handles and executing selected-worker
//! handles through direct Linux syscalls; target completion, affinity
//! attributes, `CPU_*` helper macros, and general thread handles remain
//! unselected. The adjacent CPU-clock leaf admits only the bootstrapped
//! process-main `pthread_self()` handle and encodes its direct `gettid` value;
//! it owns no dereferenceable TCB, worker handle, or general C clock surface.
//! The adjacent GNU task-name pair similarly admits only that bootstrapped
//! process-main self handle through direct Linux `prctl`; it owns neither
//! worker names nor musl's `/proc` target-name/cancellation path. The mutex
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
//! machine; the C11 lifecycle/sleep/yield siblings likewise remain static-only
//! typed-worker, direct non-cancellation realtime-sleep, and direct
//! void-returning scheduler-syscall slices. None is a claim for broader
//! pthread/C11 header support.
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
#[path = "error_strings.rs"]
mod error_strings;
#[path = "locale_error_strings.rs"]
mod locale_error_strings;
#[path = "strsignal.rs"]
mod strsignal;
#[path = "ctype.rs"]
mod ctype;
#[path = "locale_ctype.rs"]
mod locale_ctype;
#[path = "locale_multibyte.rs"]
mod locale_multibyte;
#[path = "locale_objects.rs"]
mod locale_objects;
#[path = "locale_narrow.rs"]
mod locale_narrow;
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
#[path = "math_bit_sign.rs"]
mod math_bit_sign;
#[path = "math_trunc.rs"]
mod math_trunc;
#[path = "math_minmax.rs"]
mod math_minmax;
#[path = "math_x87_extended.rs"]
mod math_x87_extended;
#[path = "math_elementary_long_double.rs"]
mod math_elementary_long_double;
#[path = "math_special.rs"]
mod math_special;
#[path = "fdim.rs"]
mod fdim;
#[path = "setjmp.rs"]
mod setjmp;
#[path = "signal_foundation.rs"]
mod signal_foundation;
#[path = "signal_control.rs"]
mod signal_control;
#[path = "signal_execution.rs"]
mod signal_execution;
#[path = "signal_pause.rs"]
mod signal_pause;
#[path = "signal_altstack.rs"]
mod signal_altstack;
#[path = "pthread_identity.rs"]
mod pthread_identity;
#[path = "pthread_create_join.rs"]
mod pthread_create_join;
#[path = "pthread_affinity.rs"]
mod pthread_affinity;
#[path = "pthread_cpuclock.rs"]
mod pthread_cpuclock;
#[path = "pthread_name.rs"]
mod pthread_name;
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
#[path = "thrd_yield.rs"]
mod thrd_yield;
#[path = "c11_sync.rs"]
mod c11_sync;
#[path = "pthread_once.rs"]
mod pthread_once;
#[path = "termios_control.rs"]
mod termios_control;
#[path = "getpass.rs"]
mod getpass;
#[path = "process_context.rs"]
mod process_context;
#[path = "environment.rs"]
mod environment;
#[path = "login_name.rs"]
mod login_name;
#[path = "auxv_observation.rs"]
mod auxv_observation;
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
#[path = "search_tree_intrusive.rs"]
mod search_tree_intrusive;
#[path = "search_hash_table.rs"]
mod search_hash_table;
#[path = "gettext_catalog.rs"]
mod gettext_catalog;
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
#[path = "mktemp.rs"]
mod mktemp;
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
#[path = "timer_fd.rs"]
mod timer_fd;
#[path = "signal_fd.rs"]
mod signal_fd;
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
#[path = "network_byte_order.rs"]
mod network_byte_order;
#[path = "in6addr_any.rs"]
mod in6addr_any;
#[path = "in6addr_loopback.rs"]
mod in6addr_loopback;
#[path = "dn_skipname.rs"]
mod dn_skipname;
#[path = "ns_get16.rs"]
mod ns_get16;
#[path = "inet_address.rs"]
mod inet_address;
#[path = "inet_ntoa.rs"]
mod inet_ntoa;
#[path = "inet_classful.rs"]
mod inet_classful;
#[path = "inet_netof.rs"]
mod inet_netof;
#[path = "inet_network.rs"]
mod inet_network;
#[path = "hstrerror.rs"]
mod hstrerror;
#[path = "numeric_netdb.rs"]
mod numeric_netdb;
#[path = "interface_discovery.rs"]
mod interface_discovery;
#[path = "socket_messages.rs"]
mod socket_messages;
#[path = "sysv_semaphore.rs"]
mod sysv_semaphore;
#[path = "posix_semaphore.rs"]
mod posix_semaphore;
#[path = "sysv_message_shared_memory.rs"]
mod sysv_message_shared_memory;
#[path = "fixed_graph_dlfcn.rs"]
mod fixed_graph_dlfcn;

// The allocator is opt-in until the complete x86 runtime can own its bundled
// backend and lifecycle. Its C contract is shared verbatim with AArch64; only
// the target-local errno accessor differs.
#[cfg(feature = "x86-allocator-runtime")]
mod allocator {
    use core::ffi::{c_int, c_void};
    use core::ptr::null_mut;

    use super::errno;

    type SizeT = usize;
    const ENOMEM: c_int = 12;
    const EINVAL: c_int = 22;

    #[inline]
    unsafe fn cabi_allocator_errno() -> c_int {
        // SAFETY: allocator entry points read only their calling thread's
        // selected initial-TLS errno slot.
        unsafe { errno::get_errno() }
    }

    #[inline]
    unsafe fn cabi_set_allocator_errno(value: c_int) {
        // SAFETY: allocator failure translation changes only the calling
        // thread's selected initial-TLS errno slot.
        unsafe { errno::set_errno(value) };
    }

    include!("../../allocator_mimalloc.rs");

    /// Link-time witness for the opt-in x86 allocator wrapper object.
    ///
    /// This is private evidence glue, not an installed libc interface. The
    /// mixed-runtime differential calls it solely to force this archive
    /// member into the candidate before pinned musl supplies the still-missing
    /// process/runtime prerequisites of the bundled allocator backend.
    #[no_mangle]
    pub extern "C" fn __crabc_x86_allocator_runtime_v1() -> usize {
        1
    }
}

// POSIX string duplication is an allocation client, not another allocator
// entry point. Keep its object and feature separate so the completed wrapper
// artifact retains its exact nine-entry public surface and this mixed-runtime
// evidence cannot imply allocator lifecycle closure.
#[cfg(feature = "x86-allocator-string-duplication")]
#[path = "allocator_string_duplication.rs"]
mod allocator_string_duplication;

// The sole AArch64 allocator-observability capability is a separate strong
// C entry, not part of the weak allocation family. Its private witness keeps
// archive ownership independently auditable in the feature-built x86 image.
#[cfg(feature = "x86-allocator-observability")]
mod allocator_observability {
    use core::ffi::c_void;

    include!("../../allocator_observability_mimalloc.rs");

    #[no_mangle]
    pub extern "C" fn __crabc_x86_allocator_observability_v1() -> usize {
        1
    }
}

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
