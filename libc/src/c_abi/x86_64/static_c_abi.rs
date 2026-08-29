//! Selected static Linux/x86-64 C ABI composition.
//!
//! This target root owns one dependency-free `libc.a` artifact containing the
//! independently evidenced metadata and credential verticals alongside the x86
//! bulk-memory, floating-environment, continuation, binary32/binary64/x87
//! classification/sign, and basic complex accessor/conjugation primitives as a
//! real C bootstrap block, plus deliberately narrow simple signal action/mask,
//! one default-attribute create/explicit-exit/join worker with private
//! initial-TLS `errno`,
//! termios-control, selected process-context, child-reaping, selected
//! descriptor-entry, bounded fcntl status-control, descriptor-I/O, and
//! selected process-resources, selected readiness/signal-waits, and selected
//! system-configuration, system-observation, UTS-namespace identity, basic socket-transport,
//! credential-observation, integer-arithmetic, integer-parsing, intmax-arithmetic,
//! find-first-set, C11 immediate-termination, callback-algorithms, and POSIX
//! `nanosleep` and `clock_nanosleep`
//! artifacts.
//! It deliberately shares only the raw
//! Linux syscall register boundary and one initial-TLS C `errno` slot. The
//! archive is not `libc.so`,
//! a general C runtime, a CRT, a general pthread/TLS lifecycle, a dynamic-TLS
//! implementation, a loader, or a sysroot. The pthread artifacts are
//! intentionally bounded to null-attribute workers that return normally or
//! use their selected explicit-exit path; it is not a claim for the broader
//! pthread header surface.
//!
//! Each child leaf owns its named C surface and must retain its own native
//! artifact evidence. The shared result translator is intentionally smaller
//! than C's variadic `syscall(long, ...)`: a complete variadic wrapper needs a
//! separately specified argument-count and cancellation contract.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the selected static C ABI requires little-endian Linux/x86-64");

#[path = "errno.rs"]
mod errno;
#[allow(dead_code)]
#[path = "syscall.rs"]
mod raw_syscall;
#[path = "stat_compat.rs"]
mod stat_compat;
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
#[path = "integer_arithmetic.rs"]
mod integer_arithmetic;
#[path = "integer_parse.rs"]
mod integer_parse;
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
#[path = "setjmp.rs"]
mod setjmp;
#[path = "signal_foundation.rs"]
mod signal_foundation;
#[path = "signal_control.rs"]
mod signal_control;
#[path = "pthread_create_join.rs"]
mod pthread_create_join;
#[path = "termios_control.rs"]
mod termios_control;
#[path = "process_context.rs"]
mod process_context;
#[path = "child_reaping.rs"]
mod child_reaping;
#[path = "immediate_termination.rs"]
mod immediate_termination;
#[path = "callback_algorithms.rs"]
mod callback_algorithms;
#[path = "clock_nanosleep.rs"]
mod clock_nanosleep;
#[path = "clock_gettime.rs"]
mod clock_gettime;
#[path = "nanosleep.rs"]
mod nanosleep;
#[path = "descriptor_entry.rs"]
mod descriptor_entry;
#[path = "descriptor_control.rs"]
mod descriptor_control;
#[path = "descriptor_io.rs"]
mod descriptor_io;
#[path = "process_resources.rs"]
mod process_resources;
#[path = "system_configuration.rs"]
mod system_configuration;
#[path = "readiness_waits.rs"]
mod readiness_waits;
#[path = "system_observation.rs"]
mod system_observation;
#[path = "uts_identity.rs"]
mod uts_identity;
#[path = "socket_transport.rs"]
mod socket_transport;

use core::ffi::c_int;

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
