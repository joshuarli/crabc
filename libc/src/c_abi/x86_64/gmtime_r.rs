//! Selected static Linux/x86-64 C `gmtime_r` boundary.
//!
//! This leaf owns exactly the caller-buffered POSIX UTC conversion from one
//! LP64 `time_t` to one 56-byte Linux `struct tm`. It normalizes the supplied
//! record as UTC and returns the caller's output pointer. It has no kernel
//! call and reads no process environment, timezone global, or zoneinfo. It is
//! not non-reentrant conversion, local civil conversion, formatting/parsing,
//! a calendar API family, clocks, timers, libc.so, CRT, dynamic TLS, loader,
//! sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/time/gmtime_r.c` maps to [`gmtime_r`].
//! - `src/time/__secs_to_tm.c` maps to [`secs_to_utc_tm`] in the sibling
//!   fixed-UTC conversion leaf.
//!
//! Musl exposes `gmtime_r` through its private `__gmtime_r` weak alias. This
//! selected archive exports only the public header spelling; the private alias
//! remains unowned.

use core::ffi::{c_int, c_long};

use super::errno::set_errno;
use super::timegm::{secs_to_utc_tm, Tm};

const EOVERFLOW: c_int = 75;

/// Convert one Unix second count into caller-owned UTC `struct tm` storage.
///
/// # Safety
///
/// `input` must designate initialized LP64 `time_t` storage and `output`
/// must designate writable 56-byte Linux/x86-64 `struct tm` storage for the
/// duration of the call. They must not overlap, matching the public header's
/// restrict contract. The output storage need not be initialized: a
/// representability failure leaves its bytes untouched, writes initial-TLS
/// errno `EOVERFLOW`, and returns null; a successful conversion preserves
/// errno and returns the original output pointer.
#[no_mangle]
pub unsafe extern "C" fn gmtime_r(input: *const c_long, output: *mut Tm) -> *mut Tm {
    // SAFETY: the C caller supplies initialized non-overlapping input storage.
    let seconds = unsafe { input.read() };
    let Some(normalized) = secs_to_utc_tm(seconds) else {
        // SAFETY: this C error boundary owns the selected initial-TLS errno.
        unsafe { set_errno(EOVERFLOW) };
        return core::ptr::null_mut();
    };
    // SAFETY: the C caller supplies writable exact struct-tm storage.
    unsafe { output.write(normalized) };
    output
}
