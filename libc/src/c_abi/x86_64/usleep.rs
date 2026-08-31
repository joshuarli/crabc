//! Selected static Linux/x86-64 `usleep` C boundary.
//!
//! This private one-symbol adapter is a source-faithful translation of pinned
//! musl 1.2.6 release revision `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license: `src/unistd/usleep.c`. Musl splits an unsigned
//! microsecond argument into a local `struct timespec`, then calls
//! `nanosleep(&tv, &tv)`. On x86 LP64, `unsigned int` is four bytes and each
//! `timespec` field is an eight-byte `long`: the largest input becomes
//! 4,294 seconds plus 967,295,000 nanoseconds.
//!
//! The exact source closure intentionally reaches the separately selected
//! static [`super::nanosleep`] boundary. That sibling publishes ordinary
//! `-1`/errno failures through initial TLS and deliberately omits musl's
//! pthread cancellation-point machinery; this adapter adds no cancellation,
//! timer, signal, or errno path of its own.
//!
//! This does not select `sleep`, `alarm`, `ualarm`, interval or POSIX timers,
//! handlers/actions, masks, signal delivery, a C sleep policy, pthread
//! behavior, libc.so, CRT, loader, sysroot, promotion, or public x86 support.

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

const MICROSECONDS_PER_SECOND: c_uint = 1_000_000;
const NANOSECONDS_PER_MICROSECOND: c_uint = 1_000;

/// Exact public Linux/x86-64 `struct timespec` storage.
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, seconds) == 0);
    assert!(offset_of!(Timespec, nanoseconds) == 8);
};

/// Sleep for an unsigned microsecond interval through the selected nanosleep seam.
///
/// This retains musl's direct source mapping: it normalizes the full unsigned
/// input into one local LP64 timespec and passes that same record as both the
/// request and the otherwise-unobservable `EINTR` remainder. Completion
/// returns zero and preserves errno; an interrupted sleep returns `-1` after
/// the selected sibling stores `EINTR` in initial TLS. This adapter neither
/// retries nor installs/blocks/delivers signals, and it has no cancellation
/// point until the x86 pthread runtime owns that policy.
#[no_mangle]
pub extern "C" fn usleep(microseconds: c_uint) -> c_int {
    let mut duration = Timespec {
        seconds: (microseconds / MICROSECONDS_PER_SECOND) as c_long,
        nanoseconds: ((microseconds % MICROSECONDS_PER_SECOND)
            * NANOSECONDS_PER_MICROSECOND) as c_long,
    };
    let duration = &mut duration as *mut Timespec;

    // SAFETY: musl passes its complete local timespec as both pointers. The
    // selected nanosleep boundary receives one valid readable/writable x86
    // record for the duration of this call; its remainder is intentionally
    // local and not observable through usleep's pointer-free C ABI.
    unsafe {
        super::nanosleep::nanosleep(
            duration.cast_const().cast::<c_void>(),
            duration.cast::<c_void>(),
        )
    }
}
