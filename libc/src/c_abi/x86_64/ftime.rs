//! Selected static Linux/x86-64 `ftime` C boundary.
//!
//! This private one-symbol legacy snapshot adapter is a source-faithful
//! translation of pinned musl 1.2.6 release revision
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/ftime.c`. Musl takes a local realtime `struct timespec` through
//! `clock_gettime(CLOCK_REALTIME, &ts)`, ignores that status, then stores the
//! whole seconds, nanoseconds divided by one million, and two zero legacy
//! fields into the caller's `struct timeb`.
//!
//! The exact source closure reaches the separately selected static
//! [`super::clock_gettime`] boundary. Its valid-local-record Linux 5.10 path
//! succeeds and preserves stale errno. Rust initializes the local record to
//! make an otherwise unobservable failed-query path defined without selecting
//! an error convention that musl's source does not provide for `ftime`.
//!
//! This does not select `time`, `clock`, `gettimeofday`, calendar/timezone
//! conversion, clock mutation, sleep, alarms, interval/POSIX timers,
//! handlers/actions, masks, signal delivery, pthread policy, libc.so, CRT,
//! loader, sysroot, promotion, or public x86 support.

use core::ffi::{c_int, c_long, c_short, c_ushort, c_void};
use core::mem::{align_of, offset_of, size_of};

const CLOCK_REALTIME: c_int = 0;
const NANOSECONDS_PER_MILLISECOND: c_long = 1_000_000;

/// Exact Linux/x86-64 `struct timespec` storage used by the selected seam.
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

/// Exact public Linux/x86-64 `struct timeb` storage.
#[repr(C)]
pub(super) struct Timeb {
    time: c_long,
    millitm: c_ushort,
    timezone: c_short,
    dstflag: c_short,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, seconds) == 0);
    assert!(offset_of!(Timespec, nanoseconds) == 8);
    assert!(size_of::<Timeb>() == 16);
    assert!(align_of::<Timeb>() == 8);
    assert!(offset_of!(Timeb, time) == 0);
    assert!(offset_of!(Timeb, millitm) == 8);
    assert!(offset_of!(Timeb, timezone) == 10);
    assert!(offset_of!(Timeb, dstflag) == 12);
};

/// Snapshot realtime into one legacy caller-owned `timeb` record.
///
/// The caller must provide writable 16-byte, align-eight Linux/x86-64
/// `struct timeb` storage. As in musl, the selected normal valid-record path
/// returns zero after passing a fixed realtime query through the static
/// `clock_gettime` seam. The source does not define a useful failed-query
/// result for this legacy adapter, so invalid output pointers and failed
/// realtime queries remain outside this private artifact.
#[no_mangle]
pub unsafe extern "C" fn ftime(output: *mut Timeb) -> c_int {
    let mut snapshot = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };

    // SAFETY: this local record is writable exact x86 timespec storage. Musl
    // intentionally ignores the selected public clock_gettime return value.
    let _ = unsafe {
        super::clock_gettime::clock_gettime(
            CLOCK_REALTIME,
            (&mut snapshot as *mut Timespec).cast::<c_void>(),
        )
    };
    let record = Timeb {
        time: snapshot.seconds,
        millitm: (snapshot.nanoseconds / NANOSECONDS_PER_MILLISECOND) as c_ushort,
        timezone: 0,
        dstflag: 0,
    };

    // SAFETY: the C caller owns the writable public timeb record contract.
    unsafe { output.write(record) };
    0
}
