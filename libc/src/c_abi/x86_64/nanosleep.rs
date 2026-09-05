//! Selected static Linux/x86-64 C `nanosleep` boundary.
//!
//! This leaf owns the selected normal-call, errno, and
//! remaining-timespec boundary of POSIX `nanosleep`. Its C contract is the
//! ordinary syscall-wrapper convention: return zero on completion, or return
//! `-1` after publishing the raw Linux errno in the calling initial-TLS errno
//! slot. It deliberately reuses the selected static archive's narrow
//! [`c_status`](super::c_status) translator rather than inventing a second
//! error path.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/nanosleep.c` maps to [`nanosleep`] below. Musl delegates the
//! realtime relative operation to `src/time/clock_nanosleep.c`, which reaches
//! `__syscall_cp` as a pthread cancellation point. The selected direct leaf
//! enters Linux `nanosleep=35`. The owned runtime supplies that cancellation
//! point; standalone archive selections retain the two-register raw syscall.
//! This does not establish public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Sleep for one relative interval using the normal POSIX C result convention.
///
/// A successful sleep returns zero and preserves the caller's errno. Linux
/// errors become `-1` and are stored in the calling initial-TLS errno slot.
/// A signal interruption returns `-1`/`EINTR`; when `remaining` is non-null,
/// Linux initializes it with a valid positive remaining interval. This direct
/// leaf does not retry interrupted sleeps. It is a pthread cancellation
/// point in the owned runtime.
///
/// # Safety
///
/// `request` must be null only when deliberately exercising Linux's pointer
/// validation; otherwise it must point to a readable 16-byte, align-eight
/// x86-64 `struct timespec` for the syscall duration. `remaining` must be null
/// or point to writable storage for the same record. The caller owns signal
/// delivery, interruption, and both record lifetimes.
// Keep the separately selected sleep wrapper as an ordinary static C caller
// whose object has one explicit nanosleep relocation rather than an inlined
// copy of this raw errno-publishing syscall boundary.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn nanosleep(request: *const c_void, remaining: *mut c_void) -> c_int {
    // SAFETY: the caller owns the complete raw Linux pointer contract. Linux
    // x86-64 receives the request and remaining pointers in rdi/rsi.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_NANOSLEEP,
                request as usize as i64,
                remaining as usize as i64,
                0,
                0,
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall2(
                raw_syscall::SYS_NANOSLEEP,
                request as usize as i64,
                remaining as usize as i64,
            )
        }
    };

    // Preserve normal C `0`/`-1 + errno` behavior; unlike clock_nanosleep,
    // this POSIX entry point must use the selected initial-TLS errno path.
    c_status(result)
}
