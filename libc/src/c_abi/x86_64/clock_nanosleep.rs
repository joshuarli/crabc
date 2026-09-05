//! Selected static Linux/x86-64 C `clock_nanosleep` boundary.
//!
//! This leaf owns the selected normal-call, result, and
//! pointer boundary of POSIX `clock_nanosleep`. Unlike ordinary C syscall
//! wrappers, its public contract returns zero on success or a *positive errno*
//! value on failure; it must not publish failures through `errno`. The
//! implementation therefore deliberately bypasses the static archive's
//! `c_status` translator and negates only Linux's raw negative errno result.
//! The owned runtime supplies musl's pthread cancellation point.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/clock_nanosleep.c` maps to [`clock_nanosleep`] below.  Musl
//! special-cases a relative realtime request through `nanosleep` and rejects
//! `CLOCK_THREAD_CPUTIME_ID` with `EINVAL` before the syscall. This bounded
//! Linux-5.10 leaf retains the latter validation before cancellation. The owned
//! runtime also preserves the relative realtime `nanosleep` route; standalone
//! archive selections retain their previously qualified `clock_nanosleep=230`
//! syscall for every accepted clock request. Both forms return positive errors
//! without changing errno and do not establish public x86 support.

use core::ffi::{c_int, c_void};

use super::raw_syscall;

const LINUX_ERRNO_MAX: i64 = 4_095;
/// Linux's realtime clock ID is the fixed clock selected by C11 `thrd_sleep`.
///
/// This remains module-private to the static x86 C ABI composition: its C11
/// sibling consumes the named value rather than duplicating a syscall ABI
/// literal.
pub(super) const CLOCK_REALTIME: c_int = 0;
const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
const EINVAL: c_int = 22;

/// Sleep against one Linux clock using the POSIX `clock_nanosleep` result
/// convention.
///
/// Returns zero after a completed sleep, or the positive Linux errno value
/// directly.  In particular, errors do not modify the calling thread's C
/// `errno` slot. `flags` is forwarded untouched for Linux's raw flag
/// semantics.
///
/// # Safety
///
/// `request` must be null only when intentionally testing Linux's pointer
/// validation; otherwise it must point to a readable 16-byte, align-eight
/// x86-64 `struct timespec` for the duration of the syscall.  For relative
/// sleeps, `remaining` must be null or point to writable storage for the same
/// record. For absolute sleeps it may be null or point to valid writable
/// storage; Linux ignores it and supplies no remaining interval in that mode.
/// The caller owns signal delivery, interruption, and any lifetime policy for
/// both records.
#[no_mangle]
pub unsafe extern "C" fn clock_nanosleep(
    clock_id: c_int,
    flags: c_int,
    request: *const c_void,
    remaining: *mut c_void,
) -> c_int {
    // Musl rejects this CPU clock locally because Linux reports EOPNOTSUPP,
    // while POSIX/musl expose EINVAL. This also preserves the direct-positive
    // error convention without touching errno.
    if clock_id == CLOCK_THREAD_CPUTIME_ID {
        return EINVAL;
    }

    // SAFETY: the caller owns the complete raw Linux record-pointer contract;
    // x86 syscall argument four is explicitly placed in r10 by this helper.
    #[cfg(feature = "x86-owned-static-runtime")]
    let result = unsafe {
        // Musl uses nanosleep for relative realtime requests; preserve that
        // syscall boundary as well as its cancellation/error behavior.
        if clock_id == CLOCK_REALTIME && flags == 0 {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_NANOSLEEP,
                request as usize as i64,
                remaining as usize as i64,
                0, 0, 0, 0,
            )
        } else {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_CLOCK_NANOSLEEP,
                i64::from(clock_id),
                i64::from(flags),
                request as usize as i64,
                remaining as usize as i64,
                0, 0,
            )
        }
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_CLOCK_NANOSLEEP,
            i64::from(clock_id),
            i64::from(flags),
            request as usize as i64,
            remaining as usize as i64,
        )
    };

    // The Linux syscall returns zero or one raw negative errno.  Preserve
    // musl/POSIX's special direct-positive-error convention rather than
    // using `c_status`, which would store errno and return -1.
    if (-LINUX_ERRNO_MAX..0).contains(&result) {
        result.wrapping_neg() as c_int
    } else {
        // A successful Linux `clock_nanosleep` result is exactly zero.  Keep
        // that literal C contract rather than exposing an impossible positive
        // raw value as an invented result convention.
        0
    }
}
