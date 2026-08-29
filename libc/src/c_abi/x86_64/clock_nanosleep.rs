//! Selected static Linux/x86-64 C `clock_nanosleep` boundary.
//!
//! This leaf owns the selected non-cancellation normal-call, result, and
//! pointer boundary of POSIX `clock_nanosleep`. Unlike ordinary C syscall
//! wrappers, its public contract returns zero on success or a *positive errno*
//! value on failure; it must not publish failures through `errno`. The
//! implementation therefore deliberately bypasses the static archive's
//! `c_status` translator and negates only Linux's raw negative errno result.
//! It is a direct, non-pthread leaf: musl 1.2.6 routes this operation through
//! `__syscall_cp` as a cancellation point, but cancellation and cleanup are
//! deferred until the x86 pthread/TLS runtime exists.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/clock_nanosleep.c` maps to [`clock_nanosleep`] below.  Musl
//! special-cases a relative realtime request through `nanosleep` and rejects
//! `CLOCK_THREAD_CPUTIME_ID` with `EINVAL` before the syscall. This bounded
//! Linux-5.10 leaf retains the latter musl-visible error rule, but intentionally
//! uses `clock_nanosleep=230` rather than musl's realtime `nanosleep` route for
//! every remaining clock request while keeping this leaf independent of the
//! separately selected `nanosleep` boundary. The
//! x86-64 raw ABI places clock ID, flags,
//! request, and remaining-timespec pointers in `rdi`, `rsi`, `rdx`, and `r10`.
//!
//! This leaf does not call or depend on the separately selected `nanosleep`
//! boundary, and it does not select `sleep`, `clock_gettime`, C timer state,
//! time-zone/calendar services, timer delivery policy, pthread cancellation,
//! libc.so, CRT, dynamic TLS, loader, sysroot, or public x86 support.

use core::ffi::{c_int, c_void};

use super::raw_syscall;

const LINUX_ERRNO_MAX: i64 = 4_095;
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
