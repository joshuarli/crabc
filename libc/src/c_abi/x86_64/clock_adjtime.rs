//! Selected static Linux/x86-64 C `clock_adjtime` error-ABI boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! `src/linux/clock_adjtime.c::clock_adjtime` reaches its final direct
//! `syscall(SYS_clock_adjtime, clock_id, utx)` branch on x86-64: there is no
//! `SYS_clock_adjtime64` path and LP64 `time_t` is not wider than `long`.
//! Linux x86-64 syscall 305 receives the signed clock ID in rdi and borrowed
//! writable `struct timex` pointer in rsi. A raw Linux `-errno` becomes C
//! `-1` after publication through the selected initial-TLS errno slot.
//!
//! The private static fixture invokes only rejected `-1` and
//! `CLOCK_MONOTONIC` IDs with a writable zero `struct timex`, so its
//! differential never asks Linux to adjust `CLOCK_REALTIME`. Linux may report
//! those rejected IDs as `EINVAL`, capability-first `EPERM`, or the direct
//! `EOPNOTSUPP` device result. This exact wrapper does not install an authority
//! guard: a valid caller can still reach Linux and remains outside the selected
//! evidence. The artifact therefore establishes only the direct rejected-ID C error
//! ABI, not clock adjustment authority, successful discipline/state semantics,
//! time observation, calendar/time-zone behavior, POSIX timers,
//! cancellation, libc.so, CRT, dynamic TLS, loader, sysroot, family completion,
//! promotion, or public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Forward one raw clock-adjustment request through Linux's C status convention.
///
/// # Safety
///
/// `state` must either be null for a deliberate raw-kernel request or point to
/// writable 208-byte, align-eight x86-64 `struct timex` storage for the syscall
/// duration. The caller owns the clock ID's authority, adjustment, and output-
/// record consequences. This private selected artifact proves only rejected-ID
/// error translation; it does not establish any successful clock-adjustment
/// contract.
#[no_mangle]
pub unsafe extern "C" fn clock_adjtime(clock_id: c_int, state: *mut c_void) -> c_int {
    // SAFETY: the caller owns the raw Linux clock ID, record validity, and
    // authority boundary. Linux/x86-64 receives these two words in rdi/rsi.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_ADJTIME,
            i64::from(clock_id),
            state as usize as i64,
        )
    };
    c_status(result)
}
