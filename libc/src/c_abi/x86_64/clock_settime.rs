//! Selected static Linux/x86-64 C `clock_settime` error-ABI boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/time/clock_settime.c::clock_settime` is the one direct
//! `syscall(SYS_clock_settime, clk, ts)` wrapper mapped below. On Linux 5.10
//! x86-64 that is syscall 227 with a signed clock ID in rdi and the borrowed
//! timespec pointer in rsi. A raw Linux `-errno` becomes C `-1` after
//! publication through the selected initial-TLS errno slot.
//!
//! The private static fixture invokes only rejected `-1` and
//! `CLOCK_MONOTONIC` requests, so its differential never asks Linux to alter
//! realtime. This exact wrapper does not add a policy guard: a valid caller
//! still reaches the kernel and remains outside the selected evidence. The
//! artifact therefore establishes only the direct rejected-request C error
//! ABI, not clock-setting authority, successful mutation/state semantics,
//! time observation, calendar/time-zone behavior, POSIX timers, cancellation,
//! libc.so, CRT, dynamic TLS, loader, sysroot, family completion, promotion,
//! or public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Forward one raw clock-setting request through Linux's C status convention.
///
/// # Safety
///
/// `value` must be null only when deliberately requesting Linux's pointer
/// error; otherwise it must point to readable 16-byte, align-eight x86-64
/// `struct timespec` storage for the syscall duration. The caller owns the
/// clock ID's authority, mutation, and lifetime consequences. This private
/// selected artifact proves only rejected-request error translation; it does
/// not establish any successful clock mutation contract.
#[no_mangle]
pub unsafe extern "C" fn clock_settime(clock_id: c_int, value: *const c_void) -> c_int {
    // SAFETY: the caller owns the raw Linux clock ID, pointer validity, and
    // authority boundary. Linux/x86-64 receives these two words in rdi/rsi.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CLOCK_SETTIME,
            i64::from(clock_id),
            value as usize as i64,
        )
    };
    c_status(result)
}
