//! Selected static Linux/x86-64 C `timer_getoverrun` error-ABI boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! For a nonnegative opaque `timer_t` bit pattern,
//! `src/time/timer_getoverrun.c::timer_getoverrun` reaches its direct
//! `syscall(SYS_timer_getoverrun, t)` branch. Linux x86-64 syscall 225 receives
//! that pointer-sized opaque word in rdi. A raw Linux `-errno` becomes C `-1`
//! after publication through the selected initial-TLS errno slot.
//!
//! Musl's negative `timer_t` bit patterns are tagged thread-owned timers and
//! require its private `pthread_impl` TCB/timer-ID representation; this static
//! leaf deliberately does not decode or dereference them. The private fixture
//! passes only nonnegative invalid opaque values and observes `EINVAL`, never
//! creating, arming, querying, deleting, or observing a valid POSIX timer.
//! The artifact therefore establishes only the direct rejected-handle C error
//! ABI, not timer ownership, overrun values, POSIX timer state, tagged pthread
//! timer IDs, signal delivery, calendar/time-zone behavior, cancellation,
//! libc.so, CRT, dynamic TLS, loader, sysroot, family completion, promotion,
//! or public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Forward one nonnegative opaque timer word through Linux's C status convention.
///
/// # Safety
///
/// `timer` must carry a nonnegative opaque Linux timer bit pattern. This leaf
/// does not interpret the pointer or support musl's negative tagged
/// thread-owned timer representation. The caller owns any valid timer's
/// lifetime and overrun semantics; this private selected artifact establishes
/// only rejected-handle error translation.
#[no_mangle]
pub unsafe extern "C" fn timer_getoverrun(timer: *mut c_void) -> c_int {
    // SAFETY: the caller owns the opaque timer word and its selected boundary.
    // Linux/x86-64 receives that one word in rdi.
    let result = unsafe {
        raw_syscall::syscall1(
            raw_syscall::SYS_TIMER_GETOVERRUN,
            timer as usize as i64,
        )
    };
    c_status(result)
}
