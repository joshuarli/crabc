//! Selected static Linux/x86-64 C `timer_settime` rejected-handle ABI boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! For a nonnegative opaque `timer_t` bit pattern,
//! `src/time/timer_settime.c::timer_settime` reaches exactly its direct
//! `return syscall(SYS_timer_settime, t, flags, val, old)` branch. Linux
//! x86-64 syscall 223 receives the pointer-sized opaque timer word in rdi, the
//! signed flags word in rsi, a borrowed readable 32-byte align-eight
//! `struct itimerspec` request in rdx, and a nullable writable 32-byte
//! align-eight old-value record in r10. A raw Linux `-errno` becomes C `-1`
//! after publication through the selected initial-TLS errno slot. Linux/x86-64
//! has no selected `SYS_timer_settime64` conversion branch.
//!
//! Musl's negative `timer_t` bit patterns are tagged thread-owned timers. Its
//! other branch reconstructs private `pthread_impl` state and reads its timer
//! ID before entering the syscall path; this static leaf excludes that branch.
//! It does not decode or dereference any timer handle. The private fixture runs
//! in a fresh process that creates no POSIX timers, passes only nonnegative `0`
//! and `INT_MAX` words, flags zero, one valid nonzero request record, and an
//! initialized old-value record, observes `-1`/`EINVAL`, and requires both
//! records to remain unchanged. The artifact never creates, arms, queries,
//! observes, or deletes a valid POSIX timer. It establishes only direct
//! rejected-handle error translation and input/output preservation, not timer
//! ownership, valid timer state, timer-control values, signal delivery,
//! calendar/time-zone behavior, cancellation, libc.so, CRT, dynamic TLS,
//! loader, sysroot, family completion, promotion, or public x86 support. This
//! is not public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Forward one nonnegative opaque timer word, request, and optional old value.
///
/// # Safety
///
/// `timer` must carry a nonnegative opaque Linux timer bit pattern. `value`
/// must point to readable 32-byte, align-eight x86-64 `struct itimerspec`
/// storage for the syscall duration; `old_value` must be null or point to
/// writable storage of that layout for the same duration. This leaf does not
/// interpret either timer record or support musl's negative tagged
/// thread-owned timer representation. The caller owns any valid timer's
/// lifetime and control semantics; this private selected artifact establishes
/// only rejected-handle error translation.
#[no_mangle]
pub unsafe extern "C" fn timer_settime(
    timer: *mut c_void,
    flags: c_int,
    value: *const c_void,
    old_value: *mut c_void,
) -> c_int {
    // SAFETY: the caller owns the opaque timer word, record pointers, flags,
    // and selected boundary. Linux/x86-64 receives these words in rdi/rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_TIMER_SETTIME,
            timer as usize as i64,
            flags as i64,
            value as usize as i64,
            old_value as usize as i64,
        )
    };
    c_status(result)
}
