//! Selected static Linux/x86-64 C `timer_gettime` rejected-handle ABI boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! For a nonnegative opaque `timer_t` bit pattern,
//! `src/time/timer_gettime.c::timer_gettime` reaches exactly its direct
//! `return syscall(SYS_timer_gettime, t, val)` branch. Linux x86-64 syscall
//! 224 receives the pointer-sized opaque timer word in rdi and a borrowed
//! writable 32-byte align-eight `struct itimerspec` record in rsi. A raw Linux
//! `-errno` becomes C `-1` after publication through the selected initial-TLS
//! errno slot. Linux/x86-64 has no selected `SYS_timer_gettime64` conversion
//! branch.
//!
//! Musl's negative `timer_t` bit patterns are tagged thread-owned timers. Its
//! other branch reconstructs private `pthread_impl` state and reads its timer
//! ID before entering the syscall path; this static leaf excludes that branch.
//! It does not decode or dereference any timer handle. The private fixture runs
//! in a fresh process that creates no POSIX timers, passes only nonnegative `0`
//! and `INT_MAX` words with initialized writable output records, observes
//! `-1`/`EINVAL`, and requires the record to remain unchanged. The artifact
//! never creates, arms, queries, observes, or deletes a valid POSIX timer. It
//! establishes only direct rejected-handle error translation and rejected-output
//! preservation, not timer ownership, valid timer state, timer query values,
//! signal delivery, calendar/time-zone behavior, cancellation, libc.so, CRT,
//! dynamic TLS, loader, sysroot, family completion, promotion, or public x86
//! support. This is not public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Forward one nonnegative opaque timer word and borrowed output record.
///
/// # Safety
///
/// `timer` must carry a nonnegative opaque Linux timer bit pattern. `value`
/// must point to writable 32-byte, align-eight x86-64 `struct itimerspec`
/// storage for the syscall duration. This leaf does not interpret either
/// object or support musl's negative tagged thread-owned timer representation.
/// The caller owns any valid timer's lifetime and query semantics; this private
/// selected artifact establishes only rejected-handle error translation.
#[no_mangle]
pub unsafe extern "C" fn timer_gettime(timer: *mut c_void, value: *mut c_void) -> c_int {
    // SAFETY: the caller owns the opaque timer word, writable record, and
    // selected boundary. Linux/x86-64 receives these words in rdi/rsi.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_TIMER_GETTIME,
            timer as usize as i64,
            value as usize as i64,
        )
    };
    c_status(result)
}
