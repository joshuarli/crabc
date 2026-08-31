//! Selected static Linux/x86-64 C `timer_delete` raw-error ABI boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! For a nonnegative opaque `timer_t` bit pattern,
//! `src/time/timer_delete.c::timer_delete` reaches exactly its direct
//! `return __syscall(SYS_timer_delete, t)` branch. Linux x86-64 syscall 226
//! receives that pointer-sized opaque word in rdi and returns raw -errno;
//! this direct musl branch does not touch errno or perform C-status
//! normalization.
//!
//! Musl's negative `timer_t` bit patterns are tagged thread-owned timers. Its
//! other branch reconstructs private `pthread_impl` state, atomically marks
//! the timer ID, and sends `SIGTIMER`; this static leaf excludes that branch.
//! It does not decode or dereference any timer handle. The private fixture runs in a fresh
//! process that creates no POSIX timers and passes only nonnegative `0` and
//! `INT_MAX` words, observing raw `-EINVAL` while its caller errno sentinel
//! remains unchanged. The artifact never creates, arms, queries, observes, or
//! deletes a valid POSIX timer. It establishes only the direct rejected-word
//! raw-error ABI, not timer ownership, deletion semantics, valid timer state,
//! signal delivery, calendar/time-zone behavior, cancellation, libc.so, CRT,
//! dynamic TLS, loader, sysroot, family completion, promotion, or public x86
//! support. This is not public x86 support.

use core::ffi::{c_int, c_void};

use super::raw_syscall;

/// Forward one nonnegative opaque timer word through musl's raw syscall branch.
///
/// # Safety
///
/// `timer` must carry a nonnegative opaque Linux timer bit pattern. This leaf
/// does not interpret the pointer or support musl's negative tagged
/// thread-owned timer representation. The caller owns any valid timer's
/// lifetime and deletion semantics; this private selected artifact establishes
/// only the raw rejected-word result boundary.
#[no_mangle]
pub unsafe extern "C" fn timer_delete(timer: *mut c_void) -> c_int {
    // SAFETY: the caller owns the opaque timer word and its selected boundary.
    // Linux/x86-64 receives that one word in rdi and returns the raw result.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_TIMER_DELETE, timer as usize as i64)
    };
    result as c_int
}
