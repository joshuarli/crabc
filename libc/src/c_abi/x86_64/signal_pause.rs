//! Selected static Linux/x86-64 sigpause C boundary.
//!
//! This is a bounded adaptation of pinned musl 1.2.6's
//! `src/signal/sigpause.c` at release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Musl queries the current mask, removes exactly one valid application signal
//! from a private one-word copy, then enters Linux `rt_sigsuspend=130`.
//! This leaf keeps that ordering without calling or exporting any broader
//! mask, action, queue, descriptor, timer, or thread interface.
//!
//! Linux consumes one eight-byte kernel signal-set word while the public C
//! `sigset_t` is wider. The temporary word is wholly local: Linux queries the
//! calling mask with `rt_sigprocmask=14`, atomically installs the derived mask
//! for the wait, and restores the old mask before it returns. Invalid signal
//! numbers, including musl-reserved 32 through 34, fail before the wait with
//! `EINVAL` exactly as musl's `sigdelset` helper does.
//!
//! This is neither general signal policy nor a cancellation point. It does
//! not select process control, handlers, masks as a public interface, queues,
//! descriptor events, readiness, timers, pthread behavior, dynamic runtime,
//! loader/CRT/sysroot state, family completion, promotion, or public x86
//! support.

use core::ffi::c_int;

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const SIGRTMAX: c_int = 64;
const KERNEL_SIGSET_SIZE: i64 = core::mem::size_of::<u64>() as i64;
const SIGMASK_QUERY: i64 = 0;

#[inline]
fn application_signal_bit(signal: c_int) -> Option<u64> {
    if signal <= 0 || signal > SIGRTMAX || (32..=34).contains(&signal) {
        return None;
    }
    Some(1_u64 << (signal - 1))
}

/// Temporarily unblock the selected signal from the current mask and suspend.
///
/// The derived mask preserves every other current bit, so any handled signal
/// unblocked by that derived mask can interrupt the wait. Linux owns the
/// temporary-mask installation, interrupted return, and old-mask restoration.
/// This scalar-only C ABI entry never borrows caller storage; signal
/// disposition, delivery, and concurrency remain entirely caller-managed.
#[no_mangle]
pub extern "C" fn sigpause(signal: c_int) -> c_int {
    let Some(signal_bit) = application_signal_bit(signal) else {
        // SAFETY: this selected C entry owns the calling initial-TLS errno
        // publication for its local validation failure.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    };

    let mut mask = 0_u64;
    // SAFETY: valid local storage receives exactly Linux x86's one kernel
    // signal-set word. Pinned musl makes the same query before its local
    // bit removal; the fixed argument shape cannot fail for caller input.
    let queried = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            SIGMASK_QUERY,
            0,
            (&mut mask as *mut u64) as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    };
    if queried < 0 {
        return c_status(queried);
    }

    mask &= !signal_bit;
    // SAFETY: the derived local mask occupies the exact eight bytes Linux
    // consumes. Linux atomically exchanges it for the wait and restores the
    // prior calling mask when a handled signal interrupts that wait.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_RT_SIGSUSPEND,
            (&mask as *const u64) as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    };
    c_status(result)
}
