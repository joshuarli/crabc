//! Selected static Linux/x86-64 signalfd C boundary.
//!
//! This is a bounded adaptation of pinned musl 1.2.6's
//! `src/linux/signalfd.c` at release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! It exposes only the public `signalfd` wrapper through Linux/x86-64
//! `signalfd4=289`. Linux 5.10 supplies `signalfd4`, so musl's legacy
//! `signalfd` fallback and its post-create `fcntl` flag adjustments are not
//! needed or selected here.
//!
//! Linux consumes one eight-byte kernel signal-set word even though the public
//! userspace `sigset_t` is larger. This wrapper passes the borrowed pointer
//! unchanged and supplies that fixed kernel size; it does not copy, inspect,
//! block, unblock, or otherwise manage signals. Linux owns flag validation,
//! descriptor creation/update, queueing, reads, and raw error results, which
//! the shared selected-static result translator converts to C `-1` plus the
//! calling initial-TLS `errno`.
//!
//! This leaf is not signal-mask or disposition policy, signal lifecycle,
//! timer/readiness policy, an event loop, a cancellation point, dynamic
//! runtime, loader/CRT/sysroot state, or public x86 support.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Linux `signalfd4` consumes exactly one native signal-set word.
const KERNEL_SIGSET_SIZE: i64 = 8;

/// Create or update one signal descriptor through Linux `signalfd4(2)`.
///
/// # Safety
///
/// For a successful call, `mask` must point to readable signal-set storage
/// for the kernel's eight-byte input word and remain valid for the syscall.
/// It may be null or inaccessible only when the C caller deliberately relies
/// on Linux returning `EFAULT`. `descriptor` must be `-1` for creation or an
/// open signalfd descriptor for an update; concurrent descriptor ownership,
/// signal masking, disposition, delivery, and consumption remain entirely
/// with the caller and Linux.
#[no_mangle]
pub unsafe extern "C" fn signalfd(
    descriptor: c_int,
    mask: *const c_void,
    flags: c_int,
) -> c_int {
    // SAFETY: The caller owns the borrowed mask and descriptor contracts. The
    // raw helper places flags in Linux x86-64's fourth-argument r10 register.
    c_status(unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SIGNALFD4,
            i64::from(descriptor),
            mask as usize as i64,
            KERNEL_SIGSET_SIZE,
            i64::from(flags),
        )
    })
}
