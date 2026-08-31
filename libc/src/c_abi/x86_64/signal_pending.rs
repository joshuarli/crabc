//! Selected static Linux/x86-64 `sigpending` C boundary.
//!
//! This private one-symbol adaptation maps exactly to pinned musl 1.2.6
//! revision `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT
//! license, `src/signal/sigpending.c`:
//!
//! ```c
//! int sigpending(sigset_t *set)
//! {
//!     return syscall(SYS_rt_sigpending, set, _NSIG/8);
//! }
//! ```
//!
//! Linux/x86-64 consumes the first eight-byte kernel signal-set word even
//! though the public x86 `sigset_t` has sixteen words. The kernel writes only
//! that first word on success and reports an invalid non-null or null output
//! pointer itself. This source shares the existing selected-static raw syscall
//! and `-1`/initial-TLS-errno conversion boundary, but no C action, mask, wait,
//! handler, process-delivery, descriptor, timer, or pthread policy surface.

use core::ffi::{c_int, c_void};

use super::{c_status, raw_syscall};

/// Query the calling thread's pending signals through Linux `rt_sigpending`.
///
/// # Safety
///
/// `set` must be null or point to writable storage for the first
/// kernel-visible word of one public x86 `sigset_t`. The direct syscall retains
/// musl's kernel-owned EFAULT behavior for either invalid pointer form and
/// leaves the public tail words caller-resident.
#[no_mangle]
pub unsafe extern "C" fn sigpending(set: *mut c_void) -> c_int {
    // SAFETY: Linux writes exactly one kernel signal-set word to `set` and
    // reports EFAULT itself for an invalid non-null caller pointer.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_RT_SIGPENDING,
            set as usize as i64,
            core::mem::size_of::<u64>() as i64,
        )
    };
    c_status(result)
}
