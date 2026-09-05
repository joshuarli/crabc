//! Owned sigpause from musl 1.2.6 (MIT), release revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, src/signal/sigpause.c.
//! Query the calling mask, remove one application signal, then compose the
//! existing cancellation-aware sigsuspend owner. The private leaf retains
//! its frozen non-canceling raw-syscall profile.

use core::ffi::c_int;
use super::{readiness_waits, signal_control, signal_set_mutation,
    signal_foundation::PUBLIC_SIGSET_WORDS};

/// Temporarily unblock one signal while waiting at a cancellation point.
/// The caller owns signal disposition and any cancellation cleanup policy.
#[no_mangle]
pub extern "C" fn sigpause(signal: c_int) -> c_int {
    let mut mask = [0u64; PUBLIC_SIGSET_WORDS];
    // Valid local storage makes the source query infallible in ordinary
    // execution. Retain the private Rust boundary's early syscall error for
    // an externally rejected query; never consume indeterminate mask bytes.
    if unsafe { signal_control::sigprocmask(0, core::ptr::null(), mask.as_mut_ptr().cast()) } < 0 {
        return -1;
    }
    if unsafe { signal_set_mutation::sigdelset(mask.as_mut_ptr().cast(), signal) } < 0 {
        return -1;
    }
    unsafe { readiness_waits::sigsuspend(mask.as_ptr().cast()) }
}
