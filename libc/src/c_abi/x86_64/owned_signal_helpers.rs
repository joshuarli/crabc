//! Owned System V signal helpers from musl 1.2.6 (MIT), release revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, src/signal/{sighold,sigignore,
//! sigrelse,sigset}.c. Unlike the frozen private raw-syscall leaf, these
//! wrappers compose the public signal set/action/mask owners. That retains
//! reserved-signal validation, sticky EINTR validity, SIGABRT serialization,
//! errno translation, and the source's two-step sigset failure behavior.

use core::ffi::c_int;
use super::{signal_control as control, signal_set_mutation,
    signal_foundation::{PublicSigAction, PUBLIC_SIGSET_WORDS}};

const SIG_ERR: usize = usize::MAX;
const SIG_HOLD: usize = 2;
const SIG_IGN: usize = 1;
const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;

fn action(handler: usize) -> PublicSigAction {
    PublicSigAction { handler, mask: [0; PUBLIC_SIGSET_WORDS],
        flags: 0, padding: 0, restorer: 0 }
}

fn signal_mask(signal: c_int) -> Option<[u64; PUBLIC_SIGSET_WORDS]> {
    let mut mask = [0; PUBLIC_SIGSET_WORDS];
    // Source sigemptyset/sigaddset composition; the latter owns invalid and
    // reserved signal errors before any action or mask syscall is issued.
    if unsafe { signal_set_mutation::sigaddset(mask.as_mut_ptr().cast(), signal) } < 0 {
        None
    } else { Some(mask) }
}

/// Block one application signal in the calling task, preserving its action.
#[no_mangle]
pub extern "C" fn sighold(signal: c_int) -> c_int {
    let Some(mask) = signal_mask(signal) else { return -1; };
    unsafe { control::sigprocmask(SIG_BLOCK, mask.as_ptr().cast(), core::ptr::null_mut()) }
}

/// Unblock one application signal in the calling task, preserving its action.
#[no_mangle]
pub extern "C" fn sigrelse(signal: c_int) -> c_int {
    let Some(mask) = signal_mask(signal) else { return -1; };
    unsafe { control::sigprocmask(SIG_UNBLOCK, mask.as_ptr().cast(), core::ptr::null_mut()) }
}

/// Ignore one application signal through the owned action transaction.
#[no_mangle]
pub extern "C" fn sigignore(signal: c_int) -> c_int {
    let ignored = action(SIG_IGN);
    unsafe { control::sigaction(signal, core::ptr::addr_of!(ignored).cast(), core::ptr::null_mut()) }
}

/// Replace a disposition and unblock its signal, or hold without replacing.
///
/// # Safety
/// `handler` is SIG_DFL, SIG_IGN, SIG_HOLD, or a callable signal-handler address
/// retained until every possible asynchronous invocation has completed. The
/// caller owns any synchronization needed to replace process-wide handlers.
#[no_mangle]
pub unsafe extern "C" fn sigset(signal: c_int, handler: usize) -> usize {
    let Some(mask) = signal_mask(signal) else { return SIG_ERR; };
    let mut old_action = action(0);
    let new_action = action(handler);
    let requested = if handler == SIG_HOLD { core::ptr::null() }
        else { core::ptr::addr_of!(new_action).cast() };
    if unsafe { control::sigaction(signal, requested, core::ptr::addr_of_mut!(old_action).cast()) } < 0 {
        return SIG_ERR;
    }
    let mut old_mask = [0u64; PUBLIC_SIGSET_WORDS];
    // Musl does not undo an installed action if this second operation fails.
    if unsafe { control::sigprocmask(if handler == SIG_HOLD { SIG_BLOCK } else { SIG_UNBLOCK },
        mask.as_ptr().cast(), old_mask.as_mut_ptr().cast()) } < 0 {
        return SIG_ERR;
    }
    if unsafe { control::sigismember(old_mask.as_ptr().cast(), signal) } != 0 {
        SIG_HOLD
    } else { old_action.handler }
}
