//! Owned siginterrupt from musl 1.2.6 (MIT), release revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, src/signal/siginterrupt.c.
//! The two action calls must compose the owned action transaction: replacing
//! SA_RESTART updates sticky EINTR bookkeeping and serializes SIGABRT actions.
//! The frozen private raw-syscall adapter remains separately selected.

use core::ffi::c_int;
use super::{signal_control, signal_foundation::{PublicSigAction, PUBLIC_SIGSET_WORDS}};

const SA_RESTART: c_int = 0x1000_0000;

/// Change only SA_RESTART on the current disposition of one signal.
/// The caller retains the existing action's asynchronous-handler lifetime.
#[no_mangle]
pub extern "C" fn siginterrupt(signal: c_int, flag: c_int) -> c_int {
    let mut action = PublicSigAction { handler: 0, mask: [0; PUBLIC_SIGSET_WORDS],
        flags: 0, padding: 0, restorer: 0 };
    // A failed source query leaves sa indeterminate; preserve the existing
    // Rust boundary's defined early error instead of reading uninitialized C
    // state. For valid application signals, this is musl's first action call.
    if unsafe { signal_control::sigaction(signal, core::ptr::null(),
        core::ptr::addr_of_mut!(action).cast()) } < 0 {
        return -1;
    }
    if flag != 0 { action.flags &= !SA_RESTART; }
    else { action.flags |= SA_RESTART; }
    unsafe { signal_control::sigaction(signal, core::ptr::addr_of!(action).cast(), core::ptr::null_mut()) }
}
