//! Selected static Linux/x86-64 `siginterrupt` C boundary.
//!
//! This private one-symbol adaptation translates the body of pinned musl
//! 1.2.6 release revision `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license, `src/signal/siginterrupt.c`:
//!
//! ```c
//! sigaction(sig, 0, &sa);
//! if (flag) sa.sa_flags &= ~SA_RESTART;
//! else sa.sa_flags |= SA_RESTART;
//! return sigaction(sig, &sa, 0);
//! ```
//!
//! The selected closure is two direct Linux `rt_sigaction=13` calls and the
//! existing private x86 public/kernel action-record conversion. The first call
//! obtains the action, only `SA_RESTART=0x10000000` changes, and the second
//! replaces it. It deliberately does not call or export the separately
//! selected `sigaction` ABI: this keeps the final static candidate to one
//! legacy-XSI action-metadata adapter rather than pulling a public action,
//! signal-set, or mask surface.
//!
//! Musl's source ignores a failed first query and then reads its uninitialized
//! local record. A sound Rust boundary cannot reproduce that undefined path,
//! so a query failure instead becomes the normal C `-1` plus initial-TLS
//! `errno` result before any replacement. For musl's defined application
//! signal domain (1 through 64 except its reserved 32 through 34), the query
//! has no caller pointers and succeeds; `SIGKILL` and `SIGSTOP` still reach
//! Linux's replacement rejection. Like the existing selected signal-control
//! action substrate, this leaf intentionally omits musl's handler-set,
//! internal-signal-unmask, EINTR-validity, and SIGABRT locking bookkeeping.
//! Those are general handler/runtime policy, not this scalar flag mutation.
//!
//! This does not select handler installation or lifetime, generic signal
//! actions, masks or signal-set helpers, delivery, waits, queues, descriptors,
//! timers, pthread policy, process control, dynamic runtime/loader/CRT/sysroot
//! state, signal-family completion, promotion, or public x86 support.

use core::ffi::c_int;
use core::mem::MaybeUninit;

use super::{
    c_status, raw_syscall,
    signal_foundation::{self, KernelSigAction, PublicSigAction},
};

const EINVAL: c_int = 22;
const APPLICATION_SIGNAL_MAX: c_int = 64;
const SA_RESTART: c_int = 0x1000_0000;
const KERNEL_SIGSET_SIZE: i64 = core::mem::size_of::<u64>() as i64;

#[inline]
fn is_application_signal(signal: c_int) -> bool {
    signal > 0 && signal <= APPLICATION_SIGNAL_MAX && !(32..=34).contains(&signal)
}

#[inline]
fn action_flags_pointer(action: *mut PublicSigAction) -> *mut c_int {
    // SAFETY: `PublicSigAction`'s x86 layout is asserted by the private
    // foundation leaf. The caller supplies storage for one complete record;
    // this scalar entry reads/writes only the initialized flags field.
    unsafe {
        action
            .cast::<u8>()
            .add(core::mem::offset_of!(PublicSigAction, flags))
            .cast::<c_int>()
    }
}

/// Toggle only `SA_RESTART` on one existing application signal action.
///
/// A nonzero `flag` clears `SA_RESTART`; zero sets it. Linux owns the existing
/// disposition, its handler/restorer lifetime, and the final `EINVAL` for a
/// nonreplaceable disposition such as `SIGKILL`. This one-symbol legacy entry
/// does not install a handler or expose a general action-management interface.
#[no_mangle]
pub extern "C" fn siginterrupt(signal: c_int, flag: c_int) -> c_int {
    if !is_application_signal(signal) {
        // `sigaction` in musl rejects this domain before it reaches the
        // source body's local-record sequence. Publish the selected C error
        // convention without a raw action query.
        return c_status(-i64::from(EINVAL));
    }

    let mut old_kernel_action = MaybeUninit::<KernelSigAction>::uninit();
    // SAFETY: the first direct query has no caller pointers and gives Linux a
    // writable local 32-byte kernel record plus its required eight-byte mask
    // size. This is the first `sigaction(sig, 0, &sa)` step in musl's body.
    let queried = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGACTION,
            i64::from(signal),
            0,
            old_kernel_action.as_mut_ptr() as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    };
    if queried < 0 {
        return c_status(queried);
    }

    // `unpack_kernel_action` initializes exactly the handler, first mask
    // word, and flags bytes that `pack_public_action` subsequently reads.
    // Keep the unused public tail uninitialized as musl does.
    let mut public_action = MaybeUninit::<PublicSigAction>::uninit();
    // SAFETY: Linux completed the local kernel record on success, and the
    // private conversion writes its exact public fields into complete local
    // storage without observing the tail.
    unsafe {
        signal_foundation::unpack_kernel_action(
            old_kernel_action.as_ptr(),
            public_action.as_mut_ptr(),
        )
    };

    let flags = action_flags_pointer(public_action.as_mut_ptr());
    // SAFETY: the conversion above initialized this exact aligned `int` field
    // and this scalar leaf is its sole mutable owner.
    let current_flags = unsafe { flags.read_unaligned() };
    let updated_flags = if flag != 0 {
        current_flags & !SA_RESTART
    } else {
        current_flags | SA_RESTART
    };
    // SAFETY: see the matching read; this modifies exactly musl's field.
    unsafe { flags.write_unaligned(updated_flags) };

    let mut new_kernel_action = MaybeUninit::<KernelSigAction>::uninit();
    // SAFETY: the local partial public record has every field this private
    // x86 converter reads, and `new_kernel_action` is complete writable local
    // storage. It adds only the existing hidden rt_sigreturn restorer.
    unsafe {
        signal_foundation::pack_public_action(
            public_action.as_ptr(),
            new_kernel_action.as_mut_ptr(),
        )
    };
    // SAFETY: Linux receives the fully packed local kernel action and no old
    // output pointer. This is musl's final `sigaction(sig, &sa, 0)` step.
    let replaced = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGACTION,
            i64::from(signal),
            new_kernel_action.as_ptr() as usize as i64,
            0,
            KERNEL_SIGSET_SIZE,
        )
    };
    c_status(replaced)
}
