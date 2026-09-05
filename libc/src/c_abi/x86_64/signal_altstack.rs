//! Selected static Linux/x86-64 alternate signal-stack boundary.
//!
//! This is a bounded adaptation of pinned musl 1.2.6
//! `src/signal/sigaltstack.c` at release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! It owns exactly the public `stack_t` preconditions and Linux
//! `sigaltstack=131` result/`errno` convention. The already selected
//! `signal_control` leaf owns action packing and its hidden `rt_sigreturn`
//! restorer; this leaf does not install a handler or choose a delivery
//! policy. The native fixture composes the two only to prove that an
//! `SA_ONSTACK` handler really enters the installed kernel stack and returns
//! through the existing restorer.
//!
//! `stack_t` is a 24-byte, align-eight x86 LP64 record: pointer at zero,
//! signed flags at eight, and `size_t` at sixteen. Linux owns the current
//! stack state, including the transient `SS_ONSTACK` bit while a handler
//! runs. Musl tests an enabled stack's size before it tests `SS_ONSTACK`, so
//! the both-invalid case reports `ENOMEM`; preserve that observable order.
//! The selected static x86 profile deliberately uses the installed fixed
//! `MINSIGSTKSZ=2048` header value, matching the existing AArch64 C-ABI
//! leaf's fixed-header preflight. Musl 1.2.6 instead obtains a dynamic
//! `_SC_MINSIGSTKSZ` value from startup-owned auxv (`AT_MINSIGSTKSZ`). That
//! auxv/sysconf selector is not selected by this archive, so this leaf does
//! not claim that larger
//! dynamic-minimum behavior in its private selection. The owned runtime uses
//! its shared source-backed `system_configuration::minimum_signal_stack_size`
//! helper, preserving musl's size-before-flags validation with startup auxv.
//! All remaining validation, query, disable, and
//! in-handler `EPERM` behavior are the direct Linux 5.10 contract.
//!
//! This is neither a generic signal-disposition framework nor pthread signal
//! policy. It excludes `signalfd`, queued/wait APIs beyond their separately
//! selected artifact, legacy signal helpers, alternate-stack allocation or
//! ownership, cancellation, dynamic runtime/loader TLS, and public x86
//! support.

use core::ffi::{c_int, c_void};

use super::{c_status, errno, raw_syscall};

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const SS_ONSTACK: c_int = 1;
const SS_DISABLE: c_int = 2;
const MINSIGSTKSZ: usize = 2_048;

/// Exact x86 LP64 public `stack_t` record accepted by `sigaltstack(2)`.
#[repr(C)]
struct PublicSignalStack {
    stack_pointer: *mut c_void,
    flags: c_int,
    // Keep C's four bytes before the eight-byte `size_t` field implicit.
    // Callers need initialize only the three public `stack_t` fields; treating
    // the ABI padding as a Rust integer field would incorrectly require those
    // otherwise indeterminate bytes to hold an initialized value.
    size: usize,
}

const _: () = {
    assert!(core::mem::size_of::<PublicSignalStack>() == 24);
    assert!(core::mem::align_of::<PublicSignalStack>() == 8);
    assert!(core::mem::offset_of!(PublicSignalStack, stack_pointer) == 0);
    assert!(core::mem::offset_of!(PublicSignalStack, flags) == 8);
    assert!(core::mem::offset_of!(PublicSignalStack, size) == 16);
};

#[inline]
fn invalid_argument() -> c_int {
    // SAFETY: this selected C ABI owns the calling initial-TLS errno slot.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

#[inline]
fn insufficient_memory() -> c_int {
    // SAFETY: this selected C ABI owns the calling initial-TLS errno slot.
    unsafe { errno::set_errno(ENOMEM) };
    -1
}

/// Install, disable, or query the calling task's alternate signal stack.
///
/// A non-null `stack` must be readable as one complete public x86 `stack_t`.
/// A non-null `old_stack` must be writable as one complete public x86
/// `stack_t`. The caller retains ownership, address validity, and lifetime of
/// an enabled stack until Linux no longer may enter a handler on it. In
/// particular, callers must not free, move, or disable it concurrently with
/// delivery. This narrow leaf neither allocates stack storage nor coordinates
/// concurrent/pthread signal handling.
#[no_mangle]
pub unsafe extern "C" fn sigaltstack(stack: *const c_void, old_stack: *mut c_void) -> c_int {
    if !stack.is_null() {
        // SAFETY: a non-null `stack` is readable for one complete public
        // record under this C entry point's documented caller obligation.
        let requested = unsafe { &*stack.cast::<PublicSignalStack>() };
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        let minimum = MINSIGSTKSZ;
        #[cfg(feature = "x86-owned-static-runtime")]
        let minimum = super::system_configuration::minimum_signal_stack_size();
        if requested.flags & SS_DISABLE == 0 && requested.size < minimum {
            return insufficient_memory();
        }
        if requested.flags & SS_ONSTACK != 0 {
            return invalid_argument();
        }
    }

    // SAFETY: the caller owns the exact public input/output record validity
    // and lifetime. Linux/x86-64 `sigaltstack=131` takes the two pointers in
    // rdi/rsi and returns zero or a raw negative errno.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SIGALTSTACK,
            stack as usize as i64,
            old_stack as usize as i64,
        )
    };
    c_status(result)
}
