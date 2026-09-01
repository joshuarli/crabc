//! Opt-in Linux/x86-64 System V signal-helper C ABI boundary.
//!
//! This private artifact is a direct adaptation of pinned musl 1.2.6 release
//! commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT
//! license. Its source mapping is `src/signal/sighold.c`,
//! `src/signal/sigignore.c`, `src/signal/sigrelse.c`, and
//! `src/signal/sigset.c`. The source's calls to `sigemptyset`, `sigaddset`,
//! `sigaction`, and `sigprocmask` reduce to one zeroed private kernel mask,
//! one application-signal validation, and direct Linux `rt_sigaction=13` /
//! `rt_sigprocmask=14` requests on x86-64.
//!
//! Keeping those calls private is intentional. The four-symbol feature must
//! not pull the separately selected public action, mask, or signal-set entry
//! points into its freestanding candidate merely because musl composes those
//! source helpers in the full libc. It uses the existing private x86 action
//! packing leaf only to retain musl's public/kernel record conversion and
//! hidden `rt_sigreturn` restorer. It has no handler bookkeeping, internal
//! signal unmasking, EINTR-validity state, SIGABRT lock, pthread policy, or
//! cancellation behavior. This artifact does not select `process.signal`, a
//! general signal-control interface, family completion, promotion, or public
//! x86 support.

use core::ffi::c_int;
use core::mem::MaybeUninit;

use super::{
    c_status, errno, raw_syscall,
    signal_foundation::{self, KernelSigAction, PublicSigAction, PUBLIC_SIGSET_WORDS},
};

const EINVAL: c_int = 22;
const APPLICATION_SIGNAL_MAX: c_int = 64;
const SIG_ERR: usize = usize::MAX;
const SIG_HOLD: usize = 2;
const SIG_BLOCK: i64 = 0;
const SIG_UNBLOCK: i64 = 1;
const KERNEL_SIGSET_SIZE: i64 = core::mem::size_of::<u64>() as i64;

#[inline]
fn application_signal_mask(signal: c_int) -> Option<u64> {
    if signal <= 0 || signal > APPLICATION_SIGNAL_MAX || (32..=34).contains(&signal) {
        return None;
    }
    Some(1_u64 << (signal - 1))
}

#[inline]
fn invalid_argument() -> c_int {
    // SAFETY: this selected C entry owns initial-TLS errno publication for
    // its pre-syscall input rejection, exactly as musl's sigaddset path does.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

/// Issue one raw Linux x86 `rt_sigprocmask` request with a local one-word set.
///
/// # Safety
///
/// `set` and `old_set` must be null or remain valid for Linux to read/write
/// one eight-byte kernel signal-set word throughout the syscall.
// Keep each helper's one-word raw syscall visible in its own freestanding
// implementation; this avoids turning the closed ABI proof into a separately
// emitted helper object with an accidental callable surface.
#[inline(always)]
unsafe fn raw_mask_change(how: i64, set: *const u64, old_set: *mut u64) -> i64 {
    // SAFETY: the caller provides the exact x86 kernel-mask pointer contract;
    // Linux expects its fixed one-word size in the fourth syscall argument.
    unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            how,
            set as usize as i64,
            old_set as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    }
}

/// Issue one raw Linux x86 `rt_sigaction` request with compact action records.
///
/// # Safety
///
/// `action` and `old_action` must be null or remain valid for Linux to read
/// and write one complete 32-byte x86 kernel signal-action record.
// The action transition has the same closed one-call shape as the mask path.
#[inline(always)]
unsafe fn raw_action_change(
    signal: c_int,
    action: *const KernelSigAction,
    old_action: *mut KernelSigAction,
) -> i64 {
    // SAFETY: the caller provides compact Linux action records and the exact
    // x86 one-word kernel signal-set size required by rt_sigaction.
    unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGACTION,
            i64::from(signal),
            action as usize as i64,
            old_action as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    }
}

#[inline]
fn public_action(handler: usize) -> PublicSigAction {
    // Musl initializes only the handler, zero flags, and its signal-set word
    // before sigaction packs the public record. The private x86 packing leaf
    // reads exactly these fields and supplies the hidden restorer itself.
    PublicSigAction {
        handler,
        mask: [0; PUBLIC_SIGSET_WORDS],
        flags: 0,
        padding: 0,
        restorer: 0,
    }
}

/// Block one valid application signal in the calling task's kernel mask.
///
/// This is musl `sighold`: it builds one private signal set and forwards it to
/// `sigprocmask(SIG_BLOCK, ...)`. It neither observes nor changes handler
/// state, cancellation, or a pthread-owned mask policy.
#[no_mangle]
pub extern "C" fn sighold(signal: c_int) -> c_int {
    let Some(mask) = application_signal_mask(signal) else {
        return invalid_argument();
    };
    // SAFETY: `mask` is a valid private one-word input for this synchronous
    // raw syscall, and no old-mask output is requested.
    c_status(unsafe { raw_mask_change(SIG_BLOCK, &mask, core::ptr::null_mut()) })
}

/// Install `SIG_IGN` for one valid application signal.
///
/// The caller retains all wider disposition and handler-lifetime obligations.
/// This source-shaped helper owns only the zero-mask/zero-flags ignore action
/// and its direct kernel result; it is not a general signal action API.
#[no_mangle]
pub extern "C" fn sigignore(signal: c_int) -> c_int {
    if application_signal_mask(signal).is_none() {
        return invalid_argument();
    }

    let action = public_action(1);
    let mut kernel_action = MaybeUninit::<KernelSigAction>::uninit();
    // SAFETY: `action` initializes every public field the private x86 packer
    // consumes, and `kernel_action` is complete writable local storage.
    unsafe {
        signal_foundation::pack_public_action(&action, kernel_action.as_mut_ptr())
    };
    // SAFETY: Linux reads the packed local record and no old action is
    // requested. The action's embedded restorer stays private to this archive.
    c_status(unsafe {
        raw_action_change(signal, kernel_action.as_ptr(), core::ptr::null_mut())
    })
}

/// Unblock one valid application signal in the calling task's kernel mask.
///
/// This is musl `sigrelse`, the exact `SIG_UNBLOCK` sibling of `sighold`; it
/// has no public signal-set, handler, pthread, or cancellation surface.
#[no_mangle]
pub extern "C" fn sigrelse(signal: c_int) -> c_int {
    let Some(mask) = application_signal_mask(signal) else {
        return invalid_argument();
    };
    // SAFETY: `mask` is a valid private one-word input for this synchronous
    // raw syscall, and no old-mask output is requested.
    c_status(unsafe { raw_mask_change(SIG_UNBLOCK, &mask, core::ptr::null_mut()) })
}

/// Install one disposition or hold one signal, returning musl's old state.
///
/// `handler` must be `SIG_DFL`, `SIG_IGN`, `SIG_HOLD`, or remain callable for
/// as long as Linux can enter it. This legacy helper does not make handler
/// lifetime safe, coordinate concurrent action changes, or supply pthread
/// signal/cancellation policy.
#[no_mangle]
pub extern "C" fn sigset(signal: c_int, handler: usize) -> usize {
    let Some(mask) = application_signal_mask(signal) else {
        let _ = invalid_argument();
        return SIG_ERR;
    };

    let mut old_action = MaybeUninit::<KernelSigAction>::uninit();
    let action_result = if handler == SIG_HOLD {
        // SAFETY: the local output record is complete writable storage; musl
        // queries the current disposition before it blocks a held signal.
        unsafe {
            raw_action_change(signal, core::ptr::null(), old_action.as_mut_ptr())
        }
    } else {
        let action = public_action(handler);
        let mut kernel_action = MaybeUninit::<KernelSigAction>::uninit();
        // SAFETY: `action` initializes every field the private packer reads.
        unsafe {
            signal_foundation::pack_public_action(&action, kernel_action.as_mut_ptr())
        };
        // SAFETY: Linux reads the packed local action and writes one complete
        // old record before the following mask transition.
        unsafe { raw_action_change(signal, kernel_action.as_ptr(), old_action.as_mut_ptr()) }
    };
    if c_status(action_result) != 0 {
        return SIG_ERR;
    }

    let mut old_mask = 0_u64;
    let how = if handler == SIG_HOLD {
        SIG_BLOCK
    } else {
        SIG_UNBLOCK
    };
    // SAFETY: the private input/output words are valid for Linux's exact
    // one-word signal-mask request. It is the second source call in either
    // musl sigset branch.
    if c_status(unsafe { raw_mask_change(how, &mask, &mut old_mask) }) != 0 {
        return SIG_ERR;
    }

    // SAFETY: the successful raw action query/replacement completed this
    // compact record. The old handler is the only returned action field musl
    // observes for this legacy ABI.
    let old_handler = unsafe { old_action.assume_init() }.handler;
    if old_mask & mask != 0 {
        SIG_HOLD
    } else {
        old_handler
    }
}
