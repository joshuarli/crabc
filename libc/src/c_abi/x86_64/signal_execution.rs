//! Selected static Linux/x86-64 C process-signal execution boundary.
//!
//! This is one coherent, deliberately bounded native C signal-state artifact.
//! It adapts pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//!
//! - `src/signal/kill.c` maps to [`kill`].
//! - `src/signal/killpg.c` maps to [`killpg`].
//! - `src/signal/raise.c` maps to [`raise`].
//! - `src/signal/sigqueue.c` maps to [`sigqueue`].
//! - `src/signal/sigtimedwait.c` maps to [`sigtimedwait`].
//! - `src/signal/sigwaitinfo.c` maps to [`sigwaitinfo`].
//! - `src/signal/sigwait.c` maps to [`sigwait`].
//!
//! `raise` and `sigqueue` retain musl's application-signal block/restore
//! transaction around their target-identification and delivery syscalls. The
//! shared selected signal-control leaf owns signal-set helpers and the public
//! mask boundary; this leaf uses its same eight-byte kernel-mask convention
//! privately rather than exporting another mask API. The selected archive has
//! no general pthread/TLS lifecycle, so `raise` obtains its one current task
//! identifier directly through Linux `gettid=186` instead of reading musl's
//! pthread record. That is sufficient for the contained static artifact, not
//! a general thread-directed delivery or pthread contract.
//!
//! The public x86 `siginfo_t` layout is fixed at 128 bytes and align-8. The
//! queued sender form has `si_signo`/`si_errno`/`si_code` at 0/4/8,
//! `si_pid`/`si_uid` at 16/20, and `si_value` at 24. Keep that exact
//! initialization record local: it is not a Rust signal-info API.
//!
//! This artifact deliberately excludes `tgkill`, sigaltstack, signalfd,
//! legacy System-V signal helpers, cancellation points, generic process
//! lifecycle, an allocator, loader/CRT/sysroot integration, and public x86
//! support. The fixture's raw clone/wait/exit plumbing is containment-only and
//! must never become a C export.

use core::ffi::{c_int, c_uint, c_void};
use core::mem::MaybeUninit;

use super::{c_status, errno, process_context, raw_syscall};

const EINVAL: c_int = 22;
const EINTR: i64 = 4;
const SIG_BLOCK: i64 = 0;
const SIG_SETMASK: i64 = 2;
const SI_QUEUE: c_int = -1;
const KERNEL_SIGSET_SIZE: i64 = core::mem::size_of::<u64>() as i64;

/// Musl's x86 application-only signal word; 32 through 34 remain reserved.
const APPLICATION_SIGNAL_MASK: u64 = 0xffff_fffc_7fff_ffff;

/// Exact C ABI payload for `union sigval`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) union SigValue {
    integer: c_int,
    pointer: *mut c_void,
}

/// Private exact x86 queued-signal initialization record.
///
/// The kernel accepts a whole 128-byte `siginfo_t` for
/// `rt_sigqueueinfo(2)`. Only the musl-selected queued sender fields are
/// initialized nonzero; the remainder must stay zero exactly as musl's
/// `memset(&si, 0, sizeof si)` establishes.
#[repr(C, align(8))]
struct QueuedSigInfo {
    signal: c_int,
    error: c_int,
    code: c_int,
    alignment_padding: c_int,
    process_id: c_int,
    user_id: c_uint,
    value: SigValue,
    tail: [u8; 96],
}

const _: () = {
    assert!(core::mem::size_of::<SigValue>() == 8);
    assert!(core::mem::align_of::<SigValue>() == 8);
    assert!(core::mem::size_of::<QueuedSigInfo>() == 128);
    assert!(core::mem::align_of::<QueuedSigInfo>() == 8);
    assert!(core::mem::offset_of!(QueuedSigInfo, signal) == 0);
    assert!(core::mem::offset_of!(QueuedSigInfo, error) == 4);
    assert!(core::mem::offset_of!(QueuedSigInfo, code) == 8);
    assert!(core::mem::offset_of!(QueuedSigInfo, process_id) == 16);
    assert!(core::mem::offset_of!(QueuedSigInfo, user_id) == 20);
    assert!(core::mem::offset_of!(QueuedSigInfo, value) == 24);
};

/// Block musl's application-signal set for one private runtime transaction.
///
/// This is shared only by selected lifecycle owners which pair it with
/// [`restore_application_signals`] on every parent/child/error path. It is not
/// a public signal-mask API or cancellation policy.
#[inline(always)]
pub(super) unsafe fn block_application_signals(saved_mask: *mut u64) {
    let application_mask = APPLICATION_SIGNAL_MASK;
    // SAFETY: both local pointers cover precisely the one x86 kernel signal
    // word. Match musl `__block_app_sigs`: errors are intentionally ignored
    // because valid local storage makes them unreachable for this transition.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            (&application_mask as *const u64) as usize as i64,
            saved_mask as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    };
}

/// Block every kernel-visible signal for one nested `_Fork` transaction.
///
/// The selected process-creation lock has musl's `__abort_lock` obligation:
/// it is acquired only while every signal is blocked, not merely the public
/// application subset. The surrounding `fork` owner restores this saved mask
/// (which still includes its outer application block) before it completes its
/// remaining registry transitions and user callbacks.
#[inline(always)]
pub(super) unsafe fn block_all_signals(saved_mask: *mut u64) {
    let all_signals = u64::MAX;
    // SAFETY: Linux ignores unmaskable bits and reads exactly this complete
    // one-word mask, matching musl's private `__block_all_sigs` transition.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            (&all_signals as *const u64) as usize as i64,
            saved_mask as usize as i64,
            KERNEL_SIGSET_SIZE,
        )
    };
}

/// Restore the saved kernel mask from [`block_application_signals`].
#[inline(always)]
pub(super) unsafe fn restore_application_signals(saved_mask: *const u64) {
    // SAFETY: `saved_mask` is the one kernel word returned by the paired
    // block transition. Match musl `__restore_sigs` and deliberately ignore
    // a kernel failure for this valid local restoration request.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            SIG_SETMASK,
            saved_mask as usize as i64,
            0,
            KERNEL_SIGSET_SIZE,
        )
    };
}

/// Send `signal` to `process_id` through Linux `kill(2)`.
///
/// The usual Linux process/group selector and permission semantics remain
/// caller-owned. This is a process-signal delivery seam only; it does not
/// establish process lifecycle, signal-disposition, or pthread coordination.
#[no_mangle]
pub extern "C" fn kill(process_id: c_int, signal: c_int) -> c_int {
    // SAFETY: Linux `kill(2)` accepts two scalar x86 `int`/`pid_t` words.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_KILL,
            i64::from(process_id),
            i64::from(signal),
        )
    };
    c_status(result)
}

/// Send `signal` to nonnegative process group `process_group`.
///
/// Musl rejects a negative group before forwarding the negated selector to
/// `kill`. Widen before negating so this Rust implementation never creates a
/// signed-overflow edge for the otherwise unspecified C `INT_MIN` expression.
#[no_mangle]
pub extern "C" fn killpg(process_group: c_int, signal: c_int) -> c_int {
    if process_group < 0 {
        // SAFETY: the selected archive owns the calling initial-TLS errno
        // slot, exactly as the shared C status translator does.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }

    // SAFETY: `killpg` is musl's `kill(-pgid, sig)` form. Widening retains
    // the exact Linux low pid_t bits even at the signed boundary.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_KILL,
            -i64::from(process_group),
            i64::from(signal),
        )
    };
    c_status(result)
}

/// Deliver `signal` to the calling task through musl's protected raise path.
///
/// The application-signal mask transaction preserves the caller's prior mask
/// after delivery setup. It is not a generic `tgkill` export or a pthread
/// signal-policy implementation.
#[no_mangle]
pub extern "C" fn raise(signal: c_int) -> c_int {
    let mut saved_mask = 0_u64;
    // SAFETY: both private helpers use complete local one-word mask storage.
    unsafe { block_application_signals(&mut saved_mask) };
    // SAFETY: `gettid` has no arguments. Its normal Linux result is the
    // current task id, which `tkill` then consumes as one scalar word.
    let thread_id = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    // SAFETY: `tkill` takes a current task id and the caller's scalar signal.
    let result = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_TKILL, thread_id, i64::from(signal))
    };
    // SAFETY: restore the exact pre-transaction kernel mask before publishing
    // the delivery syscall result, matching musl's ordering.
    unsafe { restore_application_signals(&saved_mask) };
    c_status(result)
}

/// Queue one signal with the caller's selected `sigval` payload.
///
/// The public `siginfo_t` sender fields are initialized exactly as musl's
/// `sigqueue.c` does. Linux validates target, signal, and permission; this
/// leaf provides no queue lifetime, signal-handler, or thread policy.
#[no_mangle]
pub extern "C" fn sigqueue(process_id: c_int, signal: c_int, value: SigValue) -> c_int {
    let mut info = QueuedSigInfo {
        signal,
        error: 0,
        code: SI_QUEUE,
        alignment_padding: 0,
        process_id: 0,
        // Musl captures the real uid before the protected transaction.
        user_id: process_context::getuid(),
        value,
        tail: [0; 96],
    };
    let mut saved_mask = 0_u64;
    // SAFETY: both private helpers use complete local one-word mask storage.
    unsafe { block_application_signals(&mut saved_mask) };
    // Musl captures its sender pid after application signals are blocked.
    info.process_id = process_context::getpid();
    // SAFETY: Linux reads the complete initialized 128-byte `siginfo_t` and
    // receives the two scalar C ABI words unchanged.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_RT_SIGQUEUEINFO,
            i64::from(process_id),
            i64::from(signal),
            (&info as *const QueuedSigInfo) as usize as i64,
        )
    };
    // SAFETY: restore the exact pre-transaction kernel mask before publishing
    // the queue result, matching musl's ordering.
    unsafe { restore_application_signals(&saved_mask) };
    c_status(result)
}

/// Wait for one selected pending signal, retrying interrupted waits as musl.
///
/// # Safety
///
/// `mask` must be readable for its first eight-byte kernel signal word.
/// `info` must be null or valid writable storage for one complete x86 public
/// 128-byte `siginfo_t`; `timeout` must be null or a valid readable x86
/// `struct timespec`. Their lifetimes must cover the kernel call. This direct
/// static leaf deliberately omits musl's cancellation-point machinery.
#[no_mangle]
pub unsafe extern "C" fn sigtimedwait(
    mask: *const c_void,
    info: *mut c_void,
    timeout: *const c_void,
) -> c_int {
    loop {
        // SAFETY: the caller owns all three pointer contracts. Linux x86
        // consumes one eight-byte mask word as pinned musl does.
        let result = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_RT_SIGTIMEDWAIT,
                mask as usize as i64,
                info as usize as i64,
                timeout as usize as i64,
                KERNEL_SIGSET_SIZE,
            )
        };
        if result != -EINTR {
            return c_status(result);
        }
    }
}

/// Wait indefinitely for one selected pending signal.
///
/// # Safety
///
/// `mask` and `info` have the same pointer/lifetime requirements as
/// [`sigtimedwait`].
#[no_mangle]
pub unsafe extern "C" fn sigwaitinfo(mask: *const c_void, info: *mut c_void) -> c_int {
    // SAFETY: this is musl's null-timeout forwarding wrapper.
    unsafe { sigtimedwait(mask, info, core::ptr::null()) }
}

/// Wait indefinitely and publish only the delivered signal number.
///
/// # Safety
///
/// `mask` must have the same readable kernel-word lifetime as
/// [`sigtimedwait`], and `signal` must be writable for one C `int` if a wait
/// succeeds. This source mapping follows pinned musl exactly: a failed wait
/// returns `-1` with the errno already set by [`sigtimedwait`], rather than a
/// positive errno value. The older baseline discrepancy is being corrected at
/// its source and is not selected behavior.
#[no_mangle]
pub unsafe extern "C" fn sigwait(mask: *const c_void, signal: *mut c_int) -> c_int {
    let mut info = MaybeUninit::<QueuedSigInfo>::uninit();
    // SAFETY: the complete local record is writable as one x86 `siginfo_t`.
    // The caller owns `mask`; null timeout implements `sigwaitinfo` behavior.
    let result = unsafe {
        sigtimedwait(
            mask,
            info.as_mut_ptr().cast(),
            core::ptr::null(),
        )
    };
    if result < 0 {
        return -1;
    }
    // SAFETY: a successful kernel wait initialized the leading signal field,
    // and this public entry point requires writable caller signal storage.
    unsafe { core::ptr::write(signal, result) };
    0
}
