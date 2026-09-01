//! Selected static Linux/x86-64 C signal-control boundary.
//!
//! This is a narrow, deliberately non-pthread adaptation of pinned musl 1.2.6
//! revision `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT
//! license. Its source mapping is `src/signal/sigaction.c` (validation,
//! action conversion, and partial old-action writes), `signal.c`,
//! `sigemptyset.c`, and `sigismember.c`;
//! `sigprocmask.c` supplies its public errno convention while
//! `src/thread/pthread_sigmask.c` supplies the one-word syscall and returned
//! reserved-bit filtering. It reuses the x86 `SA_RESTORER`/`rt_sigreturn`
//! machinery from `signal_foundation.rs`.
//!
//! The selected artifact owns only application signal-set helpers, simple
//! disposition installation/query, and a calling-thread mask boundary.
//! It deliberately excludes generic process or thread delivery, waits and
//! cancellation points, queues, alternate stacks, pthread signal policy,
//! legacy helpers, and a general signal-management framework. Musl's pthread
//! bookkeeping for those excluded paths is not recreated here. Kernel-to-public
//! mask and old-action expansion retain musl's partial-write contract: only
//! kernel-visible fields change; public tail storage, padding, and restorer
//! bytes remain caller-resident. `sigprocmask` still forwards the caller's raw
//! kernel-visible word and only clears musl's reserved 32–34 bits when it
//! reports an old mask. The intentionally excluded `sigaction.c` behavior is
//! the `handler_set`/`__eintr_valid_flag` bookkeeping, first-real-handler
//! internal-signal unmask, and SIGABRT abort-lock wrapping; those require the
//! pthread/runtime policy this static artifact does not claim.

use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;

use super::{
    c_status, errno, raw_syscall,
    signal_foundation::{self, KernelSigAction, PublicSigAction, PUBLIC_SIGSET_WORDS},
};

const EINVAL: c_int = 22;
const SIG_ERR: usize = usize::MAX;
const APPLICATION_SIGNAL_MAX: c_int = 64;
const SA_RESTART: i32 = 0x1000_0000;
const RESERVED_SIGNAL_MASK: u64 = (1_u64 << 31) | (1_u64 << 32) | (1_u64 << 33);

// Pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`
// implements `src/signal/signal.c::signal`, then emits
// `weak_alias(signal, bsd_signal)` and `weak_alias(signal, __sysv_signal)`.
// Keep this ABI-only compatibility leaf opt-in, and emit its alias directives
// beside the strong `signal` body. A separate archive member cannot form a
// defined ELF `.set` alias to this member's body, while a Rust forwarding
// wrapper would lose musl's weak same-address and override contract. This
// feature adds no signal behavior; it leaves the default selected-static
// archive surface unchanged.
#[cfg(feature = "x86-signal-legacy-aliases")]
core::arch::global_asm!(
    ".weak bsd_signal",
    ".set bsd_signal, signal",
    ".weak __sysv_signal",
    ".set __sysv_signal, signal",
);

#[inline]
fn invalid_argument() -> c_int {
    // SAFETY: The selected static C ABI owns the one initial-TLS errno slot.
    unsafe { errno::set_errno(EINVAL) };
    -1
}

#[inline]
fn is_application_signal(signal: c_int) -> bool {
    signal > 0 && signal <= APPLICATION_SIGNAL_MAX && !(32..=34).contains(&signal)
}

/// Install or query one application signal disposition through Linux.
///
/// # Safety
///
/// `action` and `old_action` must be null or point to complete readable and
/// writable x86 public `struct sigaction` records, respectively. An installed
/// handler must remain valid for asynchronous entry until a later replacement;
/// this narrow artifact supplies the required x86 restorer but not pthread
/// signal coordination or a general handler-lifecycle policy.
unsafe fn sigaction_impl(
    signal: c_int,
    action: *const PublicSigAction,
    old_action: *mut PublicSigAction,
) -> c_int {
    if !is_application_signal(signal) {
        return invalid_argument();
    }

    let mut kernel_action = MaybeUninit::<KernelSigAction>::uninit();
    let action_pointer = if action.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: `action` satisfies this C entry point's public-record
        // contract, and `kernel_action` is writable local storage.
        unsafe { signal_foundation::pack_public_action(action, kernel_action.as_mut_ptr()) };
        kernel_action.as_ptr()
    };
    let mut old_kernel_action = MaybeUninit::<KernelSigAction>::uninit();
    let old_action_pointer = if old_action.is_null() {
        core::ptr::null_mut()
    } else {
        old_kernel_action.as_mut_ptr()
    };
    // SAFETY: the action pointers name either null or the exact compact/public
    // records prepared above. Linux x86 requires the kernel mask size of eight.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGACTION,
            i64::from(signal),
            action_pointer as usize as i64,
            old_action_pointer as usize as i64,
            core::mem::size_of::<u64>() as i64,
        )
    };
    if result < 0 {
        return c_status(result);
    }
    if !old_action.is_null() {
        // SAFETY: Linux reported success after writing the requested compact
        // output record, and the caller supplied a complete public output.
        unsafe {
            signal_foundation::unpack_kernel_action(old_kernel_action.as_ptr(), old_action)
        };
    }
    0
}

/// Install or query one selected application signal disposition.
///
/// # Safety
///
/// `action` and `old_action` are null or valid x86 public `struct sigaction`
/// records as described by [`sigaction_impl`]. A non-default/non-ignore
/// handler must remain callable through asynchronous signal delivery until it
/// is replaced. This artifact does not make that lifetime process-wide or
/// pthread-safe.
#[no_mangle]
pub unsafe extern "C" fn sigaction(
    signal: c_int,
    action: *const c_void,
    old_action: *mut c_void,
) -> c_int {
    // SAFETY: the C caller owns both public signal-action pointer contracts.
    unsafe { sigaction_impl(signal, action.cast(), old_action.cast()) }
}

/// Set a simple BSD/musl-restart signal disposition and return the old handler.
///
/// # Safety
///
/// `handler` must be a valid signal handler address, `SIG_DFL`, or `SIG_IGN`
/// for as long as Linux may enter it. This narrow artifact does not provide a
/// pthread-safe handler lifetime or signal-disposition framework.
#[no_mangle]
pub unsafe extern "C" fn signal(signal: c_int, handler: usize) -> usize {
    let action = PublicSigAction {
        handler,
        mask: [0; PUBLIC_SIGSET_WORDS],
        flags: SA_RESTART,
        padding: 0,
        restorer: 0,
    };
    // `sigaction_impl` intentionally preserves musl's partial old-action
    // writes, so seed this local record before reading the returned handler.
    let mut old_action = PublicSigAction {
        handler: 0,
        mask: [0; PUBLIC_SIGSET_WORDS],
        flags: 0,
        padding: 0,
        restorer: 0,
    };
    // SAFETY: both records are complete local storage. The caller owns the
    // handler lifetime.
    if unsafe { sigaction_impl(signal, &action, &mut old_action) } < 0 {
        SIG_ERR
    } else {
        old_action.handler
    }
}

/// Clear the first kernel-visible word of a public x86 signal set.
///
/// # Safety
///
/// `set` must point to writable storage for one x86 public `sigset_t`.
#[no_mangle]
pub unsafe extern "C" fn sigemptyset(set: *mut c_void) -> c_int {
    // Musl exposes only the kernel-visible word through these helper APIs.
    // SAFETY: the C caller owns the writable public-set storage.
    unsafe { core::ptr::write_unaligned(set.cast::<u64>(), 0) };
    0
}

/// Report whether one valid Linux signal bit is present in a public x86 set.
///
/// # Safety
///
/// `set` must point to readable storage for one x86 public `sigset_t`.
#[no_mangle]
pub unsafe extern "C" fn sigismember(set: *const c_void, signal: c_int) -> c_int {
    if signal <= 0 || signal > APPLICATION_SIGNAL_MAX {
        return 0;
    }
    // SAFETY: the C caller owns the readable public-set storage.
    let word = unsafe { core::ptr::read_unaligned(set.cast::<u64>()) };
    ((word >> (signal - 1)) & 1) as c_int
}

/// Change or query the calling thread's selected application signal mask.
///
/// # Safety
///
/// `set` and `old_set` must be null or point to complete readable and writable
/// x86 public `sigset_t` records, respectively. Like musl, this wrapper
/// forwards the caller's kernel-visible input word, but clears 32–34 from a
/// returned old mask. It intentionally excludes pthread cancellation and
/// reserved-signal lifecycle.
#[no_mangle]
pub unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const c_void,
    old_set: *mut c_void,
) -> c_int {
    // Musl forwards a caller's raw first word to the kernel. Its pthread
    // wrapper filters the reserved bits only when publishing `old_set`.
    // SAFETY: Linux consumes or writes exactly one kernel signal-set word at
    // each non-null pointer. Passing `old_set` through directly also retains
    // musl's EFAULT behavior for an invalid non-null output pointer.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGPROCMASK,
            i64::from(how),
            set as usize as i64,
            old_set as usize as i64,
            core::mem::size_of::<u64>() as i64,
        )
    };
    if result < 0 {
        return c_status(result);
    }
    if !old_set.is_null() {
        // SAFETY: Linux filled the first public word on this successful call.
        // Match musl's pthread_sigmask post-processing for 32–34 without
        // touching the remaining caller-resident public-set tail.
        unsafe {
            let old_mask = core::ptr::read_unaligned(old_set.cast::<u64>());
            core::ptr::write_unaligned(
                old_set.cast::<u64>(),
                old_mask & !RESERVED_SIGNAL_MASK,
            );
        };
    }
    0
}
