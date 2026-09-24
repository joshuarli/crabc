//! Owned Linux/x86-64 C11 `at_quick_exit` and `quick_exit` registry.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/exit/at_quick_exit.c::{at_quick_exit,__funcs_on_quick_exit}` maps to
//! this module's registration, drain, and fork-guard seams. Its fixed
//! `COUNT == 32` function table and count are retained. Its `LOCK(lock)` and
//! `UNLOCK(lock)` use `src/thread/__lock.c::{__lock,__unlock}`'s sign-bit
//! congestion word, bounded spin, and private futex wait/wake protocol.
//! `src/exit/quick_exit.c::quick_exit` maps to this module's final dispatch
//! through the separately selected `_Exit` owner. The source archive is
//! retained locally at `.work/x86_64/source-oracles/musl-1.2.6.tar.gz` while
//! this implementation is developed.
//!
//! Musl returns `-1` at the fixed capacity without writing `errno`. The drain
//! decrements before it unlocks around each user callback, then reacquires and
//! rechecks the count. Thus a callback may make a new valid registration and
//! it is dispatched in the same quick-exit transition. The final empty-table
//! return deliberately retains the lock, just as the source does: the only
//! caller is `quick_exit`, which immediately enters `_Exit` and cannot return.
//! Fork uses the source's `__at_quick_exit_lockptr` role: the outer fork
//! transaction holds this private guard over raw fork, releases it in the
//! parent/error process, and clears its copied word in the sole child.
//!
//! This source-specific fixed registry adds no allocator, reusable lock
//! framework, errno state, stdio flush, ordinary `atexit` dispatch, DSO
//! finalization, or concurrent quick-exit supervisor. Valid C callers supply
//! an executable, non-null function pointer and keep it valid through every
//! possible quick-exit dispatch. Concurrent `quick_exit` calls follow musl's
//! quiescent-user contract and are not separately coordinated here.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("owned quick-exit support requires little-endian Linux/x86-64");

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

use super::immediate_termination;

const QUICK_EXIT_CAPACITY: usize = 32;
type QuickExitFunction = unsafe extern "C" fn();

// This is intentionally a private source-specific musl `__lock` word rather
// than a reusable lock abstraction. The sign bit records ownership and the
// remaining value tracks congestion, including its copied-child reset at fork.
static QUICK_EXIT_LOCK: AtomicI32 = AtomicI32::new(0);
static mut QUICK_EXIT_COUNT: usize = 0;
static mut QUICK_EXIT_FUNCTIONS: [Option<QuickExitFunction>; QUICK_EXIT_CAPACITY] =
    [None; QUICK_EXIT_CAPACITY];

/// Acquire the quick-exit registry lock word as pinned musl `__lock`.
#[inline]
unsafe fn lock_registry() {
    super::musl_lock::lock(&QUICK_EXIT_LOCK);
}

/// Release the quick-exit registry lock word as pinned musl `__unlock`.
#[inline]
unsafe fn unlock_registry() {
    super::musl_lock::unlock(&QUICK_EXIT_LOCK);
}

/// Register one C11 quick-exit callback in musl's fixed 32-slot table.
///
/// # Safety
///
/// `callback` is an executable C function that remains valid until it is
/// called by a later `quick_exit`; it returns normally and follows the
/// process's quiescent quick-exit contract.
#[no_mangle]
pub unsafe extern "C" fn at_quick_exit(callback: QuickExitFunction) -> c_int {
    unsafe { lock_registry() };
    let count = unsafe { QUICK_EXIT_COUNT };
    if count == QUICK_EXIT_CAPACITY {
        unsafe { unlock_registry() };
        return -1;
    }
    // SAFETY: the guard serializes the bounded table/count pair. `callback`
    // has the valid C function-pointer contract documented above.
    unsafe {
        QUICK_EXIT_FUNCTIONS[count] = Some(callback);
        QUICK_EXIT_COUNT = count + 1;
    }
    unsafe { unlock_registry() };
    0
}

/// Drain C11 quick-exit callbacks in LIFO order.
///
/// This is musl's private `__funcs_on_quick_exit` operation. At its empty
/// return the guard remains held for the immediately following `_Exit`; Rust
/// keeps it internal because musl's `libc.h` declares it hidden.
///
/// # Safety
///
/// Call only as the terminal portion of `quick_exit`; callbacks must satisfy
/// the registration contract and return normally.
unsafe fn funcs_on_quick_exit() {
    unsafe { lock_registry() };
    while unsafe { QUICK_EXIT_COUNT } != 0 {
        // Decrement before callback execution so a reentrant registration
        // observes a newly free source slot and the post-callback loop sees it.
        let index = unsafe {
            QUICK_EXIT_COUNT -= 1;
            QUICK_EXIT_COUNT
        };
        let callback = unsafe { QUICK_EXIT_FUNCTIONS[index] };
        // Valid C registration cannot contain a null callback. Preserve that
        // contract instead of manufacturing a null-pointer compatibility rule.
        let callback = unsafe { callback.unwrap_unchecked() };
        unsafe { unlock_registry() };
        unsafe { callback() };
        unsafe { lock_registry() };
    }
}

/// Run the quick-exit table and terminate without ordinary exit processing.
///
/// # Safety
///
/// Every registered callback follows the `at_quick_exit` contract. Concurrent
/// callers arrange musl's required quiescence before either calls `quick_exit`.
#[no_mangle]
pub unsafe extern "C" fn quick_exit(status: c_int) -> ! {
    unsafe { funcs_on_quick_exit() };
    immediate_termination::_Exit(status)
}

/// Acquire the copied quick-exit guard before raw `fork`.
///
/// # Safety
/// The caller makes exactly one matching parent/error or child completion
/// before user callbacks resume.
pub(super) unsafe fn pthread_fork_prepare() {
    unsafe { lock_registry() };
}

/// Release the original-process quick-exit guard after raw `fork`.
///
/// # Safety
/// This completes one preceding `pthread_fork_prepare` in the parent or
/// failed-fork process.
pub(super) unsafe fn pthread_fork_parent() {
    unsafe { unlock_registry() };
}

/// Clear the copied quick-exit guard in the sole `fork` child.
///
/// # Safety
/// This runs once after the matching prepared raw fork, before user callbacks.
pub(super) unsafe fn pthread_fork_child() {
    QUICK_EXIT_LOCK.store(0, Ordering::Relaxed);
}
