//! Linkage adapter from the shared pthread owner to retained loader TLS.
//!
//! The loader alone owns module templates, Variant-II placement, DTV and
//! module-size tables. Libc owns only an opaque allocation token, released
//! after the pthread owner proves CLONE_CHILD_CLEARTID and withdraws its
//! registry entry. No FS installation or module discovery occurs here.

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use super::raw_syscall;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct StaticInitialTlsBlock {
    mapping: *mut u8,
    mapping_size: usize,
    thread_pointer: *mut u8,
    allocation_id: usize,
}

impl StaticInitialTlsBlock {
    pub(super) const fn thread_pointer(self) -> *mut u8 { self.thread_pointer }
}

unsafe extern "C" {
    fn __crabc_x86_64_runtime_publish_initial_tid(tid: i32) -> i32;
    fn __crabc_x86_64_runtime_fork_prepare(callback_lock: i32) -> i32;
    fn __crabc_x86_64_runtime_fork_complete(parent_tid: i32, child: i32, callback_lock: i32);
    fn __crabc_x86_64_initial_tls_allocate(block: *mut StaticInitialTlsBlock) -> i32;
    fn __crabc_x86_64_initial_tls_release(block: *const StaticInitialTlsBlock) -> i64;
    fn __crabc_x86_64_resolve_initial_tls(index: *const core::ffi::c_void) -> *mut core::ffi::c_void;
}

/// Resolve compiler-generated GD TLS through its canonical loader owner.
///
/// # Safety
/// `index` must designate two readable native words (module ID, byte offset),
/// and the caller must run on a loader-materialized main or worker TP.
#[no_mangle]
pub unsafe extern "C" fn __tls_get_addr(index: *const core::ffi::c_void) -> *mut core::ffi::c_void {
    unsafe { __crabc_x86_64_resolve_initial_tls(index) }
}

static MAIN_POINTER: AtomicUsize = AtomicUsize::new(0);
static MAIN_ID: AtomicI32 = AtomicI32::new(0);
const ATTACHING_POINTER: usize = usize::MAX;

fn attach_with_tid_handoff(
    main_pointer: &AtomicUsize,
    main_id: &AtomicI32,
    pointer: usize,
    tid: i32,
    publish: impl FnOnce(i32) -> i32,
) -> bool {
    if main_pointer.compare_exchange(0, ATTACHING_POINTER, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return false;
    }
    // The reserved pointer is never a ready TLS identity. A rejected loader
    // handoff returns to the empty state before startup terminates.
    if publish(tid) != 0 {
        main_pointer.store(0, Ordering::Release);
        return false;
    }
    main_id.store(tid, Ordering::Relaxed);
    main_pointer.store(pointer, Ordering::Release);
    true
}

pub(super) unsafe fn attach_initial_thread() -> bool {
    let pointer: usize;
    unsafe { core::arch::asm!("mov {}, fs:[0]", out(reg) pointer, options(nostack, readonly)); }
    let tid = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    if pointer == 0 || tid <= 0 || tid > i32::MAX as i64 { return false; }
    attach_with_tid_handoff(&MAIN_POINTER, &MAIN_ID, pointer, tid as i32,
        |tid| unsafe { __crabc_x86_64_runtime_publish_initial_tid(tid) })
}

pub(super) fn is_ready() -> bool {
    !matches!(MAIN_POINTER.load(Ordering::Acquire), 0 | ATTACHING_POINTER)
}

/// Whether `pointer` (the caller's `%fs:0`) is the initial thread's.
///
/// As musl's `pthread_self`, the thread pointer alone identifies the caller;
/// see the static owner's predicate. No gettid is issued, so TSD and pthread
/// self-queries stay syscall-free. Fork adoption updates the pointer.
pub(super) fn is_initial_thread_pointer(pointer: *mut u8) -> bool {
    !pointer.is_null() && pointer as usize == MAIN_POINTER.load(Ordering::Acquire)
}

/// Copy the recorded initial-task TID for one opaque initial-thread target.
///
/// This target lookup intentionally omits the current-caller `gettid` check:
/// a selected worker may query a saved live process-main `pthread_t`. It
/// compares only the opaque token and copies the loader-recorded TID, without
/// exposing or dereferencing a TCB. The caller must keep the target task live
/// through CPU-clock use; [`is_initial_thread_pointer`] remains the separate
/// current-caller admission predicate.
pub(super) fn selected_initial_thread_id(pointer: *mut u8) -> Option<c_int> {
    if pointer.is_null() || pointer as usize != MAIN_POINTER.load(Ordering::Acquire) {
        return None;
    }
    let thread_id = MAIN_ID.load(Ordering::Acquire);
    (thread_id > 0).then_some(thread_id)
}

pub(super) unsafe fn allocate_thread() -> Option<StaticInitialTlsBlock> {
    if !is_ready() { return None; }
    let mut block = core::mem::MaybeUninit::uninit();
    if unsafe { __crabc_x86_64_initial_tls_allocate(block.as_mut_ptr()) } != 0 { return None; }
    Some(unsafe { block.assume_init() })
}

/// Caller must prove no thread retains this allocation (clear-child-TID and
/// registry withdrawal), and must release this token exactly once.
pub(super) unsafe fn release_thread(block: StaticInitialTlsBlock) -> i64 {
    unsafe { __crabc_x86_64_initial_tls_release(&block) }
}

/// One prepared loader graph/callback transaction. Its caller must consume
/// exactly one completion after the raw fork result; dropping this token is
/// forbidden because cancellation/unwind cannot repair inherited lock owners.
#[must_use]
pub(super) struct PreparedLoaderFork {
    parent_tid: core::num::NonZeroI32,
    callback_lock: bool,
}

impl PreparedLoaderFork {
    /// Complete this exact preparation after libc's internal owners are
    /// callable again. In a full dynamic child, its minimal TID/TSD/main,
    /// robust-list, and signal-target adoption remains earlier; this loader
    /// completion re-roots TLS and constructors before libc discards its
    /// copied selected-worker registry. `_Fork` never prepares this token.
    pub(super) unsafe fn complete(self, child: bool) {
        unsafe { __crabc_x86_64_runtime_fork_complete(
            self.parent_tid.get(), child as i32, self.callback_lock as i32,
        ) }
    }
}

/// Retain the loader's graph and, when another task exists, callback owner.
/// A positive caller TID proves both requested locks were acquired; failure
/// has released every loader lock before returning to libc's parent unwind.
pub(super) unsafe fn prepare_fork(callback_lock: bool) -> Option<PreparedLoaderFork> {
    let tid = unsafe { __crabc_x86_64_runtime_fork_prepare(callback_lock as i32) };
    if tid <= 0 { return None; }
    Some(PreparedLoaderFork { parent_tid: core::num::NonZeroI32::new(tid)?, callback_lock })
}

pub(super) fn is_inherited_initial_thread_pointer(pointer: *mut u8) -> bool {
    !pointer.is_null() && pointer as usize == MAIN_POINTER.load(Ordering::Acquire)
}

/// Fork preserves the active FS image. Only its libc main-task identity
/// changes; the paired loader completion owns allocation-registry adoption.
pub(super) fn adopt_current_thread_after_fork() -> bool {
    let pointer = super::pthread_identity::current_thread_pointer();
    let tid = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    if pointer.is_null() || tid <= 0 || tid > i32::MAX as i64 { return false; }
    MAIN_POINTER.store(pointer as usize, Ordering::Release);
    MAIN_ID.store(tid as i32, Ordering::Relaxed);
    true
}

unsafe extern "C" { fn __crabc_x86_64_reset_current_tls_v1() -> i32; }

/// Reset every current module image through its retained loader owner.
/// # Safety
/// The calling timer worker completed callback/TSD cleanup and blocked
/// application signals. It alone may access its ELF TLS during reset.
pub(super) unsafe fn reset_current_thread_images() {
    if unsafe { __crabc_x86_64_reset_current_tls_v1() } != 0 {
        unsafe { raw_syscall::syscall1(231, 127); }
        loop { core::hint::spin_loop(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_tid_handoff_rejection_rolls_back_unpublished_main_identity() {
        let pointer = AtomicUsize::new(0);
        let id = AtomicI32::new(0);
        assert!(!attach_with_tid_handoff(&pointer, &id, 0x1000, 41, |tid| {
            assert_eq!(tid, 41);
            assert_eq!(pointer.load(Ordering::Acquire), ATTACHING_POINTER);
            assert_eq!(id.load(Ordering::Acquire), 0);
            -1
        }));
        assert_eq!(pointer.load(Ordering::Acquire), 0);
        assert_eq!(id.load(Ordering::Acquire), 0);

        assert!(attach_with_tid_handoff(&pointer, &id, 0x1000, 42, |tid| {
            assert_eq!(tid, 42);
            assert_eq!(pointer.load(Ordering::Acquire), ATTACHING_POINTER);
            0
        }));
        assert_eq!(pointer.load(Ordering::Acquire), 0x1000);
        assert_eq!(id.load(Ordering::Acquire), 42);
        assert!(!attach_with_tid_handoff(&pointer, &id, 0x2000, 43, |_| {
            panic!("a ready main identity accepted a second loader handoff")
        }));
    }
}
