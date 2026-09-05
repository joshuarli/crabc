//! Linkage adapter from the shared pthread owner to retained loader TLS.
//!
//! The loader alone owns module templates, Variant-II placement, DTV and
//! module-size tables. Libc owns only an opaque allocation token, released
//! after the pthread owner proves CLONE_CHILD_CLEARTID and withdraws its
//! registry entry. No FS installation or module discovery occurs here.

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

pub(super) unsafe fn attach_initial_thread() -> bool {
    let pointer: usize;
    unsafe { core::arch::asm!("mov {}, fs:[0]", out(reg) pointer, options(nostack, readonly)); }
    let tid = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) };
    if pointer == 0 || tid <= 0 || tid > i32::MAX as i64 { return false; }
    MAIN_ID.store(tid as i32, Ordering::Relaxed);
    MAIN_POINTER.compare_exchange(0, pointer, Ordering::Release, Ordering::Relaxed).is_ok()
}

pub(super) fn is_ready() -> bool { MAIN_POINTER.load(Ordering::Acquire) != 0 }

pub(super) fn is_initial_thread_pointer(pointer: *mut u8) -> bool {
    !pointer.is_null() && pointer as usize == MAIN_POINTER.load(Ordering::Acquire)
        && unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) } == MAIN_ID.load(Ordering::Relaxed) as i64
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
