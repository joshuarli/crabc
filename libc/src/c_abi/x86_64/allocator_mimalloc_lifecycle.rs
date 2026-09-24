//! Owned lifecycle entries for the pinned C mimalloc backend.
//!
//! `libmimalloc-sys` 0.1.49 bundles mimalloc v3.3.2.  Its pinned
//! `c_src/mimalloc/v3/src/prim/prim.c` normally adds private compiler
//! constructor/destructor entries named `mi_process_attach` and
//! `mi_process_detach`.  The native static and dynamic product builders define
//! `MI_PRIM_HAS_PROCESS_ATTACH=1`, which suppresses exactly those entries; it
//! does not change the fixed upstream C source or its allocator algorithms.
//!
//! These entries replace that source-owned transport in the same libc image.
//! The existing CRT and loader therefore retain their established preinit,
//! dependency-init, application-init, application-fini, and dependency-fini
//! ordering.  C initialization may probe optional kernel files and leave an
//! incidental errno behind.  Constructor/destructor dispatch has no errno
//! result, so this bridge preserves the incoming application errno around the
//! exact upstream automatic process operations.

use super::errno;
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
use core::sync::atomic::{AtomicU8, Ordering};

unsafe extern "C" {
    // These internal upstream operations are the complete bodies called by
    // `prim.c`'s suppressed private attach/detach callbacks.  They remain
    // private Rust glue; neither name becomes part of crabc's C ABI.
    fn _mi_auto_process_init();
    fn _mi_auto_process_done();
}

/// Visible to the allocator module only so its member anchors this one in
/// the static archive; libc never calls it directly.
pub(super) unsafe extern "C" fn initialize() {
    let saved_errno = unsafe { errno::get_errno() };
    unsafe { _mi_auto_process_init() };
    #[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
    ALLOCATOR_LIFECYCLE_PHASE.store(1, Ordering::Release);
    unsafe { errno::set_errno(saved_errno) };
}

unsafe extern "C" fn finalize() {
    let saved_errno = unsafe { errno::get_errno() };
    unsafe { _mi_auto_process_done() };
    #[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
    ALLOCATOR_LIFECYCLE_PHASE.store(2, Ordering::Release);
    unsafe { errno::set_errno(saved_errno) };
}

// The ELF lifecycle owners dispatch libc's arrays at their normal positions.
// `#[used]` retains these entries in the Rust archive before the final static
// or shared link admits the allocator object that supplies their two targets.
#[used]
#[linkage = "internal"]
#[export_name = "__crabc_x86_owned_mimalloc_process_initializer"]
#[link_section = ".init_array"]
static AUTOMATIC_PROCESS_INITIALIZER: unsafe extern "C" fn() = initialize;

#[used]
#[linkage = "internal"]
#[export_name = "__crabc_x86_owned_mimalloc_process_finalizer"]
#[link_section = ".fini_array"]
static AUTOMATIC_PROCESS_FINALIZER: unsafe extern "C" fn() = finalize;

// Phase-only development evidence; absent from ordinary allocator products.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
static ALLOCATOR_LIFECYCLE_PHASE: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_owned_allocator_lifecycle_test_phase() -> core::ffi::c_int {
    core::ffi::c_int::from(ALLOCATOR_LIFECYCLE_PHASE.load(Ordering::Acquire))
}
