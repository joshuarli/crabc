//! Owned lifecycle entries for the pinned C mimalloc backend.
//!
//! The product builders compile pinned upstream mimalloc v3.5.0.  Its
//! `src/prim/prim.c` normally adds private compiler
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
//!
//! The automatic process initialization runs on the first allocating C entry
//! instead of during process startup.  The upstream sequence is only partially
//! once-guarded, so this bridge owns the whole sequence as one thread-safe
//! one-shot.  A program that never allocates does no allocator work, while the
//! retained `.fini_array` entry remains a safe no-op because
//! `_mi_auto_process_done` returns when the process was never initialized.

use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
use core::sync::atomic::AtomicUsize;

use super::errno;

unsafe extern "C" {
    // These internal upstream operations are the complete bodies called by
    // `prim.c`'s suppressed private attach/detach callbacks.  They remain
    // private Rust glue; neither name becomes part of crabc's C ABI.
    fn _mi_auto_process_init();
    fn _mi_auto_process_done();
}

const PROCESS_INIT_UNSTARTED: u8 = 0;
const PROCESS_INIT_RUNNING: u8 = 1;
const PROCESS_INIT_COMPLETE: u8 = 2;

static PROCESS_INIT_STATE: AtomicU8 = AtomicU8::new(PROCESS_INIT_UNSTARTED);

#[inline]
fn process_init_complete() -> bool {
    PROCESS_INIT_STATE.load(Ordering::Acquire) == PROCESS_INIT_COMPLETE
}

/// Run the upstream automatic process initialization exactly once.
///
/// The completed-state check is the allocation fast path; the one-shot
/// sequence is cold.  `_mi_auto_process_init` is not idempotent: it sets up
/// the automatic thread done key, thread-local storage, option
/// post-initialization, allocator initialization, and random reseeding, none
/// of which are once-guarded upstream.  Every allocating C entry reaches this
/// function before its first backend call.  The losing side waits for the
/// winning thread to publish the completed sequence.
#[inline]
pub(super) unsafe extern "C" fn initialize() {
    if process_init_complete() {
        return;
    }
    // SAFETY: the cold path owns the one-shot and the upstream sequence.
    unsafe { initialize_slow() };
}

#[cold]
#[inline(never)]
unsafe fn initialize_slow() {
    if PROCESS_INIT_STATE
        .compare_exchange(
            PROCESS_INIT_UNSTARTED,
            PROCESS_INIT_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        while !process_init_complete() {
            core::hint::spin_loop();
        }
        return;
    }
    let saved_errno = unsafe { errno::get_errno() };
    unsafe { _mi_auto_process_init() };
    #[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
    {
        ALLOCATOR_LIFECYCLE_INIT_COUNT.fetch_add(1, Ordering::Release);
        ALLOCATOR_LIFECYCLE_PHASE.store(1, Ordering::Release);
    }
    PROCESS_INIT_STATE.store(PROCESS_INIT_COMPLETE, Ordering::Release);
    unsafe { errno::set_errno(saved_errno) };
}

unsafe extern "C" fn finalize() {
    let saved_errno = unsafe { errno::get_errno() };
    unsafe { _mi_auto_process_done() };
    #[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
    ALLOCATOR_LIFECYCLE_PHASE.store(2, Ordering::Release);
    unsafe { errno::set_errno(saved_errno) };
}

// The lifecycle member is extracted from the static archive only when a
// loaded object names one of its symbols.  Every allocating entry now calls
// `initialize`, and the allocator module also retains a direct anchor.  This
// local-data function pointer keeps the evidence-visible initializer symbol in
// the same image without dispatching it from `.init_array`: no constructor
// calls the allocator at process startup.
#[used]
#[linkage = "internal"]
#[export_name = "__crabc_x86_owned_mimalloc_process_initializer"]
static AUTOMATIC_PROCESS_INITIALIZER: unsafe extern "C" fn() = initialize;

// The finalizer stays in the conventional array position.  `_mi_auto_process_done`
// returns immediately when no allocation ran the lazy initializer.
#[used]
#[linkage = "internal"]
#[export_name = "__crabc_x86_owned_mimalloc_process_finalizer"]
#[link_section = ".fini_array"]
static AUTOMATIC_PROCESS_FINALIZER: unsafe extern "C" fn() = finalize;

// Phase-only test instrumentation; absent from ordinary allocator products.
#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
static ALLOCATOR_LIFECYCLE_PHASE: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
static ALLOCATOR_LIFECYCLE_INIT_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_owned_allocator_lifecycle_test_phase() -> core::ffi::c_int {
    core::ffi::c_int::from(ALLOCATOR_LIFECYCLE_PHASE.load(Ordering::Acquire))
}

#[cfg(feature = "x86-owned-allocator-lifecycle-test-audit")]
#[no_mangle]
pub extern "C" fn __crabc_x86_owned_allocator_lifecycle_test_init_count() -> usize {
    ALLOCATOR_LIFECYCLE_INIT_COUNT.load(Ordering::Acquire)
}
