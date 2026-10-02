// Copyright (c) 2018-2026 Microsoft Research, Daan Leijen
// SPDX-License-Identifier: MIT
// Source: mimalloc v3.5.0 src/heap.c:59-259 (`_mi_heap_theap_get_or_init`,
// `_mi_heap_new_for_subproc`, `mi_heap_free_theaps`, `mi_heap_free`,
// `mi_heap_delete`, `_mi_heap_force_destroy`, `mi_heap_destroy`),
// src/theap.c:236-445, src/init.c:377-480, src/threadlocal.c:103-202,
// src/prim/prim-tls.c:211-229, src/arena.c:1661-1672,2531-2644,
// and src/alloc.c:909-941 (guarded canonical generic allocation).

//! Allocated Theaps of the process main subprocess: ordinary non-main
//! Heaps and fresh main-Heap siblings after the source fast slot is cleared.
//!
//! A Heap is a `NonMainHeapImage` allocated from the process main Heap
//! through the calling thread's source-selected main Theap, on a key of the process-global
//! thread-local registry, pushed on the main subprocess's Heap list. A
//! thread's Theap for such a Heap is a source-sized metadata image or a
//! [`MainHeapTheapImage`] in its Heap's requested parent arena, at the head of
//! the thread's TLD list, stored on the thread's regular thread-local slot
//! array (a `ThreadLocalBackingOwner`, also process metadata) and cached with
//! the source reference counts. It pages like a child thread's Theap for a
//! non-main Heap: its own queues and page state over the process arena
//! registry, with the Heap's own per-arena page records, whose allocation
//! nests an allocation from the main Heap through the thread's native owner
//! (`mi_arena_pages_alloc`); see `meta::ChildHeapTheapImage` for why each
//! Theap keeps its own engine state.
//!
//! The native runtime entry points route here: a local free of a block on
//! such a Theap's page, a nonlocal free of a block on such a Heap's page,
//! and thread exit, which collects and abandons allocated siblings before
//! the stable fixed runtime owner completes its own teardown. Main siblings
//! use the main Heap's embedded arena bitmap; non-main Heaps own separate
//! per-arena records. Both retain the existing source TLD and Heap lists.
//!
use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use crate::compiler_tls::{
    default_theap, dynamic_backing_peek, fast_slot_peek, install_dynamic_backing, install_empty_dynamic_backing,
    is_empty_dynamic_backing, DynamicThreadLocalBacking,
};
use crate::arena::{ArenaId, ExclusiveArenaTheapReservation};
use crate::lock::PrivateLock;
use crate::meta::{ChildPageEngineState, MetaAllocation, MetaAllocator};
use crate::os_page::OsAlignedPageOwner;
use crate::process_init::{ProcessMainBackingBinding, ProcessMainInitializationStorage};
use crate::runtime_lifecycle::{native_allocate_aligned, native_free, NativePageAllocationResult, NativePageFreeResult};
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
use crate::runtime_lifecycle::NativeGuardedCanonicalAllocationProgress;
use crate::subproc::MainSubprocess;
use crate::thread_local::{ThreadLocalBackingOwner, ThreadLocalKey, ThreadLocalSlotIndex, TLS_INDEX_BITS, TLS_INDEX_MASK};
use crate::types::heap_registry::lifecycle::{HeapKeySource, HeapReleaseError, HeapReleaseOutcome, NonMainHeapImage};
use crate::types::{Heap, LiveThreadId, MemoryId, Page, Theap, ThreadLocalData, ThreadSequence};

/// Native administration in the source Theap's internal alignment gap.
/// These are initialized fields, carried by whole-image moves; neither
/// allocator padding after the requested extent nor uninitialized Rust
/// padding is used as storage.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MainHeapTheapLifecycle {
    pub(crate) engine: MainHeapTheapEngineState,
    pub(crate) metadata: MainHeapTheapMetadataOwnership,
}

#[cfg(target_arch = "x86_64")]
impl MainHeapTheapLifecycle {
    pub(crate) const fn empty() -> Self {
        Self { engine: MainHeapTheapEngineState::Active, metadata: MainHeapTheapMetadataOwnership::Unowned }
    }
}

/// A page session owns this state while the Theap's local queues are held.
/// Retry and failure states remain attached to the exact source image after
/// the creating thread exits; a new caller cannot reset them to active.
#[cfg(target_arch = "x86_64")]
#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MainHeapTheapEngineState {
    Active,
    RetryPending,
    RetryComplete,
    Poisoned,
}

#[cfg(target_arch = "x86_64")]
impl MainHeapTheapEngineState {
    fn from_engine(state: ChildPageEngineState) -> Self {
        match state {
            ChildPageEngineState::Active => Self::Active,
            ChildPageEngineState::RetryPending => Self::RetryPending,
            ChildPageEngineState::RetryComplete => Self::RetryComplete,
            ChildPageEngineState::Poisoned => Self::Poisoned,
        }
    }

    fn into_engine(self) -> ChildPageEngineState {
        match self {
            Self::Active => ChildPageEngineState::Active,
            Self::RetryPending => ChildPageEngineState::RetryPending,
            Self::RetryComplete => ChildPageEngineState::RetryComplete,
            Self::Poisoned => ChildPageEngineState::Poisoned,
        }
    }
}

/// The source reference owns a transferred metadata capability until its
/// final decrement. Claiming release requires that exclusive last reference
/// and detached source lists; a failed publication stays terminally owned.
#[cfg(target_arch = "x86_64")]
#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum MainHeapTheapMetadataOwnership {
    Unowned,
    SourceOwned,
    ReleaseClaimed,
    Terminal,
}

#[cfg(target_arch = "x86_64")]
const _: [(); 2] = [(); size_of::<MainHeapTheapLifecycle>()];
#[cfg(target_arch = "x86_64")]
const _: [(); 1] = [(); align_of::<MainHeapTheapLifecycle>()];

/// A page session borrows a local engine state while its source Theap
/// reference keeps the initialized lifecycle field mapped. The session's
/// owner is gone before this guard publishes retry or poison state.
struct MainHeapPageEngineState {
    theap: NonNull<Theap>,
    state: ChildPageEngineState,
}

impl MainHeapPageEngineState {
    /// # Safety
    /// The caller owns this Theap's local queues for the whole guard lifetime
    /// and holds a source reference until after the guard is dropped.
    unsafe fn new(theap: NonNull<Theap>) -> Self {
        #[cfg(target_arch = "x86_64")]
        let state = unsafe { (*Theap::main_heap_lifecycle_at(theap)).engine }.into_engine();
        #[cfg(not(target_arch = "x86_64"))]
        let state = unsafe { (*theap.cast::<MainHeapTheapImage>().as_ptr()).page_engine };
        Self { theap, state }
    }
}

impl Drop for MainHeapPageEngineState {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the guard's source reference and exclusive queue operation
        // still hold; every page session borrowing state has already ended.
        unsafe { (*Theap::main_heap_lifecycle_at(self.theap)).engine = MainHeapTheapEngineState::from_engine(self.state); }
        #[cfg(not(target_arch = "x86_64"))]
        unsafe { (*self.theap.cast::<MainHeapTheapImage>().as_ptr()).page_engine = self.state; }
    }
}

/// An auxiliary Theap placed in a requested arena's minimum-object slice.
/// The source image is at offset zero; the exact reservation capability fits
/// within that same reserved slice. Ordinary x86 metadata uses only `Theap`,
/// with release authority transferred into its source reference lifetime.
/// Other targets retain their existing metadata wrapper representation.
#[repr(C)]
pub(crate) struct MainHeapTheapImage {
    theap: Theap,
    page_engine: ChildPageEngineState,
    allocation: Option<MainHeapTheapAllocation>,
    retained_deleted_next: *mut MainHeapTheapImage,
    retained_deleted_os_pages: usize,
}

/// Holds the exact Theap image while a deleted Heap still has an OS page in
/// one of its local queues. The page keeps its source Heap identity and may
/// need the queue again when its final block is freed. Only pointer identity
/// is observed through the list; a borrow of the image requires a matching
/// source-local page observation and native process admission.
struct RetainedDeletedHeapTheaps {
    lock: PrivateLock,
    head: UnsafeCell<*mut Theap>,
}

// SAFETY: the lock serializes list links. A listed image has one additional
// Theap reference, so its metadata stays mapped until list removal.
unsafe impl Sync for RetainedDeletedHeapTheaps {}

static RETAINED_DELETED_HEAP_THEAPS: RetainedDeletedHeapTheaps = RetainedDeletedHeapTheaps {
    lock: PrivateLock::new(),
    head: UnsafeCell::new(core::ptr::null_mut()),
};

/// # Safety
/// The retained-list lock is held, and this exact image has left the Heap
/// list permanently. The list's source reference keeps its link mapped.
unsafe fn retained_deleted_next(theap: NonNull<Theap>) -> *mut Theap {
    #[cfg(target_arch = "x86_64")]
    return unsafe { Theap::main_heap_retained_next_at(theap) };
    #[cfg(not(target_arch = "x86_64"))]
    unsafe { (*theap.cast::<MainHeapTheapImage>().as_ptr()).retained_deleted_next.cast() }
}

/// # Safety
/// As for `retained_deleted_next`; the lock also excludes every writer.
unsafe fn set_retained_deleted_next(theap: NonNull<Theap>, next: *mut Theap) {
    #[cfg(target_arch = "x86_64")]
    unsafe { Theap::set_main_heap_retained_next_at(theap, next); }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe { (*theap.cast::<MainHeapTheapImage>().as_ptr()).retained_deleted_next = next.cast(); }
}

#[cfg(test)]
pub(crate) fn retained_deleted_heap_owner_count_for_test() -> Option<usize> {
    let retained = &RETAINED_DELETED_HEAP_THEAPS;
    let guard = retained.lock.lock().ok()?;
    let mut count = 0usize;
    // SAFETY: the lock protects every link and each listed image has a live
    // reference until it is removed.
    let mut image = unsafe { *retained.head.get() };
    while !image.is_null() {
        count = count.checked_add(1)?;
        image = unsafe { retained_deleted_next(NonNull::new_unchecked(image)) };
    }
    drop(guard);
    Some(count)
}

enum MainHeapTheapAllocation {
    Metadata(MetaAllocation<'static>),
    Arena(ExclusiveArenaTheapReservation<'static, 'static>),
}

const _: [(); 1] = [(); (size_of::<MainHeapTheapImage>() <= crate::config::ARENA_MIN_OBJ_SIZE) as usize];

/// Independent custody acquired while the actual issuing source owner is
/// admitted, before any candidate. Terminal task handoff moves this genuine
/// Theap reference and operation guard; copied addresses never replace them.
#[cfg(target_arch = "x86_64")]
struct AuxiliaryAllocationIssuer {
    heap: NonNull<Heap>,
    theap: NonNull<Theap>,
    _operation: crate::runtime_lifecycle::NativeSubprocessOperation,
}

#[cfg(target_arch = "x86_64")]
impl AuxiliaryAllocationIssuer {
    /// # Safety
    /// The caller's actual admitted source owner retains this Heap, Theap
    /// and TLD continuously, with all conflicting projections ended.
    unsafe fn capture(heap: NonNull<Heap>, theap: NonNull<Theap>) -> Option<Self> {
        let operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
        unsafe { Theap::incref_at(theap) };
        Some(Self { heap, theap, _operation: operation })
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for AuxiliaryAllocationIssuer {
    fn drop(&mut self) {
        // This independent reference ends before its enclosing original
        // source admission. The caller's list/root references, or the stored
        // task's independent issuer, still retain the image; this is not its
        // final release and must not consume a protected list reference.
        if unsafe { Theap::decref_at(self.theap) } {
            crabc_core::process::exit_immediately(134);
        }
    }
}

#[cfg(target_arch = "x86_64")]
struct RetainedAuxiliaryFreshInitialization {
    issuer: AuxiliaryAllocationIssuer,
    task: crate::single_thread::PendingFreshOsPageInitialization,
}

#[cfg(target_arch = "x86_64")]
struct RetainedAuxiliaryLiveValidity {
    issuer: AuxiliaryAllocationIssuer,
    _task: crate::single_thread::PendingLivePageValidity,
}

/// # Safety
/// The original allocation issuer remains admitted through this handoff;
/// every engine and metadata projection ended before the task was delivered.
#[cfg(target_arch = "x86_64")]
unsafe fn retain_auxiliary_live_validity(mut task: crate::single_thread::PendingLivePageValidity, issuer: AuxiliaryAllocationIssuer) {
    let marked = unsafe { task.ensure_retirement_refusal(issuer.theap, issuer.heap) }.is_ok()
        || task.has_retirement_refusal_marker();
    if !marked || has_retained_auxiliary_fresh_initialization() {
        core::hint::black_box((&task, &issuer));
        crabc_core::process::exit_immediately(134);
    }
    unsafe { thread_heaps() }.pending_live_page_validity = Some(RetainedAuxiliaryLiveValidity { issuer, _task: task });
}

fn has_retained_auxiliary_fresh_initialization() -> bool {
    #[cfg(target_arch = "x86_64")]
    { let state = unsafe { thread_heaps() }; state.pending_fresh_initialization.is_some() || state.pending_live_page_validity.is_some() }
    #[cfg(not(target_arch = "x86_64"))]
    { false }
}

/// # Safety
/// This is the actual issuer captured before this task's candidate. The
/// enclosing original owner remains admitted throughout the terminal handoff.
#[cfg(target_arch = "x86_64")]
unsafe fn retain_auxiliary_fresh_initialization(
    mut task: crate::single_thread::PendingFreshOsPageInitialization,
    issuer: AuxiliaryAllocationIssuer,
) {
    let occupied = has_retained_auxiliary_fresh_initialization();
    let marked = if occupied { false } else {
        unsafe { task.ensure_retirement_refusal(issuer.theap, issuer.heap) }.is_ok()
            || task.has_retirement_refusal_marker()
    };
    if !marked {
        // A failed first publication cannot end the real originating scope.
        // Both linear owners remain on this stack until process fail-stop;
        // no source null or replacement admission is manufactured.
        core::hint::black_box((&task, &issuer));
        crabc_core::process::exit_immediately(134);
    }
    unsafe { thread_heaps() }.pending_fresh_initialization = Some(
        RetainedAuxiliaryFreshInitialization { issuer, task },
    );
}

/// The calling thread's state for its auxiliary allocated Theaps.
///
/// Source keeps the slot array and the cached Theap in thread-local roots.
/// The fixed runtime page owner retains its own metadata capability and
/// requires empty compiler-TLS backing and cache projections during a page
/// session. This module retains the source slot backing and cache lifetime:
/// slot operations publish the backing only for their bounded operation, and
/// `cached` holds the actual source cached Theap pointer, with null standing
/// only for the empty Theap. Source fast-slot replacement leaves the fixed
/// runtime capability pinned independently of the selected sibling.
struct ThreadHeaps {
    /// The regular thread-local slot array (`mi_thread_locals_t`).
    thread_locals: Option<ThreadLocalBackingOwner>,
    /// The slot array's current image while it is not published.
    backing: Option<NonNull<DynamicThreadLocalBacking>>,
    /// `_mi_theap_cached`, including the stable fixed runtime owner.
    cached: *mut Theap,
    /// The one retained raw-unmap retry of these Theaps, with the Theap whose
    /// engine it latched (`None` once that Theap is freed).
    pending_os_release: Option<(Option<NonNull<Theap>>, OsAlignedPageOwner)>,
    /// The actual original issuer stays pinned with the terminal unpublished
    /// claim. Its Heap marker and these live source roots forbid teardown.
    #[cfg(target_arch = "x86_64")]
    pending_fresh_initialization: Option<RetainedAuxiliaryFreshInitialization>,
    #[cfg(target_arch = "x86_64")]
    pending_live_page_validity: Option<RetainedAuxiliaryLiveValidity>,
}

#[thread_local]
static THREAD_HEAPS: UnsafeCell<ThreadHeaps> =
    UnsafeCell::new(ThreadHeaps {
        thread_locals: None,
        backing: None,
        cached: core::ptr::null_mut(),
        pending_os_release: None,
        #[cfg(target_arch = "x86_64")]
        pending_fresh_initialization: None,
        #[cfg(target_arch = "x86_64")]
        pending_live_page_validity: None,
    });

/// Preserve the live main-subprocess Heap slots until the pthread's source
/// attachment finishes, including across timer callback TLS reset.
#[cfg(target_arch = "x86_64")]
pub(crate) fn native_timer_tls_span() -> crate::runtime_lifecycle::NativeAllocatorTlsSpan {
    crate::runtime_lifecycle::NativeAllocatorTlsSpan::of(core::ptr::addr_of!(THREAD_HEAPS))
}

/// # Safety
/// The caller is on the current thread and forms no other reference to the
/// state while the returned one is live.
#[inline]
unsafe fn thread_heaps() -> &'static mut ThreadHeaps {
    // SAFETY: a `#[thread_local]` is reachable only from its own thread.
    unsafe { &mut *THREAD_HEAPS.get() }
}

/// Actual source TLS addresses published while the originating worker runs.
/// The lifecycle registry pins these exact mappings across a prepared fork;
/// the child never reconstructs TLS offsets or borrows the survivor's roots.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub(crate) struct CopiedThreadHeapTls {
    state: NonNull<ThreadHeaps>,
    roots: [crate::runtime_lifecycle::NativeAllocatorTlsSpan; 5],
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn current_thread_heap_tls() -> CopiedThreadHeapTls {
    CopiedThreadHeapTls {
        // SAFETY: the current compiler-TLS image is non-null and remains at
        // this address until its registered owner completes teardown.
        state: unsafe { NonNull::new_unchecked(THREAD_HEAPS.get()) },
        roots: crate::compiler_tls::native_timer_tls_spans(),
    }
}

#[cfg(target_arch = "x86_64")]
impl CopiedThreadHeapTls {
    /// Source regular-backing release precedes the thread statistics prefix
    /// and all Theap drains. Source fast/default/cache remain distinct roots.
    ///
    /// # Safety
    /// The prepared-fork child retains the vanished worker's published TLS
    /// mapping with entry, signals and hooks excluded and all outer locks
    /// released. No former observer or callback may resume, even on failure.
    pub(crate) unsafe fn release_vanished_regular_backing(self) -> bool {
        // SAFETY: sole-child ownership of the pinned originating TLS field.
        let state = unsafe { self.state.as_ptr().as_mut() }.unwrap();
        if state.pending_os_release.is_some() || (state.pending_fresh_initialization.is_some() || state.pending_live_page_validity.is_some()) { return false; }
        if let Some(owner) = state.thread_locals.as_mut() {
            // The image is parked in this exact lifecycle outside a bounded
            // slot operation, rather than installed in the survivor's TLS.
            if unsafe { owner.teardown_vanished_child(state.backing) }.is_err() { return false; }
        } else if state.backing.is_some() { return false; }
        state.thread_locals = None;
        state.backing = None;
        // SAFETY: these are actual root-field addresses published by this
        // worker before the registry pinned its descriptor, not TLS offsets.
        unsafe {
            (self.roots[0].start as *mut *mut DynamicThreadLocalBacking).write(core::ptr::null_mut());
            (self.roots[1].start as *mut *mut ()).write(core::ptr::null_mut());
        }
        true
    }

    /// Collect auxiliary Theaps in source TLD order before the oldest fixed
    /// owner. Every image remains linked and cache references stay live.
    ///
    /// # Safety
    /// The exact authority of `release_vanished_regular_backing` continues;
    /// the fixed source engine is retained until its following drain.
    pub(crate) unsafe fn drain_vanished_auxiliary_theaps(
        self, fixed: NonNull<Theap>, thread: LiveThreadId,
        main_heap: crate::main_theap::MainStaticHeapLease<'static>,
    ) -> bool {
        let Some(tld) = NonNull::new(unsafe { Theap::tld_at(fixed) }) else { return false; };
        let Some((identity, sequence, numa_node)) = (unsafe {
            ThreadLocalData::attached_thread_identity_at(tld, MainSubprocess::global().identity())
        }) else { return false; };
        if identity != thread { return false; }
        let source = MainThread { theap: fixed, tld, thread, sequence, numa_node };
        let mut current = unsafe { ThreadLocalData::theaps_head_at(tld) };
        while let Some(theap) = NonNull::new(current) {
            current = unsafe { Theap::tld_next_at(theap) };
            if theap == fixed { continue; }
            if !unsafe { drain_vanished_auxiliary_theap(source, theap, main_heap, self.state) } { return false; }
        }
        true
    }

    /// Release the actual cache only after every Theap page drain, then
    /// unlink and free auxiliary metadata while retaining the fixed owner.
    ///
    /// # Safety
    /// The sole-child authority continues. All auxiliary and fixed page
    /// drains succeeded, and no former observer, callback or producer resumes.
    pub(crate) unsafe fn retire_vanished_auxiliary_theaps(
        self, fixed: NonNull<Theap>,
    ) -> bool {
        let Some(tld) = NonNull::new(unsafe { Theap::tld_at(fixed) }) else { return false; };
        // All pages have moved to the retained source Heap graph. Empty the
        // foreign roots before any list reference can release its metadata.
        let empty = crate::bootstrap::empty_default_theap_ptr();
        let state = unsafe { &mut *self.state.as_ptr() };
        let cached = core::mem::replace(&mut state.cached, core::ptr::null_mut());
        unsafe {
            (self.roots[2].start as *mut *mut Theap).write(empty);
            (self.roots[3].start as *mut *mut Theap).write(empty);
        }
        if let Some(cached) = NonNull::new(cached) {
            // Its Heap-list reference still retains this exact cached image.
            if unsafe { Theap::decref_at(cached) } { return false; }
        }
        loop {
            let theap = match unsafe {
                ThreadLocalData::take_next_auxiliary_theap_for_thread_done(tld, fixed, MainSubprocess::global().identity())
            } {
                Ok(Some(theap)) => theap,
                Ok(None) => break,
                Err(_) => return false,
            };
            if unsafe { theap.as_ref().refcount() } != 1 { return false; }
            // SAFETY: all source roots and lists have relinquished this
            // drained image, leaving the one returned Heap-list reference.
            if !unsafe { release_detached_theap_reference(theap) } { return false; }
        }
        true
    }
}

/// The calling thread's identity in the process main subprocess.
#[derive(Clone, Copy)]
struct MainThread {
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    thread: LiveThreadId,
    sequence: ThreadSequence,
    numa_node: i32,
}

/// The calling thread with a retained fixed main-Heap owner outside a child.
/// The default root may name another live Theap of this TLD.
fn current_main_thread() -> Option<MainThread> {
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return None;
    }
    let main = MainSubprocess::global();
    let selected = default_theap();
    // SAFETY: the default root retains this thread's attached TLD, even
    // after child destruction clears the independently selected fast slot.
    let tld = NonNull::new(unsafe { Theap::tld_at(selected) })?;
    // The oldest main-Heap list member is the fixed runtime owner. Source
    // fast-slot replacement can publish younger siblings without moving it.
    // SAFETY: the initialized default retains this TLD and all linked
    // Theaps; same-thread teardown cannot run during this observation.
    let theap = unsafe {
        ThreadLocalData::linked_theap_for_heap_at(tld, main.ready_main_heap_pointer())
    }.ok()??;
    // SAFETY: the initialized default retains this thread's TLD; its
    // identity and NUMA fields stay stable independently of list unlinking.
    let (thread, sequence, numa_node) = unsafe {
        ThreadLocalData::attached_thread_identity_at(tld, main.identity())
    }?;
    if crate::compiler_tls::current_thread_identity() != Some(thread)
        // SAFETY: the fixed owner belongs to this subprocess main Heap.
        || unsafe { Theap::heap_at(theap) } != main.ready_main_heap_pointer()
        // SAFETY: a switched default must share this thread's TLD.
        || unsafe { Theap::tld_at(default_theap()) } != tld.as_ptr()
    {
        return None;
    }
    Some(MainThread { theap, tld, thread, sequence, numa_node })
}

/// The fixed runtime owner remains independent of the source fast selector.
pub(crate) fn fixed_main_theap() -> Option<NonNull<Theap>> {
    current_main_thread().map(|thread| thread.theap)
}

fn is_process_main_heap(heap: NonNull<Heap>) -> bool {
    heap.as_ptr() == MainSubprocess::global().ready_main_heap_pointer()
}

fn is_current_subprocess_heap(heap: NonNull<Heap>) -> bool {
    is_process_main_heap(heap) || is_main_subprocess_heap(heap)
}

fn binding() -> Option<ProcessMainBackingBinding> {
    ProcessMainInitializationStorage::global().ready_child_subprocess_inputs().map(|(binding, _)| binding)
}

/// The regular thread-local key a Heap's Theaps use (`heap->theap`).
fn heap_key(heap: NonNull<Heap>) -> Option<ThreadLocalKey> {
    // SAFETY: the caller's live Heap; an immutable field.
    let raw = unsafe { heap.as_ref() }.regular_theap_slot() as u64;
    ThreadLocalKey::from_parts(ThreadLocalSlotIndex::new((raw & TLS_INDEX_MASK) as usize)?, raw >> TLS_INDEX_BITS)
}

/// Whether `heap` is a non-main Heap of the process main subprocess.
fn is_main_subprocess_heap(heap: NonNull<Heap>) -> bool {
    // SAFETY: the caller's live Heap; immutable fields.
    let heap = unsafe { heap.as_ref() };
    !heap.is_subprocess_main() && core::ptr::eq(heap.subprocess_pointer(), MainSubprocess::global().identity().as_ptr())
}

/// The live non-main Heap of a page, without taking the subprocess Heap-list
/// lock. Source `mi_page_heap` reads the page identity directly: deletion
/// moves surviving arena pages to the main Heap before freeing the old image.
/// OS pages retained by a deleted Heap are the exception in this engine;
/// their retained Theap registry must exclude the stale identity first.
/// This also permits allocation/free in a statistics output callback while
/// the source visitor holds the Heap-list lock.
///
/// # Safety
/// `page` is held live by an allocation observation, and its Heap identity
/// cannot move or be destroyed concurrently with this call.
unsafe fn live_non_main_heap_of_page(page: NonNull<Page>) -> Option<NonNull<Heap>> {
    // SAFETY: the held allocation retains the immutable page identity;
    // independently changing counters and remote-free atomics are not borrowed.
    let heap = NonNull::new(unsafe { Page::heap_identity_at(page) })?;
    if is_process_main_heap(heap) {
        return None;
    }
    // SAFETY: the observation retains the page and the deleted-Heap registry
    // compares only its raw Theap identity, never the potentially freed Heap.
    if unsafe { retained_deleted_heap_os_page(page) }? {
        return None;
    }
    // SAFETY: surviving arena pages have moved before Heap release; an OS
    // page naming a released Heap was excluded above. Valid use excludes
    // concurrent destruction of the remaining Heap.
    (unsafe { Heap::non_main_subprocess_at(heap) } == Some(NonNull::from(MainSubprocess::global().identity()))).then_some(heap)
}

/// Runs one operation on this thread's slot array with its image published
/// in the compiler-TLS root, where `ThreadLocalBackingOwner` keeps it, then
/// takes the (possibly grown) image back and restores the empty image.
fn with_published_slots<R>(state: &mut ThreadHeaps, operation: impl FnOnce(&mut ThreadLocalBackingOwner) -> R) -> Option<R> {
    let owner = state.thread_locals.as_mut()?;
    if let Some(backing) = state.backing {
        install_dynamic_backing(backing);
    }
    let value = operation(owner);
    state.backing = dynamic_backing_peek().filter(|backing| !is_empty_dynamic_backing(*backing));
    install_empty_dynamic_backing();
    Some(value)
}

/// `_mi_thread_local_get` on this thread's slot array.
fn thread_local_get(key: ThreadLocalKey) -> *mut () {
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    with_published_slots(state, |owner| owner.get(key).ok()).flatten().unwrap_or(core::ptr::null_mut())
}

/// Reads one versioned regular slot through its actual main-subprocess
/// backing owner, without initializing a Theap or changing the cache.
///
/// # Safety
/// This runs on the retained calling thread. Its slot owner and all published
/// slot values remain live, and no slot mutation or thread teardown overlaps
/// the synchronous query. No allocator callback or output occurs here.
#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
pub(crate) unsafe fn source_regular_slot_peek(key: ThreadLocalKey) -> *mut () {
    thread_local_get(key)
}

/// `_mi_thread_local_set` on this thread's slot array, created on first use.
fn thread_local_set(key: ThreadLocalKey, value: *mut ()) -> bool {
    let Some(config) = binding().and_then(|binding| binding.page_map().memory_config().ok()) else { return false };
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    if state.thread_locals.is_none() {
        // SAFETY: this module is the only owner of the main-subprocess
        // thread's regular slot root, which no native owner uses; the root
        // holds the empty image between this module's slot operations.
        match unsafe { ThreadLocalBackingOwner::begin(config) } {
            Ok(owner) => state.thread_locals = Some(owner),
            Err(_) => return false,
        }
    }
    with_published_slots(state, |owner| owner.set(key, value).is_ok()).unwrap_or(false)
}

/// The number of slots in this thread's array (`mi_thread_locals->count`).
#[cfg(test)]
fn thread_local_count() -> i64 {
    // SAFETY: the current thread's own state.
    unsafe { thread_heaps() }.backing.map_or(0, |backing| unsafe { backing.as_ref() }.count() as i64)
}

/// `_mi_thread_locals_thread_done` on the thread calling
/// `mi_subproc_destroy`: release its regular slot table while leaving its
/// live Heap/Theap list, default root, and cached Theap reference intact.
/// The fast slot is cleared after the regular table is released. A pre-release
/// metadata failure keeps the table available for the next operation.
pub(crate) fn release_current_thread_locals_for_child_destroy() -> bool {
    if has_retained_auxiliary_fresh_initialization() { return false; }
    // SAFETY: this thread owns its regular TLS table, and the public child
    // destroy entry keeps native admission open through this transition.
    let state = unsafe { thread_heaps() };
    if let Some(backing) = state.backing {
        install_dynamic_backing(backing);
    }
    let released = state.thread_locals.as_mut().is_none_or(|owner| owner.teardown().is_ok());
    if released {
        state.thread_locals = None;
        state.backing = None;
    } else {
        state.backing = dynamic_backing_peek().filter(|backing| !is_empty_dynamic_backing(*backing));
    }
    install_empty_dynamic_backing();
    if released {
        crate::compiler_tls::set_fast_slot(None);
    }
    released
}

/// The calling thread's `_mi_theap_cached` for these Heaps.
fn cached_theap() -> NonNull<Theap> {
    // SAFETY: the current thread's own state.
    NonNull::new(unsafe { thread_heaps() }.cached)
        // SAFETY: the immutable source empty Theap is process-static.
        .unwrap_or_else(|| unsafe { NonNull::new_unchecked(crate::bootstrap::empty_default_theap_ptr()) })
}

fn set_cached_theap(theap: NonNull<Theap>) {
    let stored = if core::ptr::eq(theap.as_ptr(), crate::bootstrap::empty_default_theap_ptr()) {
        core::ptr::null_mut()
    } else {
        theap.as_ptr()
    };
    // SAFETY: the current thread's own state.
    unsafe { thread_heaps() }.cached = stored;
}

/// Cache the stable fixed runtime Theap through the ordinary source reference
/// transition. Static metadata needs no counted cache reference; allocated
/// metadata retains one independently of the runtime capability that pins it.
fn cached_set_main() {
    if let Some(theap) = fixed_main_theap() {
        cached_set(theap);
    }
}

/// Whether the current thread's source cache owns this exact Theap reference.
/// This scalar root observation does not borrow any metadata or list lock.
pub(crate) fn is_current_cached_theap(theap: NonNull<Theap>) -> bool {
    // SAFETY: only the current thread accesses its cached root.
    unsafe { thread_heaps() }.cached == theap.as_ptr()
}

/// `_mi_theap_cached_set` (`prim-tls.c:211-229`).
fn cached_set(theap: NonNull<Theap>) {
    let previous = cached_theap();
    if previous == theap {
        return;
    }
    set_cached_theap(theap);
    // SAFETY: both are live Theaps of this thread or the empty Theap.
    unsafe {
        Theap::incref_at(theap);
        theap_decref(previous);
    }
}

/// Takes the metadata capability only after the final source reference has
/// been consumed. Source provenance remains in the exact image; the claim
/// marker excludes another inverse if publication is refused.
///
/// # Safety
/// No source list, root, page session, or callback can access this image;
/// the caller has consumed its final reference and owns release exclusively.
unsafe fn take_main_heap_theap_allocation(theap: NonNull<Theap>) -> Option<MainHeapTheapAllocation> {
    #[cfg(target_arch = "x86_64")]
    if unsafe { Theap::memory_id_at(theap) }.kind() == crate::types::MemoryKind::Malloc {
        // SAFETY: the prior source transfer and exclusive final decrement
        // prove this separate inverse's obligations. It validates the exact
        // provenance before claiming release under the exclusive final reference.
        let allocation = unsafe {
            MetaAllocation::recover_last_reference_main_heap_theap(MetaAllocator::global(), theap)
        };
        return allocation.map(MainHeapTheapAllocation::Metadata);
    }
    let image = theap.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: a requested-arena image (or the preserved non-x86 image) holds
    // its capability inside the original allocation's reserved extent.
    unsafe { core::ptr::replace(core::ptr::addr_of_mut!((*image).allocation), None) }
}

/// Records refused metadata publication while the exact block remains live.
///
/// # Safety
/// Publication failed before releasing this image; the caller holds its
/// unique rejected capability and no source user can access it.
unsafe fn retain_refused_main_heap_metadata(theap: NonNull<Theap>, allocation: MetaAllocation<'static>) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { (*Theap::main_heap_lifecycle_at(theap)).metadata = MainHeapTheapMetadataOwnership::Terminal; }
        // This rejected capability is never reconstructed for a retry. Its
        // source memory ID and terminal state preserve the retained block.
        core::mem::forget(allocation);
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe { (*theap.cast::<MainHeapTheapImage>().as_ptr()).allocation = Some(MainHeapTheapAllocation::Metadata(allocation)); }
}

/// `_mi_theap_decref` with `mi_theap_free_mem` (`theap.c:347-370`) for a
/// Theap of a non-main main-subprocess Heap (or this thread's default Theap,
/// whose Heap reference keeps it above zero).
///
/// # Safety
/// `theap` is live and holds the reference being dropped; a Theap freed here
/// is on no list and no root names it.
unsafe fn theap_decref(theap: NonNull<Theap>) {
    #[cfg(target_arch = "x86_64")]
    if unsafe { thread_heaps() }.pending_fresh_initialization.as_ref()
        .is_some_and(|retained| retained.issuer.theap == theap)
        || unsafe { thread_heaps() }.pending_live_page_validity.as_ref().is_some_and(|retained| retained.issuer.theap == theap) { return; }
    // SAFETY: forwarded.
    if !unsafe { Theap::decref_at(theap) } {
        return;
    }
    // SAFETY: a freed Theap is not detached (it belonged to a Heap).
    if !unsafe { Theap::is_detached_at(theap) } {
        MainSubprocess::global().identity().record_statistics_theap_unlinked();
    }
    // SAFETY: the current thread's own state.
    if let Some((named @ Some(_), _)) = unsafe { thread_heaps() }.pending_os_release.as_mut() {
        if *named == Some(theap) {
            *named = None;
        }
    }
    let image = theap.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: the final source reference was consumed above; all roots and
    // lists have relinquished this exact image.
    let allocation = unsafe { take_main_heap_theap_allocation(theap) };
    match allocation {
        Some(MainHeapTheapAllocation::Metadata(mut allocation)) => {
            // SAFETY: the last Theap reference has left its Heap and TLD lists;
            // no owner can access the image after the remote publication.
            if unsafe { MetaAllocator::global().free_detached_heap_theap(&mut allocation) }.is_err() {
                unsafe { retain_refused_main_heap_metadata(theap, allocation) };
            }
        }
        Some(MainHeapTheapAllocation::Arena(reservation)) => {
            // SAFETY: the final reference has left every root and list; the
            // typed Rust image must be dropped before its slice is returned.
            unsafe { core::ptr::drop_in_place(core::ptr::addr_of_mut!((*image).theap)) };
            let _ = reservation.release();
        }
        None => {}
    }
}


/// # Safety
/// The drained image has left every source root and list, and the caller
/// owns its sole remaining reference under exclusive lifecycle authority.
#[cfg(target_arch = "x86_64")]
unsafe fn release_detached_theap_reference(theap: NonNull<Theap>) -> bool {
    if !unsafe { Theap::decref_at(theap) } { return false; }
    if !unsafe { Theap::is_detached_at(theap) } {
        MainSubprocess::global().identity().record_statistics_theap_unlinked();
    }
    unsafe { free_vanished_theap_metadata(theap) }
}

/// # Safety
/// The caller has consumed the last source reference after page drain and
/// all root/list detach. No TLS access is needed to release this capability.
#[cfg(target_arch = "x86_64")]
unsafe fn free_vanished_theap_metadata(theap: NonNull<Theap>) -> bool {
    let image = theap.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: the final source reference was consumed above; all roots and
    // lists have relinquished this exact image.
    let allocation = unsafe { take_main_heap_theap_allocation(theap) };
    match allocation {
        Some(MainHeapTheapAllocation::Metadata(mut allocation)) => {
            // SAFETY: the last Theap reference has left its Heap and TLD lists;
            // no owner can access the image after the remote publication.
            if unsafe { MetaAllocator::global().free_detached_heap_theap(&mut allocation) }.is_err() {
                // Failed remote publication leaves this exact image mapped.
                // Retain its rejected capability in terminal source ownership;
                // the child must refuse metadata retirement completion.
                unsafe { retain_refused_main_heap_metadata(theap, allocation) };
                return false;
            }
            true
        }
        Some(MainHeapTheapAllocation::Arena(reservation)) => {
            // SAFETY: the final reference has left every root and list; the
            // typed Rust image must be dropped before its slice is returned.
            unsafe { core::ptr::drop_in_place(core::ptr::addr_of_mut!((*image).theap)) };
            match reservation.release() {
                Ok(released) => released,
                Err(reservation) => {
                    unsafe { (*image).allocation = Some(MainHeapTheapAllocation::Arena(reservation)); }
                    false
                }
            }
        }
        None => false
    }
}

/// Whether a still-linked Theap queue contains an OS page that Heap deletion
/// cannot reach through the Heap's abandoned OS-page list.
///
/// # Safety
/// The caller excludes mutation of this Theap's queues and their pages.
unsafe fn local_os_page_count(theap: NonNull<Theap>) -> Option<usize> {
    let mut found = 0usize;
    for bin in 0..crate::config::BIN_COUNT {
        // SAFETY: the caller retains the live Theap and its queue exclusion.
        let queue = unsafe { theap.as_ref() }.queue(bin)?;
        let mut page = queue.first();
        let mut seen = 0;
        while let Some(current) = NonNull::new(page) {
            if seen >= queue.count() {
                return None;
            }
            // SAFETY: each linked page stays live until this Heap operation
            // has finished detaching the Theap.
            let image = unsafe { current.as_ref() };
            if image.memid().is_os() && unsafe { Page::theap_at(current) } == theap.as_ptr() {
                found = found.checked_add(1)?;
            }
            page = unsafe { Page::next_at(current) };
            seen += 1;
        }
        if seen != queue.count() {
            return None;
        }
    }
    Some(found)
}

/// Takes an additional image reference before its Heap and cached references
/// can disappear, then publishes that owner for a later page-local free.
///
/// # Safety
/// The Theap belongs to the Heap being deleted, its queues are quiescent,
/// and its image remains live through this call.
unsafe fn retain_deleted_theap_if_needed(theap: NonNull<Theap>) -> bool {
    let needed = unsafe { local_os_page_count(theap) };
    if needed == Some(0) {
        return true;
    }
    // SAFETY: the Heap still owns its listed Theap reference. On an unusual
    // queue or lock failure, this additional reference deliberately remains
    // terminally retained instead of exposing a stale page->theap pointer.
    unsafe { Theap::incref_at(theap) };
    let Some(needed) = needed else {
        return false;
    };
    let retained = &RETAINED_DELETED_HEAP_THEAPS;
    let Ok(guard) = retained.lock.lock() else { return false };
    // SAFETY: Heap detach cleared its links before invoking this callback.
    // The held retained-list lock and extra source reference protect the
    // detached link until its final page leaves the source queues.
    unsafe {
        #[cfg(not(target_arch = "x86_64"))]
        { (*theap.cast::<MainHeapTheapImage>().as_ptr()).retained_deleted_os_pages = needed; }
        set_retained_deleted_next(theap, *retained.head.get());
        *retained.head.get() = theap.as_ptr();
    }
    drop(guard);
    true
}

/// Observe the source cache and thread slot without creating or republishing
/// a Theap. Abandoned-page reclaim uses this same cache-first selection.
fn existing_heap_theap(heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    let cached = cached_theap();
    // SAFETY: the current thread owns this live cached root.
    if unsafe { Theap::heap_at(cached) } == heap.as_ptr() {
        return Some(cached);
    }
    if is_process_main_heap(heap) {
        fast_slot_peek().map(|slot| slot.cast::<Theap>())
    } else {
        NonNull::new(thread_local_get(heap_key(heap)?).cast::<Theap>())
    }
}

/// The source-selected main sibling, when its pages belong to a distinct
/// engine from the stable fixed runtime owner.
pub(crate) fn selected_auxiliary_main_heap() -> Option<NonNull<Heap>> {
    let heap = NonNull::new(MainSubprocess::global().ready_main_heap_pointer())?;
    let selected = existing_heap_theap(heap)?;
    (Some(selected) != fixed_main_theap()).then_some(heap)
}

/// Pinned `_mi_heap_theap` (`prim-tls.h:389-397`, `heap.c:59-99`) on this
/// thread for a Heap of the process main subprocess.
fn heap_theap(thread: MainThread, heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    let cached = cached_theap();
    // SAFETY: the cached root names a live Theap or the empty Theap.
    if unsafe { Theap::heap_at(cached) } == heap.as_ptr() {
        return Some(cached);
    }
    let main = is_process_main_heap(heap);
    let existing = if main {
        fast_slot_peek().map(|slot| slot.cast::<Theap>())
    } else {
        NonNull::new(thread_local_get(heap_key(heap)?).cast::<Theap>())
    };
    let theap = match existing {
        Some(theap) => theap,
        None => {
            if !crate::runtime_lifecycle::prepare_current_thread_native_owner_for_heap_theaps() {
                return None;
            }
            let theap = create_theap(thread, heap)?;
            if main {
                crate::compiler_tls::set_fast_slot(Some(theap.cast()));
            } else {
                // Source retains the linked Theap even if regular-slot
                // growth fails; this call and the cache can still use it.
                let _ = thread_local_set(heap_key(heap)?, theap.as_ptr().cast());
            }
            theap
        }
    };
    if theap == thread.theap {
        cached_set_main();
    } else {
        cached_set(theap);
    }
    Some(theap)
}

/// Resolve the calling thread's Theap for a live non-main Heap before a
/// reallocation kernel examines its old block or checks request overflow.
/// The public Heap wrappers make this transition even when no replacement
/// allocation is needed.
pub(crate) fn native_heap_select_theap(heap: NonNull<Heap>) -> bool {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return false };
    let Some(thread) = current_main_thread() else { return false };
    is_main_subprocess_heap(heap) && heap_theap(thread, heap).is_some()
}

/// Resolve the calling thread's Theap for a live Heap in the process main
/// subprocess, including its source cached-Theap transition.
pub(crate) fn native_heap_theap(heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let thread = current_main_thread()?;
    is_current_subprocess_heap(heap).then_some(())?;
    heap_theap(thread, heap)
}

/// `_mi_theap_create(heap, tld)` with the source-sized metadata image.
#[cfg(target_arch = "x86_64")]
fn create_theap(thread: MainThread, heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    // SAFETY: the live Heap retains its selected arena for this operation.
    if !unsafe { heap.as_ref() }.exclusive_arena_id()?.as_ptr().is_null() {
        return create_theap_image(thread, heap);
    }
    let config = binding()?.page_map().memory_config().ok()?;
    let mut allocation = MetaAllocator::global()
        .zalloc_for_main_subprocess(config, MainSubprocess::global(), size_of::<Theap>())
        .ok()?;
    let theap = NonNull::from(allocation.initialize_dynamic_theap_metadata()?);
    // SAFETY: this initialized role is still exclusively held by allocation.
    // Transfer precedes list publication, so a foreign final decrement cannot
    // race a surviving Rust capability. The source initializer preserves this
    // typed administration alongside its concrete memory ID.
    unsafe { (*Theap::main_heap_lifecycle_at(theap)).metadata = MainHeapTheapMetadataOwnership::SourceOwned; }
    let theap = allocation.into_source_retained_theap().ok()?;
    initialize_source_owned_theap(thread, heap, theap)?;
    Some(theap)
}

#[cfg(not(target_arch = "x86_64"))]
fn create_theap(thread: MainThread, heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    create_theap_image(thread, heap)
}

/// Completes the source initializer through short typed projections. The
/// transferred metadata reference or retained arena reservation owns this
/// incoming image; the existing fixed owner retains process/output admission
/// across ordinary and guarded option getters before Heap publication.
#[cfg(target_arch = "x86_64")]
fn initialize_source_owned_theap(
    thread: MainThread, heap: NonNull<Heap>, theap: NonNull<Theap>,
) -> Option<()> {
    // SAFETY: this operation retains the initialized fixed current-thread
    // owner, and the incoming image's original source allocation remains
    // held. No image, engine or list projection crosses owner acquisition.
    unsafe { crate::runtime_lifecycle::with_native_allocation_owner(thread.theap, |owner| {
        let prepared = unsafe { Theap::prepare_initialization_at(
            theap, heap, thread.tld, crate::types::TheapInitializationKind::Dynamic {
                page_mode: crate::types::TheapPageMode::OrdinaryAbandoning,
                tld_may_have_theaps: true,
            },
        ) }.ok()?;
        // The admitted fixed owner supplies this actual process's output;
        // all incoming/Heap/TLD projections ended before these lazy reads.
        let options = unsafe { crate::types::SourceTheapOptions::capture_from_output(owner.output()) };
        let linked = match unsafe { prepared.apply_source_options_and_attach(options) }.ok()? {
            crate::types::TheapRandomInitialization::SplitComplete(linked) => linked,
            // This ordinary current-thread source path already has its main
            // Theap. Missing that real member retains the partial image.
            crate::types::TheapRandomInitialization::FirstHead(_) => return None,
        };
        #[cfg(feature = "mi-guarded")]
        let ready = {
            let sample = unsafe { crate::types::GuardedSampleOptions::capture_from_output(owner.output()) };
            let sampled = unsafe { linked.apply_guarded_sample_options(sample) };
            let bounds = unsafe { crate::types::GuardedSizeOptions::capture_from_output(owner.output()) };
            unsafe { sampled.apply_guarded_size_options(bounds) }
        };
        #[cfg(not(feature = "mi-guarded"))]
        let ready = linked.finish_without_guarded_options();
        MainSubprocess::global().identity().record_statistics_theap_linked();
        // SAFETY: original source storage, fixed admission and actual list
        // members remain retained through this final release publication.
        unsafe { ready.publish_heap() }.ok()?;
        Some(())
    }) }.ok().flatten()
}

/// The requested arena's source reservation is a minimum-object slice and
/// retains its exact Rust release capability within that reserved extent.
fn create_theap_image(thread: MainThread, heap: NonNull<Heap>) -> Option<NonNull<Theap>> {
    let binding = binding()?;
    let config = binding.page_map().memory_config().ok()?;
    // SAFETY: this live Heap retains its selected arena for the operation.
    let requested = unsafe { heap.as_ref() }.exclusive_arena_id()?;
    let (block, allocation, memory) = if requested.as_ptr().is_null() {
        let size = size_of::<MainHeapTheapImage>();
        let allocation = MetaAllocator::global()
            .zalloc_for_main_subprocess(config, MainSubprocess::global(), size)
            .ok()?;
        let block = allocation.pointer();
        (block, MainHeapTheapAllocation::Metadata(allocation),
            MemoryId::malloc(block.as_ptr(), size, true))
    } else {
        // SAFETY: the Heap's arena came from a live parent ID, and the
        // process arena backing remains live through all Heap Theaps.
        let reservation = unsafe { MainSubprocess::global().arena_backing().try_reserve_exclusive_theap(
            binding.process(), config, MainSubprocess::global(), requested,
            thread.sequence, thread.numa_node,
        ) }.ok()?;
        let block = NonNull::new(reservation.start())?;
        let memory = reservation.memory_id();
        (block, MainHeapTheapAllocation::Arena(reservation), memory)
    };
    let image = block.cast::<MainHeapTheapImage>().as_ptr();
    // SAFETY: a fresh, exclusively owned block; all Rust fields are written
    // whole before the Theap is published. The TLD is this thread's and the
    // Heap's lists take their own locks.
    let initialized = unsafe {
        core::ptr::addr_of_mut!((*image).theap).write(Theap::empty());
        core::ptr::addr_of_mut!((*image).page_engine).write(ChildPageEngineState::Active);
        core::ptr::addr_of_mut!((*image).allocation).write(Some(allocation));
        core::ptr::addr_of_mut!((*image).retained_deleted_next).write(core::ptr::null_mut());
        core::ptr::addr_of_mut!((*image).retained_deleted_os_pages).write(0);
        let theap = &mut (*image).theap;
        let provenance = if requested.as_ptr().is_null() {
            theap.set_dynamic_metadata_memid(memory)
        } else {
            theap.set_requested_arena_metadata_memid(memory)
        };
        #[cfg(target_arch = "x86_64")]
        { provenance }
        #[cfg(not(target_arch = "x86_64"))]
        {
            provenance && theap.initialize_dynamic_metadata_on_tld(
                &mut *heap.as_ptr(), &mut *thread.tld.as_ptr(),
                crate::types::TheapPageMode::OrdinaryAbandoning, true,
            ).is_ok()
        }
    };
    if !initialized { return None; }
    #[cfg(target_arch = "x86_64")]
    initialize_source_owned_theap(thread, heap, block.cast())?;
    #[cfg(not(target_arch = "x86_64"))]
    MainSubprocess::global().identity().record_statistics_theap_linked();
    Some(block.cast())
}

/// Allocate metadata through the source-selected main Theap. Its fixed
/// runtime owner and freshly linked siblings have separate queue engines.
fn allocate_main_heap_image(thread: MainThread, size: usize, alignment: usize) -> Option<NonNull<u8>> {
    let heap = NonNull::new(MainSubprocess::global().ready_main_heap_pointer())?;
    let theap = heap_theap(thread, heap)?;
    if theap == thread.theap {
        match native_allocate_aligned(size, alignment, true) {
            NativePageAllocationResult::Allocated(block) => Some(block),
            _ => None,
        }
    } else {
        // SAFETY: native admission retains this thread's fixed main owner
        // through the complete metadata allocation and its callbacks.
        unsafe { allocate_on_theap(thread, theap, size, Some((alignment, 0)), true) }
    }
}

/// # Safety
/// The sole-child continuation pins this vanished thread's complete source
/// graph, excludes all observations and callbacks, and retains failed owners.
#[cfg(target_arch = "x86_64")]
unsafe fn drain_vanished_auxiliary_theap(
    thread: MainThread, theap: NonNull<Theap>,
    main_heap: crate::main_theap::MainStaticHeapLease<'static>,
    state: NonNull<ThreadHeaps>,
) -> bool {
    let Some(binding) = binding() else { return false; };
    let Some(heap) = NonNull::new(unsafe { Theap::heap_at(theap) }) else { return false; };
    let Some(requested_arena) = (unsafe { heap.as_ref() }).exclusive_arena_id() else { return false; };
    let mut engine_state = unsafe { MainHeapPageEngineState::new(theap) };
    let page_engine = &mut engine_state.state;
    let mut pending = None;
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), thread.numa_node);
    let Ok(page_map) = (unsafe { binding.page_map().page_map_for_owned_ranges() }) else { return false; };
    // Source collect-abandon only traverses existing page/arena records.
    // Refusing fresh storage prevents a survivor TLS allocation fallback.
    let mut no_allocation = |_: usize, _: usize| None;
    let Some(session) = (unsafe {
        crate::types::metadata_session::ChildOrdinaryTheapPageSession::new_for_vanished_main_subprocess_heap(
            MainSubprocess::global(), thread.tld, theap, heap, thread.thread, thread.sequence,
            &mut pending, page_engine, &mut no_allocation,
        )
    }) else { return false; };
    let mut engine = unsafe {
        crate::single_thread::PageAllocatorEngine::activate_owned_session(
            session, backing, page_map, thread.sequence, requested_arena,
        )
    };
    let drained = unsafe { engine.collect_abandon_vanished_child(theap, thread.thread, main_heap) };
    let finished = engine.finish_owned_session().map_err(drop).is_ok();
    if let Some(owner) = pending.take() {
        let retained = unsafe { &mut (*state.as_ptr()).pending_os_release };
        if retained.is_none() { *retained = Some((Some(theap), owner)); }
        else { core::mem::forget(owner); *page_engine = ChildPageEngineState::Poisoned; }
    }
    drained && finished
}

/// Runs one page operation on `theap`, this thread's Theap for a non-main
/// Heap of the process main subprocess, with that Theap's own engine state.
fn with_theap_engine<R>(
    thread: MainThread,
    theap: NonNull<Theap>,
    operation: impl for<'session> FnOnce(
        &mut crate::single_thread::PageAllocatorEngine<
            'static,
            'static,
            crate::types::metadata_session::ChildOrdinaryTheapPageSession<'session, 'static>,
            crate::page_backing::RuntimeFirstRegularPageBacking,
        >,
    ) -> R,
) -> Option<R> {
    if has_retained_auxiliary_fresh_initialization() { return None; }
    let binding = binding()?;
    if !binding.is_active() || !binding.is_allocation_ready() {
        return None;
    }
    // SAFETY: a live Theap of this thread.
    let heap = NonNull::new(unsafe { Theap::heap_at(theap) })?;
    // SAFETY: the live Heap's selected parent remains published during this
    // page operation and is fixed for the Heap lifetime.
    let requested_arena = unsafe { heap.as_ref() }.exclusive_arena_id()?;
    #[cfg(target_arch = "x86_64")]
    let issuer = unsafe { AuxiliaryAllocationIssuer::capture(heap, theap) }?;
    // SAFETY: this operation holds the owner's local queue authority and a
    // live source reference until after the page session is finished.
    let mut engine_state = unsafe { MainHeapPageEngineState::new(theap) };
    let page_engine = &mut engine_state.state;
    let mut pending_os_release = None;
    #[cfg(target_arch = "x86_64")]
    let mut pending_fresh_initialization = None;
    #[cfg(target_arch = "x86_64")]
    let mut pending_live_page_validity = None;
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), thread.numa_node);
    // SAFETY: this engine registers and unregisters only its own pages.
    let page_map = unsafe { binding.page_map().page_map_for_owned_ranges() }.ok()?;
    let mut allocate_arena_pages = |size: usize, alignment: usize| -> Option<NonNull<u8>> {
        // `mi_heap_zalloc_aligned(heap_main)` through `_mi_heap_theap`.
        allocate_main_heap_image(thread, size, alignment)
    };
    // SAFETY: this thread's live TLD/Theap and the Heap outlive the
    // operation, which runs on this thread only.
    let session = unsafe {
        crate::types::metadata_session::ChildOrdinaryTheapPageSession::new_for_main_subprocess_heap(
            MainSubprocess::global(), thread.tld, theap, heap, thread.thread, thread.sequence,
            &mut pending_os_release, &mut *page_engine, &mut allocate_arena_pages,
        )
    }?;
    #[cfg(target_arch = "x86_64")]
    let session = unsafe { session.with_fresh_initialization_slot(&mut pending_fresh_initialization)
        .and_then(|session| session.with_live_page_validity_slot(&mut pending_live_page_validity)) }?;
    // SAFETY: the process registry backing and its PageMap are held for the
    // operation.
    let mut engine = unsafe {
        crate::single_thread::PageAllocatorEngine::activate_owned_session(
            session, backing, page_map, thread.sequence, requested_arena,
        )
    };
    let value = operation(&mut engine);
    let finished = engine.finish_owned_session().map_err(drop).is_ok();
    #[cfg(target_arch = "x86_64")]
    if let Some(task) = pending_fresh_initialization.take() {
        // Session projections ended; move the exact before-candidate custody
        // with this task, preserving any completed marker stage.
        unsafe { retain_auxiliary_fresh_initialization(task, issuer) };
    } else if let Some(task) = pending_live_page_validity.take() {
        unsafe { retain_auxiliary_live_validity(task, issuer) };
    }
    if let Some(owner) = pending_os_release.take() {
        // SAFETY: the current thread's own state.
        let slot = unsafe { &mut thread_heaps().pending_os_release };
        if slot.is_none() && *page_engine == ChildPageEngineState::RetryPending {
            *slot = Some((Some(theap), owner));
        } else {
            core::mem::forget(owner);
            *page_engine = ChildPageEngineState::Poisoned;
        }
    }
    finished.then_some(value)
}

/// Captures the linear phase outside a short engine projection. A refused
/// session finish must still return its original unpublished claim to the
/// retained issuer's driver instead of dropping it inside an Option adapter.
fn with_theap_allocation_phase(
    thread: MainThread,
    theap: NonNull<Theap>,
    operation: impl for<'session> FnOnce(
        &mut crate::single_thread::PageAllocatorEngine<
            'static,
            'static,
            crate::types::metadata_session::ChildOrdinaryTheapPageSession<'session, 'static>,
            crate::page_backing::RuntimeFirstRegularPageBacking,
        >,
    ) -> crate::single_thread::GuardedCanonicalAllocationPhase,
) -> Option<crate::single_thread::GuardedCanonicalAllocationPhase> {
    let mut phase = None;
    let finished = with_theap_engine(thread, theap, |engine| {
        phase = Some(operation(engine));
    });
    if finished.is_some()
        || matches!(&phase, Some(Ok(crate::single_thread::DeferredFreeAllocationPhase::FreshInitialization(_)
            | crate::single_thread::DeferredFreeAllocationPhase::LiveValidity(_))))
    {
        phase
    } else {
        None
    }
}

/// Pinned `mi_heap_new()` (`heap.c:127-157`) on an ordinary thread of the
/// process main subprocess: the image from the process main Heap (the
/// thread's main-Heap Theap becoming the cached Theap), a dynamic key, then
/// `_mi_heap_init` and the list push. `None` is source null.
pub(crate) fn native_heap_new() -> Option<NonNull<Heap>> {
    // SAFETY: the absent ID selects the ordinary source Heap path.
    unsafe { native_heap_new_in_arena(ArenaId::none()) }
}

/// Create a process-main non-main Heap bound to a live selected parent.
///
/// # Safety
/// A non-null `arena` is a live parent ID of this process and remains live
/// until all Theaps and pages of the returned Heap have been released.
pub(crate) unsafe fn native_heap_new_in_arena(arena: ArenaId) -> Option<NonNull<Heap>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let thread = current_main_thread()?;
    let binding = binding()?;
    let config = binding.page_map().memory_config().ok()?;
    #[cfg(target_arch = "x86_64")]
    let block = {
        // Source Heap birth is ordinary zalloc, not aligned over-allocation.
        // The selected class naturally aligns the entire private image.
        let size = crate::source_heap_api::SOURCE_HEAP_IMAGE_REQUEST_SIZE;
        let main = NonNull::new(MainSubprocess::global().ready_main_heap_pointer())?;
        let theap = heap_theap(thread, main)?;
        let block = if theap == thread.theap {
            match crate::runtime_lifecycle::native_allocate(size, true) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => return None,
            }
        } else {
            // SAFETY: native admission retains this thread's fixed main
            // owner while allocating the unpublished Heap image.
            unsafe { allocate_on_theap(thread, theap, size, None, true) }?
        };
        // SAFETY: this exact new ordinary block remains exclusively owned
        // and unpublished while its source extent is checked.
        let usable = unsafe { crate::runtime_lifecycle::native_usable_size(block) };
        if block.as_ptr().addr() % align_of::<NonMainHeapImage>() != 0
            || usable.is_none_or(|usable| usable < size)
        {
            // SAFETY: no image or client was published in this live block.
            let _ = unsafe { native_free(block) };
            return None;
        }
        block
    };
    #[cfg(not(target_arch = "x86_64"))]
    let block = allocate_main_heap_image(thread, size_of::<NonMainHeapImage>(), align_of::<NonMainHeapImage>())?;
    let keys = HeapKeySource::global();
    let slot = match keys.registry.claim_for_main_subprocess(config, keys.subprocess, keys.metadata) {
        Ok(slot) => slot,
        Err(_) => {
            // SAFETY: the exact live block allocated above.
            let _ = unsafe { native_free(block) };
            return None;
        }
    };
    let identity = MainSubprocess::global().identity();
    // SAFETY: a fresh, zeroed, exclusively owned image block.
    unsafe { crate::types::heap_registry::lifecycle::initialize_and_link_non_main_heap(block, slot, identity, arena) }.ok()
}

/// Pinned `mi_heap_malloc` and its zeroing and aligned forms on the calling
/// thread for a Heap of the process main subprocess.
///
/// # Safety
/// `heap` is the permanent process-main Heap or a live Heap from
/// [`native_heap_new`]. It belongs to the calling thread's subprocess and
/// remains live through this call.
pub(crate) unsafe fn native_heap_allocate(
    heap: NonNull<Heap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<NonNull<u8>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let thread = current_main_thread()?;
    if !is_current_subprocess_heap(heap) {
        return None;
    }
    let theap = heap_theap(thread, heap)?;
    // SAFETY: the caller retains the Heap for the full call and native
    // admission retains the selected thread owner through callbacks.
    unsafe { allocate_on_theap(thread, theap, size, aligned, zero) }
}

/// Allocate through one exact current-thread Theap of a non-main Heap.
///
/// # Safety
/// `theap` remains linked to its live Heap and this thread's TLD for the
/// operation, with no concurrent Heap destruction or thread exit.
pub(crate) unsafe fn native_theap_allocate(
    theap: NonNull<Theap>,
    size: usize,
    zero: bool,
) -> Option<NonNull<u8>> {
    // SAFETY: forwarded current-thread Theap lifetime.
    unsafe { native_theap_allocate_variant(theap, size, None, zero) }
}

/// Allocate on an exact auxiliary Theap without selecting its Heap or
/// publishing a different cached root.
///
/// # Safety
/// `theap` stays linked to its live Heap and this thread's TLD. A supplied
/// alignment is a validated power of two and the Heap is not destroyed.
pub(crate) unsafe fn native_theap_allocate_variant(
    theap: NonNull<Theap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<NonNull<u8>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let thread = current_main_thread()?;
    // SAFETY: caller retains the Theap and its TLD for this thread.
    let heap = NonNull::new(unsafe { Theap::heap_at(theap) })?;
    if !is_current_subprocess_heap(heap) || theap == thread.theap
        || unsafe { Theap::tld_at(theap) } != thread.tld.as_ptr() {
        return None;
    }
    // SAFETY: the caller retains this exact Theap, Heap and TLD through
    // callbacks; native admission remains held until allocation completes.
    unsafe { allocate_on_theap(thread, theap, size, aligned, zero) }
}

/// Allocate one guarded backing block on the exact auxiliary main Theap.
/// The request is already the source generic size, including its padding
/// allowance; this route neither samples nor zeroes the eventual client.
/// `None` declines another owner domain. `Some(None)` preserves a recognized
/// owner's refusal so callers cannot retry through the default allocator.
///
/// # Safety
/// `theap` and its Heap remain live and linked to the calling thread's TLD.
/// The caller excludes concurrent Heap destruction and thread exit, and
/// retains the exact selected owner across any synchronous user callback.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) unsafe fn native_theap_allocate_guarded_canonical(
    theap: NonNull<Theap>,
    source_size: usize,
) -> Option<Option<NonNull<u8>>> {
    // SAFETY: this compatibility adapter forwards the retained exact-owner
    // obligations; source drivers use the explicit progress transport.
    match unsafe { native_theap_allocate_guarded_canonical_progress(theap, source_size) } {
        NativeGuardedCanonicalAllocationProgress::OtherDomain => None,
        NativeGuardedCanonicalAllocationProgress::Refused => Some(None),
        NativeGuardedCanonicalAllocationProgress::Complete(block) => Some(block),
    }
}

/// Allocates the canonical backing extent with explicit source completion.
///
/// # Safety
/// The exact selected Theap, Heap, TLD and native admission remain retained
/// before allocation through every getter, callback and continuation. The
/// caller excludes retirement, thread exit and concurrent local fields.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) unsafe fn native_theap_allocate_guarded_canonical_progress(
    theap: NonNull<Theap>, source_size: usize,
) -> NativeGuardedCanonicalAllocationProgress {
    use NativeGuardedCanonicalAllocationProgress::{OtherDomain, Refused, Complete};
    // SAFETY: the caller retains the selected source image and its Heap.
    let Some(heap) = NonNull::new(unsafe { Theap::heap_at(theap) }) else { return OtherDomain };
    // SAFETY: the retained Heap's immutable subprocess identity is copied
    // without borrowing independently accessed Heap metadata.
    if unsafe { Heap::subprocess_pointer_at(heap) } != MainSubprocess::global().identity_ptr() {
        return OtherDomain;
    }
    let Some(thread) = current_main_thread() else { return Refused };
    if theap == thread.theap { return OtherDomain; }
    // SAFETY: the source image remains initialized for this scalar check.
    if unsafe { Theap::tld_at(theap) } != thread.tld.as_ptr() { return Refused; }
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return Refused;
    };
    // SAFETY: the caller retains this exact initialized source owner. The
    // admission and independent issuer custody precede the first candidate.
    unsafe { crate::runtime_lifecycle::with_native_allocation_owner(theap, |owner| {
        let Some(issuer) = (unsafe { AuxiliaryAllocationIssuer::capture(heap, theap) }) else { return Refused; };
        let mut issuer = Some(issuer);
        let Some(Ok(phase)) = with_theap_allocation_phase(thread, theap, |engine| {
            engine.begin_deferred_free_guarded_canonical_checked(source_size)
        }) else { return Refused };
        match unsafe { finish_guarded_canonical_allocation_on_theap(thread, theap, phase, &owner, &mut issuer) } {
            Ok(block) => Complete(block),
            Err(()) => Refused,
        }
    }) }.unwrap_or(Refused)
}

/// # Safety
/// The exact Theap, Heap and TLD stay retained under native admission for
/// every callback and resumed phase; callbacks may not retire these images.
unsafe fn allocate_on_theap(
    thread: MainThread,
    theap: NonNull<Theap>,
    size: usize,
    aligned: Option<(usize, usize)>,
    zero: bool,
) -> Option<NonNull<u8>> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: this actual selected owner remains live throughout the
        // callback, and admission precedes every candidate or source getter.
        unsafe { crate::runtime_lifecycle::with_native_allocation_owner(theap, |owner| {
            let heap = NonNull::new(unsafe { Theap::heap_at(theap) })?;
            let mut issuer = Some(unsafe { AuxiliaryAllocationIssuer::capture(heap, theap) }?);
    // `_mi_malloc_generic`'s collections run `_mi_deferred_free` first; the
    // engine returns each selected collection so that the callback runs with
    // no engine or Theap projection live, then resumes.
    let phase = with_theap_allocation_phase(thread, theap, |engine| Ok(match aligned {
        None => engine.begin_deferred_free_allocation(size, zero),
        Some((alignment, offset)) => engine.begin_deferred_free_aligned_allocation_at(size, alignment, offset, zero),
    })).and_then(Result::ok)?;
    // SAFETY: forwarded retained source-owner and admission obligations.
    unsafe { finish_allocation_on_theap(thread, theap, phase, &owner, &mut issuer) }
        }) }.ok().flatten()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
    // `_mi_malloc_generic`'s collections run `_mi_deferred_free` first; the
    // engine returns each selected collection so that the callback runs with
    // no engine or Theap projection live, then resumes.
    let phase = with_theap_allocation_phase(thread, theap, |engine| Ok(match aligned {
        None => engine.begin_deferred_free_allocation(size, zero),
        Some((alignment, offset)) => engine.begin_deferred_free_aligned_allocation_at(size, alignment, offset, zero),
    })).and_then(Result::ok)?;
    // SAFETY: forwarded retained source-owner and admission obligations.
    unsafe { finish_allocation_on_theap(thread, theap, phase) }
    }
}

/// # Safety
/// The phase's originating Theap, Heap and TLD remain live and admitted
/// through getter callbacks and completion. Matching addresses alone do not
/// authorize resuming an image after its originating owner was withdrawn.
unsafe fn finish_allocation_on_theap(
    thread: MainThread,
    theap: NonNull<Theap>,
    mut phase: crate::single_thread::DeferredFreeAllocationPhase,
    #[cfg(target_arch = "x86_64")] owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    #[cfg(target_arch = "x86_64")] issuer: &mut Option<AuxiliaryAllocationIssuer>,
) -> Option<NonNull<u8>> {
    use crate::single_thread::{DeferredFreeAllocationPhase, GenericAllocationCollection};
    loop {
        match phase {
            DeferredFreeAllocationPhase::LiveValidity(mut task) => {
                #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
                { task = match unsafe { task.dispatch(owner) } { Ok(never) => match never {}, Err(task) => task }; }
                #[cfg(target_arch = "x86_64")]
                {
                    let Some(original) = issuer.take() else {
                        core::hint::black_box(&task); crabc_core::process::exit_immediately(134);
                    };
                    unsafe { retain_auxiliary_live_validity(task, original); }
                }
                #[cfg(not(target_arch = "x86_64"))]
                { core::hint::black_box(&task); crabc_core::process::exit_immediately(134); }
                return None;
            }
            DeferredFreeAllocationPhase::FreshInitialization(task) => {
                #[cfg(target_arch = "x86_64")]
                unsafe { finish_auxiliary_fresh_initialization(thread, theap, task, owner, issuer) };
                #[cfg(not(target_arch = "x86_64"))]
                { core::hint::black_box(&task); crabc_core::process::exit_immediately(134); }
                return None;
            }
            DeferredFreeAllocationPhase::Complete(block) => return block,
            #[cfg(target_arch = "x86_64")]
            DeferredFreeAllocationPhase::GenericFrequency { request, continuation } => {
                // The actual process binding and selected owner outlive this
                // operation; no engine or TLS projection crosses the getter.
                let frequency = binding()?.process().policy().generic_collect_frequency();
                phase = with_theap_allocation_phase(thread, theap, |engine| {
                    // SAFETY: the caller retained this original issuer
                    // across the getter, with native admission still held.
                    Ok(unsafe { engine.resume_generic_allocation_frequency(request, frequency, continuation) })
                }).and_then(Result::ok)?;
            }
            DeferredFreeAllocationPhase::Collect { collection, continuation } => {
                let force = matches!(collection, GenericAllocationCollection::Force);
                if let Ok(invocation) = crate::deferred_free::begin_process(theap, thread.tld, force) {
                    // SAFETY: this thread's live TLD outlives the synchronous
                    // callback, and nothing of this module is borrowed across it.
                    let _ = unsafe {
                        crate::__crabc_runtime::with_native_allocator_callback_boundary(|| unsafe { invocation.invoke() })
                    };
                }
                phase = with_theap_allocation_phase(thread, theap, |engine| {
                    Ok(engine.resume_deferred_free_allocation(collection, continuation))
                }).and_then(Result::ok)?;
            }
        }
    }
}


/// # Safety
/// The caller retains the phase's original Theap, Heap, TLD and admission
/// through every synchronous getter, callback and continuation.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
unsafe fn finish_guarded_canonical_allocation_on_theap(
    thread: MainThread,
    theap: NonNull<Theap>,
    mut phase: crate::single_thread::DeferredFreeAllocationPhase,
    owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    issuer: &mut Option<AuxiliaryAllocationIssuer>,
) -> Result<Option<NonNull<u8>>, ()> {
    use crate::single_thread::{DeferredFreeAllocationPhase, GenericAllocationCollection};
    loop {
        match phase {
            DeferredFreeAllocationPhase::LiveValidity(mut task) => {
                #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
                { task = match unsafe { task.dispatch(owner) } { Ok(never) => match never {}, Err(task) => task }; }
                #[cfg(target_arch = "x86_64")]
                {
                    let Some(original) = issuer.take() else {
                        core::hint::black_box(&task); crabc_core::process::exit_immediately(134);
                    };
                    unsafe { retain_auxiliary_live_validity(task, original); }
                }
                #[cfg(not(target_arch = "x86_64"))]
                { core::hint::black_box(&task); crabc_core::process::exit_immediately(134); }
                return Err(());
            }
            DeferredFreeAllocationPhase::FreshInitialization(task) => {
                unsafe { finish_auxiliary_fresh_initialization(thread, theap, task, owner, issuer) };
                return Err(());
            }
            DeferredFreeAllocationPhase::Complete(block) => return Ok(block),
            #[cfg(target_arch = "x86_64")]
            DeferredFreeAllocationPhase::GenericFrequency { request, continuation } => {
                // The actual process binding and selected owner outlive this
                // operation; no engine or TLS projection crosses the getter.
                let frequency = binding().ok_or(())?.process().policy().generic_collect_frequency();
                phase = with_theap_allocation_phase(thread, theap, |engine| {
                    // SAFETY: the caller retained this original issuer
                    // across the getter, with native admission still held.
                    unsafe { engine.resume_guarded_canonical_frequency_checked(request, frequency, continuation) }
                }).ok_or(())?.map_err(|_| ())?;
            }
            DeferredFreeAllocationPhase::Collect { collection, continuation } => {
                let force = matches!(collection, GenericAllocationCollection::Force);
                if let Ok(invocation) = crate::deferred_free::begin_process(theap, thread.tld, force) {
                    // SAFETY: this thread's live TLD outlives the synchronous
                    // callback, and nothing of this module is borrowed across it.
                    let _ = unsafe {
                        crate::__crabc_runtime::with_native_allocator_callback_boundary(|| unsafe { invocation.invoke() })
                    };
                }
                phase = with_theap_allocation_phase(thread, theap, |engine| {
                    engine.resume_deferred_free_guarded_canonical_checked(collection, continuation)
                }).ok_or(())?.map_err(|_| ())?;
            }
        }
    }
}

/// # Safety
/// `owner` and `issuer` are the actual original admissions retained from
/// before this candidate. No engine, metadata or owner projection survives
/// dispatch. Cleanup may run only before persistent terminal marking.
#[cfg(target_arch = "x86_64")]
unsafe fn finish_auxiliary_fresh_initialization(
    thread: MainThread, theap: NonNull<Theap>,
    task: crate::single_thread::PendingFreshOsPageInitialization,
    owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    issuer: &mut Option<AuxiliaryAllocationIssuer>,
) {
    #[cfg(any(feature = "mi-debug-1", feature = "mi-debug-2", feature = "mi-debug-3"))]
    let task = match unsafe { task.dispatch(owner) } {
        Ok(never) => match never {},
        Err(task) => task,
    };
    // An actually observed source assertion cannot be made into source null
    // by cleanup after refused dispatch. Keep its exact original claim.
    let source_assertion = matches!(task.failure(),
        crate::single_thread::FreshOsPageInitializationFailure::SourceObservation(_));
    let mut unresolved = Some(task);
    if !source_assertion {
        let _ = with_theap_engine(thread, theap, |engine| {
            let task = unresolved.take().unwrap();
            // SAFETY: the original READY owner and before-candidate custody
            // remain admitted; this is its precise issuing engine projection.
            if let Err(task) = unsafe { engine.cleanup_fresh_os_initialization(task) } {
                unresolved = Some(task);
            }
        });
    }
    if let Some(task) = unresolved {
        let Some(original) = issuer.take() else {
            core::hint::black_box((&task, owner));
            crabc_core::process::exit_immediately(134);
        };
        unsafe { retain_auxiliary_fresh_initialization(task, original) };
    }
}

/// The calling thread's Theap for a non-main Heap that owns `page`, when
/// that page is local to it: the native local free routes such a block here.
///
/// # Safety
/// `page` is the page of a live block associated with the calling thread.
pub(crate) unsafe fn local_heap_theap_of_page(page: NonNull<crate::types::Page>) -> Option<NonNull<Theap>> {
    // SAFETY: the caller retains this page and excludes an ownership move.
    let heap = NonNull::new(unsafe { Page::heap_identity_at(page) })?;
    if !is_process_main_heap(heap) && unsafe { live_non_main_heap_of_page(page) }.is_none() {
        return None;
    }
    // SAFETY: forwarded; a raw field read of a page this thread owns.
    let theap = NonNull::new(unsafe { crate::types::Page::theap_at(page) })?;
    let thread = current_main_thread()?;
    // SAFETY: a page this thread owns names one of its live Theaps.
    (theap != thread.theap && unsafe { Theap::tld_at(theap) } == thread.tld.as_ptr()).then_some(theap)
}

/// Whether an OS page still names a Theap retained after its process-main
/// Heap was deleted. The page's Heap field may already name freed memory;
/// this classification follows only the live retained Theap registry.
/// `None` means the registry lock was unavailable and callers must not try
/// another Heap classification from the same raw page identity.
///
/// # Safety
/// `page` is held live by one exact allocation observation for this call.
pub(crate) unsafe fn retained_deleted_heap_os_page(page: NonNull<Page>) -> Option<bool> {
    // SAFETY: the held allocation keeps the immutable OS provenance and raw
    // Theap identity stable. The latter is compared by value only.
    if !unsafe { Page::is_os_backed_at(page) } {
        return Some(false);
    }
    let source_theap = unsafe { Page::theap_at(page) };
    if source_theap.is_null() {
        return Some(false);
    }
    let retained = &RETAINED_DELETED_HEAP_THEAPS;
    let guard = retained.lock.lock().ok()?;
    // SAFETY: the lock protects every link, and each image owns its extra
    // reference until it is removed from this list.
    let mut image = unsafe { *retained.head.get() };
    while !image.is_null() {
        if image == source_theap {
            drop(guard);
            return Some(true);
        }
        image = unsafe { retained_deleted_next(NonNull::new_unchecked(image)) };
    }
    drop(guard);
    Some(false)
}

/// Frees a source-local OS block whose Heap has already left the public Heap
/// list, using the separately retained Theap queue instead of a stale Heap
/// or TLD pointer. `None` means the page has no such retained owner.
///
/// # Safety
/// `allocation` is one exact live block associated with `current`, and the
/// caller has admitted the native operation. No concurrent local owner may
/// change this page's ordinary fields during the free.
pub(crate) unsafe fn native_free_deleted_heap_local(
    allocation: &mut Option<crate::process_page_map::LiveAllocationPointer>,
    current: LiveThreadId,
) -> Option<NativePageFreeResult> {
    let page = allocation.as_ref()?.page();
    // SAFETY: the held live allocation keeps the page metadata initialized;
    // this raw pointer value is compared with retained owners, never followed.
    let source_theap = unsafe { Page::theap_at(page) };
    let retained = &RETAINED_DELETED_HEAP_THEAPS;
    let guard = match retained.lock.lock() {
        Ok(guard) => guard,
        Err(_) => return Some(NativePageFreeResult::Retained),
    };
    // SAFETY: the held lock protects each list link. Every listed image owns
    // an additional Theap reference until it is unlinked.
    let mut image = unsafe { *retained.head.get() };
    while !image.is_null() && image != source_theap {
        image = unsafe { retained_deleted_next(NonNull::new_unchecked(image)) };
    }
    drop(guard);
    let theap = NonNull::new(image.cast::<Theap>())?;
    let allocation = allocation.take()?;
    let Some(thread) = current_main_thread() else { return Some(NativePageFreeResult::Retained) };
    if thread.thread != current {
        return Some(NativePageFreeResult::Retained);
    }
    let Some(binding) = binding() else { return Some(NativePageFreeResult::Retained) };
    let Ok(page_map) = (unsafe { binding.page_map().page_map_for_owned_ranges() }) else {
        return Some(NativePageFreeResult::Retained);
    };
    let session = match unsafe {
        crate::single_thread::SourceRetainedTheapSession::from_deleted_heap_local_allocation(
            &allocation, current, theap, thread.sequence.get(),
        )
    } {
        Ok(session) => session,
        Err(_) => return Some(NativePageFreeResult::Retained),
    };
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), thread.numa_node);
    // SAFETY: the registry's ref keeps the exact Theap and queue mapped;
    // the held allocation proves the page, block, and local thread identity.
    let Some(mut engine) = (unsafe {
        crate::single_thread::PageAllocatorEngine::activate_source_retained_local_free(
            session, backing, ArenaId::none(), page_map,
        )
    }) else { return Some(NativePageFreeResult::Retained) };
    // SAFETY: the retained list reference keeps this queue image live through
    // the local free and forced retirement. Arena pages may leave too; only
    // OS pages consume the deleted-Heap claim.
    let Some(os_pages_before) = (unsafe { local_os_page_count(theap) }) else {
        return Some(NativePageFreeResult::Retained);
    };
    // SAFETY: the session owns the page's ordinary local fields for this
    // exact current block and the caller consumes it once.
    let freed = unsafe { engine.free_captured_live_allocation(allocation) }.is_ok();
    let retired = freed && engine.collect_deleted_heap_retired_pages();
    let finished = engine.finish_source_retained_local_free().is_ok();
    if !(freed && retired && finished) {
        return Some(NativePageFreeResult::Retained);
    }
    let Some(os_pages_after) = (unsafe { local_os_page_count(theap) }) else {
        return Some(NativePageFreeResult::Retained);
    };
    let Some(released_pages) = os_pages_before.checked_sub(os_pages_after) else {
        return Some(NativePageFreeResult::Retained);
    };
    if !release_retained_deleted_os_pages(theap, released_pages, os_pages_after) {
        return Some(NativePageFreeResult::Retained);
    }
    Some(NativePageFreeResult::Freed)
}

fn release_retained_deleted_os_pages(theap: NonNull<Theap>, _released_pages: usize, remaining_pages: usize) -> bool {
    let retained = &RETAINED_DELETED_HEAP_THEAPS;
    let Ok(guard) = retained.lock.lock() else { return false };
    // SAFETY: the lock protects the intrusive list and this image's extra
    // reference; no queue remains when the caller enters this removal.
    let mut previous = core::ptr::null_mut::<Theap>();
    let mut current = unsafe { *retained.head.get() };
    while !current.is_null() && current.cast::<Theap>() != theap.as_ptr() {
        previous = current;
        current = unsafe { retained_deleted_next(NonNull::new_unchecked(current)) };
    }
    if current.is_null() {
        drop(guard);
        return false;
    }
    // The successful local free already counted the exact quiescent source
    // queues. Keeping another count in an allocation tail would enlarge the
    // source request and duplicate the queues' ownership state.
    #[cfg(target_arch = "x86_64")]
    let remaining = remaining_pages;
    #[cfg(not(target_arch = "x86_64"))]
    let remaining = {
        let image = current.cast::<MainHeapTheapImage>();
        let Some(remaining) = (unsafe { (*image).retained_deleted_os_pages }).checked_sub(_released_pages) else {
            drop(guard);
            return false;
        };
        unsafe { (*image).retained_deleted_os_pages = remaining; }
        remaining
    };
    if remaining != 0 {
        drop(guard);
        return true;
    }
    let next = unsafe { retained_deleted_next(NonNull::new_unchecked(current)) };
    unsafe {
        if previous.is_null() { *retained.head.get() = next; }
        else { set_retained_deleted_next(NonNull::new_unchecked(previous), next); }
        set_retained_deleted_next(NonNull::new_unchecked(current), core::ptr::null_mut());
    }
    drop(guard);
    // SAFETY: the list reference is consumed exactly once after no page
    // queue can name this image again.
    unsafe { theap_decref(theap) };
    true
}

/// The native local free of `block` through `theap` (see
/// [`local_heap_theap_of_page`]).
///
/// # Safety
/// `block` is live on a page `theap` owns, and freed once.
pub(crate) unsafe fn native_free_local(theap: NonNull<Theap>, block: NonNull<u8>) -> NativePageFreeResult {
    let Some(thread) = current_main_thread() else { return NativePageFreeResult::Retained };
    // SAFETY: forwarded.
    match with_theap_engine(thread, theap, |engine| unsafe { engine.free(block) }) {
        Some(Ok(())) => NativePageFreeResult::Freed,
        _ => NativePageFreeResult::Retained,
    }
}

/// Frees a canonical guarded backing allocation on its original auxiliary
/// main Theap, retaining consumption even if finishing the local session
/// subsequently retains an incomplete backing release. `None` declines a
/// different owner domain; a recognized owner's refusal remains explicit.
///
/// # Safety
/// `allocation` is the original live local classification issued while this
/// exact Theap, Heap, TLD and native admission were retained. The canonical
/// backing block has no guard tag or interior client placement yet. The caller
/// excludes retirement, thread exit, another free and concurrent page/queue
/// access. Consumed discharges the client even after a later failure, so it
/// must never be retried or returned as a live allocation.
#[cfg(all(target_arch = "x86_64", feature = "mi-guarded"))]
pub(crate) unsafe fn native_theap_free_guarded_canonical_progress(
    theap: NonNull<Theap>,
    allocation: crate::process_page_map::LiveAllocationPointer,
) -> Option<crate::single_thread::LocalClientFreeProgress> {
    use crate::single_thread::{FreeError, LocalClientFreeProgress};
    // SAFETY: the original selected owner remains retained by the caller;
    // only its immutable Heap and subprocess identities are projected here.
    let heap = NonNull::new(unsafe { Theap::heap_at(theap) })?;
    if unsafe { Heap::subprocess_pointer_at(heap) } != MainSubprocess::global().identity_ptr() {
        return None;
    }
    let Some(thread) = current_main_thread() else {
        return Some(LocalClientFreeProgress::RefusedBeforeConsumption(FreeError::Lifecycle));
    };
    if theap == thread.theap { return None; }
    // SAFETY: the retained source image supplies this scalar TLD identity.
    if unsafe { Theap::tld_at(theap) } != thread.tld.as_ptr() {
        return Some(LocalClientFreeProgress::RefusedBeforeConsumption(FreeError::ForeignPage));
    }
    let mut progress = None;
    let finished = with_theap_engine(thread, theap, |engine| {
        // SAFETY: the caller retains the original classified client and
        // selected local fields through this source publication boundary.
        progress = Some(unsafe { engine.free_captured_live_allocation_with_progress(allocation) });
    }).is_some();
    Some(match progress {
        Some(LocalClientFreeProgress::Consumed(Ok(()))) if !finished => {
            LocalClientFreeProgress::Consumed(Err(FreeError::Lifecycle))
        }
        Some(progress) => progress,
        None => LocalClientFreeProgress::RefusedBeforeConsumption(FreeError::Lifecycle),
    })
}

/// The non-main Heap of the process main subprocess that owns `page`.
///
/// # Safety
/// `page` is the page of a live block.
#[inline]
pub(crate) unsafe fn heap_of_page(page: NonNull<crate::types::Page>) -> Option<NonNull<Heap>> {
    // SAFETY: the caller retains the live block and its stable page identity.
    unsafe { live_non_main_heap_of_page(page) }
}

/// `mi_free_block_mt` with `mi_free_try_collect_mt` for a block of such a
/// Heap that the calling thread does not own, reclaiming into its Theap for
/// the Heap when source would.
///
/// # Safety
/// `allocation` is an exact live allocation on a page of `heap`.
pub(crate) unsafe fn native_free_nonlocal(
    heap: NonNull<Heap>,
    allocation: crate::process_page_map::LiveAllocationPointer,
) -> NativePageFreeResult {
    let Some(binding) = binding() else { return NativePageFreeResult::Retained };
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), -1);
    // SAFETY: this free touches only the claimed page's range.
    let Ok(page_map) = (unsafe { binding.page_map().page_map_for_owned_ranges() }) else {
        return NativePageFreeResult::Retained;
    };
    // SAFETY: forwarded.
    match unsafe {
        crate::single_thread::free_child_page_block_nonlocal(allocation, page_map, &backing, heap, reclaim_on_free)
    } {
        crate::single_thread::ChildNonlocalFreeResult::Freed | crate::single_thread::ChildNonlocalFreeResult::Released => {
            NativePageFreeResult::Freed
        }
        _ => NativePageFreeResult::Retained,
    }
}

/// `mi_abandoned_page_try_reclaim` (`free.c:423-469`) into the calling
/// thread's Theap for the claimed page's Heap, if it has one.
fn reclaim_on_free(
    candidate: crate::abandoned::ReclaimOnFreeCandidate<'_, crate::single_thread::ChildMappedAbandonedPage<'static>>,
) -> crate::abandoned::ReclaimOnFreeOutcome {
    use crate::abandoned::ReclaimOnFreeOutcome::Declined;
    let Some(thread) = current_main_thread() else { return Declined };
    let Some(heap) = NonNull::new(candidate.page_heap()) else { return Declined };
    let Some(theap) = existing_heap_theap(heap) else { return Declined };
    if is_process_main_heap(heap) && theap == thread.theap { return Declined; }
    // SAFETY: a Theap on this thread's slots is live.
    if unsafe { Theap::heap_at(theap) } != heap.as_ptr() {
        return Declined;
    }
    with_theap_engine(thread, theap, |engine| engine.reclaim_abandoned_page_on_free(candidate)).unwrap_or(Declined)
}

/// Pinned `mi_heap_delete` (`heap.c:228-238`) or, with `destroy`,
/// `mi_heap_destroy` (`heap.c:240-259`) of a non-main Heap of the process
/// main subprocess on the calling thread: `mi_heap_free_theaps`, then
/// `_mi_heap_move_pages` to the process main Heap (the calling thread's
/// main-Heap Theap as target and cached Theap) or `_mi_heap_destroy_pages`,
/// then `mi_heap_free` (page records and image back to the main Heap).
///
/// # Safety
/// `heap` is a live Heap from [`native_heap_new`] or the process main Heap;
/// after a destroy no block of it is used again.
pub(crate) unsafe fn native_heap_release(heap: NonNull<Heap>, destroy: bool) -> Result<HeapReleaseOutcome, HeapReleaseError> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter().ok_or(HeapReleaseError::InvalidChild)?;
    let thread = current_main_thread().ok_or(HeapReleaseError::InvalidChild)?;
    // SAFETY: the caller's live Heap.
    if unsafe { heap.as_ref() }.is_subprocess_main() {
        return Ok(HeapReleaseOutcome::MainHeapRefused);
    }
    if !is_main_subprocess_heap(heap) {
        return Err(HeapReleaseError::InvalidChild);
    }
    let main_subprocess = MainSubprocess::global();
    let main_heap = NonNull::new(main_subprocess.ready_main_heap_pointer()).ok_or(HeapReleaseError::InvalidChild)?;
    let mut retained_os_pages = true;
    // `mi_heap_free_theaps`.
    // SAFETY: the Heap and its Theaps are live.
    unsafe {
        heap.as_ref().detach_and_take_theaps(main_subprocess.identity(), |theap| {
            // SAFETY: the detached Theap still has its Heap-list reference,
            // and no caller may mutate this Heap's pages during deletion.
            if !destroy {
                retained_os_pages &= unsafe { retain_deleted_theap_if_needed(theap) };
            }
            heap.as_ref().merge_detached_theap_statistics(theap.as_ref());
            theap_decref(theap);
        })
    }
    .map_err(HeapReleaseError::List)?;
    if !retained_os_pages {
        return Err(HeapReleaseError::Retained);
    }
    let target = if destroy {
        None
    } else {
        // `mi_heap_delete_pages`: `_mi_heap_theap(heap_target)`.
        let theap = heap_theap(thread, main_heap).ok_or(HeapReleaseError::Retained)?;
        Some(crate::single_thread::NonMainHeapPageTarget { heap: main_heap, theap })
    };
    let binding = binding().ok_or(HeapReleaseError::InvalidChild)?;
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), thread.numa_node);
    // SAFETY: the detached Heap's pages are owned by this operation.
    let page_map = unsafe { binding.page_map().page_map_for_owned_ranges() }.map_err(|_| HeapReleaseError::Retained)?;
    // SAFETY: every Theap of the Heap is detached above.
    let moved = unsafe {
        crate::single_thread::delete_non_main_heap_pages(
            heap, target, main_subprocess.arena_backing().registry(), page_map, &backing,
        )
    };
    if !moved {
        return Err(HeapReleaseError::Retained);
    }
    // `mi_heap_free`: page records, then statistics, counts, list, key, and
    // image, each record and the image back through the native free.
    // SAFETY: the live Heap; each record is a live main-Heap block.
    let freed = unsafe { heap.as_ref() }.take_non_main_arena_pages(|record| {
        // SAFETY: the exact live record block, freed once.
        unsafe { free_subproc_safe(record) }
    });
    if !freed {
        return Err(HeapReleaseError::Retained);
    }
    // SAFETY: forwarded; the Heap has no Theap or page left.
    let image = unsafe { crate::types::heap_registry::lifecycle::unlink_non_main_heap(heap, main_heap, main_subprocess.identity()) }?;
    // SAFETY: the exact live image block; nothing names it any longer.
    if unsafe { free_subproc_safe(image.cast()) } {
        Ok(HeapReleaseOutcome::Released)
    } else {
        Err(HeapReleaseError::Retained)
    }
}

/// Pinned `mi_subproc_unsafe_destroy`'s Heap walk (`subproc.c:212-225`) for
/// the process main subprocess at process destruction: each non-main Heap is
/// force-destroyed (`_mi_heap_force_destroy`) before the main Heap, then the
/// destroying thread's thread-locals are released
/// (`_mi_thread_locals_thread_done`).
///
/// The native entry points are closed, so, as for a child at process
/// destruction, each Heap's per-arena page records and its image are left as
/// live blocks on the main Heap's pages for the main-Heap destruction that
/// follows; its Theaps leave their TLDs and Heap and are freed unless a
/// thread's cached entry still references one (as in source). A failed step
/// returns `false` and process destruction retains the rest.
///
/// # Safety
/// Permanent terminal admission holds: no native entry point or Heap
/// operation runs or can start, the process coordinator is still ready, and
/// no block of a destroyed Heap is used again. The caller destroys the main
/// Heap next.
pub(crate) unsafe fn destroy_all_terminal() -> bool {
    if has_retained_auxiliary_fresh_initialization() { return false; }
    let main_subprocess = MainSubprocess::global();
    let identity = main_subprocess.identity();
    let Some(main_heap) = NonNull::new(main_subprocess.ready_main_heap_pointer()) else { return false };
    let Some(binding) = binding() else { return false };
    let backing = crate::page_backing::RuntimeFirstRegularPageBacking::source_registry(binding.process(), -1);
    // SAFETY: terminal exclusion leaves these Heaps' pages to this walk.
    let Ok(page_map) = (unsafe { binding.page_map().page_map_for_owned_ranges() }) else { return false };
    loop {
        let mut next = None;
        let visited = identity.heap_list().visit_heaps(|heap| {
            if heap == main_heap {
                return true;
            }
            next = Some(heap);
            false
        });
        if visited.is_err() {
            return false;
        }
        let Some(heap) = next else { break };
        // `mi_heap_free_theaps`.
        // SAFETY: the Heap and its Theaps are live; no thread runs on them.
        let detached = unsafe {
            heap.as_ref().detach_and_take_theaps(identity, |theap| {
                heap.as_ref().merge_detached_theap_statistics(theap.as_ref());
                theap_decref(theap);
            })
        };
        // `_mi_heap_destroy_pages`.
        // SAFETY: every Theap of the Heap is detached above.
        if detached.is_err()
            || !unsafe {
                crate::single_thread::delete_non_main_heap_pages(
                    heap, None, main_subprocess.arena_backing().registry(), page_map, &backing,
                )
            }
        {
            return false;
        }
        // `mi_heap_free`: the records stay live main-Heap blocks.
        // SAFETY: the live Heap; its records are dropped, not freed.
        if !unsafe { heap.as_ref() }.take_non_main_arena_pages(|_| true) {
            return false;
        }
        // SAFETY: the Heap has no Theap or page left; its image stays a
        // live main-Heap block.
        if unsafe { crate::types::heap_registry::lifecycle::unlink_non_main_heap(heap, main_heap, identity) }.is_err() {
            return false;
        }
    }
    // `_mi_thread_locals_thread_done` on the destroying thread.
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    state.cached = core::ptr::null_mut();
    if let Some(backing) = state.backing.take() {
        install_dynamic_backing(backing);
    }
    if let Some(mut owner) = state.thread_locals.take() {
        let torn_down = owner.teardown().is_ok();
        install_empty_dynamic_backing();
        return torn_down;
    }
    true
}

// Auxiliary refusal codes: regular backing teardown, failed page drain,
// missing session with retained list membership, and locked list detach.
#[cfg(crabc_native_thread_done_audit)]
fn record_thread_done_branch(code: usize) {
    unsafe extern "C" {
        fn crabc_test_record_thread_done_branch(code: usize);
    }
    // SAFETY: the isolated test adapter supplies this scalar-only observer.
    // It neither enters the allocator nor accesses the finishing TLS owner.
    unsafe { crabc_test_record_thread_done_branch(code) };
}

/// `mi_thread_theaps_done` and `_mi_thread_locals_thread_done` for the calling thread's Theaps of
/// non-main Heaps of the process main subprocess, before the thread's own
/// finish: the slot array is freed, each such Theap is collected with its
/// live pages abandoned to its Heap, the cached Theap is reset, and each
/// leaves its Heap and TLD and drops the Heap's reference. `false` when a
/// Theap could not be drained.
pub(crate) fn native_thread_done() -> bool {
    if has_retained_auxiliary_fresh_initialization() { return false; }
    let Some(thread) = current_main_thread() else { return true };
    // SAFETY: the current thread's own state.
    let state = unsafe { thread_heaps() };
    if let Some(backing) = state.backing.take() {
        install_dynamic_backing(backing);
    }
    if let Some(mut owner) = state.thread_locals.take() {
        let torn_down = owner.teardown().is_ok();
        install_empty_dynamic_backing();
        if !torn_down {
            #[cfg(crabc_native_thread_done_audit)]
            record_thread_done_branch(0);
            return false;
        }
    }
    crate::compiler_tls::set_fast_slot(None);
    // SAFETY: this finishing thread retains its TLD and fixed owner. The
    // source list lock pins each auxiliary image and Heap throughout its
    // owner-side collection; callbacks neither detach lists nor reenter TLS.
    let drained = unsafe { ThreadLocalData::drain_auxiliary_theaps_for_thread_done(
        thread.tld, thread.theap, |theap| {
            let drained = with_theap_engine(thread, theap, |engine| {
                #[cfg(crabc_native_thread_done_audit)]
                {
                    unsafe extern "C" { fn crabc_test_thread_done_drain_gate(); }
                    // SAFETY: the test-only driver parks this exact worker and
                    // releases it without entering its allocator or TLS owner.
                    crabc_test_thread_done_drain_gate();
                }
                // SAFETY: the source lock retains this finishing thread's
                // own Theap and Heap for the complete owner-side drain.
                engine.collect_abandon_child_thread_done(theap, thread.thread)
                    && engine.finish_quiescent_in_place()
            });
            if drained != Some(true) {
                #[cfg(crabc_native_thread_done_audit)]
                record_thread_done_branch(if drained.is_some() { 1 } else { 2 });
                return false;
            }
            true
        },
    ) };
    if drained != Ok(true) {
        return false;
    }
    // SAFETY: the immutable source empty Theap is process-static.
    let empty = unsafe { NonNull::new_unchecked(crate::bootstrap::empty_default_theap_ptr()) };
    // Auxiliary default selections must stop naming metadata before that
    // metadata leaves the lists. The fixed owner completes its own finalizer.
    crate::compiler_tls::set_default_theap(thread.theap);
    cached_set(empty);
    let identity = MainSubprocess::global().identity();
    loop {
        // SAFETY: this finishing thread has drained its auxiliary Theaps and
        // cleared its cached root. The TLD lock keeps each selected image
        // live across a concurrent Heap destroy until both lists are unlinked.
        let theap = match unsafe {
            ThreadLocalData::take_next_auxiliary_theap_for_thread_done(thread.tld, thread.theap, identity)
        } {
            Ok(Some(theap)) => theap,
            Ok(None) => break,
            Err(_) => {
                #[cfg(crabc_native_thread_done_audit)]
                record_thread_done_branch(3);
                return false;
            },
        };
        // SAFETY: the Heap's reference, dropped once.
        unsafe { theap_decref(theap) };
    }
    true
}

/// `_mi_free_subproc_safe` (`free.c:299-304`): `mi_free_nonnull` with
/// `allow_collect=false`. A block on a page this thread owns is freed
/// locally; any other is published to its page's remote list, and an
/// abandoned page is not reclaimed or released here.
///
/// # Safety
/// `block` is an exact live block, freed once.
unsafe fn free_subproc_safe(block: NonNull<u8>) -> bool {
    let Some(binding) = binding() else { return false };
    // SAFETY: forwarded live-block contract.
    let Ok(Some(allocation)) = (unsafe { binding.page_map().lookup_live_allocation(block) }) else { return false };
    let local = crate::compiler_tls::current_thread_identity().is_some_and(|thread| allocation.is_associated_with(thread));
    if local {
        drop(allocation);
        // SAFETY: forwarded; the local free never collects foreign pages.
        return (unsafe { native_free(block) }) == NativePageFreeResult::Freed;
    }
    // SAFETY: forwarded; this thread does not own the page.
    unsafe { crate::remote_free::push_live_allocation_without_collect(allocation) }.is_ok()
}

/// The Heap of the page that holds `block` (`mi_page_heap(_mi_ptr_page(p))`),
/// or `None` when the process PageMap registers no page for it.
///
/// # Safety
/// `block` is null or a live block that no thread frees during the call.
pub(crate) unsafe fn heap_of_block(block: NonNull<u8>) -> Option<NonNull<Heap>> {
    let binding = binding()?;
    // SAFETY: forwarded; the live block keeps its page and its Heap field.
    let allocation = unsafe { binding.page_map().lookup_live_allocation(block) }.ok()??;
    // SAFETY: as above.
    NonNull::new(unsafe { allocation.page().as_ref() }.heap())
}

/// The current Heap identity of any registered page containing `pointer`.
/// The pointer may be inside a live block; no block-start validation or
/// Theap ownership check is part of source Heap membership.
///
/// # Safety
/// The caller excludes concurrent registration or unregistration of the
/// pointer's arena slice and any concurrent move of that page to another
/// Heap through this query. A live block held without a concurrent Heap
/// transition satisfies these obligations.
pub(crate) unsafe fn heap_of_pointer(pointer: *const u8) -> Option<NonNull<Heap>> {
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter()?;
    let pointer = NonNull::new(pointer.cast_mut())?;
    let binding = binding()?;
    // SAFETY: forwarded page-lifetime and slice-exclusion obligations.
    let page = unsafe { binding.page_map().lookup_registered_page(pointer.as_ptr()) }.ok()??;
    // SAFETY: the raw page stays registered and its Heap identity is stable
    // through this immediate field read.
    NonNull::new(unsafe { page.as_ref() }.heap())
}

/// Pinned `mi_heap_collect(heap, force)` (`theap.c:123-166`) for a non-main
/// Heap of the process main subprocess on the calling thread:
/// `mi_heap_theap` (creating the Theap), `_mi_deferred_free`, then the
/// Theap's retired/page/arena collection and its statistics merge.
///
/// # Safety
/// `heap` is a live Heap from [`native_heap_new`].
pub(crate) unsafe fn native_heap_collect(heap: NonNull<Heap>, force: bool) {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return };
    let Some(thread) = current_main_thread() else { return };
    if !is_main_subprocess_heap(heap) {
        return;
    }
    let Some(theap) = heap_theap(thread, heap) else { return };
    collect_on_theap(thread, theap, force);
}

/// Collect an already selected auxiliary Theap without reading or replacing
/// the cached Heap selector.
///
/// # Safety
/// `theap` stays linked to the calling thread's live TLD and Heap, with no
/// concurrent Heap destruction or thread exit.
pub(crate) unsafe fn native_theap_collect(theap: NonNull<Theap>, force: bool) {
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else { return };
    let Some(thread) = current_main_thread() else { return };
    // SAFETY: the caller retains this Theap and its current-thread TLD.
    let Some(heap) = NonNull::new(unsafe { Theap::heap_at(theap) }) else { return };
    if !is_current_subprocess_heap(heap) || theap == thread.theap
        || unsafe { Theap::tld_at(theap) } != thread.tld.as_ptr() {
        return;
    }
    collect_on_theap(thread, theap, force);
}

fn collect_on_theap(thread: MainThread, theap: NonNull<Theap>, force: bool) {
    // `_mi_deferred_free(theap, force)`: the selected callback runs with no
    // engine or Theap projection live.
    if let Ok(invocation) = crate::deferred_free::begin_process(theap, thread.tld, force) {
        // SAFETY: this thread's live TLD outlives the synchronous callback
        // and nothing of this module is borrowed across it.
        let _ = unsafe { crate::__crabc_runtime::with_native_allocator_callback_boundary(|| unsafe { invocation.invoke() }) };
    }
    let collection = if force {
        crate::single_thread::GenericAllocationCollection::Force
    } else {
        crate::single_thread::GenericAllocationCollection::Full
    };
    let _ = with_theap_engine(thread, theap, |engine| {
        engine.resume_deferred_free_allocation(collection, crate::single_thread::DeferredFreeAllocationContinuation::Collection)
    });
}

/// `mi_heap_get_stats(heap)`'s merge (`stats.c:453-465`) for a non-main Heap
/// of the process main subprocess: the calling thread's Theap for the Heap,
/// if it has one (`_mi_heap_theap_peek`), moves its statistics into the
/// Heap's before `mi_stats_get` adds them.
///
/// # Safety
/// `heap` is a live Heap, kept alive for the call (the caller holds the
/// subprocess Heap-list lock, which its destruction takes to unlink it).
pub(crate) unsafe fn merge_current_thread_theap_statistics(heap: NonNull<Heap>) {
    if !is_main_subprocess_heap(heap) || current_main_thread().is_none() {
        return;
    }
    let Some(theap) = heap_key(heap).and_then(|key| NonNull::new(thread_local_get(key).cast::<Theap>())) else {
        return;
    };
    // SAFETY: this thread's live Theap for `heap`, which only this thread
    // frees; its statistics are relaxed atomics shared with the Heap's.
    unsafe { heap.as_ref().merge_attached_theap_statistics_at(theap) };
}

/// `_mi_heap_theap(heap_main)` on an ordinary thread of the process main
/// subprocess: the thread's main-Heap Theap becomes the cached Theap before a
/// `mi_heap_*` entry allocates from the main Heap.
pub(crate) fn select_main_heap_theap() {
    if let Some(thread) = current_main_thread() {
        if let Some(heap) = NonNull::new(MainSubprocess::global().ready_main_heap_pointer()) {
            let _ = heap_theap(thread, heap);
        }
    }
}

/// Pinned `mi_reserve_os_memory_ex2` (`arena.c:1886-1907`) into the process
/// main subprocess: `_mi_os_alloc_aligned` then `mi_manage_os_memory_ex2`,
/// through the process arena group's one source reservation. Every failure
/// is source `ENOMEM`; it says which step failed.
pub(crate) fn native_reserve_os_memory(
    size: usize,
    commit: bool,
    allow_large: bool,
    exclusive: bool,
    diagnostic: &mut Option<crate::diagnostic_output::RegularReservationDiagnostic>,
) -> Result<crate::arena::ArenaId, crate::arena::ReserveOsMemoryFailure> {
    use crate::arena::ReserveOsMemoryFailure::Unmanaged;
    *diagnostic = None;
    let _operation = crate::runtime_lifecycle::NativeSubprocessOperation::enter().ok_or(Unmanaged)?;
    let binding = binding().ok_or(Unmanaged)?;
    let config = binding.page_map().memory_config().map_err(|_| Unmanaged)?;
    let access = if commit { crate::os::MapAccess::Committed } else { crate::os::MapAccess::Reserved };
    // SAFETY: the calling thread's default root names its live Theap or the
    // empty image for this whole operation, and nothing else borrows its
    // random field during the reservation.
    let mut random = unsafe { crate::os::CurrentDefaultTheapRandom::new() };
    // SAFETY: the process main subprocess owns the process's sole arena
    // group, bound to this ready binding's process and configuration for the
    // process lifetime; its reserve lock serializes the reservation.
    unsafe {
        MainSubprocess::global().arena_backing().reserve_os_memory_reporting_failure(
            binding.process(), config, size, access, allow_large, exclusive, Some(&mut random), diagnostic,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
    #[test]
    fn auxiliary_fresh_os_assertion_preserves_original_issuer_during_output_reentry() {
        const CHILD: &str = "CRABC_AUXILIARY_FRESH_OS_ASSERTION";
        struct Probe {
            selected: NonNull<Theap>,
            map: crate::process_page_map::ProcessPageMapRoot,
            observed: core::cell::Cell<Option<(NonNull<Page>, NonNull<u8>, usize)>>,
        }
        unsafe fn observe(state: &crate::types::PageValiditySnapshot, page: NonNull<Page>, argument: *mut core::ffi::c_void) {
            // SAFETY: the synchronous fixture and original engine retain
            // this probe and exclusively own the unpublished committed byte.
            let probe = unsafe { &*argument.cast::<Probe>() };
            assert!(probe.observed.get().is_none());
            assert_eq!((state.used, state.capacity), (0, 0));
            assert!(state.free.is_null());
            assert_eq!(unsafe { probe.map.lookup_registered_page(state.area.as_ptr()) }.unwrap(), Some(page));
            probe.observed.set(Some((page, state.area, state.area_bytes)));
            unsafe { state.area.as_ptr().write(0x5A) };
        }
        unsafe fn passive(_: &crate::types::PageValiditySnapshot, _: NonNull<Page>, _: *mut core::ffi::c_void) {}
        unsafe extern "C" fn output(message: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
            unsafe extern "C" { fn write(fd: core::ffi::c_int, bytes: *const core::ffi::c_void, size: usize) -> isize; }
            // SAFETY: the original pre-candidate READY scope and auxiliary
            // Heap caller retain this probe through synchronous fatal output.
            let probe = unsafe { &*argument.cast::<Probe>() };
            let message = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if message.starts_with(b"mimalloc: assertion failed:") {
                let (page, area, bytes) = probe.observed.get().unwrap();
                assert!(!has_retained_auxiliary_fresh_initialization(),
                    "live fatal output is protected by its original scope, before persistent handoff");
                assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), Some(page));
                let state = unsafe { Page::validity_snapshot_at(page) };
                assert_eq!((state.used, state.capacity), (0, 0));
                assert!(state.free.is_null());
                assert!(state.local_free.is_null());
                let nested = unsafe { crate::page_validity::with_fresh_page_initialization_observer_for_test(
                    passive, core::ptr::null_mut(), || native_theap_allocate(probe.selected, 96, false)
                ) }.expect("the exact original auxiliary owner permits ordinary output reentry");
                assert!(nested.addr().get() < area.addr().get() || nested.addr().get() >= area.addr().get() + bytes);
                assert_eq!(unsafe { native_free(nested) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), Some(page));
                assert_eq!(unsafe { area.as_ptr().read() }, 0x5A);
                let marker = b"original auxiliary fresh backing retained during native reentry\n";
                assert_eq!(unsafe { write(2, marker.as_ptr().cast(), marker.len()) }, marker.len() as isize);
            }
            assert_eq!(unsafe { write(2, message.as_ptr().cast(), message.len()) }, message.len() as isize);
        }
        if std::env::var_os(CHILD).is_some() {
            crabc_core::process::setrlimit_raw(4, &crabc_core::process::KernelRlimit64 { rlim_cur: 0, rlim_max: 0 }).unwrap();
            assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
            }));
            let heap = native_heap_new().unwrap();
            let selected = native_heap_theap(heap).unwrap();
            crate::source_options_api::option_set(crate::config::SourceOption::DisallowArenaAlloc as i32, 1);
            // SAFETY: the actual original READY admission precedes the
            // candidate. The enclosing caller retains its auxiliary Heap and
            // TLD throughout output, nested allocation and terminal dispatch.
            unsafe { crate::runtime_lifecycle::with_native_allocation_owner(selected, |owner| {
                let probe = Probe { selected, map: owner.page_map().unwrap(), observed: core::cell::Cell::new(None) };
                owner.output().register_output(Some(output), core::ptr::from_ref(&probe).cast_mut().cast());
                crate::page_validity::with_fresh_page_initialization_observer_for_test(
                    observe, core::ptr::from_ref(&probe).cast_mut().cast(), || {
                        let _ = native_theap_allocate(selected, 2 * 1024 * 1024, false);
                        panic!("an observed source assertion cannot return source null");
                    },
                );
            }) }.unwrap();
            return;
        }
        use std::os::unix::process::ExitStatusExt;
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "subproc::main_heaps::tests::auxiliary_fresh_os_assertion_preserves_original_issuer_during_output_reentry",
                "--nocapture", "--test-threads=1"])
            .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.work"))
            .env(CHILD, "1").output().unwrap();
        let stderr = std::string::String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.signal(), Some(6), "{stderr}");
        assert!(stderr.contains("original auxiliary fresh backing retained during native reentry"), "{stderr}");
        assert!(stderr.contains("mi_mem_is_zero(page_start, mi_page_committed(page))"), "{stderr}");
    }


    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
    #[test]
    fn auxiliary_unpublished_fresh_task_retains_issuer_before_foreign_heap_destroy() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::auxiliary_unpublished_fresh_task_retains_issuer_before_foreign_heap_destroy",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                let heap = native_heap_new().unwrap();
                let selected = native_heap_theap(heap).unwrap();
                let foreign_heap = native_heap_new().unwrap();
                let foreign = native_heap_theap(foreign_heap).unwrap();
                crate::source_options_api::option_set(crate::config::SourceOption::DisallowArenaAlloc as i32, 1);
                let thread = current_main_thread().unwrap();
                struct Observed {
                    page: Option<NonNull<Page>>,
                    area: Option<NonNull<u8>>,
                    calls: usize,
                }
                unsafe fn disturb_initial_zero(
                    state: &crate::types::PageValiditySnapshot, page: NonNull<Page>,
                    argument: *mut core::ffi::c_void,
                ) {
                    // SAFETY: the synchronous observer retains this stack
                    // state and the engine's exclusively owned committed claim.
                    let observed = unsafe { &mut *argument.cast::<Observed>() };
                    observed.page = Some(page);
                    observed.area = Some(state.area);
                    observed.calls += 1;
                    unsafe { state.area.as_ptr().write(0x6D) };
                }
                let mut observed = Observed { page: None, area: None, calls: 0 };
                // Both genuine READY owners precede the real candidate. The
                // foreign owner may refuse dispatch but cannot replace its
                // original Heap, Theap, process or OS claim.
                unsafe { crate::runtime_lifecycle::with_native_allocation_owner(selected, |original_owner| {
                    let issuer = AuxiliaryAllocationIssuer::capture(heap, selected).unwrap();
                    crate::runtime_lifecycle::with_native_allocation_owner(foreign, |foreign_owner| {
                        let task = crate::page_validity::with_fresh_page_initialization_observer_for_test(
                            disturb_initial_zero, core::ptr::addr_of_mut!(observed).cast(), || {
                                use crate::single_thread::DeferredFreeAllocationPhase;
                                let mut phase = with_theap_allocation_phase(thread, selected, |engine| {
                                    Ok(engine.begin_deferred_free_allocation(2 * 1024 * 1024, false))
                                }).unwrap().unwrap();
                                loop {
                                    phase = match phase {
                                        DeferredFreeAllocationPhase::FreshInitialization(task) => break task,
                                        DeferredFreeAllocationPhase::LiveValidity(_) => panic!("fresh candidate expected, live assertion received"),
                                        DeferredFreeAllocationPhase::Complete(_) => panic!("the actual OS candidate must fail its observed source zero assertion"),
                                        DeferredFreeAllocationPhase::GenericFrequency { request, continuation } => {
                                            let frequency = binding().unwrap().process().policy().generic_collect_frequency();
                                            with_theap_allocation_phase(thread, selected, |engine| {
                                                Ok(engine.resume_generic_allocation_frequency(request, frequency, continuation))
                                            }).unwrap().unwrap()
                                        }
                                        DeferredFreeAllocationPhase::Collect { collection, continuation } => {
                                            with_theap_allocation_phase(thread, selected, |engine| {
                                                Ok(engine.resume_deferred_free_allocation(collection, continuation))
                                            }).unwrap().unwrap()
                                        }
                                    };
                                }
                            },
                        );
                        assert_eq!(task.failure(), crate::single_thread::FreshOsPageInitializationFailure::SourceObservation(
                            crate::page_validity::SourcePageInvariant::InitiallyZero));
                        let task = match task.dispatch(&foreign_owner) {
                            Err(task) => task,
                            Ok(never) => match never {},
                        };
                        assert!(task.matches_theap(original_owner.selected_theap()));
                        retain_auxiliary_fresh_initialization(task, issuer);
                    }).unwrap();
                }) }.unwrap();
                assert_eq!(observed.calls, 1);
                let page = observed.page.unwrap();
                let area = observed.area.unwrap();
                let refcount = unsafe { selected.as_ref().refcount() };
                let page_count = unsafe { selected.as_ref().page_count() };
                let backing = unsafe { thread_heaps() }.backing;
                let cached = cached_theap();
                // No client or list was published; the retained task owns the
                // registered primary and its exact unchanged backing instead.
                assert_eq!(unsafe { page.as_ref().used() }, 0);
                assert_eq!(unsafe { page.as_ref().capacity() }, 0);
                assert_eq!(unsafe { binding().unwrap().page_map().page_map().unwrap().checked_lookup(area.as_ptr()) }, page.as_ptr());
                assert_eq!(unsafe { ThreadLocalData::has_linked_theap_member_blocking(thread.tld, selected.as_ptr()) }, Ok(true));
                let address = heap.as_ptr().addr();
                std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    assert!(unsafe { crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(crate::runtime_lifecycle::attach_current_thread(), crate::runtime_lifecycle::ThreadAttachResult::Attached);
                    // SAFETY: the joined original thread retains the actual
                    // Heap, source member and unpublished task throughout.
                    let heap = NonNull::new(address as *mut Heap).unwrap();
                    assert_eq!(unsafe { native_heap_release(heap, true) }, Err(HeapReleaseError::List(
                        crate::types::heap_registry::SourceHeapRegistryError::RetainedFreshTask)));
                    assert_eq!(crate::runtime_lifecycle::finish_current_thread_native_after_user_destructors(),
                        crate::runtime_lifecycle::ThreadFinishResult::Finished);
                }).join().unwrap();
                assert!(!native_thread_done());
                assert!(!release_current_thread_locals_for_child_destroy());
                assert!(!unsafe { destroy_all_terminal() });
                assert_eq!(unsafe { selected.as_ref().refcount() }, refcount);
                assert_eq!(unsafe { selected.as_ref().page_count() }, page_count);
                assert!(unsafe { heap.as_ref().has_exact_theap_member(selected.as_ptr()) });
                assert_eq!(unsafe { ThreadLocalData::has_linked_theap_member_blocking(thread.tld, selected.as_ptr()) }, Ok(true));
                assert_eq!(unsafe { thread_heaps() }.backing, backing);
                assert_eq!(cached_theap(), cached);
                assert_eq!(unsafe { area.as_ptr().read() }, 0x6D);
                assert_eq!(unsafe { binding().unwrap().page_map().page_map().unwrap().checked_lookup(area.as_ptr()) }, page.as_ptr());
                let retained = unsafe { thread_heaps() }.pending_fresh_initialization.as_ref().unwrap();
                assert_eq!(retained.issuer.heap, heap);
                assert_eq!(retained.issuer.theap, selected);
                assert!(retained.task.has_retirement_refusal_marker());
                // This fresh subprocess ends with the exact terminal task
                // retained. Marked source assertions are never quiet cleanup.
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    fn child_initial_sampler_tail_protection(entropy_refusal: bool) -> ([[bool; 3]; 2], usize) {
        use crate::runtime_lifecycle::{finish_current_thread_native_after_user_destructors,
            prepare_native_later_thread_arena, ThreadFinishResult};
        use crate::subproc::lifecycle::{native_subproc_new, native_subproc_add_current_thread,
            native_subproc_destroy, NativeChildThreadAdd};
        assert!(prepare_native_later_thread_arena());
        let id = native_subproc_new().expect("an actual live child subprocess");
        let observations = std::thread::spawn(move || {
            // SAFETY: this worker registers its own actual descriptor
            // before entering the child's ordinary thread admission.
            assert!(unsafe {
                crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(
                    crate::runtime_lifecycle::current_native_allocator_thread_descriptor())
            });
            let injection = entropy_refusal.then(|| crate::os::fault::install(
                crate::os::fault::Plan::at(crate::os::fault::Point::Entropy, 1, crabc_core::Errno::AGAIN),
            ));
            // SAFETY: the parent retains this actual child id until
            // this worker joins, and only this worker owns its TLS roots.
            assert_eq!(unsafe { native_subproc_add_current_thread(id) }, Ok(NativeChildThreadAdd::Added));
            let entropy_draws = injection.as_ref().map_or(0, |guard| guard.observed());
            if let Some(guard) = injection.as_ref() { guard.set(crate::os::fault::Plan::disabled()); }
            let base = crate::source_heap_api::theap_get_default();
            let heap = crate::source_heap_api::heap_new();
            assert!(!base.is_null() && !heap.is_null());
            // SAFETY: the actual Heap and this worker's attached TLD
            // remain retained until both clients have been released.
            let other = unsafe { crate::source_heap_api::heap_theap(heap) };
            assert!(!other.is_null());
            // SAFETY: the worker retains these original initialized images
            // and no allocator image projection overlaps these scalar reads.
            for theap in [base, other] {
                assert_eq!(unsafe { Theap::guarded_sample_rate_at(core::ptr::NonNull::new(theap.cast()).unwrap()) }, 1,
                    "the original child image receives the live source sampling rate");
            }
            let maps = |address| {
                std::fs::read_to_string("/proc/self/maps").unwrap().lines().find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let (begin, end) = fields.next()?.split_once('-')?;
                    let begin = usize::from_str_radix(begin, 16).ok()?;
                    let end = usize::from_str_radix(end, 16).ok()?;
                    (begin <= address && address < end).then(||
                        std::string::String::from(fields.next().unwrap()))
                }).expect("the actual allocation tail belongs to a process mapping")
            };
            let mut protected = [[false; 3]; 2];
            for (index, theap) in [base, other].into_iter().enumerate() {
                // SAFETY: both original Theaps are owned by this
                // worker and remain attached through allocation/free.
                for (size_index, size) in [79, 91, 97].into_iter().enumerate() {
                    let block = unsafe { crate::source_api::theap_calloc(theap, 1, size) }
                        .value.expect("a valid public child calloc succeeds");
                    // SAFETY: this client has its requested initialized bytes
                    // and stays retained through content/usable-size reads.
                    unsafe {
                        assert!(core::slice::from_raw_parts(block.as_ptr(), size).iter().all(|byte| *byte == 0));
                        let tail = block.as_ptr().addr() + crate::source_api::usable_size(block.as_ptr());
                        protected[index][size_index] = maps(tail).starts_with("---");
                        crate::source_api::free(block.as_ptr());
                    }
                }
            }
            // SAFETY: all auxiliary clients were released, and this
            // worker still retains the original actual Heap and member.
            assert!(unsafe { crate::source_heap_api::heap_release(heap, false) });
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            (protected, entropy_draws)
        }).join().expect("the actual child worker finishes");
        // SAFETY: the worker ended all real TLS membership and client
        // ownership before the parent destroys this exact child id.
        assert_eq!(unsafe { native_subproc_destroy(id) }, Ok(()));
        observations
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn child_initial_theaps_inherit_live_process_guarded_sample_rate() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::child_initial_theaps_inherit_live_process_guarded_sample_rate",
            || {
                // The newly exec'd fixture selects this valid source option
                // before any process owner or environment reader exists.
                std::env::set_var("mimalloc_guarded_sample_rate", "1");
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert_eq!(child_initial_sampler_tail_protection(false).0, [[true; 3]; 2],
                    "both child initial samplers inherit the live process rate before public allocation");
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn child_initial_sampler_reads_live_rate_and_bounds_after_entropy_warning() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::child_initial_sampler_reads_live_rate_and_bounds_after_entropy_warning",
            || {
                static WARNINGS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
                unsafe extern "C" fn output(message: *const core::ffi::c_char, _: *mut core::ffi::c_void) {
                    // SAFETY: the actual synchronous source output route
                    // supplies a live terminated fragment for this callback.
                    let bytes = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
                    if !bytes.windows(b"unable to use secure randomness\n".len()).any(|window|
                        window == b"unable to use secure randomness\n") { return; }
                    WARNINGS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    use crate::config::SourceOption;
                    crate::source_options_api::option_set(SourceOption::GuardedSampleRate as i32, 1);
                    crate::source_options_api::option_set(SourceOption::GuardedMin as i32, 80);
                    crate::source_options_api::option_set(SourceOption::GuardedMax as i32, 96);
                }
                // The real process table starts with sampling disabled. Only
                // an actual OS entropy refusal's warning changes these values.
                std::env::set_var("mimalloc_guarded_sample_rate", "0");
                std::env::set_var("mimalloc_show_errors", "1");
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                // SAFETY: this permanent callback is installed before the
                // worker begins; no competing registration changes its route.
                unsafe { crate::source_options_api::register_output(Some(output), core::ptr::null_mut()); }
                let (protected, entropy_draws) = child_initial_sampler_tail_protection(true);
                assert_eq!(entropy_draws, 1, "the actual first child TLD head makes one entropy attempt");
                assert_eq!(WARNINGS.load(core::sync::atomic::Ordering::Relaxed), 1);
                assert_eq!(protected, [[false, true, false]; 2],
                    "source getters observe the warning's live sample rate and both size bounds");
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn auxiliary_theap_initialization_reads_actual_guarded_options_before_publication() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::auxiliary_theap_initialization_reads_actual_guarded_options_before_publication",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                use crate::config::SourceOption;
                crate::source_options_api::option_set(SourceOption::GuardedSampleRate as i32, 1);
                let first = native_heap_new().unwrap();
                let first_theap = native_heap_theap(first).unwrap();
                // Source's default upper bound includes ordinary large
                // requests; a zeroed legacy sampler wrongly refuses these.
                assert!(unsafe { Theap::guarded_sample_at(first_theap, 32 * 1024) });
                crate::source_options_api::option_set(SourceOption::GuardedMin as i32, 80);
                crate::source_options_api::option_set(SourceOption::GuardedMax as i32, 96);
                let second = native_heap_new().unwrap();
                let second_theap = native_heap_theap(second).unwrap();
                assert_ne!(first_theap, second_theap);
                assert!(!unsafe { Theap::guarded_sample_at(second_theap, 79) });
                assert!(unsafe { Theap::guarded_sample_at(second_theap, 80) });
                assert!(unsafe { Theap::guarded_sample_at(second_theap, 96) });
                assert!(!unsafe { Theap::guarded_sample_at(second_theap, 97) });
                // Each setter initializes its own incoming Theap; changing
                // process options does not rewrite an existing sampler.
                assert!(unsafe { Theap::guarded_sample_at(first_theap, 32 * 1024) });
                assert_eq!(unsafe { native_heap_release(second, true) }, Ok(HeapReleaseOutcome::Released));
                assert_eq!(unsafe { native_heap_release(first, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn guarded_canonical_auxiliary_main_theap_preserves_source_block_geometry_and_owner() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::guarded_canonical_auxiliary_main_theap_preserves_source_block_geometry_and_owner",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                let heap = native_heap_new().expect("a live auxiliary main Heap");
                let selected = native_heap_theap(heap).expect("its exact current-thread Theap");
                let other_heap = native_heap_new().expect("another live auxiliary main Heap");
                let other = native_heap_theap(other_heap).expect("a different cached Theap");
                assert_ne!(selected, other);
                let default = crate::compiler_tls::default_theap();
                let cached = cached_theap();
                assert_eq!(cached, other);
                struct CallbackState {
                    selected: NonNull<Theap>,
                    calls: core::cell::Cell<usize>,
                    entered: core::cell::Cell<bool>,
                    nested: core::cell::Cell<bool>,
                }
                unsafe extern "C" fn callback(_: bool, _: u64, context: *mut core::ffi::c_void) {
                    // SAFETY: registration holds this stack state and its
                    // selected source owner through every synchronous call.
                    let state = unsafe { &*context.cast::<CallbackState>() };
                    state.calls.set(state.calls.get() + 1);
                    if !state.entered.replace(true) {
                        // A nested request uses the same exact owner while
                        // the outer canonical engine has released its session.
                        if let Some(block) = unsafe { native_theap_allocate(state.selected, 64, false) } {
                            state.nested.set(unsafe { native_free(block) } == NativePageFreeResult::Freed);
                        }
                    }
                }
                let mut state = CallbackState {
                    selected, calls: core::cell::Cell::new(0),
                    entered: core::cell::Cell::new(false), nested: core::cell::Cell::new(false),
                };
                // SAFETY: this fresh process serializes registration. The
                // stack context and Heap outlive callback removal below.
                unsafe { crate::deferred_free::register_process_callback(Some(callback),
                    core::ptr::addr_of_mut!(state).cast()) };
                assert_eq!(unsafe { native_theap_allocate_guarded_canonical(selected, 1) }, Some(None));
                assert_eq!(unsafe { native_theap_allocate_guarded_canonical(default, 8192) }, None);
                assert_eq!(unsafe { native_theap_allocate_guarded_canonical_progress(default, 8192) },
                    NativeGuardedCanonicalAllocationProgress::OtherDomain);
                let first = unsafe { native_theap_allocate_guarded_canonical(selected, 8192) }.expect("the selected auxiliary main domain")
                    .expect("one canonical guarded backing block");
                let second = unsafe { native_theap_allocate_guarded_canonical(selected, 8192) }.expect("the selected auxiliary main domain")
                    .expect("another simultaneously live backing block");
                assert_ne!(first, second);
                // The source administrative callback runs after the generic
                // counter reaches its threshold, not on every allocation.
                for _ in 0..1001 {
                    let temporary = unsafe { native_theap_allocate_guarded_canonical(selected, 8192) }
                        .expect("the exact auxiliary domain").expect("a generic counter step");
                    assert_eq!(unsafe { native_free(temporary) }, NativePageFreeResult::Freed);
                }
                // SAFETY: all synchronous invocations ended, and no other
                // thread can observe this fresh process's registration.
                unsafe { crate::deferred_free::register_process_callback(None, core::ptr::null_mut()) };
                assert!(state.calls.get() > 0);
                assert!(state.nested.get(), "the canonical callback permits same-owner allocation/free");
                for block in [first, second] {
                    assert_eq!(unsafe { crate::runtime_lifecycle::native_usable_size(block) },
                        Some(8192 - crate::config::PADDING_SIZE));
                    let allocation = unsafe { binding().unwrap().page_map().lookup_live_allocation(block) }
                        .unwrap().expect("registered live canonical allocation");
                    let page = allocation.page();
                    assert_eq!(unsafe { Page::theap_at(page) }, selected.as_ptr());
                    assert_eq!(unsafe { Page::heap_identity_at(page) }, heap.as_ptr());
                    assert_eq!(unsafe { page.as_ref() }.block_size(), 8192,
                        "the source generic input already includes padding allowance");
                    drop(allocation);
                }
                assert_eq!(crate::compiler_tls::default_theap(), default);
                // Fresh canonical page metadata is allocated through the
                // fixed main Heap, updating the source Heap API cache while
                // retaining the caller's default and selected page owner.
                assert_eq!(cached_theap(), fixed_main_theap().unwrap());
                for block in [first, second] {
                    let _admission = crate::runtime_lifecycle::NativeSubprocessOperation::enter()
                        .expect("the selected owner remains admitted for canonical cleanup");
                    let allocation = unsafe { binding().unwrap().page_map().lookup_live_allocation(block) }
                        .unwrap().unwrap();
                    let page = allocation.page();
                    let used = unsafe { page.as_ref() }.used();
                    assert_eq!(unsafe { native_theap_free_guarded_canonical_progress(selected, allocation) },
                        Some(crate::single_thread::LocalClientFreeProgress::Consumed(Ok(()))));
                    assert_eq!(unsafe { page.as_ref() }.used(), used - 1,
                        "canonical cleanup consumes exactly one original client");
                }
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                assert_eq!(unsafe { native_heap_release(other_heap, false) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn guarded_canonical_auxiliary_main_theap_retries_after_real_mapping_failure() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::guarded_canonical_auxiliary_main_theap_retries_after_real_mapping_failure",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                let heap = native_heap_new().expect("a live auxiliary main Heap");
                let selected = native_heap_theap(heap).expect("its source-selected Theap");
                unsafe extern "C" {
                    fn getrlimit(resource: core::ffi::c_int, limit: *mut [usize; 2]) -> core::ffi::c_int;
                    fn setrlimit(resource: core::ffi::c_int, limit: *const [usize; 2]) -> core::ffi::c_int;
                }
                let mut previous = [0usize; 2];
                // SAFETY: Linux's native rlimit is two unsigned long fields;
                // this private child changes only its own address-space limit.
                assert_eq!(unsafe { getrlimit(9, &mut previous) }, 0);
                let limited = [1usize, previous[1]];
                assert_eq!(unsafe { setrlimit(9, &limited) }, 0);
                let refused = unsafe { native_theap_allocate_guarded_canonical_progress(selected, 1 << 30) };
                // Restore before assertions or client diagnostics can allocate.
                let restored = unsafe { setrlimit(9, &previous) };
                assert_eq!(restored, 0);
                assert_eq!(refused, NativeGuardedCanonicalAllocationProgress::Complete(None),
                    "a completed source mapping failure remains distinct from refused admission");
                let NativeGuardedCanonicalAllocationProgress::Complete(Some(block)) =
                    (unsafe { native_theap_allocate_guarded_canonical_progress(selected, 8192) })
                    else { panic!("the same source owner resumes after mapping failure") };
                assert_eq!(unsafe { heap_of_block(block) }, Some(heap));
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }

    /// A joined remote free can remain queued on the creating thread's
    /// arena page until Heap deletion collects it during target abandonment.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn heap_delete_retires_page_emptied_by_joined_remote_free() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::heap_delete_retires_page_emptied_by_joined_remote_free",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                let heap = native_heap_new().expect("a non-main Heap");
                let block = unsafe { native_heap_allocate(heap, 80, None, false) }.expect("an arena block");
                let address = block.as_ptr().addr();
                std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: the fresh worker registers its own descriptor.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(crate::runtime_lifecycle::attach_current_thread(), crate::runtime_lifecycle::ThreadAttachResult::Attached);
                    // SAFETY: the join protocol transfers the sole client to
                    // this worker and keeps its Heap and page live until join.
                    let block = NonNull::new(address as *mut u8).unwrap();
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    assert_eq!(crate::runtime_lifecycle::finish_current_thread_native_after_user_destructors(), crate::runtime_lifecycle::ThreadFinishResult::Finished);
                }).join().expect("the freeing worker joins");
                // SAFETY: no worker or live client remains. Source deletion
                // must collect the queued free and retire the moved empty page.
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                // SAFETY: every worker joined; this sole native-runtime
                // caller excludes slice registration changes. Only address
                // bits are queried, with no departed client dereference.
                assert!(!unsafe { binding().unwrap().page_map().registers_address(address as *const u8) }.unwrap());
            },
        );
    }

    /// Membership follows the registered page through an ordinary Heap
    /// delete, which moves live pages to the subprocess main Heap.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn heap_membership_tracks_interior_and_moved_page() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::heap_membership_tracks_interior_and_moved_page",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let heap = native_heap_new().expect("a non-main Heap");
                let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("a live page");
                let main = MainSubprocess::global().ready_main_heap_pointer().cast();
                let pointer = block.as_ptr();
                let interior = pointer.wrapping_add(1);
                let foreign = 0u8;
                assert_eq!(unsafe { crate::source_heap_api::heap_of(pointer) }, heap.as_ptr().cast());
                assert_eq!(unsafe { crate::source_heap_api::heap_of(interior) }, heap.as_ptr().cast());
                assert!(unsafe { crate::source_heap_api::heap_contains(heap.as_ptr().cast(), pointer) });
                assert!(!unsafe { crate::source_heap_api::heap_contains(core::ptr::null_mut(), pointer) });
                assert!(unsafe { crate::source_heap_api::any_heap_contains(interior) });
                assert!(unsafe { crate::source_heap_api::heap_of(&foreign) }.is_null());
                assert!(!unsafe { crate::source_heap_api::any_heap_contains(&foreign) });
                assert!(!unsafe { crate::source_heap_api::heap_contains(core::ptr::null_mut(), &foreign) });
                assert!(unsafe { crate::source_heap_api::heap_of(core::ptr::null()) }.is_null());
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                assert_eq!(unsafe { crate::source_heap_api::heap_of(pointer) }, main);
                assert!(unsafe { crate::source_heap_api::heap_contains(core::ptr::null_mut(), pointer) });
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
            },
        );
    }

    /// Child subprocess destruction releases the destroying thread's regular
    /// TLS slot table even when that table belongs to an unrelated live Heap
    /// of the process main subprocess. The Heap and its Theap remain live.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn child_destroy_releases_destroying_threads_regular_slots() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::child_destroy_releases_destroying_threads_regular_slots",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let heap = native_heap_new().expect("a main-subprocess Heap");
                let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("its first Theap");
                let slots_before = thread_local_count() > 0;
                assert!(slots_before);
                let child = crate::source_heap_api::subproc_new();
                assert!(!child.is_null());
                let default_before = crate::compiler_tls::default_theap();
                let initial_cached_refs = unsafe { default_before.as_ref() }.refcount();
                assert_eq!(initial_cached_refs, 1);
                let cached_before = cached_theap();
                assert!(crate::compiler_tls::fast_slot_peek().is_some());
                assert!(unsafe { crate::source_heap_api::subproc_destroy(child) });
                let fast_cleared = crate::compiler_tls::fast_slot_peek().is_none();
                let default_preserved = crate::compiler_tls::default_theap() == default_before;
                let cached_preserved = cached_theap() == cached_before;
                assert!(fast_cleared, "child destruction clears the destroying thread fast slot");
                assert!(default_preserved);
                assert!(cached_preserved);
                let default_block = crate::source_api::malloc(48).value.expect("the live default still allocates");
                let default_allocates = unsafe { heap_of_block(default_block) }
                    .is_some_and(|heap| heap.as_ptr() == MainSubprocess::global().ready_main_heap_pointer());
                let fast_stays_empty = crate::compiler_tls::fast_slot_peek().is_none();
                assert!(default_allocates && fast_stays_empty);
                assert_eq!(unsafe { native_free(default_block) }, NativePageFreeResult::Freed);
                let slots_released = thread_local_count() == 0;
                assert!(slots_released);
                let old_block_live = unsafe { heap_of_block(block) } == Some(heap);
                assert!(old_block_live);
                let next = unsafe { native_heap_allocate(heap, 64, None, false) }
                    .expect("the Heap allocates after child destruction");
                let next_allocation = thread_local_count() > 0;
                assert!(next_allocation);
                let selected = unsafe { native_heap_theap(heap) }.expect("the retained Heap Theap");
                assert_eq!(unsafe { crate::source_heap_api::theap_set_default(selected.as_ptr().cast()) }, default_before.as_ptr().cast());
                let switched_block = crate::source_api::malloc(48).value.expect("the selected default allocates");
                let switched_allocates = unsafe { heap_of_block(switched_block) } == Some(heap);
                assert!(switched_allocates, "an empty fast root does not replace the selected default Heap");
                let direct = unsafe { crate::source_heap_api::theap_malloc(default_before.as_ptr().cast(), 24, false) }
                    .value.expect("the retained main Theap allocates directly");
                let direct_main = unsafe { heap_of_block(direct) }
                    .is_some_and(|heap| heap.as_ptr() == MainSubprocess::global().ready_main_heap_pointer());
                let selected_preserved = crate::compiler_tls::default_theap() == selected;
                assert!(direct_main && selected_preserved);
                let fresh = NonNull::new(unsafe { crate::source_heap_api::heap_theap(
                    crate::source_heap_api::heap_main(),
                ) }.cast::<Theap>()).expect("main lookup creates a fresh Theap after fast-slot clearing");
                let fresh_main = fresh != default_before;
                let fresh_fast = crate::compiler_tls::fast_slot_peek() == Some(fresh.cast());
                let fresh_cached = cached_theap() == fresh;
                let fresh_default_preserved = crate::compiler_tls::default_theap() == selected;
                assert!(fresh_main && fresh_fast && fresh_cached && fresh_default_preserved);
                let page_owner = |block: NonNull<u8>| unsafe {
                    binding().unwrap().page_map().lookup_registered_page(block.as_ptr())
                        .unwrap().is_some_and(|page| crate::types::Page::theap_at(page) == fresh.as_ptr())
                };
                let fresh_block = unsafe { crate::source_heap_api::theap_malloc(fresh.as_ptr().cast(), 64, false) }
                    .value.expect("the fresh Theap allocates");
                let fresh_allocates = page_owner(fresh_block);
                let aligned = unsafe { crate::source_api::theap_malloc_aligned_at(fresh.as_ptr().cast(), 127, 128, 0, false) }
                    .value.expect("the fresh Theap aligns");
                let fresh_aligns = page_owner(aligned) && aligned.as_ptr() as usize % 128 == 0;
                let grown = unsafe { crate::source_api::theap_realloc(fresh.as_ptr().cast(), fresh_block.as_ptr(), 4096, false) }
                    .value.expect("the fresh Theap reallocates");
                let fresh_reallocates = page_owner(grown);
                assert_eq!(unsafe { crate::source_heap_api::theap_set_default(fresh.as_ptr().cast()) }, selected.as_ptr().cast());
                let chosen = crate::source_api::malloc(37).value.expect("the fresh default allocates");
                let fresh_default_allocates = page_owner(chosen);
                let chosen_aligned = crate::source_api::malloc_aligned(99, 128).value.expect("the fresh default aligns");
                let fresh_default_aligns = page_owner(chosen_aligned);
                let chosen_grown = unsafe { crate::source_api::realloc(chosen.as_ptr(), 2048) }
                    .value.expect("the fresh default reallocates");
                let fresh_default_reallocates = page_owner(chosen_grown);
                assert_eq!(unsafe { crate::source_heap_api::theap_set_default(selected.as_ptr().cast()) }, fresh.as_ptr().cast());
                let second_heap = native_heap_new().expect("another Heap beside the fresh main Theap");
                let fresh_heap_image = page_owner(second_heap.cast());
                assert!(fresh_heap_image, "Heap metadata allocation selects the fresh main Theap");
                assert_eq!(unsafe { native_heap_release(second_heap, true) }, Ok(HeapReleaseOutcome::Released));
                for block in [aligned, grown, chosen_aligned, chosen_grown] {
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                }
                unsafe { crate::source_api::theap_collect(fresh.as_ptr().cast(), true) };
                let fresh_collected = unsafe { fresh.as_ref() }.page_count() == 0;
                assert!(fresh_allocates && fresh_aligns && fresh_reallocates
                    && fresh_default_allocates && fresh_default_aligns && fresh_default_reallocates && fresh_collected);
                assert_eq!(unsafe { crate::source_heap_api::theap_set_default(default_before.as_ptr().cast()) }, selected.as_ptr().cast());
                assert_eq!(unsafe { native_free(direct) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_free(switched_block) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_free(next) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
                let threads_before = MainSubprocess::global().identity().live_thread_count();
                let (worker_regular, worker_second, worker_os, worker_finished, worker_cached_hit, worker_cached_refs,
                    worker_fixed_refs_after_miss, worker_sibling_refs, worker_linked_theaps) = std::thread::spawn(|| {
                    let descriptor = crate::runtime_lifecycle::current_native_allocator_thread_descriptor();
                    // SAFETY: this worker retains its own allocator TLS until
                    // it completes the source thread finalizer below.
                    assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor) });
                    assert_eq!(crate::runtime_lifecycle::attach_current_thread(),
                        crate::runtime_lifecycle::ThreadAttachResult::Attached);
                    let original = crate::compiler_tls::default_theap();
                    let auxiliary = native_heap_new().expect("a worker auxiliary Heap");
                    let temporary = unsafe { native_heap_allocate(auxiliary, 64, None, false) }.unwrap();
                    let child = crate::source_heap_api::subproc_new();
                    assert!(!child.is_null());
                    assert_eq!(unsafe { crate::source_heap_api::heap_theap(crate::source_heap_api::heap_main()) }, original.as_ptr().cast());
                    assert!(unsafe { crate::source_heap_api::subproc_destroy(child) });
                    let cached_hit = unsafe { crate::source_heap_api::heap_theap(crate::source_heap_api::heap_main()) }
                        == original.as_ptr().cast() && crate::compiler_tls::fast_slot_peek().is_none();
                    assert!(cached_hit, "a cached main Theap remains usable without republishing the cleared fast slot");
                    let cached_refs = unsafe { original.as_ref() }.refcount();
                    assert_eq!(cached_refs, 2, "the fixed Theap owns a Heap-list and a cache reference");
                    assert!(native_heap_theap(auxiliary).is_some());
                    let sibling = NonNull::new(unsafe { crate::source_heap_api::heap_theap(
                        crate::source_heap_api::heap_main(),
                    ) }.cast::<Theap>()).expect("the worker's fresh main Theap");
                    assert_ne!(sibling, original);
                    assert_eq!(fixed_main_theap(), Some(original));
                    let regular = unsafe { crate::source_heap_api::theap_malloc(sibling.as_ptr().cast(), 64, false) }.value.unwrap();
                    let second = unsafe { crate::source_heap_api::theap_malloc(sibling.as_ptr().cast(), 64, false) }.value.unwrap();
                    let os = unsafe { crate::source_api::theap_malloc_aligned_at(
                        sibling.as_ptr().cast(), 2 * 1024 * 1024, 4096, 0, false,
                    ) }.value.unwrap();
                    assert_eq!(unsafe { native_free(temporary) }, NativePageFreeResult::Freed);
                    assert_eq!(unsafe { native_heap_release(auxiliary, true) }, Ok(HeapReleaseOutcome::Released));
                    unsafe { crate::source_heap_api::theap_set_default(sibling.as_ptr().cast()) };
                    let fixed_refs_after_miss = unsafe { original.as_ref() }.refcount();
                    let sibling_refs = unsafe { sibling.as_ref() }.refcount();
                    let tld = NonNull::new(unsafe { Theap::tld_at(sibling) }).unwrap();
                    let mut linked_theaps = 0;
                    let mut current = unsafe { ThreadLocalData::theaps_head_at(tld) };
                    while let Some(theap) = NonNull::new(current) {
                        linked_theaps += 1;
                        current = unsafe { Theap::tld_next_at(theap) };
                    }
                    assert_eq!((fixed_refs_after_miss, sibling_refs, linked_theaps), (1, 2, 2));
                    let finished = matches!(crate::runtime_lifecycle::finish_current_thread_native_after_user_destructors(),
                        crate::runtime_lifecycle::ThreadFinishResult::Finished);
                    (regular.as_ptr() as usize, second.as_ptr() as usize, os.as_ptr() as usize, finished, cached_hit, cached_refs,
                        fixed_refs_after_miss, sibling_refs, linked_theaps)
                }).join().unwrap();
                assert!(worker_finished, "fresh sibling teardown leaves the fixed runtime owner finishable");
                let worker_count_restored = MainSubprocess::global().identity().live_thread_count() == threads_before;
                let regular = NonNull::new(worker_regular as *mut u8).unwrap();
                let second = NonNull::new(worker_second as *mut u8).unwrap();
                let os = NonNull::new(worker_os as *mut u8).unwrap();
                let worker_pages_live = unsafe { heap_of_block(second) }.is_some()
                    && unsafe { heap_of_block(os) }.is_some();
                assert_eq!(unsafe { native_free(regular) }, NativePageFreeResult::Freed);
                let worker_reclaimed_fresh = page_owner(second);
                assert_eq!(unsafe { native_free(second) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_free(os) }, NativePageFreeResult::Freed);
                unsafe { crate::source_api::theap_collect(fresh.as_ptr().cast(), true) };
                let worker_regular_released = unsafe { heap_of_block(second) }.is_none();
                let worker_os_released = unsafe { heap_of_block(os) }.is_none();
                assert!(worker_count_restored && worker_pages_live && worker_reclaimed_fresh && worker_regular_released && worker_os_released,
                    "worker count={worker_count_restored} live={worker_pages_live} reclaimed={worker_reclaimed_fresh} regular_released={worker_regular_released} os_released={worker_os_released}");
                for (index, value) in [slots_before, slots_released, old_block_live, next_allocation,
                    fast_cleared, default_preserved, cached_preserved,
                    default_allocates, fast_stays_empty,
                    switched_allocates, direct_main, selected_preserved,
                    fresh_main, fresh_fast, fresh_cached, fresh_default_preserved,
                    fresh_allocates, fresh_aligns, fresh_reallocates, fresh_default_allocates,
                    fresh_default_aligns, fresh_default_reallocates, fresh_heap_image, fresh_collected,
                    worker_finished, worker_count_restored, worker_pages_live, worker_reclaimed_fresh,
                    worker_regular_released, worker_os_released, worker_cached_hit].iter().enumerate() {
                    std::println!("m6.subproc.destroy_slots.{index}={}", i32::from(*value));
                }
                std::println!("m6.subproc.destroy_slots.31={worker_cached_refs}");
                std::println!("m6.subproc.destroy_slots.32={initial_cached_refs}");
                std::println!("m6.subproc.destroy_slots.33={worker_fixed_refs_after_miss}");
                std::println!("m6.subproc.destroy_slots.34={worker_sibling_refs}");
                std::println!("m6.subproc.destroy_slots.35={worker_linked_theaps}");
            },
        );
    }

    /// A copied fixed cache owns a distinct reference until the vanished
    /// worker's page drain completes; child list detach then frees its metadata.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn cached_main_theap_reference_retires_vanished_fork_owner_after_page_drain() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::cached_main_theap_reference_retires_vanished_fork_owner_after_page_drain",
            || {
                use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
                use std::sync::Arc;
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let main = crate::source_heap_api::heap_main();
                let selected = NonNull::new(unsafe { crate::source_heap_api::heap_theap(main) }.cast::<Theap>()).unwrap();
                assert_eq!(unsafe { selected.as_ref() }.refcount(), 1);
                let ready = Arc::new(AtomicBool::new(false));
                let finish = Arc::new(AtomicBool::new(false));
                let regular = Arc::new(AtomicUsize::new(0));
                let os = Arc::new(AtomicUsize::new(0));
                let descriptor_address = Arc::new(AtomicUsize::new(0));
                let worker = {
                    let ready = ready.clone();
                    let finish = finish.clone();
                    let regular = regular.clone();
                    let os = os.clone();
                    let descriptor_address = descriptor_address.clone();
                    std::thread::spawn(move || {
                        let descriptor = crate::runtime_lifecycle::current_native_allocator_thread_descriptor();
                        // SAFETY: this worker's descriptor remains mapped
                        // through its source finalizer and the fork snapshot.
                        assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor) });
                        assert_eq!(crate::runtime_lifecycle::attach_current_thread(), crate::runtime_lifecycle::ThreadAttachResult::Attached);
                        let main = crate::source_heap_api::heap_main();
                        let cached = NonNull::new(unsafe { crate::source_heap_api::heap_theap(main) }.cast::<Theap>()).unwrap();
                        assert_eq!(unsafe { cached.as_ref() }.refcount(), 2);
                        let block = unsafe { crate::source_heap_api::theap_malloc(cached.as_ptr().cast(), 64, false) }.value.unwrap();
                        let large = unsafe { crate::source_api::theap_malloc_aligned_at(cached.as_ptr().cast(), 2 * 1024 * 1024, 4096, 0, false) }.value.unwrap();
                        regular.store(block.as_ptr() as usize, Ordering::Relaxed);
                        os.store(large.as_ptr() as usize, Ordering::Relaxed);
                        descriptor_address.store(descriptor.as_ptr() as usize, Ordering::Relaxed);
                        ready.store(true, Ordering::Release);
                        while !finish.load(Ordering::Acquire) { std::thread::yield_now(); }
                        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                        assert_eq!(unsafe { native_free(large) }, NativePageFreeResult::Freed);
                        assert!(matches!(crate::runtime_lifecycle::finish_current_thread_native_after_user_destructors(), crate::runtime_lifecycle::ThreadFinishResult::Finished));
                    })
                };
                while !ready.load(Ordering::Acquire) { std::thread::yield_now(); }
                let regular = NonNull::new(regular.load(Ordering::Relaxed) as *mut u8).unwrap();
                let os = NonNull::new(os.load(Ordering::Relaxed) as *mut u8).unwrap();
                assert_eq!(MainSubprocess::global().identity().live_thread_count(), 2);
                struct PinnedForkDescriptors([NonNull<crate::runtime_lifecycle::NativeAllocatorThreadDescriptor>; 2]);
                // SAFETY: exactly these two registered descriptors remain mapped;
                // the worker waits without allocator entry, and the initial
                // thread holds this fixture's publication/removal boundary.
                unsafe impl crate::runtime_lifecycle::NativeAllocatorPinnedThreadRegistry for PinnedForkDescriptors {
                    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<crate::runtime_lifecycle::NativeAllocatorThreadDescriptor>)) {
                        for descriptor in self.0 { visitor(descriptor); }
                    }
                }
                // SAFETY: the sole child retains the exact same two mappings,
                // visits without locks, and consumes repair before hooks or entry.
                unsafe impl crate::runtime_lifecycle::NativeAllocatorChildRetainedThreadRegistry for PinnedForkDescriptors {
                    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<crate::runtime_lifecycle::NativeAllocatorThreadDescriptor>)) {
                        for descriptor in self.0 { visitor(descriptor); }
                    }
                }
                let registry = PinnedForkDescriptors([
                    crate::runtime_lifecycle::current_native_allocator_thread_descriptor(),
                    NonNull::new(descriptor_address.load(Ordering::Relaxed) as *mut crate::runtime_lifecycle::NativeAllocatorThreadDescriptor).unwrap(),
                ]);
                let blocked_signals = !0u64;
                let mut previous_signals = 0u64;
                // SAFETY: both mask buffers are live, and this thread restores
                // its mask only after the copied allocator interval completes.
                unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &blocked_signals, &mut previous_signals) }.unwrap();
                // SAFETY: both descriptors and the exact owner graph are pinned
                // until the parent resumes or the sole child consumes repair.
                let interval = unsafe { crate::runtime_lifecycle::begin_native_allocator_source_fork_quiescence(&registry) }.unwrap();
                let child = crabc_core::process::fork_raw().expect("the prepared native fork");
                if child == 0 {
                    // SAFETY: first after the raw copy, before any allocator
                    // operation, with the copied pinned graph unchanged.
                    let repaired = unsafe { interval.into_child_repair().into_unlocked_continuation() }
                        .and_then(|continuation| unsafe { continuation.repair_source_owners(&registry) });
                    if repaired.is_err() { crabc_core::process::exit_immediately(72); }
                    // SAFETY: source repair ended before restoring handlers.
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_signals, core::ptr::null_mut()) }.unwrap();
                    let count = MainSubprocess::global().identity().live_thread_count() == 1;
                    let refs = unsafe { selected.as_ref() }.refcount() == 1;
                    let allocation = unsafe { crate::source_heap_api::heap_malloc(main, 80) }.value;
                    let regular_freed = unsafe { native_free(regular) } == NativePageFreeResult::Freed;
                    let os_freed = unsafe { native_free(os) } == NativePageFreeResult::Freed;
                    let allocated = allocation.is_some_and(|block| unsafe { native_free(block) } == NativePageFreeResult::Freed);
                    crabc_core::process::exit_immediately(if !count { 73 } else if !refs { 74 }
                        else if !allocated { 75 } else if !regular_freed { 76 } else if !os_freed { 77 } else { 0 });
                }
                // SAFETY: only the raw syscall crossed the closed interval.
                unsafe { interval.resume_parent() }.unwrap();
                // SAFETY: parent completion reopened ordinary entry.
                unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_signals, core::ptr::null_mut()) }.unwrap();
                let mut status = 0;
                // SAFETY: the local status output stays writable until the
                // exact child is reaped; no other waiter handles this child.
                assert_eq!(unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }.unwrap(), child);
                assert_eq!(status, 0, "copied worker drain releases its cache before list detach");
                assert_eq!(MainSubprocess::global().identity().live_thread_count(), 2);
                assert_eq!(unsafe { selected.as_ref() }.refcount(), 1);
                finish.store(true, Ordering::Release);
                worker.join().unwrap();
                assert_eq!(MainSubprocess::global().identity().live_thread_count(), 1);
                std::println!("cached main Theap fork: copied owner pages drained, cache released, metadata detached; parent preserved");
            },
        );
    }

    /// A vanished worker retains both its fixed runtime owner and a fresh
    /// main sibling with live regular and OS pages until child repair drains them.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn fresh_main_theap_siblings_retire_vanished_fork_owner_after_page_drain() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::fresh_main_theap_siblings_retire_vanished_fork_owner_after_page_drain",
            || {
                use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
                use std::sync::Arc;
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let main = crate::source_heap_api::heap_main();
                let selected = NonNull::new(unsafe { crate::source_heap_api::heap_theap(main) }.cast::<Theap>()).unwrap();
                assert_eq!(unsafe { selected.as_ref() }.refcount(), 1);
                let ready = Arc::new(AtomicBool::new(false));
                let finish = Arc::new(AtomicBool::new(false));
                let regular = Arc::new(AtomicUsize::new(0));
                let os = Arc::new(AtomicUsize::new(0));
                let descriptor_address = Arc::new(AtomicUsize::new(0));
                let copied_tls = Arc::new([const { AtomicUsize::new(0) }; 6]);
                let worker_theaps = Arc::new([const { AtomicUsize::new(0) }; 2]);
                let source_theaps = || {
                    let heap = NonNull::new(MainSubprocess::global().ready_main_heap_pointer()).unwrap();
                    let mut count = 0;
                    // SAFETY: the worker waits without entry and this sole
                    // fixture controls every source list mutation.
                    assert!(unsafe { heap.as_ref().visit_theaps_quiescent(|_, _| { count += 1; true }) });
                    count
                };
                let source_theaps_before = source_theaps();
                let worker = {
                    let ready = ready.clone();
                    let finish = finish.clone();
                    let regular = regular.clone();
                    let os = os.clone();
                    let descriptor_address = descriptor_address.clone();
                    let copied_tls = copied_tls.clone();
                    let worker_theaps = worker_theaps.clone();
                    std::thread::spawn(move || {
                        let descriptor = crate::runtime_lifecycle::current_native_allocator_thread_descriptor();
                        // SAFETY: this worker's descriptor remains mapped
                        // through its source finalizer and the fork snapshot.
                        assert!(unsafe { crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor) });
                        assert_eq!(crate::runtime_lifecycle::attach_current_thread(), crate::runtime_lifecycle::ThreadAttachResult::Attached);
                        let main = crate::source_heap_api::heap_main();
                        let cached = NonNull::new(unsafe { crate::source_heap_api::heap_theap(main) }.cast::<Theap>()).unwrap();
                        assert_eq!(unsafe { cached.as_ref() }.refcount(), 2);
                        let auxiliary = native_heap_new().unwrap();
                        let temporary = unsafe { native_heap_allocate(auxiliary, 32, None, false) }.unwrap();
                        let child = crate::source_heap_api::subproc_new();
                        assert!(!child.is_null());
                        assert!(unsafe { crate::source_heap_api::subproc_destroy(child) });
                        assert!(crate::compiler_tls::fast_slot_peek().is_none());
                        unsafe { native_heap_theap(auxiliary) }.unwrap();
                        let fresh = NonNull::new(unsafe { crate::source_heap_api::heap_theap(main) }.cast::<Theap>()).unwrap();
                        assert_ne!(fresh, cached);
                        assert_eq!(unsafe { cached.as_ref() }.refcount(), 1);
                        assert_eq!(unsafe { fresh.as_ref() }.refcount(), 2);
                        assert_eq!(unsafe { native_free(temporary) }, NativePageFreeResult::Freed);
                        assert_eq!(unsafe { native_heap_release(auxiliary, true) }, Ok(HeapReleaseOutcome::Released));
                        unsafe { crate::source_heap_api::theap_set_default(fresh.as_ptr().cast()) };
                        worker_theaps[0].store(cached.as_ptr() as usize, Ordering::Relaxed);
                        worker_theaps[1].store(fresh.as_ptr() as usize, Ordering::Relaxed);
                        let cached = fresh;
                        let block = unsafe { crate::source_heap_api::theap_malloc(cached.as_ptr().cast(), 64, false) }.value.unwrap();
                        let large = unsafe { crate::source_api::theap_malloc_aligned_at(cached.as_ptr().cast(), 2 * 1024 * 1024, 4096, 0, false) }.value.unwrap();
                        unsafe { block.as_ptr().write(0x5a); large.as_ptr().write(0xa5); }
                        let tls = current_thread_heap_tls();
                        for (index, root) in tls.roots.iter().enumerate() {
                            copied_tls[index].store(root.start, Ordering::Relaxed);
                        }
                        copied_tls[5].store(tls.state.as_ptr() as usize, Ordering::Relaxed);
                        regular.store(block.as_ptr() as usize, Ordering::Relaxed);
                        os.store(large.as_ptr() as usize, Ordering::Relaxed);
                        descriptor_address.store(descriptor.as_ptr() as usize, Ordering::Relaxed);
                        ready.store(true, Ordering::Release);
                        while !finish.load(Ordering::Acquire) { std::thread::yield_now(); }
                        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                        assert_eq!(unsafe { native_free(large) }, NativePageFreeResult::Freed);
                        assert!(matches!(crate::runtime_lifecycle::finish_current_thread_native_after_user_destructors(), crate::runtime_lifecycle::ThreadFinishResult::Finished));
                    })
                };
                while !ready.load(Ordering::Acquire) { std::thread::yield_now(); }
                let regular = NonNull::new(regular.load(Ordering::Relaxed) as *mut u8).unwrap();
                let os = NonNull::new(os.load(Ordering::Relaxed) as *mut u8).unwrap();
                assert_eq!(MainSubprocess::global().identity().live_thread_count(), 2);
                assert_eq!(source_theaps(), source_theaps_before + 2);
                struct PinnedForkDescriptors([NonNull<crate::runtime_lifecycle::NativeAllocatorThreadDescriptor>; 2]);
                // SAFETY: exactly these two registered descriptors remain mapped;
                // the worker waits without allocator entry, and the initial
                // thread holds this fixture's publication/removal boundary.
                unsafe impl crate::runtime_lifecycle::NativeAllocatorPinnedThreadRegistry for PinnedForkDescriptors {
                    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<crate::runtime_lifecycle::NativeAllocatorThreadDescriptor>)) {
                        for descriptor in self.0 { visitor(descriptor); }
                    }
                }
                // SAFETY: the sole child retains the exact same two mappings,
                // visits without locks, and consumes repair before hooks or entry.
                unsafe impl crate::runtime_lifecycle::NativeAllocatorChildRetainedThreadRegistry for PinnedForkDescriptors {
                    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<crate::runtime_lifecycle::NativeAllocatorThreadDescriptor>)) {
                        for descriptor in self.0 { visitor(descriptor); }
                    }
                }
                let registry = PinnedForkDescriptors([
                    crate::runtime_lifecycle::current_native_allocator_thread_descriptor(),
                    NonNull::new(descriptor_address.load(Ordering::Relaxed) as *mut crate::runtime_lifecycle::NativeAllocatorThreadDescriptor).unwrap(),
                ]);
                let blocked_signals = !0u64;
                let fixed = NonNull::new(worker_theaps[0].load(Ordering::Relaxed) as *mut Theap).unwrap();
                let fresh = NonNull::new(worker_theaps[1].load(Ordering::Relaxed) as *mut Theap).unwrap();
                for regular_release_failure in [true, false] {
                    let mut previous_signals = 0u64;
                    // SAFETY: all signals remain blocked while this pinned
                    // registry crosses the prepared source interval.
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &blocked_signals, &mut previous_signals) }.unwrap();
                    let interval = unsafe { crate::runtime_lifecycle::begin_native_allocator_source_fork_quiescence(&registry) }.unwrap();
                    let child = crabc_core::process::fork_raw().unwrap();
                    if child == 0 {
                        let state = copied_tls[5].load(Ordering::Relaxed) as *const ThreadHeaps;
                        let root_addresses = [
                            copied_tls[0].load(Ordering::Relaxed), copied_tls[1].load(Ordering::Relaxed),
                            copied_tls[2].load(Ordering::Relaxed), copied_tls[3].load(Ordering::Relaxed),
                        ];
                        // SAFETY: the child retains the exact original TLS
                        // fields with all observations excluded by the epoch.
                        let before = root_addresses.map(|address| unsafe { (address as *const usize).read() });
                        let metadata_before = MetaAllocator::global().test_allocation_audit();
                        if !regular_release_failure {
                            // A child-only source-engine refusal cannot free
                            // cache/list metadata while inherited pages live.
                            unsafe { MainHeapPageEngineState::new(fresh) }.state = ChildPageEngineState::Poisoned;
                        }
                        let continuation = unsafe { interval.into_child_repair().into_unlocked_continuation() }.unwrap();
                        let repaired = if regular_release_failure {
                            // Existing test-only metadata entry authority
                            // exercises a real pre-claim recursive rejection.
                            // The guard is created after fork, then released
                            // before observing the refused child transition.
                            MetaAllocator::global().test_with_held_backing_entry(|| unsafe {
                                continuation.repair_source_owners(&registry)
                            }).unwrap()
                        } else {
                            unsafe { continuation.repair_source_owners(&registry) }
                        };
                        let after = root_addresses.map(|address| unsafe { (address as *const usize).read() });
                        let entry_closed = crate::runtime_lifecycle::NativeSubprocessOperation::enter().is_none();
                        let metadata_after = MetaAllocator::global().test_allocation_audit();
                        let metadata_retained = metadata_after.high_water_capability_count == metadata_before.high_water_capability_count
                            && metadata_after.live_capability_count + usize::from(!regular_release_failure)
                                == metadata_before.live_capability_count;
                        let retained = source_theaps() == source_theaps_before + 2
                            && MainSubprocess::global().identity().live_thread_count() == 2
                            && unsafe { fixed.as_ref() }.refcount() == 1
                            && unsafe { fresh.as_ref() }.refcount() == 2
                            && unsafe { fresh.as_ref() }.page_count() > 0
                            && unsafe { (*state).cached } == fresh.as_ptr()
                            && unsafe { regular.as_ptr().read() == 0x5a && os.as_ptr().read() == 0xa5 };
                        let roots = if regular_release_failure {
                            before == after && unsafe { (*state).thread_locals.is_some() && (*state).backing.is_some() }
                        } else {
                            after[0] == 0 && after[1] == 0 && after[2..] == before[2..]
                                && unsafe { (*state).thread_locals.is_none() && (*state).backing.is_none() }
                        };
                        crabc_core::process::exit_immediately(if repaired.is_ok() { 88 }
                            else if !entry_closed { 89 } else if !retained { 90 } else if !roots { 91 }
                            else if !metadata_retained { 92 } else { 0 });
                    }
                    // SAFETY: no parent source state changed while its raw
                    // copy was closed; the worker continues waiting untouched.
                    unsafe { interval.resume_parent() }.unwrap();
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_signals, core::ptr::null_mut()) }.unwrap();
                    let mut status = 0;
                    assert_eq!(unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }.unwrap(), child);
                    assert_eq!(status, 0, "refused child repair retains exact backing/pages/cache/list owners with source closed");
                    assert_eq!(source_theaps(), source_theaps_before + 2);
                    assert_eq!(unsafe { fixed.as_ref() }.refcount(), 1);
                    assert_eq!(unsafe { fresh.as_ref() }.refcount(), 2);
                }
                let mut previous_signals = 0u64;
                // SAFETY: both mask buffers are live, and this thread restores
                // its mask only after the copied allocator interval completes.
                unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &blocked_signals, &mut previous_signals) }.unwrap();
                // SAFETY: both descriptors and the exact owner graph are pinned
                // until the parent resumes or the sole child consumes repair.
                let interval = unsafe { crate::runtime_lifecycle::begin_native_allocator_source_fork_quiescence(&registry) }.unwrap();
                let child = crabc_core::process::fork_raw().expect("the prepared native fork");
                if child == 0 {
                    // SAFETY: first after the raw copy, before any allocator
                    // operation, with the copied pinned graph unchanged.
                    let repaired = unsafe { interval.into_child_repair().into_unlocked_continuation() }
                        .and_then(|continuation| unsafe { continuation.repair_source_owners(&registry) });
                    if repaired.is_err() { crabc_core::process::exit_immediately(72); }
                    // SAFETY: source repair ended before restoring handlers.
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_signals, core::ptr::null_mut()) }.unwrap();
                    let count = MainSubprocess::global().identity().live_thread_count() == 1;
                    let graph = source_theaps() == source_theaps_before;
                    let state = copied_tls[5].load(Ordering::Relaxed) as *const ThreadHeaps;
                    // SAFETY: the child registry still pins the vanished
                    // worker's inline TLS; no freed TLD/Theap is projected.
                    let roots = unsafe {
                        (*state).thread_locals.is_none() && (*state).backing.is_none()
                            && (*state).cached.is_null() && (*state).pending_os_release.is_none()
                            && (copied_tls[0].load(Ordering::Relaxed) as *const *mut DynamicThreadLocalBacking).read().is_null()
                            && (copied_tls[1].load(Ordering::Relaxed) as *const *mut ()).read().is_null()
                            && (copied_tls[2].load(Ordering::Relaxed) as *const *mut Theap).read() == crate::bootstrap::empty_default_theap_ptr()
                            && (copied_tls[3].load(Ordering::Relaxed) as *const *mut Theap).read() == crate::bootstrap::empty_default_theap_ptr()
                    };
                    let inherited = unsafe { regular.as_ptr().read() == 0x5a && os.as_ptr().read() == 0xa5 };
                    let survivor_roots = crate::compiler_tls::default_theap() == selected
                        && cached_theap() == selected
                        && crate::compiler_tls::fast_slot_peek() == Some(selected.cast());
                    let refs = unsafe { selected.as_ref() }.refcount() == 1;
                    let allocation = unsafe { crate::source_heap_api::heap_malloc(main, 80) }.value;
                    let regular_freed = unsafe { native_free(regular) } == NativePageFreeResult::Freed;
                    let os_freed = unsafe { native_free(os) } == NativePageFreeResult::Freed;
                    let allocated = allocation.is_some_and(|block| unsafe { native_free(block) } == NativePageFreeResult::Freed);
                    unsafe { crate::source_heap_api::heap_collect(main, true) };
                    let pages_released = unsafe { heap_of_block(regular) }.is_none() && unsafe { heap_of_block(os) }.is_none();
                    // A second prepared fork sees the copied worker's finished
                    // slot, without repeating cache release or thread uncount.
                    // SAFETY: the same registry still pins both descriptor/TLS
                    // mappings, and signals stay blocked across the new copy.
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &blocked_signals, core::ptr::null_mut()) }.unwrap();
                    let Ok(next_interval) = (unsafe {
                        crate::runtime_lifecycle::begin_native_allocator_source_fork_quiescence(&registry)
                    }) else { crabc_core::process::exit_immediately(83); };
                    let Ok(next_child) = crabc_core::process::fork_raw() else {
                        crabc_core::process::exit_immediately(84);
                    };
                    if next_child == 0 {
                        // SAFETY: first in the sole grandchild with its exact
                        // retained registry and no source entry or outer hook.
                        let repaired = unsafe { next_interval.into_child_repair().into_unlocked_continuation() }
                            .and_then(|continuation| unsafe { continuation.repair_source_owners(&registry) });
                        let stable = repaired.is_ok() && source_theaps() == source_theaps_before
                            && MainSubprocess::global().identity().live_thread_count() == 1
                            && unsafe { selected.as_ref() }.refcount() == 1;
                        crabc_core::process::exit_immediately(if stable { 0 } else { 85 });
                    }
                    // SAFETY: only the raw syscall crossed this closed interval.
                    if unsafe { next_interval.resume_parent() }.is_err() { crabc_core::process::exit_immediately(86); }
                    let mut next_status = 0;
                    // SAFETY: the child owns the exact grandchild wait and
                    // writable output; no other thread or waiter can overlap.
                    let waited = unsafe { crabc_core::process::wait4_raw(next_child, &mut next_status, 0) };
                    let reentered = waited == Ok(next_child) && next_status == 0;
                    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_signals, core::ptr::null_mut()) }.unwrap();
                    crabc_core::process::exit_immediately(if !count { 73 } else if !refs { 74 }
                        else if !allocated { 75 } else if !regular_freed { 76 } else if !os_freed { 77 }
                        else if !graph { 78 } else if !roots { 79 } else if !inherited { 80 }
                        else if !survivor_roots { 81 } else if !pages_released { 82 } else if !reentered { 87 } else { 0 });
                }
                // SAFETY: only the raw syscall crossed the closed interval.
                unsafe { interval.resume_parent() }.unwrap();
                // SAFETY: parent completion reopened ordinary entry.
                unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous_signals, core::ptr::null_mut()) }.unwrap();
                let mut status = 0;
                // SAFETY: the local status output stays writable until the
                // exact child is reaped; no other waiter handles this child.
                assert_eq!(unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }.unwrap(), child);
                assert_eq!(status, 0, "copied fresh sibling pages drain before cache release and metadata detach");
                assert_eq!(MainSubprocess::global().identity().live_thread_count(), 2);
                assert_eq!(unsafe { selected.as_ref() }.refcount(), 1);
                assert_eq!(source_theaps(), source_theaps_before + 2);
                finish.store(true, Ordering::Release);
                worker.join().unwrap();
                assert_eq!(MainSubprocess::global().identity().live_thread_count(), 1);
                assert_eq!(source_theaps(), source_theaps_before);
                std::println!("fresh main sibling fork: regular/OS pages drained and retired, source TLS roots cleared, literal cache/list references released; refused children remain closed and retained; fork reentry, survivor and parent preserved");
            },
        );
    }

    use std::vec::Vec;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn live_page_heap_identity_allows_stats_callback_and_excludes_deleted_heap() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::live_page_heap_identity_allows_stats_callback_and_excludes_deleted_heap",
            || {
                struct Callback { heap: NonNull<Heap>, completed: bool }
                unsafe extern "C" fn output(_: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
                    // SAFETY: this synchronous call owns the callback state;
                    // the Heap remains live and its list membership is unchanged.
                    let state = unsafe { &mut *argument.cast::<Callback>() };
                    if state.completed { return; }
                    let block = unsafe { crate::source_heap_api::heap_malloc(state.heap.as_ptr().cast(), 37) }
                        .value.expect("the existing non-main Heap allocates in the callback");
                    // SAFETY: this callback owns all 37 initialized bytes and
                    // returns its exact live block once through ordinary free.
                    unsafe { block.as_ptr().write_bytes(0xa7, 37) };
                    assert_eq!(unsafe { block.as_ptr().add(36).read() }, 0xa7);
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    state.completed = true;
                }
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                let heap = native_heap_new().expect("an existing non-main Heap");
                let regular = unsafe { native_heap_allocate(heap, 43, None, false) }.expect("an arena block");
                let page_of = |block: NonNull<u8>| {
                    unsafe { binding().unwrap().page_map().lookup_live_allocation(block) }
                        .unwrap().unwrap().page()
                };
                let regular_page = page_of(regular);
                assert!(!unsafe { Page::is_os_backed_at(regular_page) });
                assert_eq!(unsafe { heap_of_page(regular_page) }, Some(heap));
                let mut state = Callback { heap, completed: false };
                // SAFETY: the public synchronous output keeps this state and
                // its existing Heap live. The callback does not change the list.
                unsafe { crate::source_options_api::subproc_heap_stats_print_out(
                    crate::source_heap_api::subproc_main(), Some(output),
                    core::ptr::addr_of_mut!(state).cast(),
                ) };
                assert!(state.completed);
                crate::source_options_api::option_set(crate::config::SourceOption::ArenaReserve as i32, 0);
                // Exclude this Heap's existing arena for the new regular OS
                // page. A huge OS singleton would instead join the abandoned
                // list and move to the main Heap during deletion.
                crate::source_options_api::option_set(crate::config::SourceOption::DisallowArenaAlloc as i32, 1);
                let os = unsafe { native_heap_allocate(heap, 81, Some((128, 11)), true) }.expect("an OS block");
                let os_page = page_of(os);
                assert!(unsafe { Page::is_os_backed_at(os_page) });
                assert_eq!(unsafe { heap_of_page(os_page) }, Some(heap));
                // SAFETY: the test excludes all concurrent Heap operations;
                // deletion preserves both exact live client blocks.
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                assert_eq!(unsafe { Page::heap_identity_at(regular_page) }, MainSubprocess::global().ready_main_heap_pointer());
                assert_eq!(unsafe { heap_of_page(regular_page) }, None);
                assert_eq!(unsafe { Page::heap_identity_at(os_page) }, heap.as_ptr());
                assert_eq!(retained_deleted_heap_owner_count_for_test(), Some(1));
                // The stale OS Heap address is never projected, even while
                // another source visitor holds the subprocess Heap-list lock.
                MainSubprocess::global().identity().heap_list().visit_heaps(|_| {
                    assert_eq!(unsafe { heap_of_page(os_page) }, None);
                    assert_eq!(unsafe { local_heap_theap_of_page(os_page) }, None);
                    true
                }).unwrap();
                assert_eq!(unsafe { native_free(regular) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_free(os) }, NativePageFreeResult::Freed);
                assert_eq!(retained_deleted_heap_owner_count_for_test(), Some(0));
            },
        );
    }

    /// Pinned-C/Rust differential for Heaps of the process main subprocess on
    /// the main thread (`compat/allocator/heap_lifecycle.c` with `main`):
    /// test-api.c's heap-os1, heap-os2, and heap-many shapes.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn source_ordered_main_subprocess_heap_trace() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::source_ordered_main_subprocess_heap_trace",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                // The main thread's first allocation initializes its owner.
                let first = match native_allocate_aligned(16, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    _ => panic!("the main thread allocates"),
                };
                unsafe { native_free(first) };
                let mut trace: Vec<i64> = Vec::new();
                let main = MainSubprocess::global();
                let identity = main.identity();
                let main_heap = NonNull::new(main.ready_main_heap_pointer()).unwrap();
                let theap = default_theap();
                let tld = NonNull::new(unsafe { Theap::tld_at(theap) }).unwrap();
                let theaps = || identity.statistics().final_output_snapshot().theaps;
                let heap_count = || identity.heap_list().test_counts().0 as i64;
                let (theaps0, heaps0) = (theaps(), heap_count());
                let page_of = |block: NonNull<u8>| {
                    let binding = binding().unwrap();
                    unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap().page()
                };
                let links = |t: NonNull<Theap>| unsafe { Theap::test_list_links(t) };

                // heap-os1.
                let h = native_heap_new().expect("a Heap");
                trace.push(i64::from(unsafe { h.as_ref() }.subprocess_pointer() == identity.as_ptr()
                    && unsafe { h.as_ref() }.test_theaps_head().is_null()
                    && identity.heap_list().test_head() == h.as_ptr()));
                trace.push(heap_count() - heaps0);
                let p = unsafe { native_heap_allocate(h, 1 << 20, Some((2 << 20, 0)), false) }.expect("an OS block");
                let page = page_of(p);
                let h_theap = NonNull::new(unsafe { h.as_ref() }.test_theaps_head()).unwrap();
                trace.push(i64::from(unsafe { page.as_ref() }.heap() == h.as_ptr()
                    && unsafe { page.as_ref() }.memid().kind().is_os()
                    && unsafe { page.as_ref() }.theap() == h_theap.as_ptr()));
                let (_, _, h_tnext, _, h_tld) = links(h_theap);
                trace.push(i64::from(h_tld == tld.as_ptr()
                    && unsafe { ThreadLocalData::theaps_head_at(tld) } == h_theap.as_ptr()
                    && h_tnext == theap.as_ptr()));
                trace.push(i64::from(cached_theap() == h_theap));
                trace.push(theaps().current - theaps0.current);
                assert_eq!(unsafe { native_heap_release(h, false) }, Ok(HeapReleaseOutcome::Released));
                trace.push(i64::from(unsafe { page.as_ref() }.heap() == main_heap.as_ptr()
                    && unsafe { Heap::os_abandoned_head_at(main_heap) } == page.as_ptr()));
                let (_, _, _, main_tprev, _) = links(theap);
                trace.push(i64::from(unsafe { ThreadLocalData::theaps_head_at(tld) } == theap.as_ptr() && main_tprev.is_null()));
                trace.push(heap_count() - heaps0);
                assert_eq!(unsafe { native_free(p) }, NativePageFreeResult::Freed);
                trace.push(i64::from(unsafe { Heap::os_abandoned_head_at(main_heap) }.is_null()));

                // heap-os2.
                let h2 = native_heap_new().expect("a second Heap");
                trace.push(i64::from(cached_theap() == theap));
                trace.push(theaps().current - theaps0.current);
                let mut failed = 0;
                for _ in 0..10 {
                    match unsafe { native_heap_allocate(h2, 1 << 20, Some((2 << 20, 0)), false) } {
                        Some(block) => unsafe { block.as_ptr().cast::<i32>().write(42) },
                        None => failed += 1,
                    }
                }
                trace.push(failed);
                trace.push(unsafe { NonNull::new(h2.as_ref().test_theaps_head()).unwrap().as_ref() }.page_count() as i64);
                assert_eq!(unsafe { native_heap_release(h2, true) }, Ok(HeapReleaseOutcome::Released));
                trace.push(i64::from(unsafe { Heap::os_abandoned_head_at(main_heap) }.is_null()));
                trace.push(heap_count() - heaps0);

                // heap-many.
                let mut heaps = Vec::new();
                let mut allocated = true;
                for _ in 0..1000 {
                    let Some(heap) = native_heap_new() else { allocated = false; break };
                    heaps.push(heap);
                    if unsafe { native_heap_allocate(heap, 32, None, false) }.is_none() { allocated = false; break }
                }
                trace.push(i64::from(allocated));
                trace.push(heap_count() - heaps0);
                let slots = thread_local_count;
                trace.push(slots());
                trace.push(theaps().current - theaps0.current);
                let mut on_tld = 0;
                let mut current = unsafe { ThreadLocalData::theaps_head_at(tld) };
                while let Some(t) = NonNull::new(current) {
                    on_tld += 1;
                    current = unsafe { Theap::tld_next_at(t) };
                }
                trace.push(on_tld);
                for heap in heaps {
                    assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
                }
                trace.push(heap_count() - heaps0);
                trace.push(i64::from(identity.heap_list().test_head() == main_heap.as_ptr()
                    && unsafe { Heap::test_links(main_heap) }.1.is_null()));
                trace.push(i64::from(unsafe { ThreadLocalData::theaps_head_at(tld) } == theap.as_ptr()));
                trace.push(theaps().current - theaps0.current);
                trace.push(theaps().total - theaps0.total);
                trace.push(slots());

                // A Heap on a reused key whose slot holds a stale Theap.
                let reused = native_heap_new().unwrap();
                let block = unsafe { native_heap_allocate(reused, 64, None, false) };
                trace.push(i64::from(block.is_some()));
                trace.push(theaps().current - theaps0.current);
                trace.push(slots());
                if let Some(block) = block {
                    unsafe { native_free(block) };
                }
                assert_eq!(unsafe { native_heap_release(reused, true) }, Ok(HeapReleaseOutcome::Released));
                trace.push(heap_count() - heaps0);
                trace.push(theaps().current - theaps0.current);
                for (index, value) in trace.iter().enumerate() {
                    std::println!("m6.heap.main.{index}={value}");
                }
            },
        );
    }

    /// A later thread of the process main subprocess allocates from a Heap
    /// another thread created (an arena block and an OS-backed one), creates
    /// and deletes its own Heap, and finishes: its Theap's pages pass to the
    /// Heap, and the creating thread frees one block and destroys the Heap.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn later_thread_finishes_with_live_blocks_on_a_shared_heap() {
        use crate::runtime_lifecycle::{
            attach_current_thread, finish_current_thread_native_after_user_destructors, ThreadAttachResult,
            ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::later_thread_finishes_with_live_blocks_on_a_shared_heap",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let first = match native_allocate_aligned(16, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    _ => panic!("the main thread allocates"),
                };
                unsafe { native_free(first) };
                let shared = native_heap_new().expect("the main thread creates a Heap");
                let local = unsafe { native_heap_allocate(shared, 64, None, false) }.expect("a local block");
                let heap_address = shared.as_ptr().addr();
                let blocks = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: the fresh thread registers its own descriptor once.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    let shared = NonNull::new(heap_address as *mut Heap).unwrap();
                    let allocate = |size, aligned| unsafe { native_heap_allocate(shared, size, aligned, false) }
                        .expect("a worker block")
                        .as_ptr()
                        .addr();
                    let blocks = [allocate(64, None), allocate(64, None), allocate(1 << 20, Some((2 << 20, 0)))];
                    let own = native_heap_new().expect("the worker creates a Heap");
                    let block = unsafe { native_heap_allocate(own, 100, None, false) }.unwrap();
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    assert_eq!(unsafe { native_heap_release(own, false) }, Ok(HeapReleaseOutcome::Released));
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                    blocks
                })
                .join()
                .expect("the worker finishes with live blocks");
                let free = |address: usize| unsafe { native_free(NonNull::new(address as *mut u8).unwrap()) };
                assert_eq!(free(blocks[0]), NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_heap_release(shared, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }

    /// Destroy a shared Heap after its worker stops allocating but before the
    /// worker exits. Its cached Theap reference must remain valid through the
    /// worker's thread teardown even though the Heap list no longer owns it.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn destroy_shared_heap_while_worker_theap_is_cached() {
        use crate::runtime_lifecycle::{
            attach_current_thread, finish_current_thread_native_after_user_destructors,
            ThreadAttachResult, ThreadFinishResult,
        };
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::destroy_shared_heap_while_worker_theap_is_cached",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let heap = native_heap_new().expect("a shared Heap");
                let heap_address = heap.as_ptr().addr();
                let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
                let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
                let worker = std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: this worker registers its live descriptor once.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    let heap = NonNull::new(heap_address as *mut Heap).unwrap();
                    let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("worker allocation");
                    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    let current = current_main_thread().expect("the attached worker owns a TLD");
                    let cached = heap_theap(current, heap).expect("the worker selects the Heap Theap");
                    assert_eq!(unsafe { Theap::heap_at(cached) }, heap.as_ptr());
                    ready_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                    assert_eq!(unsafe { Theap::heap_at(cached) }, heap.as_ptr());
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                });
                ready_rx.recv().unwrap();
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
                resume_tx.send(()).unwrap();
                worker.join().expect("the worker finishes after Heap destruction");
            },
        );
    }

    /// `_mi_heap_theap_set` can fail while growing regular thread-local
    /// storage. The source still returns and caches the new Theap, allowing
    /// this allocation to proceed; a later call may create another Theap.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn heap_theap_survives_first_regular_slot_allocation_failure() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::heap_theap_survives_first_regular_slot_allocation_failure",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                let heap = native_heap_new().expect("a Heap");
                let count = crate::thread_local::expanded_slot_count(0, heap_key(heap).unwrap().index().get()).unwrap();
                let size = DynamicThreadLocalBacking::allocation_size(count).unwrap();
                MetaAllocator::global().test_fail_next_direct_zeroed_size(size);
                let thread = current_main_thread().expect("the main thread has its default Theap");
                let theap = heap_theap(thread, heap).expect("the newly linked Theap remains usable");
                assert_eq!(cached_theap(), theap);
                assert_eq!(unsafe { Theap::heap_at(theap) }, heap.as_ptr());
                let block = unsafe { native_heap_allocate(heap, 64, None, false) }
                    .expect("a Heap allocation uses the cached Theap after slot failure");
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }


    /// Pinned `mi_realloc` of a non-main Heap's block through the default
    /// Theap: its Heap is not the default Theap's, so a fitting block is not
    /// reused; a main-Heap replacement takes its contents and the block is
    /// freed.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn default_realloc_of_a_heap_block_replaces_it_from_the_main_heap() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::default_realloc_of_a_heap_block_replaces_it_from_the_main_heap",
            || {
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let first = match native_allocate_aligned(16, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    _ => panic!("the main thread allocates"),
                };
                unsafe { native_free(first) };
                let heap = native_heap_new().expect("a Heap");
                let block = unsafe { native_heap_allocate(heap, 100, None, false) }.expect("a block");
                unsafe { block.as_ptr().write_bytes(0x11, 100) };
                let replaced = match unsafe { crate::runtime_lifecycle::native_reallocate_source(Some(block), 80, false) } {
                    NativePageAllocationResult::Allocated(replaced) => replaced,
                    _ => panic!("the default Theap replaces the block"),
                };
                assert_ne!(replaced, block);
                assert!(unsafe { core::slice::from_raw_parts(replaced.as_ptr(), 80) }.iter().all(|byte| *byte == 0x11));
                assert_eq!(unsafe { heap_of_block(replaced) }, NonNull::new(MainSubprocess::global().ready_main_heap_pointer()));
                assert_eq!(unsafe { native_free(replaced) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }


    /// Pinned-C/Rust differential for a non-main Heap of the process main
    /// subprocess attached by a later thread (`compat/allocator/heap_lifecycle.c`
    /// with `later`): the first allocation creates the thread's Theap at the
    /// TLD-list head on the regular thread-local slot as the cached Theap, a
    /// second Heap moves the cached root and back without a new Theap, and
    /// thread done releases the Theap while the Heap lives on.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn source_ordered_main_subprocess_later_thread_heap_trace() {
        crate::test_process::run_in_fresh_process(
            "subproc::main_heaps::tests::source_ordered_main_subprocess_later_thread_heap_trace",
            || {
                use crate::runtime_lifecycle::{
                    ThreadAttachResult, ThreadFinishResult, attach_current_thread,
                    current_native_allocator_thread_descriptor,
                    finish_current_thread_native_after_user_destructors,
                };
                assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
                    crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
                }));
                assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
                let first = match native_allocate_aligned(16, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    _ => panic!("the main thread allocates"),
                };
                unsafe { native_free(first) };
                let identity = MainSubprocess::global().identity();
                let theaps = move || identity.statistics().final_output_snapshot().theaps;
                let heap_count = move || identity.heap_list().test_counts().0 as i64;
                let heaps0 = heap_count();
                let mut trace: Vec<i64> = Vec::new();

                let h = native_heap_new().expect("a Heap");
                trace.push(i64::from(unsafe { h.as_ref() }.test_theaps_head().is_null()));
                let theaps0 = theaps();
                let heap_address = h.as_ptr() as usize;
                let worker = std::thread::spawn(move || {
                    let h = NonNull::new(heap_address as *mut Heap).unwrap();
                    let mut trace: Vec<i64> = Vec::new();
                    let descriptor = current_native_allocator_thread_descriptor();
                    // SAFETY: this test thread's own allocator-TLS descriptor,
                    // live until the thread exits; no libc registry visits it.
                    assert!(unsafe {
                        crate::runtime_lifecycle::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    let def = default_theap();
                    let tld = NonNull::new(unsafe { Theap::tld_at(def) }).unwrap();
                    let links = |t: NonNull<Theap>| unsafe { Theap::test_list_links(t) };
                    let refcount = |t: NonNull<Theap>| unsafe { t.as_ref() }.refcount() as i64;
                    let page_of = |block: NonNull<u8>| {
                        let binding = binding().unwrap();
                        unsafe { binding.page_map().lookup_live_allocation(block) }.unwrap().unwrap().page()
                    };
                    trace.push(theaps().current - theaps0.current);
                    let p1 = unsafe { native_heap_allocate(h, 64, None, false) }.expect("a Heap block");
                    let ht = NonNull::new(unsafe { h.as_ref() }.test_theaps_head()).unwrap();
                    let (_, _, ht_tnext, _, ht_tld) = links(ht);
                    trace.push(i64::from(ht_tld == tld.as_ptr()
                        && unsafe { ThreadLocalData::theaps_head_at(tld) } == ht.as_ptr()
                        && ht_tnext == def.as_ptr()
                        && unsafe { Theap::heap_at(ht) } == h.as_ptr()));
                    trace.push(i64::from(cached_theap() == ht));
                    trace.push(refcount(ht));
                    trace.push(theaps().current - theaps0.current);
                    trace.push(thread_local_count());
                    let h2 = native_heap_new().expect("a second Heap");
                    trace.push(i64::from(cached_theap() == def));
                    trace.push(refcount(ht));
                    let p2 = unsafe { native_heap_allocate(h, 64, None, false) }.expect("a Heap block");
                    trace.push(i64::from(unsafe { h.as_ref() }.test_theaps_head() == ht.as_ptr()
                        && cached_theap() == ht
                        && unsafe { page_of(p2).as_ref() }.theap() == ht.as_ptr()));
                    trace.push(refcount(ht));
                    trace.push(theaps().current - theaps0.current);
                    let p3 = unsafe { native_heap_allocate(h2, 64, None, false) }.expect("a second Heap block");
                    let h2t = NonNull::new(unsafe { h2.as_ref() }.test_theaps_head());
                    trace.push(i64::from(h2t.is_some_and(|h2t| {
                        (unsafe { ThreadLocalData::theaps_head_at(tld) } == h2t.as_ptr())
                            && links(h2t).2 == ht.as_ptr()
                    })));
                    trace.push(theaps().current - theaps0.current);
                    for block in [p1, p2, p3] {
                        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    }
                    assert_eq!(unsafe { native_heap_release(h2, false) }, Ok(HeapReleaseOutcome::Released));
                    trace.push(i64::from(unsafe { ThreadLocalData::theaps_head_at(tld) } == ht.as_ptr()
                        && links(ht).3.is_null()));
                    trace.push(theaps().current - theaps0.current);
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                    trace
                });
                trace.extend(worker.join().expect("the later thread finishes"));
                trace.push(i64::from(unsafe { h.as_ref() }.test_theaps_head().is_null()));
                trace.push(theaps().current - theaps0.current);
                trace.push(theaps().total - theaps0.total);
                trace.push(heap_count() - heaps0);
                assert_eq!(unsafe { native_heap_release(h, false) }, Ok(HeapReleaseOutcome::Released));
                trace.push(heap_count() - heaps0);
                for (index, value) in trace.iter().enumerate() {
                    std::println!("m6.heap.later.{index}={value}");
                }
            },
        );
    }
}
