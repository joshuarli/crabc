// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:43-148,724-729`
// (page-list containment, owner-list accounting, and the fresh committed
// area's initially-zero check). Owner binding and queue observations are
// copied at the caller's retained, exclusively selected lifecycle boundary.

use core::ffi::CStr;
use core::ptr::NonNull;

use crate::page_map::PageMap;
use crate::config::{ARENA_SLICE_SIZE, LARGE_PAGE_SIZE};
use crate::types::{Block, PageValiditySnapshot};

/// A source leaf assertion or an explicit observation-boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourcePageInvariant {
    BlockSize,
    UsedCapacity,
    CapacityReserved,
    HeapNonNull,
    HeapTheapBinding,
    SecurePageKey,
    QueueContains,
    QueueBlockSize,
    FreeList,
    LocalFreeList,
    RemoteFreeList,
    FreeCount,
    PageStartMapping,
    ListNodeMapping,
    InitiallyZero,
    /// The observation lacks the readable, finite backing required by the
    /// source traversal; this is a Rust memory-access boundary failure.
    ObservationGeometry,
}

/// A live-page source assertion observed while its original owner retained
/// the page. This carries only the failure site; the allocation operation
/// separately keeps the actual page unselectable until terminal delivery or
/// a refused output admission returns it to that same operation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LivePageValidityAssertion {
    invariant: SourcePageInvariant,
}

impl LivePageValidityAssertion {
    fn source_site(&self) -> (&'static CStr, u32, &'static CStr) {
        match self.invariant {
            SourcePageInvariant::BlockSize => (c"include/mimalloc/internal.h", 812, c"mi_page_block_size"),
            SourcePageInvariant::UsedCapacity => (c"src/page.c", 86, c"mi_page_is_valid_init"),
            SourcePageInvariant::CapacityReserved => (c"src/page.c", 87, c"mi_page_is_valid_init"),
            SourcePageInvariant::HeapNonNull => (c"src/page.c", 89, c"mi_page_is_valid_init"),
            SourcePageInvariant::HeapTheapBinding => (c"src/page.c", 91, c"mi_page_is_valid_init"),
            SourcePageInvariant::SecurePageKey => (c"src/page.c", 127, c"_mi_page_is_valid"),
            SourcePageInvariant::QueueContains => (c"src/page.c", 136, c"_mi_page_is_valid"),
            SourcePageInvariant::QueueBlockSize => (c"src/page.c", 137, c"_mi_page_is_valid"),
            SourcePageInvariant::FreeList => (c"src/page.c", 97, c"mi_page_is_valid_init"),
            SourcePageInvariant::LocalFreeList => (c"src/page.c", 98, c"mi_page_is_valid_init"),
            SourcePageInvariant::RemoteFreeList => (c"src/page.c", 111, c"mi_page_is_valid_init"),
            SourcePageInvariant::FreeCount => (c"src/page.c", 117, c"mi_page_is_valid_init"),
            SourcePageInvariant::PageStartMapping => (c"src/page.c", 45, c"mi_page_list_count"),
            SourcePageInvariant::ListNodeMapping => (c"src/page.c", 50, c"mi_page_list_count"),
            // Construction rejects initialization-only and Rust observation
            // failures, which have no live-page assertion delivery site.
            _ => unreachable!(),
        }
    }

    /// Delivers within the original attached startup operation, preserving
    /// the descriptor when its output admission refuses delivery.
    ///
    /// # Safety
    /// The caller continuously retains the original winning startup and its
    /// selected ordinary Theap, Heap, TLD, process, map and output binding.
    /// Its actual page stays alive and unselectable through delivery or
    /// refusal. Every allocator and metadata projection or lock ends before
    /// entry. Callback registration and arguments remain live and serialized;
    /// nested operations cannot reuse that retained page or attachment.
    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
    pub(crate) unsafe fn dispatch_source_attached(
        self, witness: &crate::process_init::SourceAttachedRuntimeOutputWitness<'_>,
    ) -> Result<core::convert::Infallible, Self> {
        let output = match witness.output() {
            Ok(output) => output,
            Err(_) => return Err(self),
        };
        let (file, line, function) = self.source_site();
        // SAFETY: the retained original startup revalidated its output after
        // projections ended; callback arguments and the page remain live.
        unsafe { crate::diagnostic_output::source_assert_fail(output,
            self.invariant.assertion().unwrap(), file, line, Some(function)) }
    }

    /// Delivers within the original metadata startup domain, preserving the
    /// descriptor when the same domain cannot admit output.
    ///
    /// # Safety
    /// The caller retains its original owned page and complete backing, kept
    /// unselectable through delivery or refusal. The witness was captured
    /// before that candidate; its process, metadata issuer, selected map and
    /// output binding stay live without teardown or rebinding. Every allocator
    /// and metadata projection or lock ends before entry. Callback registration
    /// and arguments remain valid and serialized; nested operations cannot
    /// reuse the retained candidate.
    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
    pub(crate) unsafe fn dispatch_source_initialization(
        self, witness: &crate::meta::SourceInitializationOutputWitness<'_, '_, '_>,
    ) -> Result<core::convert::Infallible, Self> {
        let output = match witness.output() {
            Ok(output) => output,
            Err(_) => return Err(self),
        };
        let (file, line, function) = self.source_site();
        // SAFETY: the original startup witness revalidated its own domain
        // after projections ended, with page and callback lifetimes retained.
        unsafe { crate::diagnostic_output::source_assert_fail(output,
            self.invariant.assertion().unwrap(), file, line, Some(function)) }
    }

    /// Delivers the observed assertion after every allocator projection ends.
    ///
    /// # Safety
    /// `owner` belongs to the same admitted operation that observed this
    /// failure. Its original process, output binding, Heap and Theap remain
    /// continuously retained. The caller keeps the actual page and backing
    /// alive and unselectable through terminal delivery; this descriptor
    /// supplies no page retention or release authority. Every Page, Heap,
    /// Theap, map and allocator projection or lock ends before entry. Output
    /// callback registration and arguments remain live and serialized, and
    /// nested operations cannot reuse the retained page.
    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
    pub(crate) unsafe fn dispatch(self, owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>) -> ! {
        let (file, line, function) = self.source_site();
        // SAFETY: the original operation retains its output domain and page
        // after ending projections, throughout terminal callback delivery.
        unsafe { crate::diagnostic_output::source_assert_fail(owner.output(),
            self.invariant.assertion().unwrap(), file, line, Some(function)) }
    }
}

/// Identifies only the fresh committed-region assertion at page initialization.
/// This descriptor carries no Page reference, backing ownership or release
/// permission; the allocation caller separately retains the original candidate.
/// Source fresh-page creation has already registered PageMap reachability and
/// charged page registration statistics before reaching this assertion. Engine
/// paths that initialize lists before those transitions expose a different
/// callback-visible state. A primary Page or its aliases cannot certify that
/// registration/accounting happened; the caller retains its actual progress.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FreshPageInitializationAssertion {
    _private: (),
}

impl FreshPageInitializationAssertion {
    /// Delivers the source assertion for the original ordinary startup Theap.
    /// An output admission refusal preserves the descriptor for its caller.
    ///
    /// # Safety
    /// `witness` was captured from the actual winning startup before creating
    /// this candidate. The caller continuously retains that completion, the
    /// original ordinary Theap, Heap and TLD attachment, its process/output/map
    /// binding, and the owned fresh backing with its actual registration
    /// progress until dispatch terminates or returns refusal. Startup cannot
    /// finish and the attachment cannot be torn down or rebound during this
    /// scope. Every allocator, Page, Heap, Theap, TLD and random projection or
    /// lock ends before entry. Output callback registration and arguments stay
    /// valid and serialized; nested operations cannot reuse the candidate or
    /// select it as an initialized free list.
    #[cfg(all(target_arch = "x86_64", any(feature = "mi-debug-1", feature = "mi-debug-2", feature = "mi-debug-3")))]
    pub(crate) unsafe fn dispatch_source_attached(
        self,
        witness: &crate::process_init::SourceAttachedRuntimeOutputWitness<'_>,
    ) -> Result<core::convert::Infallible, Self> {
        let output = match witness.output() {
            Ok(output) => output,
            Err(_) => return Err(self),
        };
        // SAFETY: the retained winning startup revalidated its original
        // output after projections ended; backing and callback arguments
        // remain live continuously through terminal delivery.
        unsafe { crate::diagnostic_output::source_assert_fail(
            output,
            c"mi_mem_is_zero(page_start, mi_page_committed(page))",
            c"src/page.c",
            729,
            Some(c"_mi_page_init"),
        ) }
    }

    /// Delivers the same source assertion within the original startup domain.
    /// An output admission refusal preserves the descriptor for its caller.
    ///
    /// # Safety
    /// The caller retains the original owned fresh backing and its actual
    /// registration progress until dispatch terminates or returns refusal.
    /// `witness` is the actual startup scope captured before that candidate;
    /// its original process, pinned metadata issuer and selected PageMap
    /// remain live, without teardown or rebinding. Every allocator, metadata,
    /// Page, Heap, Theap, TLD and random projection or lock ends before entry.
    /// Output callback registration and arguments remain valid and serialized
    /// throughout delivery. Nested operations must not reuse the retained
    /// candidate or select it as an initialized free list.
    #[cfg(all(target_arch = "x86_64", any(feature = "mi-debug-1", feature = "mi-debug-2", feature = "mi-debug-3")))]
    pub(crate) unsafe fn dispatch_source_initialization(
        self,
        witness: &crate::meta::SourceInitializationOutputWitness<'_, '_, '_>,
    ) -> Result<core::convert::Infallible, Self> {
        let output = match witness.output() {
            Ok(output) => output,
            Err(_) => return Err(self),
        };
        // SAFETY: the original startup witness revalidated its own output
        // domain after projections ended; the caller retains backing and
        // callback arguments continuously through terminal delivery.
        unsafe { crate::diagnostic_output::source_assert_fail(
            output,
            c"mi_mem_is_zero(page_start, mi_page_committed(page))",
            c"src/page.c",
            729,
            Some(c"_mi_page_init"),
        ) }
    }

    /// Delivers the source assertion after initialization observations end.
    ///
    /// # Safety
    /// The caller must retain the original owned fresh backing and its actual
    /// registration progress until this nonreturning dispatch terminates the
    /// process. No Page, Heap, Theap, engine or member projection or allocator
    /// lock may remain live across output callback reentry. `owner` must be the
    /// same admitted allocation scope acquired before creating that candidate.
    /// Its output callback registration and argument lifetime must remain
    /// serialized and valid throughout delivery. Nested allocation must not
    /// reuse the retained candidate or observe it as an initialized free list.
    #[cfg(all(target_arch = "x86_64", any(feature = "mi-debug-1", feature = "mi-debug-2", feature = "mi-debug-3")))]
    pub(crate) unsafe fn dispatch(
        self,
        owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
    ) -> ! {
        // SAFETY: the caller keeps the preadmitted owner and original backing
        // live, ends all metadata projections, and retains callback arguments.
        unsafe { crate::diagnostic_output::source_assert_fail(
            owner.output(),
            c"mi_mem_is_zero(page_start, mi_page_committed(page))",
            c"src/page.c",
            729,
            Some(c"_mi_page_init"),
        ) }
    }
}

impl SourcePageInvariant {
    /// Separates actual live-page source assertions from fresh zero checks
    /// and memory-observation refusal, without transferring any page rights.
    pub(crate) const fn into_live_page_validity_assertion(self) -> Result<LivePageValidityAssertion, Self> {
        match self {
            Self::InitiallyZero | Self::ObservationGeometry => Err(self),
            invariant => Ok(LivePageValidityAssertion { invariant }),
        }
    }

    /// An observation-boundary or list failure belongs to a different caller
    /// contract and cannot be delivered as the fresh zero assertion.
    pub(crate) const fn into_fresh_initialization_assertion(self) -> Result<FreshPageInitializationAssertion, Self> {
        match self {
            Self::InitiallyZero => Ok(FreshPageInitializationAssertion { _private: () }),
            failure => Err(failure),
        }
    }

    /// The exact C expression, for later delivery after observations end.
    /// A Rust observation-boundary failure has no invented source assertion.
    pub(crate) const fn assertion(self) -> Option<&'static CStr> {
        Some(match self {
            // The accessor asserts this field before the outer initialization
            // predicate can evaluate its returned block size.
            Self::BlockSize => c"page->block_size > 0",
            Self::UsedCapacity => c"page->used <= page->capacity",
            Self::CapacityReserved => c"page->capacity <= page->reserved",
            Self::HeapNonNull => c"page->heap!=NULL",
            Self::HeapTheapBinding => c"page_theap == NULL || mi_page_theap(page)==page_theap || mi_page_theap(page)->tld->thread_id == MI_THREADID_DETACHED",
            Self::SecurePageKey => c"page->keys[0] != 0",
            Self::QueueContains => c"mi_page_queue_contains(pq, page)",
            Self::QueueBlockSize => c"pq->block_size==mi_page_block_size(page) || mi_page_is_huge(page) || mi_page_is_in_full(page)",
            Self::FreeList => c"mi_page_list_is_valid(page,page->free)",
            Self::LocalFreeList => c"mi_page_list_is_valid(page,page->local_free)",
            Self::RemoteFreeList => c"mi_page_list_is_valid(page, tfree)",
            Self::FreeCount => c"page->used + free_count == page->capacity",
            Self::PageStartMapping => c"_mi_ptr_page(mi_page_start(page)) == page",
            Self::ListNodeMapping => c"(uint8_t*)head - slice_start > (ptrdiff_t)MI_LARGE_PAGE_SIZE || page == _mi_ptr_page(head)",
            Self::InitiallyZero => c"mi_mem_is_zero(page_start, mi_page_committed(page))",
            Self::ObservationGeometry => return None,
        })
    }
}

/// Copied source owner and queue facts. No pointer from this image can be
/// followed: the selected owner separately retains every actual image and
/// finishes its short field and queue observations before assertion delivery.
#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PageSourceOwnerSnapshot {
    pub(crate) heap_present: bool,
    pub(crate) heap_theap_absent: bool,
    pub(crate) heap_theap_matches: bool,
    pub(crate) page_theap_detached: bool,
    pub(crate) secure_key: usize,
    pub(crate) abandoned: bool,
    pub(crate) queue_contains: bool,
    pub(crate) queue_block_size: Option<usize>,
    pub(crate) block_size: usize,
    pub(crate) is_huge: bool,
    pub(crate) in_full: bool,
}

#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
impl PageSourceOwnerSnapshot {
    /// Copies the source owner disjunction after a retained Page projection.
    /// Queue facts come from the same selected owner's stable queues.
    ///
    /// # Safety
    /// The original Page, its Heap, Theap and named TLD are initialized and
    /// continuously retained by this active operation. Their copied fields
    /// and the calling thread's actual TLS roots cannot change or retire
    /// during this query. A former owner's TLD cannot be followed here.
    /// Queue facts must describe this exact Page under the same owner.
    pub(crate) unsafe fn observe_at(
        state: &PageValiditySnapshot, queue_contains: bool, queue_block_size: Option<usize>,
    ) -> Self {
        let heap_theap = match NonNull::new(state.heap) {
            // SAFETY: the caller retains the actual Heap and current TLS owners.
            Some(heap) => unsafe { crate::types::Heap::source_theap_peek_at(heap) },
            None => core::ptr::null_mut(),
        };
        let page_theap_detached = if !heap_theap.is_null() && heap_theap != state.theap {
            NonNull::new(state.theap).is_some_and(|theap| {
                // SAFETY: this active Page operation retains its actual
                // Theap and named TLD; no former post-exit pointer is read.
                (unsafe { crate::types::Theap::page_validity_thread_id_at(theap) })
                    == crate::types::THREAD_ID_DETACHED
            })
        } else { false };
        Self {
            heap_present: !state.heap.is_null(),
            heap_theap_absent: heap_theap.is_null(),
            heap_theap_matches: heap_theap == state.theap,
            page_theap_detached,
            secure_key: state.keys[0],
            abandoned: state.thread_id <= crate::types::THREAD_ID_ABANDONED_MAPPED,
            queue_contains, queue_block_size, block_size: state.block_size,
            is_huge: state.is_huge, in_full: state.in_full,
        }
    }

    fn valid_init(&self) -> Result<(), SourcePageInvariant> {
        if !self.heap_present { return Err(SourcePageInvariant::HeapNonNull); }
        if !self.heap_theap_absent && !self.heap_theap_matches && !self.page_theap_detached {
            return Err(SourcePageInvariant::HeapTheapBinding);
        }
        Ok(())
    }

    fn valid_queued(&self) -> Result<(), SourcePageInvariant> {
        if crate::config::SECURE_LEVEL != 0 && self.secure_key == 0 {
            return Err(SourcePageInvariant::SecurePageKey);
        }
        if !self.abandoned {
            // The initialization predicate already checked the identical
            // Heap/Theap disjunction under this stable observation.
            if !self.queue_contains { return Err(SourcePageInvariant::QueueContains); }
            if self.queue_block_size != Some(self.block_size) && !self.is_huge && !self.in_full {
                return Err(SourcePageInvariant::QueueBlockSize);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
#[derive(Clone, Copy)]
struct LivePageOwnerValidityTestObserver {
    observe: unsafe fn(&PageValiditySnapshot, &mut PageSourceOwnerSnapshot, *mut core::ffi::c_void),
    argument: *mut core::ffi::c_void,
}

#[cfg(all(test, target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
std::thread_local! {
    static LIVE_PAGE_OWNER_VALIDITY_TEST_OBSERVER:
        core::cell::Cell<Option<LivePageOwnerValidityTestObserver>> = const { core::cell::Cell::new(None) };
}

/// Observes one native operation's copied owner and queue inputs. The test
/// may alter these scalars while actual Page metadata and clients stay valid.
/// The previous observer is restored on return or unwind.
///
/// # Safety
/// The observer and its argument remain live through this same-thread
/// synchronous operation, including assertion dispatch. It may inspect
/// copied inputs and modify its own test state, but cannot retain snapshots
/// or pointers, mutate allocator metadata or backing, allocate, emit output
/// or reenter the allocator. This supplies no Page or issuer lifetime rights.
#[cfg(all(test, target_arch = "x86_64", feature = "mi-debug-3", not(miri)))]
pub(crate) unsafe fn with_live_page_owner_validity_observer_for_test<R>(
    observe: unsafe fn(&PageValiditySnapshot, &mut PageSourceOwnerSnapshot, *mut core::ffi::c_void),
    argument: *mut core::ffi::c_void,
    operation: impl FnOnce() -> R,
) -> R {
    struct RestoreObserver(Option<LivePageOwnerValidityTestObserver>);
    impl Drop for RestoreObserver {
        fn drop(&mut self) { LIVE_PAGE_OWNER_VALIDITY_TEST_OBSERVER.with(|slot| slot.set(self.0)); }
    }
    let _restore = RestoreObserver(LIVE_PAGE_OWNER_VALIDITY_TEST_OBSERVER.with(|slot| {
        slot.replace(Some(LivePageOwnerValidityTestObserver { observe, argument }))
    }));
    operation()
}

/// Checks initialized owner/list validity and optionally the queued-page
/// source assertions. Fresh initialized pages have no queue membership yet.
///
/// # Safety
/// The same retained backing, immutable captured links, collector exclusion
/// and stable PageMap obligations as `source_page_lists_valid` apply. `owner`
/// was copied from this exact Page and its retained issuer under the same
/// operation; its queue facts remain stable until this predicate returns.
#[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
pub(crate) unsafe fn source_page_is_valid(
    state: &PageValiditySnapshot, map: &PageMap, owner: &PageSourceOwnerSnapshot, queued: bool,
) -> Result<(), SourcePageInvariant> {
    #[cfg(all(test, not(miri)))]
    let observed_owner = {
        let mut observed = *owner;
        if let Some(observer) = LIVE_PAGE_OWNER_VALIDITY_TEST_OBSERVER.with(|slot| slot.get()) {
            // SAFETY: this test scope retains its own argument and changes
            // only copied assertion inputs, after every pointer projection.
            unsafe { (observer.observe)(state, &mut observed, observer.argument) };
        }
        observed
    };
    #[cfg(all(test, not(miri)))]
    let owner = &observed_owner;
    // SAFETY: the caller retains the original Page and initialized links;
    // the internal predicate reads no owner pointer from the scalar image.
    unsafe { source_page_lists_valid_with_owner(state, map, Some(owner)) }?;
    if queued { owner.valid_queued()?; }
    Ok(())
}

#[cfg(all(test, target_arch = "x86_64", not(miri)))]
#[derive(Clone, Copy)]
struct LivePageValidityTestObserver {
    observe: unsafe fn(&PageValiditySnapshot, *mut core::ffi::c_void) -> Option<usize>,
    argument: *mut core::ffi::c_void,
}

#[cfg(all(test, target_arch = "x86_64", not(miri)))]
std::thread_local! {
    static LIVE_PAGE_VALIDITY_TEST_OBSERVER:
        core::cell::Cell<Option<LivePageValidityTestObserver>> = const { core::cell::Cell::new(None) };
}

/// Observes one synchronous native operation's actual Page snapshots. A
/// returned count replaces only the copied `used` input to the source scalar
/// predicates; live metadata, list links and client bytes remain unchanged.
/// The previous observer is restored on return or unwind.
///
/// # Safety
/// `argument` and the observer's accessed state stay live through `operation`,
/// including terminal delivery or output-admission refusal. The observer may
/// inspect copied scalar fields and update its own test state, but must not
/// mutate allocator metadata or backing, allocate, emit output or reenter the
/// allocator or validity predicate. It may record a Page address as an identity
/// scalar, but may not retain the snapshot or derived memory-access pointers.
/// This scope stays on the same native thread; it supplies no Page retention,
/// observation, registration or release authority to the operation.
#[cfg(all(test, target_arch = "x86_64", not(miri)))]
pub(crate) unsafe fn with_live_page_validity_observer_for_test<R>(
    observe: unsafe fn(&PageValiditySnapshot, *mut core::ffi::c_void) -> Option<usize>,
    argument: *mut core::ffi::c_void,
    operation: impl FnOnce() -> R,
) -> R {
    struct RestoreObserver(Option<LivePageValidityTestObserver>);
    impl Drop for RestoreObserver {
        fn drop(&mut self) {
            LIVE_PAGE_VALIDITY_TEST_OBSERVER.with(|slot| slot.set(self.0));
        }
    }
    let _restore = RestoreObserver(LIVE_PAGE_VALIDITY_TEST_OBSERVER.with(|slot| {
        slot.replace(Some(LivePageValidityTestObserver { observe, argument }))
    }));
    operation()
}

/// Checks the source scalar/list assertions without taking ownership or
/// invoking diagnostic callbacks. Remote blocks remain included in `used`.
///
/// # Safety
/// The snapshot's live metadata and complete block backing must remain
/// retained. The caller excludes ordinary owner mutation, collection, retirement and
/// reuse throughout this operation. On an owned page, remote producers may
/// prepend exclusively held clients: the captured remote head was acquired
/// after release publication, and every node reachable from that head keeps
/// its initialized link immutable until collection. Producers which can
/// collect after publication, and every independent collector, are excluded.
/// Each contained list node has an initialized readable link word. The map
/// stays active and no overlapping registration changes during the reads.
/// These obligations provide observation permission, never release rights.
pub(crate) unsafe fn source_page_lists_valid(
    state: &PageValiditySnapshot,
    map: &PageMap,
) -> Result<(), SourcePageInvariant> {
    // SAFETY: the caller's original list observation contract is unchanged;
    // this leaf intentionally supplies no owner or queue observation.
    unsafe { source_page_lists_valid_with_owner(state, map, None) }
}

unsafe fn source_page_lists_valid_with_owner(
    state: &PageValiditySnapshot, map: &PageMap,
    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))] owner: Option<&PageSourceOwnerSnapshot>,
    #[cfg(not(all(target_arch = "x86_64", feature = "mi-debug-3")))] _owner: Option<&()>,
) -> Result<(), SourcePageInvariant> {
    #[cfg(all(test, target_arch = "x86_64", not(miri)))]
    let observed = {
        let mut observed = *state;
        if let Some(observer) = LIVE_PAGE_VALIDITY_TEST_OBSERVER.with(|slot| slot.get()) {
            // SAFETY: the installed test scope retains its argument and only
            // observes copied inputs; it cannot change the actual Page.
            if let Some(used) = unsafe { (observer.observe)(state, observer.argument) } {
                observed.used = used;
            }
        }
        observed
    };
    #[cfg(all(test, target_arch = "x86_64", not(miri)))]
    let state = &observed;
    if state.block_size == 0 { return Err(SourcePageInvariant::BlockSize); }
    if state.used > usize::from(state.capacity) { return Err(SourcePageInvariant::UsedCapacity); }
    if state.capacity > state.reserved { return Err(SourcePageInvariant::CapacityReserved); }
    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
    if let Some(owner) = owner { owner.valid_init()?; }
    // SAFETY: the caller supplies stable backing and initialized list links
    // with collection excluded and immutable published links; each walk
    // checks containment before reading its initialized link.
    unsafe {
        walk_list(state, state.free, SourcePageInvariant::FreeList, None)?;
        walk_list(state, state.local_free, SourcePageInvariant::LocalFreeList, None)?;
        walk_list(state, state.remote, SourcePageInvariant::RemoteFreeList, None)?;
        if map.checked_lookup(state.area.as_ptr()) != state.page.as_ptr() {
            return Err(SourcePageInvariant::PageStartMapping);
        }
        let count = walk_list(state, state.free, SourcePageInvariant::FreeList, Some(map))?
            + walk_list(state, state.local_free, SourcePageInvariant::LocalFreeList, Some(map))?;
        if state.used.wrapping_add(count) != usize::from(state.capacity) {
            return Err(SourcePageInvariant::FreeCount);
        }
    }
    Ok(())
}

unsafe fn walk_list(
    state: &PageValiditySnapshot,
    mut node: *mut Block,
    containment_failure: SourcePageInvariant,
    count_map: Option<&PageMap>,
) -> Result<usize, SourcePageInvariant> {
    let start = state.area.addr().get();
    let end = start.checked_add(state.area_bytes)
        .ok_or(SourcePageInvariant::ObservationGeometry)?;
    let slice_start = start & !(ARENA_SLICE_SIZE - 1);
    let mut count = 0usize;
    while !node.is_null() {
        let address = node.addr();
        if address < start || address >= end { return Err(containment_failure); }
        if end - address < core::mem::size_of::<usize>() || count >= usize::from(state.reserved) {
            return Err(SourcePageInvariant::ObservationGeometry);
        }
        if let Some(map) = count_map {
            // SAFETY: the stable active map and no-registration-race proof
            // covers this plain entry read; no Page is dereferenced.
            if address - slice_start <= LARGE_PAGE_SIZE
                && unsafe { map.checked_lookup(node.cast()) } != state.page.as_ptr()
            { return Err(SourcePageInvariant::ListNodeMapping); }
        }
        count += 1;
        // SAFETY: containment and the readable-word bound above precede this
        // exact link read. The caller retains initialized node bytes and
        // excludes collection and reuse; a concurrent producer only prepends
        // its own unpublished node and never rewrites this captured chain.
        #[cfg(not(any(feature = "mi-debug-1", feature = "mi-secure-3")))]
        { node = unsafe { node.cast::<*mut Block>().read_unaligned() }; }
        #[cfg(any(feature = "mi-debug-1", feature = "mi-secure-3"))]
        {
            let word = unsafe { node.cast::<usize>().read_unaligned() };
            let address = crate::free_list::decode_page_link(state.page.addr().get(), state.keys, word);
            node = if address == 0 { core::ptr::null_mut() }
                else { state.area.as_ptr().with_addr(address).cast() };
        }
    }
    Ok(count)
}

/// Checks only the fresh-page initially-zero site before free-list links or
/// client bytes have been written. Ordinary page validity never calls this.
///
/// # Safety
/// Above debug level two, the caller exclusively retains the fresh backing
/// from `area`. If committed-extent validation succeeds, every computed byte
/// must be initialized and readable, and the actual OS page size and source
/// committed-prefix count must describe that same region. A malformed extent
/// rejected before any read provides no permission to inspect bytes. The
/// accepted region can extend beyond `reserved * block_size`. No concurrent
/// client, producer, free-list initialization, or protection change is allowed.
pub(crate) unsafe fn source_initial_page_is_zero(
    state: &PageValiditySnapshot,
    os_page_size: usize,
) -> Result<(), SourcePageInvariant> {
    // The source compiles this expensive initialization assertion only above
    // debug level two. In lower profiles neither byte nor geometry observation
    // is permitted by this assertion site.
    if crate::config::DEBUG_LEVEL <= 2 { return Ok(()); }
    if !state.initially_zero { return Ok(()); }
    let bytes = if state.slice_pcommitted == 0 { state.area_bytes } else {
        if !os_page_size.is_power_of_two() { return Err(SourcePageInvariant::ObservationGeometry); }
        usize::from(state.slice_pcommitted).checked_mul(os_page_size)
            .and_then(|committed| committed.checked_sub(state.area.addr().get() & (ARENA_SLICE_SIZE - 1)))
            .ok_or(SourcePageInvariant::ObservationGeometry)?
    };
    for offset in 0..bytes {
        // SAFETY: the caller proves the entire fresh committed region is
        // initialized and readable; no source block or client is borrowed.
        if unsafe { state.area.as_ptr().add(offset).read() } != 0 {
            return Err(SourcePageInvariant::InitiallyZero);
        }
    }
    Ok(())
}

#[cfg(all(test, target_arch = "x86_64", not(miri)))]
#[derive(Clone, Copy)]
struct FreshInitializationTestObserver {
    observe: unsafe fn(&PageValiditySnapshot, NonNull<crate::types::Page>, *mut core::ffi::c_void),
    argument: *mut core::ffi::c_void,
}

#[cfg(all(test, target_arch = "x86_64", not(miri)))]
std::thread_local! {
    static FRESH_INITIALIZATION_TEST_OBSERVER:
        core::cell::Cell<Option<FreshInitializationTestObserver>> = const { core::cell::Cell::new(None) };
}

/// Installs one observer only for a synchronous native test operation.
/// The previous observer is restored on return or unwind. This supplies no
/// Page, claim, admission, registration, or release authority to the operation.
///
/// # Safety
/// `argument` and everything the observer accesses remain valid throughout
/// `operation`. The observer runs only at the engine's actual original fresh
/// claim boundary. It may inspect the copied snapshot and exclusively owned
/// initialized committed backing, including writing an owned backing byte.
/// It must not allocate, emit output, reenter the allocator, mutate metadata
/// or registration, change protection, or retain the snapshot reference.
/// `operation` must not transfer the observer or argument to another thread.
#[cfg(all(test, target_arch = "x86_64", not(miri)))]
pub(crate) unsafe fn with_fresh_page_initialization_observer_for_test<R>(
    observe: unsafe fn(&PageValiditySnapshot, NonNull<crate::types::Page>, *mut core::ffi::c_void),
    argument: *mut core::ffi::c_void,
    operation: impl FnOnce() -> R,
) -> R {
    struct RestoreObserver(Option<FreshInitializationTestObserver>);
    impl Drop for RestoreObserver {
        fn drop(&mut self) {
            FRESH_INITIALIZATION_TEST_OBSERVER.with(|slot| slot.set(self.0));
        }
    }
    let _restore = RestoreObserver(FRESH_INITIALIZATION_TEST_OBSERVER.with(|slot| {
        slot.replace(Some(FreshInitializationTestObserver { observe, argument }))
    }));
    operation()
}

/// Observes actual fresh-page initialization for one isolated native control.
/// The observer supplies no publication, admission, allocation or release right.
///
/// # Safety
/// `state` was copied from `page`, the initialized primary of the caller's
/// original fresh OS claim. The caller exclusively retains its metadata and
/// complete committed backing while this synchronous observer runs. The
/// observer's argument remains live; it may inspect copied fields and actual
/// registration/statistics, and modify an owned backing byte, but may not
/// allocate, emit output, reenter the allocator, mutate metadata or registration,
/// change protection, or retain a reference to the snapshot after returning.
#[cfg(all(test, target_arch = "x86_64", not(miri)))]
pub(crate) unsafe fn observe_fresh_page_initialization_for_test(
    state: &PageValiditySnapshot,
    page: NonNull<crate::types::Page>,
) {
    FRESH_INITIALIZATION_TEST_OBSERVER.with(|slot| {
        if let Some(observer) = slot.get() {
            // SAFETY: the caller retains the original claim and serialized
            // observer argument for this short, nonreentrant observation.
            unsafe { (observer.observe)(state, page, observer.argument) };
        }
    });
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{MaybeUninit, size_of};
    use crate::config::ARENA_SLICE_SIZE;
    use crate::free_list::LocalFreeList;
    use crate::os::{MemoryConfig, PageSize};
    use crate::types::{Heap, LiveThreadId, MemoryId, Page, Theap, ThreadLocalData};

    #[repr(C, align(65536))]
    struct PageStorage {
        metadata: MaybeUninit<Page>,
        bytes: [u8; 2 * ARENA_SLICE_SIZE - size_of::<Page>()],
    }

    fn with_page(test: impl FnOnce(NonNull<Page>, &PageMap)) {
        with_page_zero_state(true, true, test);
    }

    fn with_page_zero_state(
        initially_zero: bool,
        free_is_zero: bool,
        test: impl FnOnce(NonNull<Page>, &PageMap),
    ) {
        with_page_initial_state(initially_zero, free_is_zero, 0, test);
    }

    fn with_page_initial_state(
        initially_zero: bool,
        free_is_zero: bool,
        slice_pcommitted: u16,
        test: impl FnOnce(NonNull<Page>, &PageMap),
    ) {
        let mut storage = std::boxed::Box::new(PageStorage {
            metadata: MaybeUninit::uninit(),
            bytes: [0; 2 * ARENA_SLICE_SIZE - size_of::<Page>()],
        });
        // Keep the allocation-wide origin: the page's area lies beyond the
        // metadata field, so a borrow of that field cannot authorize reads
        // of the block backing in the next slice.
        let page = unsafe {
            NonNull::new_unchecked(core::ptr::addr_of_mut!(*storage).cast::<Page>())
        };
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        let id = LiveThreadId::new(12).unwrap();
        tld.attach_bootstrap_exclusive(id);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));
        // Selected source metadata is separated from the area's aligned
        // slice. Both remain in this one typed backing allocation.
        let offset = ARENA_SLICE_SIZE;
        let memory = MemoryId::external(page.as_ptr().cast(), 2 * ARENA_SLICE_SIZE,
            slice_pcommitted == 0, false, initially_zero);
        // SAFETY: the aligned typed allocation contains both metadata and
        // complete block backing; publication precedes every observer.
        unsafe {
            Page::publish_fresh_exclusive_at(page, &mut theap, &heap, id,
                32, offset, 8, slice_pcommitted, free_is_zero, memory)
        }.unwrap();
        let config = MemoryConfig::from_observations(PageSize::new(4096).unwrap(),
            8 * 1024 * 1024, true, false);
        let mut map = PageMap::initialize(config, 47, true).unwrap();
        // SAFETY: publication and map mutation are exclusive. The storage
        // and all owner images remain live through the test callback.
        unsafe { map.register_range(page.as_ptr().cast::<u8>().add(offset), ARENA_SLICE_SIZE, page) }.unwrap();
        test(page, &map);
        // SAFETY: the callback has ended and no producer or reader survives.
        unsafe {
            map.unregister_range(page.as_ptr().cast::<u8>().add(offset), ARENA_SLICE_SIZE).unwrap();
            map.destroy().unwrap();
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    unsafe extern "C" fn fresh_assertion_stderr(message: *const core::ffi::c_char) {
        unsafe extern "C" {
            fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void) -> core::ffi::c_int;
            static mut stderr: *mut core::ffi::c_void;
        }
        // SAFETY: the pinned native test process retains musl's actual FILE
        // owner for its lifetime; the synchronous message is terminated.
        unsafe { let _ = fputs(message, stderr); }
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    enum FreshAssertionTestClaim {
        Os(crate::os_page::OsAlignedPageClaim),
        Arena(crate::arena::SourceInitializationClaimCustody),
    }

    /// Creates actual fresh backing inside the already-admitted owner scope.
    /// Page publication records the real selected Theap; no list or client
    /// initialization occurs in this backing before the assertion control.
    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    fn with_admitted_fresh_page(
        owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>,
        arena: bool,
        test: impl FnOnce(NonNull<Page>, &PageMap),
    ) {
        use crate::arena::{ArenaId, ArenaSearch, ProcessArenaBacking};
        use crate::os::{MapAccess, MemoryConfig, PageSize, StartupInput};
        use crate::os_page::OsAlignedPageClaim;
        use crate::types::TheapOwner;
        let process = owner.process();
        let issuer = process.subprocess().arena_backing();
        // The real runtime bound its arena group to these startup observations;
        // an independently invented configuration cannot reserve in that group.
        let config = MemoryConfig::detect(StartupInput::new(PageSize::new(4096).unwrap()));
        let block_size = 32;
        let (claim, metadata, memory, offset, reserved) = if arena {
            let mut diagnostic = None;
            // SAFETY: actual preadmission and this single-threaded fixture
            // retain the issuing process and its sole arena backing.
            let id = unsafe { issuer.reserve_os_memory_reporting_failure(process, config,
                crate::config::ARENA_MIN_SIZE, MapAccess::Committed, false, true, None,
                &mut diagnostic) }
                .unwrap_or_else(|_| panic!("actual admitted arena reservation"));
            let search = ArenaSearch { heap_sequence: 0, heap_count: 1, thread_sequence: 0,
                numa_node: -1, requested: id, allow_pinned: false };
            let claim = unsafe { issuer.try_find_free(search, 1, ARENA_SLICE_SIZE, true) }.unwrap();
            let start = claim.start();
            let metadata = claim.page_metadata().unwrap();
            let memory = claim.memory_id();
            let block_offset = crate::page::page_usable_start_offset(block_size).unwrap();
            let offset = (start as usize).checked_sub(metadata.as_ptr() as usize).unwrap() + block_offset;
            let reserved = crate::page::reserved_object_count(ARENA_SLICE_SIZE, block_offset, block_size).unwrap();
            // SAFETY: the actual admitted owner retains issuer, arena and
            // original span independently of this short claim projection.
            let custody = unsafe { claim.into_source_initialization_custody() }
                .unwrap_or_else(|_| panic!("actual arena claim has original custody"));
            let foreign = ProcessArenaBacking::new();
            let custody = match foreign.restore_source_initialization_claim(custody) {
                Err((crate::arena::SourceInitializationClaimCustodyError::WrongBacking, custody)) => custody,
                _ => panic!("wrong issuer must return the original custody"),
            };
            let restored = issuer.restore_source_initialization_claim(custody)
                .unwrap_or_else(|_| panic!("the exact original issuer still restores custody"));
            assert_eq!(restored.start(), start);
            assert_eq!(restored.slice_count(), 1);
            let custody = unsafe { restored.into_source_initialization_custody() }
                .unwrap_or_else(|_| panic!("the restored original claim retains custody"));
            (FreshAssertionTestClaim::Arena(custody), metadata, memory, offset, reserved)
        } else {
            // SAFETY: actual preadmission retains this original issuing pair
            // throughout publication, assertion and eventual explicit release.
            let claim = unsafe { OsAlignedPageClaim::allocate_for_borrowed_process_with_random(
                process, config, block_size, 1, ArenaId::none(), None) }
                .unwrap_or_else(|_| panic!("actual admitted OS claim"));
            let original = claim.metadata().unwrap();
            assert!(claim.belongs_to_subprocess(process.subprocess()));
            assert!(!claim.belongs_to_subprocess(crate::subproc::MainSubprocess::test_static_owner().identity()));
            assert_eq!(claim.metadata().unwrap(), original);
            let layout = claim.layout();
            let memory = claim.memory_id().unwrap();
            (FreshAssertionTestClaim::Os(claim), original, memory, layout.page_offset(), layout.reserved())
        };
        assert!(memory.initially_zero());
        let selected = owner.selected_theap();
        let heap = NonNull::new(unsafe { Theap::heap_at(selected) }).unwrap();
        let thread = crate::compiler_tls::current_thread_identity().unwrap();
        // SAFETY: only this thread owns the selected ordinary fields, while
        // the admitted scope retains actual Heap/Theap and original backing.
        // Raw identity projections avoid a whole Heap or Theap reference.
        let page = unsafe { Page::publish_fresh_exclusive_owner_at_with_pointers(
            metadata, selected, heap, TheapOwner::Live(thread), block_size,
            offset, reserved, 0, true, memory) }.unwrap();
        let state = unsafe { Page::validity_snapshot_at(page) };
        assert_eq!(state.used, 0);
        assert_eq!(state.capacity, 0);
        assert!(state.free.is_null());
        let area = state.area;
        let area_bytes = state.area_bytes;
        let mut map = PageMap::initialize(config, 47, true).unwrap();
        // SAFETY: original ownership and source publication precede this
        // isolated map registration; no client or producer sees the page.
        unsafe { map.register_range(area.as_ptr(), area_bytes, page) }.unwrap();
        let claim = core::mem::ManuallyDrop::new(claim);
        test(page, &map);
        unsafe { map.unregister_range(area.as_ptr(), area_bytes) }.unwrap();
        unsafe { map.destroy() }.unwrap();
        match core::mem::ManuallyDrop::into_inner(claim) {
            FreshAssertionTestClaim::Os(claim) => {
                use crate::os::{fault, VmProcess};
                use crate::os_page::OsAlignedPageOwner;
                let fault = fault::install(fault::Plan::disabled());
                let base = claim.base().unwrap();
                let metadata = claim.metadata().unwrap();
                assert!(claim.belongs_to_subprocess(process.subprocess()));
                let foreign = VmProcess::new_main(process.policy(),
                    crate::subproc::MainSubprocess::test_static_owner());
                let before = process.subprocess().vm_statistics().snapshot();
                // SAFETY: the admitted owner retains the original issuer and
                // sole private claim; the foreign view supplies no authority.
                let mismatch = unsafe { claim.release_for_process(foreign) }
                    .expect_err("observation refusal cannot change the mapping issuer");
                assert_eq!(fault.observed(), 0);
                assert_eq!(process.subprocess().vm_statistics().snapshot(), before);
                let OsAlignedPageOwner::Claim(claim) = mismatch.into_owner()
                    else { panic!("issuer refusal returns the original fresh claim"); };
                assert_eq!(claim.base().unwrap(), base);
                assert_eq!(claim.metadata().unwrap(), metadata);
                assert!(claim.belongs_to_subprocess(process.subprocess()));

                fault.set(fault::Plan::at(fault::Point::Unmap, 1, crabc_core::Errno::NOMEM));
                // SAFETY: all PageMap and metadata observations have ended;
                // the original admitted issuer and sole claim remain live.
                let failure = unsafe { claim.release_for_process(process) }
                    .expect_err("failed cleanup retains the original fresh mapping");
                assert_eq!(fault.observed(), 1);
                let accounted = process.subprocess().vm_statistics().snapshot();
                assert_ne!(accounted, before);
                let OsAlignedPageOwner::Claim(claim) = failure.into_owner()
                    else { panic!("failed cleanup retains a claim, not a published owner"); };
                assert_eq!(claim.base().unwrap(), base);
                assert_eq!(claim.metadata().unwrap(), metadata);
                // SAFETY: the original issuer still lives; presenting a
                // foreign pair must not bypass the accounted retry boundary.
                let mismatch = unsafe { claim.release_for_process(foreign) }
                    .expect_err("a raw retry does not acquire a different issuer");
                assert_eq!(fault.observed(), 1);
                assert_eq!(process.subprocess().vm_statistics().snapshot(), accounted);
                let OsAlignedPageOwner::Claim(claim) = mismatch.into_owner()
                    else { panic!("retry refusal preserves the original fresh claim"); };
                assert!(claim.belongs_to_subprocess(process.subprocess()));
                assert_eq!(claim.base().unwrap(), base);
                fault.set(fault::Plan::disabled());
                // SAFETY: cleanup has already been accounted, and the same
                // admitted owner retains its identity through this raw retry.
                unsafe { claim.retry_release() }
                    .unwrap_or_else(|_| panic!("the original fresh claim retries explicitly"));
                assert_eq!(fault.observed(), 0);
                assert_eq!(process.subprocess().vm_statistics().snapshot(), accounted);
            }
            FreshAssertionTestClaim::Arena(custody) => {
                let restored = issuer.restore_source_initialization_claim(custody)
                    .unwrap_or_else(|_| panic!("nonfatal control preserves original arena custody"));
                assert!(restored.release());
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    fn with_fresh_assertion_owner(
        test: impl for<'scope> FnOnce(crate::runtime_lifecycle::NativeAllocationOwner<'scope>),
    ) {
        use crate::runtime_lifecycle::{self as runtime, NativePageAllocationResult, NativePageFreeResult};
        // SAFETY: this callback uses the pinned process's actual FILE output
        // primitive and remains available throughout the isolated process.
        let stderr = unsafe { crate::diagnostic_output::RuntimeStderrOutput::new(fresh_assertion_stderr) };
        assert!(runtime::test_initialize_process_from_host_environment(4096, stderr));
        let NativePageAllocationResult::Allocated(seed) = runtime::native_allocate(32, false)
            else { panic!("the genuine native client initializes its selected Theap"); };
        let selected = crate::compiler_tls::default_theap();
        // SAFETY: the original client retains this initialized selected
        // owner and member; no metadata projection crosses admission.
        unsafe { runtime::with_native_allocation_owner(selected, test) }.unwrap();
        assert_eq!(unsafe { runtime::native_free(seed) }, NativePageFreeResult::Freed);
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn actual_os_and_arena_claims_preserve_nonfatal_initialization_errors() {
        crate::test_process::run_in_fresh_process(
            "page_validity::tests::actual_os_and_arena_claims_preserve_nonfatal_initialization_errors", || {
                with_fresh_assertion_owner(|owner| {
                    for arena in [false, true] {
                        with_admitted_fresh_page(&owner, arena, |page, map| unsafe {
                            let mut state = Page::validity_snapshot_at(page);
                            assert_eq!(source_initial_page_is_zero(&state, 4096), Ok(()));
                            state.capacity = 1;
                            let failure = source_page_lists_valid(&state, map).unwrap_err();
                            assert_eq!(failure, SourcePageInvariant::FreeCount);
                            assert_eq!(failure.into_fresh_initialization_assertion(), Err(failure));
                            // This copied observation has malformed OS-page
                            // geometry. Its rejection precedes any byte read;
                            // the actual Page and original claim stay intact.
                            state.slice_pcommitted = 1;
                            let geometry = source_initial_page_is_zero(&state, 3).unwrap_err();
                            assert_eq!(geometry, SourcePageInvariant::ObservationGeometry);
                            assert_eq!(geometry.into_fresh_initialization_assertion(), Err(geometry));
                            // Rejection has neither changed the retained Page
                            // nor consumed its independently owned backing.
                            let restored = Page::validity_snapshot_at(page);
                            assert_eq!(restored.capacity, 0);
                            assert_eq!(source_initial_page_is_zero(&restored, 4096), Ok(()));
                        });
                    }
                });
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn actual_initially_zero_assertion_retains_os_and_arena_backing_until_abort() {
        const CHILD: &str = "CRABC_FRESH_PAGE_ASSERTION_CHILD";
        struct Capture {
            area: NonNull<u8>,
            bytes: usize,
            delivered: core::sync::atomic::AtomicBool,
        }
        unsafe extern "C" fn output(message: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
            use crate::runtime_lifecycle::{self as runtime, NativePageAllocationResult, NativePageFreeResult};
            unsafe extern "C" { fn write(fd: core::ffi::c_int, bytes: *const u8, size: usize) -> isize; }
            // SAFETY: serialized synchronous registration retains this
            // capture and the original committed backing through abort.
            let capture = unsafe { &*argument.cast::<Capture>() };
            let bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
            if bytes.starts_with(b"mimalloc: assertion failed:") {
                assert!(!capture.delivered.swap(true, core::sync::atomic::Ordering::AcqRel));
                assert_eq!(unsafe { capture.area.as_ptr().read() }, 0x5a);
                let NativePageAllocationResult::Allocated(nested) = runtime::native_allocate(96, false)
                    else { panic!("assertion output may reenter the idle admitted owner"); };
                assert!(nested.addr().get() < capture.area.addr().get()
                    || nested.addr().get() >= capture.area.addr().get() + capture.bytes);
                assert_eq!(unsafe { runtime::native_free(nested) }, NativePageFreeResult::Freed);
                let marker = b"original backing retained during reentry\n";
                assert_eq!(unsafe { write(2, marker.as_ptr(), marker.len()) }, marker.len() as isize);
            }
            assert_eq!(unsafe { write(2, bytes.as_ptr(), bytes.len()) }, bytes.len() as isize);
        }
        if let Some(kind) = std::env::var_os(CHILD) {
            with_fresh_assertion_owner(|owner| {
                with_admitted_fresh_page(&owner, kind == "arena", |page, _map| {
                    // Every snapshot/ordinary field observation ends before
                    // registering output or entering terminal dispatch.
                    let (assertion, area, bytes) = unsafe {
                        let state = Page::validity_snapshot_at(page);
                        state.area.as_ptr().write(0x5a);
                        (source_initial_page_is_zero(&state, 4096).unwrap_err()
                            .into_fresh_initialization_assertion().unwrap(), state.area, state.area_bytes)
                    };
                    let capture = Capture { area, bytes,
                        delivered: core::sync::atomic::AtomicBool::new(false) };
                    // SAFETY: this fresh process excludes callback replacement
                    // and retains the argument, admitted owner and original
                    // claim across reentry until the nonreturning abort.
                    unsafe {
                        owner.output().register_output(Some(output), core::ptr::from_ref(&capture).cast_mut().cast());
                        assertion.dispatch(&owner);
                    }
                });
            });
            panic!("a genuine source assertion cannot return");
        }
        use std::os::unix::process::ExitStatusExt;
        for kind in ["os", "arena"] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "page_validity::tests::actual_initially_zero_assertion_retains_os_and_arena_backing_until_abort",
                    "--nocapture", "--test-threads=1"])
                // Native launchers bind temporary storage to checkout-owned
                // scratch, including any process-terminal core image.
                .current_dir(std::env::temp_dir())
                .env(CHILD, kind).output().unwrap();
            assert_eq!(result.status.signal(), Some(6), "{kind}");
            assert_eq!(result.stderr, b"\noriginal backing retained during reentry\nmimalloc: assertion failed: at \"src/page.c\":729, _mi_page_init\n  assertion: \"mi_mem_is_zero(page_start, mi_page_committed(page))\"\n", "{kind}");
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    struct NativeFreshProbe {
        map: crate::process_page_map::ProcessPageMapRoot,
        theap: NonNull<Theap>,
        heap: *mut Heap,
        baseline: crate::statistics::FinalStatCount,
        observed: core::cell::Cell<Option<(NonNull<Page>, NonNull<u8>, usize)>>,
        poison: bool,
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    impl NativeFreshProbe {
        fn new(owner: &crate::runtime_lifecycle::NativeAllocationOwner<'_>, poison: bool) -> Self {
            let theap = owner.selected_theap();
            // SAFETY: the actual preadmitted owner retains initialized roots;
            // these short projections end before any native allocator call.
            Self { map: owner.page_map().unwrap(), theap,
                heap: unsafe { Theap::heap_at(theap) },
                baseline: unsafe { Theap::final_statistics_at(theap) }.unwrap().1.pages,
                observed: core::cell::Cell::new(None), poison }
        }

        unsafe fn observe(state: &PageValiditySnapshot, page: NonNull<Page>, argument: *mut core::ffi::c_void) {
            // SAFETY: installation retains this probe through the synchronous
            // call; the engine retains the original claim and selected Heap.
            let probe = unsafe { &*argument.cast::<Self>() };
            if unsafe { Page::heap_identity_at(page) } != probe.heap { return; }
            assert!(probe.observed.get().is_none(), "one real fresh OS candidate");
            assert_eq!(state.page, page);
            assert_eq!(state.used, 0);
            assert_eq!(state.capacity, 0);
            assert!(state.free.is_null());
            assert!(state.local_free.is_null());
            assert!(state.remote.is_null());
            let registered = unsafe { probe.map.lookup_registered_page(state.area.as_ptr()) }.unwrap();
            let pages = unsafe { Theap::final_statistics_at(probe.theap) }.unwrap().1.pages;
            assert_eq!((registered, pages.total, pages.current),
                (Some(page), probe.baseline.total + 1, probe.baseline.current + 1),
                "actual PageMap identity and registration counters before source initialization");
            probe.observed.set(Some((page, state.area, state.area_bytes)));
            if probe.poison {
                // SAFETY: only this test observer and the engine own this
                // still-uninitialized committed block backing.
                unsafe { state.area.as_ptr().write(0x5a) };
            }
        }

        fn install(&self) -> NativeFreshProbeGuard<'_> {
            let previous = FRESH_INITIALIZATION_TEST_OBSERVER.with(|slot| slot.replace(Some(
                FreshInitializationTestObserver { observe: Self::observe,
                    argument: core::ptr::from_ref(self).cast_mut().cast() })));
            NativeFreshProbeGuard { previous, retained: core::marker::PhantomData }
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    struct NativeFreshProbeGuard<'a> {
        previous: Option<FreshInitializationTestObserver>,
        retained: core::marker::PhantomData<&'a NativeFreshProbe>,
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    impl Drop for NativeFreshProbeGuard<'_> {
        fn drop(&mut self) {
            FRESH_INITIALIZATION_TEST_OBSERVER.with(|slot| slot.set(self.previous));
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn native_fresh_os_initialization_publishes_map_and_stats_before_lists() {
        crate::test_process::run_in_fresh_process(
            "page_validity::tests::native_fresh_os_initialization_publishes_map_and_stats_before_lists", || {
                with_fresh_assertion_owner(|owner| {
                    use crate::runtime_lifecycle::{self as runtime, NativePageAllocationResult, NativePageFreeResult};
                    let probe = NativeFreshProbe::new(&owner, false);
                    let guard = probe.install();
                    let NativePageAllocationResult::Allocated(client) = runtime::native_allocate_aligned(7, 128 * 1024, false)
                        else { panic!("actual aligned native ingress"); };
                    drop(guard);
                    let (page, area, _) = probe.observed.get().expect("actual engine observation");
                    // SAFETY: this actual client and original admission retain
                    // the registered page until its native free consumes it.
                    assert_eq!(unsafe { probe.map.lookup_registered_page(client.as_ptr()) }.unwrap(), Some(page));
                    assert_eq!(unsafe { runtime::native_free(client) }, NativePageFreeResult::Freed);
                    assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), None);
                    let after = unsafe { Theap::final_statistics_at(probe.theap) }.unwrap().1.pages;
                    assert_eq!(after.current, probe.baseline.current);
                    assert_eq!(after.total, probe.baseline.total + 1);
                });
            });
    }

    #[cfg(all(target_arch = "x86_64", not(miri), feature = "mi-debug-3"))]
    #[test]
    fn native_fresh_os_zero_assertion_retains_registered_backing_during_reentry() {
        const CHILD: &str = "CRABC_NATIVE_FRESH_ZERO_CHILD";
        unsafe extern "C" fn output(message: *const core::ffi::c_char, argument: *mut core::ffi::c_void) {
            use crate::runtime_lifecycle::{self as runtime, NativePageAllocationResult, NativePageFreeResult};
            unsafe extern "C" { fn write(fd: core::ffi::c_int, bytes: *const u8, size: usize) -> isize; }
            // SAFETY: the registered argument and actual pending claim remain
            // live until the nonreturning assertion dispatch finishes.
            let probe = unsafe { &*argument.cast::<NativeFreshProbe>() };
            let message = unsafe { CStr::from_ptr(message) }.to_bytes();
            if message.starts_with(b"mimalloc: assertion failed:") {
                FRESH_INITIALIZATION_TEST_OBSERVER.with(|slot| slot.set(None));
                let (page, area, bytes) = probe.observed.get().expect("production observation precedes dispatch");
                assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), Some(page));
                let pages = unsafe { Theap::final_statistics_at(probe.theap) }.unwrap().1.pages;
                assert_eq!(pages.current, probe.baseline.current + 1);
                assert_eq!(pages.total, probe.baseline.total + 1);
                let state = unsafe { Page::validity_snapshot_at(page) };
                assert_eq!(state.used, 0);
                assert_eq!(state.capacity, 0);
                assert!(state.free.is_null());
                assert_eq!(unsafe { area.as_ptr().read() }, 0x5a);
                // No Page/Heap/Theap reference or engine projection survives
                // these copied observations into the callback's native reentry.
                let NativePageAllocationResult::Allocated(nested) = runtime::native_allocate(96, false)
                    else { panic!("actual pending source assertion permits callback reentry"); };
                assert!(nested.addr().get() < area.addr().get() || nested.addr().get() >= area.addr().get() + bytes);
                assert_eq!(unsafe { runtime::native_free(nested) }, NativePageFreeResult::Freed);
                assert_eq!(unsafe { probe.map.lookup_registered_page(area.as_ptr()) }.unwrap(), Some(page));
                assert_eq!(unsafe { area.as_ptr().read() }, 0x5a);
                let marker = b"registered fresh backing retained during native reentry\n";
                assert_eq!(unsafe { write(2, marker.as_ptr(), marker.len()) }, marker.len() as isize);
            }
            assert_eq!(unsafe { write(2, message.as_ptr(), message.len()) }, message.len() as isize);
        }
        if std::env::var_os(CHILD).is_some() {
            with_fresh_assertion_owner(|owner| {
                let probe = NativeFreshProbe::new(&owner, true);
                let _guard = probe.install();
                // SAFETY: the actual preadmitted owner and scoped probe remain
                // live through production dispatch and its output callback.
                unsafe { owner.output().register_output(Some(output), core::ptr::from_ref(&probe).cast_mut().cast()) };
                let _ = crate::runtime_lifecycle::native_allocate_aligned(7, 128 * 1024, false);
                panic!("actual source zero assertion cannot return");
            });
        }
        use std::os::unix::process::ExitStatusExt;
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "page_validity::tests::native_fresh_os_zero_assertion_retains_registered_backing_during_reentry",
                "--nocapture", "--test-threads=1"])
            .current_dir(std::env::temp_dir()).env(CHILD, "1").output().unwrap();
        assert_eq!(result.status.signal(), Some(6), "{}", std::string::String::from_utf8_lossy(&result.stderr));
        assert_eq!(result.stderr, b"\nregistered fresh backing retained during native reentry\nmimalloc: assertion failed: at \"src/page.c\":729, _mi_page_init\n  assertion: \"mi_mem_is_zero(page_start, mi_page_committed(page))\"\n");
    }

    #[test]
    fn actual_page_local_lists_preserve_source_equation_after_pop_and_free() {
        with_page(|page, map| unsafe {
            // SAFETY: this fixture exclusively owns the ordinary fields and
            // has no remote producers throughout the complete observation.
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            let client = list.pop(false).unwrap().unwrap();
            list.push_local(client).unwrap();
            drop(list);
            let mut state = Page::validity_snapshot_at(page);
            assert_eq!(source_page_lists_valid(&state, map), Ok(()));
            state.used = 1;
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::FreeCount));
            state.used = 0;
            state.capacity = 7;
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::FreeCount));
            state.capacity = 8;
            state.used = 9;
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::UsedCapacity));
            state.used = 0;
            state.capacity = 9;
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::CapacityReserved));
            state.block_size = 0;
            let failure = source_page_lists_valid(&state, map).unwrap_err();
            assert_eq!(failure, SourcePageInvariant::BlockSize);
            std::println!("source_page_assertion={}", failure.assertion().unwrap().to_str().unwrap());
        });
    }

    #[test]
    fn source_containment_rejects_external_head_before_reading_its_link() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            drop(list);
            let mut state = Page::validity_snapshot_at(page);
            let mut outside = 0usize;
            let saved = state.free;
            state.free = core::ptr::from_mut(&mut outside).cast::<Block>();
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::FreeList));
            state.free = saved;
            state.local_free = core::ptr::from_mut(&mut outside).cast::<Block>();
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::LocalFreeList));
            state.local_free = core::ptr::null_mut();
            state.remote = core::ptr::from_mut(&mut outside).cast::<Block>();
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::RemoteFreeList));
        });
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn live_validity_observer_changes_only_one_copied_count_and_restores_scope() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            drop(list);
            let state = Page::validity_snapshot_at(page);
            let observed = core::cell::Cell::new(false);
            unsafe fn observe(state: &PageValiditySnapshot, argument: *mut core::ffi::c_void) -> Option<usize> {
                // SAFETY: the owning test retains this Cell through its
                // synchronous scope; the callback retains no reference.
                let observed = unsafe { &*argument.cast::<core::cell::Cell<bool>>() };
                if observed.replace(true) { None } else { Some(usize::from(state.capacity) + 1) }
            }
            with_live_page_validity_observer_for_test(observe,
                core::ptr::from_ref(&observed).cast_mut().cast(), || {
                    let failure = source_page_lists_valid(&state, map).unwrap_err();
                    assert_eq!(failure, SourcePageInvariant::UsedCapacity);
                    assert!(failure.into_live_page_validity_assertion().is_ok());
                    assert_eq!(source_page_lists_valid(&state, map), Ok(()));
                });
            assert!(observed.get());
            assert_eq!(Page::validity_snapshot_at(page).used, state.used);
            assert_eq!(source_page_lists_valid(&state, map), Ok(()));
        });
    }

    #[test]
    fn live_validity_descriptor_keeps_initialization_and_observation_failures_distinct() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            drop(list);
            let mut state = Page::validity_snapshot_at(page);
            state.used = 1;
            let failure = source_page_lists_valid(&state, map).unwrap_err();
            assert_eq!(failure, SourcePageInvariant::FreeCount);
            let descriptor = failure.into_live_page_validity_assertion().unwrap();
            assert_eq!(descriptor.invariant, failure);
            assert_eq!(descriptor.source_site(), (c"src/page.c", 117, c"mi_page_is_valid_init"));
            assert_eq!(SourcePageInvariant::InitiallyZero.into_live_page_validity_assertion(),
                Err(SourcePageInvariant::InitiallyZero));
            assert_eq!(SourcePageInvariant::ObservationGeometry.into_live_page_validity_assertion(),
                Err(SourcePageInvariant::ObservationGeometry));
        });
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-debug-3"))]
    #[test]
    fn copied_owner_and_queue_inputs_preserve_source_validity_disjunctions() {
        with_page(|page, map| unsafe {
            let state = Page::validity_snapshot_at(page);
            let owner = PageSourceOwnerSnapshot::observe_at(&state, true, Some(state.block_size));
            assert_eq!(source_page_is_valid(&state, map, &owner, true), Ok(()));
            let mut copied = owner;
            copied.heap_present = false;
            assert_eq!(source_page_is_valid(&state, map, &copied, false), Err(SourcePageInvariant::HeapNonNull));
            copied = owner;
            copied.heap_theap_absent = false;
            copied.heap_theap_matches = false;
            copied.page_theap_detached = false;
            assert_eq!(source_page_is_valid(&state, map, &copied, false), Err(SourcePageInvariant::HeapTheapBinding));
            copied.page_theap_detached = true;
            assert_eq!(source_page_is_valid(&state, map, &copied, false), Ok(()));
            copied.page_theap_detached = false;
            copied.heap_theap_matches = true;
            assert_eq!(source_page_is_valid(&state, map, &copied, false), Ok(()));
            copied.heap_theap_matches = false;
            copied.heap_theap_absent = true;
            assert_eq!(source_page_is_valid(&state, map, &copied, false), Ok(()));
            copied = owner;
            copied.queue_contains = false;
            assert_eq!(source_page_is_valid(&state, map, &copied, false), Ok(()));
            assert_eq!(source_page_is_valid(&state, map, &copied, true), Err(SourcePageInvariant::QueueContains));
            copied.abandoned = true;
            assert_eq!(source_page_is_valid(&state, map, &copied, true), Ok(()));
            copied = owner;
            copied.queue_block_size = Some(state.block_size + crate::config::WORD_SIZE);
            assert_eq!(source_page_is_valid(&state, map, &copied, true), Err(SourcePageInvariant::QueueBlockSize));
            copied.is_huge = true;
            assert_eq!(source_page_is_valid(&state, map, &copied, true), Ok(()));
            copied.is_huge = false;
            copied.in_full = true;
            assert_eq!(source_page_is_valid(&state, map, &copied, true), Ok(()));
            copied = owner;
            copied.secure_key = 0;
            let expected = if crate::config::SECURE_LEVEL == 0 { Ok(()) } else { Err(SourcePageInvariant::SecurePageKey) };
            assert_eq!(source_page_is_valid(&state, map, &copied, true), expected);
            // Only copied predicate inputs changed; the live Page, real
            // initialized owner and complete backing remain untouched.
            let restored = Page::validity_snapshot_at(page);
            assert_eq!(restored.heap, state.heap);
            assert_eq!(restored.theap, state.theap);
            assert_eq!(restored.keys, state.keys);
            assert_eq!(source_page_is_valid(&restored, map, &owner, true), Ok(()));
        });
    }

    #[test]
    fn fresh_initialization_dispatch_accepts_only_the_observed_zero_assertion() {
        with_page(|page, map| unsafe {
            let mut state = Page::validity_snapshot_at(page);
            state.area.as_ptr().write(0x5a);
            let failure = source_initial_page_is_zero(&state, 4096).err();
            assert_eq!(failure.map(SourcePageInvariant::into_fresh_initialization_assertion)
                .is_some_and(|result| result.is_ok()),
                crate::config::DEBUG_LEVEL > 2);

            // A real list-accounting failure belongs to its own source site,
            // even when observed in the same retained Page allocation.
            state.capacity = 1;
            let failure = source_page_lists_valid(&state, map).unwrap_err();
            assert_eq!(failure, SourcePageInvariant::FreeCount);
            assert_eq!(failure.into_fresh_initialization_assertion(), Err(failure));

            // The observation boundary can retain backing without providing
            // the source assertion needed by this terminal delivery site.
            assert_eq!(SourcePageInvariant::ObservationGeometry.into_fresh_initialization_assertion(),
                Err(SourcePageInvariant::ObservationGeometry));
        });
    }

    #[test]
    fn initially_zero_assertion_uses_source_expensive_debug_threshold() {
        with_page(|page, _map| unsafe {
            let state = Page::validity_snapshot_at(page);
            assert_eq!(state.used, 0);
            assert_eq!(state.capacity, 0);
            assert!(state.free.is_null());
            state.area.as_ptr().write(0x5a);
            let expected = if crate::config::DEBUG_LEVEL > 2 {
                Err(SourcePageInvariant::InitiallyZero)
            } else { Ok(()) };
            assert_eq!(source_initial_page_is_zero(&state, 4096), expected);
        });
    }

    #[test]
    fn initially_zero_assertion_uses_birth_flag_instead_of_local_free_zero() {
        with_page_zero_state(false, true, |page, _map| unsafe {
            let state = Page::validity_snapshot_at(page);
            assert!(!state.initially_zero);
            state.area.as_ptr().write(0x5a);
            assert_eq!(source_initial_page_is_zero(&state, 4096), Ok(()));
        });
    }

    #[test]
    fn initially_zero_checks_only_fresh_committed_region_before_list_initialization() {
        with_page(|page, _map| unsafe {
            // SAFETY: all area bytes are initialized and exclusively owned;
            // this observation precedes writing the first free-list link.
            let mut state = Page::validity_snapshot_at(page);
            assert_eq!(source_initial_page_is_zero(&state, 4096), Ok(()));
            state.area.as_ptr().add(255).write(1);
            let expected = if crate::config::DEBUG_LEVEL > 2 {
                Err(SourcePageInvariant::InitiallyZero)
            } else { Ok(()) };
            assert_eq!(source_initial_page_is_zero(&state, 4096), expected);
            state.initially_zero = false;
            assert_eq!(source_initial_page_is_zero(&state, 4096), Ok(()));
        });
    }

    struct OwnedRemoteClient(NonNull<u8>);
    // SAFETY: each wrapper transfers one distinct exclusively held
    // live client to the worker; the owner retains backing, and no
    // client pointer is accessed after the worker publishes its link.
    unsafe impl Send for OwnedRemoteClient {}
    impl OwnedRemoteClient {
        unsafe fn publish(self, producer: crate::types::PageRemoteFreeProducerState) {
            // SAFETY: the wrapper retains this exact exclusive client
            // until production publication transfers its ownership.
            unsafe { crate::remote_free::push(producer, self.0).unwrap(); }
        }
    }

    #[test]
    fn remote_blocks_remain_in_used_after_actual_producer_has_joined() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            let block = list.pop(false).unwrap().unwrap();
            drop(list);
            let producer = Page::remote_free_producer_state_at(page);
            // Keep only the producer's disjoint atomic projection and its
            // own allocated block while the worker publishes. Join provides
            // actual producer exclusion before any ordinary-field snapshot.
            let client = OwnedRemoteClient(block);
            std::thread::spawn(move || {
                client.publish(producer);
            }).join().unwrap();
            let state = Page::validity_snapshot_at(page);
            assert_eq!(state.used, 1);
            assert!(!state.remote.is_null());
            assert_eq!(source_page_lists_valid(&state, map), Ok(()));
        });
    }

    #[test]
    fn acquired_remote_chain_stays_valid_after_live_producer_prepends() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            let mut clients = std::vec::Vec::new();
            for _ in 0..8 { clients.push(list.pop(false).unwrap().unwrap()); }
            drop(list);
            let producer = Page::remote_free_producer_state_at(page);
            crate::remote_free::push(producer, clients.remove(0)).unwrap();
            let rendezvous = std::sync::Arc::new(std::sync::Barrier::new(2));
            let worker_barrier = rendezvous.clone();
            let clients: std::vec::Vec<_> = clients.into_iter().map(OwnedRemoteClient).collect();
            let worker = std::thread::spawn(move || {
                for client in clients {
                    worker_barrier.wait();
                    unsafe { client.publish(producer); }
                    worker_barrier.wait();
                }
            });
            for _ in 1..8 {
                let captured = Page::validity_snapshot_at(page);
                rendezvous.wait();
                rendezvous.wait();
                // The worker has published a new head and stays live. The
                // acquired old chain remains immutable; no collector can
                // detach or reuse it while the owner observes either head.
                assert_eq!(source_page_lists_valid(&captured, map), Ok(()));
                let extended = Page::validity_snapshot_at(page);
                assert_ne!(extended.remote, captured.remote);
                assert_eq!(extended.used, 8);
                assert_eq!(source_page_lists_valid(&extended, map), Ok(()));
            }
            worker.join().unwrap();
        });
    }

    #[test]
    fn page_start_must_resolve_through_the_retained_actual_map() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            drop(list);
            let state = Page::validity_snapshot_at(page);
            map.unregister_range(state.area.as_ptr(), ARENA_SLICE_SIZE).unwrap();
            assert_eq!(source_page_lists_valid(&state, map), Err(SourcePageInvariant::PageStartMapping));
            map.register_range(state.area.as_ptr(), ARENA_SLICE_SIZE, page).unwrap();
            assert_eq!(source_page_lists_valid(&state, map), Ok(()));
        });
    }

    #[test]
    fn initialized_client_bytes_are_not_scanned_by_level_three_list_validity() {
        with_page(|page, map| unsafe {
            let mut list = LocalFreeList::from_page_at(page).unwrap();
            list.extend_count(8).unwrap();
            let client = list.pop(false).unwrap().unwrap();
            core::ptr::write_bytes(client.as_ptr(), 0xa5, 32);
            drop(list);
            let state = Page::validity_snapshot_at(page);
            assert_eq!(source_page_lists_valid(&state, map), Ok(()));
        });
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    fn native_registered_regular_client(test_name: &'static str, block_size: usize, span: usize) {
        use crate::runtime_lifecycle::{self as runtime, NativePageAllocationResult, NativePageFreeResult};
        crate::test_process::run_in_fresh_process(
            test_name, || {
                unsafe extern "C" fn stderr(message: *const core::ffi::c_char) {
                    unsafe extern "C" {
                        fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void) -> core::ffi::c_int;
                        #[link_name = "stderr"] static mut STREAM: *mut core::ffi::c_void;
                    }
                    // SAFETY: the native process retains its stderr FILE;
                    // the source callback supplies a terminated fragment.
                    unsafe { let _ = fputs(message, STREAM); }
                }
                let output = unsafe { crate::diagnostic_output::RuntimeStderrOutput::new(stderr) };
                assert!(runtime::test_initialize_process_from_host_environment(4096, output));
                let request = block_size - crate::config::PADDING_SIZE;
                let block = match runtime::native_allocate(request, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    NativePageAllocationResult::Unavailable => panic!("regular client unavailable"),
                    NativePageAllocationResult::AllocationFailed => panic!("regular client allocation failed"),
                    NativePageAllocationResult::Retained => panic!("regular client retained"),
                };
                let selected = crate::compiler_tls::default_theap();
                // SAFETY: this actual client retains its Page, sole current
                // owner and PageMap; the observation ends before its free.
                unsafe { runtime::with_native_allocation_owner(selected, |owner| {
                    let map = owner.page_map().unwrap().page_map().unwrap();
                    let page = NonNull::new(map.checked_lookup(block.as_ptr())).unwrap();
                    let state = Page::validity_snapshot_at(page);
                    assert_eq!(state.block_size, block_size);
                    let os_page = crate::os::PageSize::new(4096).unwrap();
                    assert_eq!(state.reserved, crate::page::page_reserved_object_count(
                        span, crate::page::page_usable_start_offset(block_size).unwrap(),
                        state.block_size, os_page).unwrap());
                    if state.slice_pcommitted != 0 {
                        assert!(usize::from(state.slice_pcommitted) * os_page.bytes()
                            <= crate::page::page_noguard_size(span, os_page).unwrap());
                    }
                    assert_eq!(source_page_lists_valid(&state, map), Ok(()));
                }) }.unwrap();
                assert_eq!(unsafe { runtime::native_free(block) }, NativePageFreeResult::Freed);
                runtime::native_collect(true);
            },
        );
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_first_medium_client_has_registered_valid_lists() {
        native_registered_regular_client(
            "page_validity::tests::native_first_medium_client_has_registered_valid_lists",
            12_288, crate::config::MEDIUM_PAGE_SIZE);
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn native_small_client_reservation_excludes_the_source_protected_tail() {
        native_registered_regular_client(
            "page_validity::tests::native_small_client_reservation_excludes_the_source_protected_tail",
            256, crate::config::SMALL_PAGE_SIZE);
    }

    #[cfg(all(target_arch = "x86_64", feature = "mi-guarded", not(miri)))]
    #[test]
    fn native_sampled_clients_retain_valid_page_lists_through_legal_use() {
        use crate::runtime_lifecycle::{self as runtime, NativePageAllocationResult, NativePageFreeResult};
        crate::test_process::run_in_fresh_process(
            "page_validity::tests::native_sampled_clients_retain_valid_page_lists_through_legal_use", || {
                unsafe extern "C" fn stderr(message: *const core::ffi::c_char) {
                    unsafe extern "C" {
                        fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void) -> core::ffi::c_int;
                        #[link_name = "stderr"] static mut STREAM: *mut core::ffi::c_void;
                    }
                    // SAFETY: the pinned native process retains its stderr
                    // FILE and the source supplies a NUL-terminated fragment.
                    unsafe { let _ = fputs(message, STREAM); }
                }
                let output = unsafe { crate::diagnostic_output::RuntimeStderrOutput::new(stderr) };
                assert!(runtime::test_initialize_process_from_host_environment(4096, output));
                let NativePageAllocationResult::Allocated(seed) = runtime::native_allocate(32, false)
                    else { panic!("native owner seed"); };
                let selected = crate::compiler_tls::default_theap();
                // SAFETY: this isolated current owner has no concurrent sampler
                // access. The live seed retains its initialized selected Theap.
                unsafe {
                    Theap::guarded_set_sample_rate_at(selected, 1, 1);
                    Theap::guarded_set_size_bound_at(selected, 0, 100_000);
                }
                for request in [1, 81, 4096, 8193, 65_536] {
                    let block = crate::source_api::malloc(request).value
                        .unwrap_or_else(|| panic!("sampled source client for {request}"));
                    // SAFETY: this thread retains exact clients and the sole
                    // owner; no collector, producer, teardown or map mutation
                    // overlaps these short observations or client accesses.
                    unsafe { runtime::with_native_allocation_owner(selected, |owner| {
                        let root = owner.page_map().unwrap();
                        let allocation = root.lookup_live_allocation(block).unwrap().unwrap();
                        assert!(allocation.is_guarded());
                        assert!(allocation.guarded_tail_page(4096).is_some());
                        assert!(allocation.usable_size() >= request);
                        let state = Page::validity_snapshot_at(allocation.page());
                        assert_eq!(source_page_lists_valid(&state, root.page_map().unwrap()), Ok(()));
                        block.as_ptr().write_bytes(0x5a, request);
                        assert_eq!(source_page_lists_valid(&Page::validity_snapshot_at(allocation.page()),
                            root.page_map().unwrap()), Ok(()));
                    }) }.unwrap();
                    assert_eq!(unsafe { runtime::native_free(block) }, NativePageFreeResult::Freed);
                }
                assert_eq!(unsafe { runtime::native_free(seed) }, NativePageFreeResult::Freed);
                unsafe { runtime::native_collect(true); }
            },
        );
    }

    #[test]
    fn initialization_checks_committed_prefix_beyond_reserved_block_bytes() {
        with_page_initial_state(true, true, 1, |page, _map| unsafe {
            let state = Page::validity_snapshot_at(page);
            assert_eq!(state.slice_pcommitted, 1);
            assert_eq!(state.area_bytes, 256);
            assert_eq!(source_initial_page_is_zero(&state, 4096), Ok(()));
            state.area.as_ptr().add(256).write(1);
            let expected = if crate::config::DEBUG_LEVEL > 2 {
                Err(SourcePageInvariant::InitiallyZero)
            } else { Ok(()) };
            assert_eq!(source_initial_page_is_zero(&state, 4096), expected);
        });
    }
}
