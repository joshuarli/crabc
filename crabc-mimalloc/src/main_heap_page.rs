// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-360,377-421,448-481`,
// `src/theap.c:89-152`, `src/page.c:214-243`,
// `src/arena.c:674-723,781-821,951-1114,1240-1282`, and
// `src/page-map.c:228-365`.

//! Page-bearing later-thread attachment to the source static main Heap.
//!
//! The normal source `_mi_thread_init_with_heap(mi_heap_main())` branch gives
//! every later thread a metadata TLD/Theap but keeps the one process-static
//! main Heap. `MainHeapThreadProcessPageAllocator` joins that exact later
//! owner to the same frozen process PageMap/arena pair used by the bounded
//! ticket-zero page owner. It holds the pair's exclusive Rust PageMap
//! lifecycle lease for its complete engine and scoped remote-producer
//! lifetime, and uses the selected arena's in-place `pages_main` bitmap.
//!
//! This is deliberately one sequential later-thread page lifecycle, not
//! process initialization, concurrent PageMap routing, a dynamic heap-local
//! bitmap path, or pthread integration. In addition to its normal empty
//! finish, it owns one first source-shaped `_mi_thread_done` boundary: a
//! consuming exit drain clears the fixed main fast slot, force-collects every
//! queue, and releases only pages that become all-free before returning to
//! attachment root/list/TLD teardown. It does not abandon a remaining live
//! regular/full/unmapped/huge page, route later frees, or implement source
//! deferred callbacks or arena collection.

use core::ptr::NonNull;

use crate::arena::ArenaId;
use crate::main_heap_thread::{
    MainHeapThreadAttachment, MainHeapThreadAttachmentError, MainHeapThreadPageDrainSession,
    MainHeapThreadPageSession, MainHeapThreadPageSessionError,
};
use crate::process_arena::{ProcessPageArenaLease, ProcessPageArenaLeaseError};
use crate::process_page_map::{ProcessPageMapError, ProcessPageMapMutationLease};
use crate::single_thread::{
    FreeError, PageAllocatorEngine, RemoteFreePreparationError, RemoteFreeProducer,
};
#[cfg(test)]
use crate::types::Page;

#[cfg(test)]
extern crate std;

/// One bounded page engine for a later metadata Theap linked to `mi_heap_main`.
///
/// Field order is intentional: an unfinished drop first gives the generic
/// engine a chance to latch the later attachment terminal, then drops the
/// process PageMap lifecycle lease, which poisons rather than reopens a root
/// that may retain live entries or a producer relation.
#[must_use = "a later main-heap process page allocator must finish or retain its owner explicitly"]
pub(crate) struct MainHeapThreadProcessPageAllocator<'attachment, 'main> {
    engine: PageAllocatorEngine<'static, 'static, MainHeapThreadPageSession<'attachment, 'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// The post-fast-slot later-main owner that can only finish its all-free
/// source thread-exit drain. It retains the process-map mutation lease until
/// every page release is complete or the exact draining attachment is kept
/// terminally retained.
#[must_use = "a later main-heap thread-exit drain must finish or remain retained"]
pub(crate) struct MainHeapThreadProcessPageExitDrain<'attachment, 'main> {
    engine: PageAllocatorEngine<'static, 'static, MainHeapThreadPageDrainSession<'attachment, 'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// A pre-publication refusal while opening a later-thread process page owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainHeapThreadProcessPageAllocatorBeginError {
    Pair(ProcessPageArenaLeaseError),
    Attachment(MainHeapThreadAttachmentError),
    /// The metadata TLD/Theap attachment belongs to a different process-main
    /// image than the already paired PageMap and arena.
    SubprocessMismatch,
    /// The pair's frozen map/arena configuration differs from the metadata
    /// configuration that initialized this later TLD/Theap.
    ConfigurationMismatch,
    Session(MainHeapThreadPageSessionError),
    PageMap(ProcessPageMapError),
}

/// The outcomes while consuming a later-thread shared process page engine.
#[must_use = "a retained later-thread page allocator still owns live page state"]
pub(crate) enum MainHeapThreadProcessPageAllocatorFinishError<'attachment, 'main> {
    /// Pages, queues, a scoped producer, or a detached OS-release owner
    /// remain. The engine and process map mutation lease remain coupled for
    /// an explicit retry or terminal decision.
    Retained(MainHeapThreadProcessPageAllocator<'attachment, 'main>),
    /// The engine became empty but the process-private PageMap lease observed
    /// a post-Release wake failure. The map owner is terminally poisoned.
    PageMap(ProcessPageMapError),
}

/// A consuming transition that could not enter the post-fast-slot all-free
/// drain without retaining its original normal page engine.
#[must_use = "a failed later-main thread-exit transition retains its page allocator"]
pub(crate) enum MainHeapThreadProcessPageExitDrainFailure<'attachment, 'main> {
    Retained {
        allocator: MainHeapThreadProcessPageAllocator<'attachment, 'main>,
        error: MainHeapThreadAttachmentError,
    },
}

/// The outcomes while finishing the bounded all-free later-main exit drain.
#[must_use = "a retained later-main thread-exit drain still owns live source state"]
pub(crate) enum MainHeapThreadProcessPageExitDrainFinishError<'attachment, 'main> {
    /// A live page, failed force collection, or pending OS release remains.
    /// The attachment is already post-fast-slot, so only this retained drain
    /// may make a later source-complete owner-exit decision.
    Retained(MainHeapThreadProcessPageExitDrain<'attachment, 'main>),
    /// Every page drained, but PageMap lifecycle release observed a post-
    /// Release wake failure. The map owner is terminally poisoned while the
    /// attachment remains in its valid empty post-fast-slot state for explicit
    /// root/list/TLD teardown.
    PageMap(ProcessPageMapError),
}

impl<'attachment, 'main> MainHeapThreadProcessPageAllocator<'attachment, 'main> {
    /// Starts one source-shaped page lifecycle for a later main-heap thread.
    ///
    /// The exact PageMap/arena tuple and frozen configuration are checked
    /// before the later attachment is mutably borrowed as a page session. The
    /// resulting map mutation lease then excludes a second safe page engine
    /// from the source map's plain entry accesses until this engine and any
    /// scoped producer have become quiescent.
    pub(crate) fn begin(
        attachment: &'attachment mut MainHeapThreadAttachment<'main>,
        pair: ProcessPageArenaLease,
    ) -> Result<Self, MainHeapThreadProcessPageAllocatorBeginError> {
        let attachment_subprocess = attachment
            .subprocess()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Attachment)?;
        let process = pair
            .subprocess()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        if !core::ptr::eq(attachment_subprocess.as_ptr(), process.as_ptr()) {
            return Err(MainHeapThreadProcessPageAllocatorBeginError::SubprocessMismatch);
        }
        let attachment_config = attachment
            .memory_config()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Attachment)?;
        let pair_config = pair
            .memory_config()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        if attachment_config != pair_config {
            return Err(MainHeapThreadProcessPageAllocatorBeginError::ConfigurationMismatch);
        }
        let arena = pair
            .arena()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        let session = attachment
            .page_session()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Session)?;
        let page_map_lifecycle = pair
            .begin_page_lifecycle()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::Pair)?;
        let page_map = page_map_lifecycle
            .page_map()
            .map_err(MainHeapThreadProcessPageAllocatorBeginError::PageMap)?;
        // SAFETY: `pair` proved the exact process identity/root/configuration,
        // the retained mutation lease serializes the source map's plain
        // entries, and `session` keeps the current metadata Theap plus the
        // live static-main Heap lease alive for this complete engine.
        let engine = unsafe {
            PageAllocatorEngine::activate_later_main_thread(
                session,
                arena,
                ArenaId::none(),
                page_map,
            )
        };
        Ok(Self {
            engine,
            page_map_lifecycle,
        })
    }

    /// Allocates one ordinary block through the later-thread source page
    /// engine.
    #[inline]
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        self.engine.allocate(request, zero)
    }

    /// Frees one current allocation belonging to this exact later-thread
    /// owner.
    ///
    /// # Safety
    ///
    /// `block` must be one current allocation returned by this engine. It
    /// must not have been freed, transferred to a scoped producer, or used
    /// concurrently through another owner.
    #[inline]
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), FreeError> {
        unsafe { self.engine.free(block) }
    }

    /// Runs the bounded local retired-page collector after every scoped
    /// producer has joined.
    #[inline]
    pub(crate) fn collect_retired(&mut self, force: bool) -> bool {
        self.engine.collect_retired(force)
    }

    /// Prepares one joined scoped remote free for a live later-thread page.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation in this engine. The producer must
    /// publish or cancel before this owner resumes allocation, collection,
    /// finish, or drop.
    #[inline]
    pub(crate) unsafe fn begin_remote_free<'owner>(
        &'owner mut self,
        block: NonNull<u8>,
    ) -> Result<RemoteFreeProducer<'owner>, RemoteFreePreparationError> {
        unsafe { self.engine.begin_remote_free(block) }
    }

    /// Consumes the ordinary later-main allocator into its bounded source
    /// thread-exit page drain. On success the returned owner deliberately has
    /// no allocate/free/producer APIs: the fixed fast TLS slot is already
    /// clear, so it may only force-collect and release all-free pages before
    /// the attachment's final root/list/TLD teardown.
    pub(crate) fn begin_thread_exit_drain(
        self,
    ) -> Result<
        MainHeapThreadProcessPageExitDrain<'attachment, 'main>,
        MainHeapThreadProcessPageExitDrainFailure<'attachment, 'main>,
    > {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.begin_thread_exit_drain() {
            Ok(engine) => Ok(MainHeapThreadProcessPageExitDrain {
                engine,
                page_map_lifecycle,
            }),
            Err((engine, error)) => Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                allocator: Self {
                    engine,
                    page_map_lifecycle,
                },
                error,
            }),
        }
    }

    /// Finishes only after every page, queue, map entry, bitmap transition,
    /// and scoped producer is quiescent. The caller must then invoke the
    /// attachment's source-ordered user-destructor/teardown boundary.
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainHeapThreadProcessPageAllocatorFinishError<'attachment, 'main>> {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.finish() {
            Ok(()) => page_map_lifecycle
                .finish()
                .map_err(MainHeapThreadProcessPageAllocatorFinishError::PageMap),
            Err(engine) => Err(MainHeapThreadProcessPageAllocatorFinishError::Retained(Self {
                engine,
                page_map_lifecycle,
            })),
        }
    }

    #[cfg(test)]
    #[inline]
    unsafe fn test_page_for_block(&self, block: NonNull<u8>) -> *mut Page {
        unsafe { self.engine.page_for_block(block) }
    }
}

impl<'attachment, 'main> MainHeapThreadProcessPageExitDrain<'attachment, 'main> {
    /// Finishes the all-free half of source `_mi_theap_collect_abandon` and
    /// then releases the paired process PageMap lifecycle. A successful return
    /// leaves the borrowed attachment in `DrainingPages`; callers must finish
    /// its explicit root/list/TLD boundary with
    /// [`MainHeapThreadAttachment::finish_after_page_drain`].
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainHeapThreadProcessPageExitDrainFinishError<'attachment, 'main>> {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.finish_after_all_free_thread_exit() {
            Ok(()) => page_map_lifecycle
                .finish()
                .map_err(MainHeapThreadProcessPageExitDrainFinishError::PageMap),
            Err(engine) => Err(MainHeapThreadProcessPageExitDrainFinishError::Retained(Self {
                engine,
                page_map_lifecycle,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE, SMALL_MAX_OBJ_SIZE};
    use crate::main_heap_thread::{
        MainHeapThreadAttachment, MainHeapThreadAttachmentBeginError,
    };
    use crate::main_theap::{MainStaticAttachmentStorage, MainStaticTheapAttachment};
    use crate::meta::MetaAllocator;
    use crate::os::{MapAccess, Mapping, MemoryConfig, PageSize};
    use crate::process_arena::{ProcessSharedArenaLease, ProcessSharedArenaStorage};
    use crate::process_page_map::{ProcessPageMapLease, ProcessPageMapStorage};
    use crate::subproc::MainSubprocess;
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn paired_process_owner(
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> (ProcessPageMapLease, ProcessSharedArenaLease) {
        let page_map = ProcessPageMapStorage::test_static_owner()
            .initialize(config, subprocess)
            .expect("the isolated process map initializes");
        let mapping = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        )
        .expect("the test owns one complete source arena mapping");
        let arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(page_map, mapping)
        {
            Ok(arena) => arena,
            Err(_) => panic!("the selected mapping becomes the one process arena"),
        };
        (page_map, arena)
    }

    #[test]
    fn later_thread_page_engine_uses_the_static_main_heap_and_in_place_arena_bitmap() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let expected_heap = {
                let mut main = unsafe {
                    MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
                }
                .expect("ticket zero attaches the source-static main images");
                let expected = main.test_heap_pointer() as usize;
                let main_heap = main
                    .shared_main_heap_lease()
                    .expect("the live main attachment lends its static heap");

                thread::scope(|scope| {
                    let worker = scope.spawn(move || {
                        let arena = process_arena
                            .arena()
                            .expect("the process arena remains published for the worker lifecycle");
                        let mut owner = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap,
                                metadata,
                                config,
                            )
                        } {
                            Ok(owner) => owner,
                            Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                                panic!("later source thread attachment rejected: {error:?}")
                            }
                            Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                                panic!("later source thread attachment retained: {error:?}")
                            }
                        };
                        let expected_theap = owner.test_theap_pointer().expect("metadata Theap stays live");
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                            .expect("the matched process pair admits the later-thread page engine");
                        assert!(matches!(
                            page_map.begin_page_lifecycle(),
                            Err(ProcessPageMapError::LifecycleBusy)
                        ));
                        let block = allocator
                            .allocate(37, false)
                            .expect("the later thread allocates a source regular page");
                        let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                            .expect("the later block remains PageMap-published");
                        // SAFETY: the engine retains the map lease and this
                        // exact current allocation/page relation.
                        let memory = unsafe { page.as_ref().memid() };
                        let slice = memory
                            .arena_memory()
                            .expect("the later page uses the paired arena")
                            .slice_index as usize;
                        assert_eq!(unsafe { page.as_ref().heap() } as usize, expected);
                        assert_eq!(unsafe { page.as_ref().theap() }, expected_theap);
                        assert_eq!(
                            unsafe { arena.pages() }.unwrap().is_set_range(slice, 1),
                            Some(true),
                            "fresh later pages set the main Heap's embedded bitmap"
                        );
                        assert_eq!(
                            unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                            page.as_ptr(),
                            "the process map observes the fully initialized later page"
                        );
                        // SAFETY: `block` is still this exact engine's local allocation.
                        unsafe { allocator.free(block) }.expect("the local later free succeeds");
                        assert!(matches!(
                            allocator.finish(),
                            Ok(())
                        ), "all-free release clears the page engine");
                        owner
                            .finish_after_user_destructors()
                            .expect("the empty later source thread tears down after its page engine");
                    });
                    worker.join().expect("the later page owner remains current-thread local");
                });
                main.teardown()
                    .expect("the static main images retire after later page teardown");
                expected
            };
            assert_ne!(expected_heap, 0);
            let mutation = page_map
                .begin_page_lifecycle()
                .expect("the finished later engine releases the process map lease");
            mutation.finish().expect("the empty follow-on map lifetime releases");
        })
        .join()
        .expect("later main-heap page fixture remains current-thread local");
    }

    #[test]
    fn later_thread_rejects_a_foreign_process_pair_before_static_heap_or_map_mutation() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let foreign_subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (foreign_map, foreign_arena) = paired_process_owner(config, foreign_subprocess);
            let pair = ProcessPageArenaLease::join(foreign_map, foreign_arena)
                .expect("the foreign map and arena remain internally matched");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the independent main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    assert!(matches!(
                        MainHeapThreadProcessPageAllocator::begin(&mut owner, pair),
                        Err(MainHeapThreadProcessPageAllocatorBeginError::SubprocessMismatch)
                    ));
                    owner
                        .finish_after_user_destructors()
                        .expect("the foreign-pair rejection leaves the later owner no-page");
                });
                worker.join().expect("foreign pair check remains on the worker thread");
            });
            let mutation = foreign_map
                .begin_page_lifecycle()
                .expect("a foreign-pair refusal never takes or poisons its map lease");
            mutation.finish().expect("the untouched foreign map remains reusable");
            main.teardown()
                .expect("the foreign-pair refusal leaves the static main owner intact");
        })
        .join()
        .expect("foreign later-pair fixture remains current-thread local");
    }

    #[test]
    fn later_thread_scoped_remote_producer_is_collected_before_source_teardown() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let block = allocator.allocate(37, false).expect("the later page allocates");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                        .expect("the regular page remains mapped");
                    let capacity = unsafe { page.as_ref().capacity() as usize };
                    let mut local_blocks = std::vec::Vec::with_capacity(capacity);
                    local_blocks.push(block);
                    while unsafe { page.as_ref().used() } < capacity {
                        let next = allocator.allocate(37, false).expect("the direct page supplies capacity");
                        assert_eq!(unsafe { allocator.test_page_for_block(next) }, page.as_ptr());
                        local_blocks.push(next);
                    }
                    let producer = unsafe { allocator.begin_remote_free(block) }
                        .expect("the full regular later page admits its scoped producer");
                    thread::scope(|scope| {
                        let producer_thread = scope.spawn(move || producer.publish());
                        match producer_thread.join().expect("the scoped producer completes") {
                            Ok(()) => {}
                            Err((producer, _)) => {
                                let _ = producer.cancel();
                                panic!("the later remote producer must publish its exact page block");
                            }
                        }
                    });
                    let reused = allocator
                        .allocate(37, false)
                        .expect("the normal later scan false-collects the joined remote block");
                    assert_eq!(reused, block);
                    // SAFETY: collection returned this same remote block to local ownership.
                    unsafe { allocator.free(reused) }.expect("the reused remote block frees locally");
                    for local in local_blocks.into_iter().skip(1) {
                        // SAFETY: each sibling was never transferred and remains local.
                        unsafe { allocator.free(local) }.expect("the later sibling frees locally");
                    }
                    assert!(matches!(
                        allocator.finish(),
                        Ok(())
                    ), "all pages drain before user-destructor teardown");
                    owner
                        .finish_after_user_destructors()
                        .expect("the later owner tears down only after its producer joined");
                });
                worker.join().expect("later producer fixture remains scoped to its owner thread");
            });
            main.teardown()
                .expect("the static main owner waits for the later producer lifecycle");
        })
        .join()
        .expect("later remote-producer fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_force_collects_joined_remote_full_page_before_teardown() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let mut main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena stays published through thread exit");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits one later page engine");
                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the later thread allocates one regular page");
                    let page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the regular page stays PageMap-published");
                    let memory = unsafe { page.as_ref().memid() };
                    let slice = memory
                        .arena_memory()
                        .expect("the full page belongs to the paired arena")
                        .slice_index as usize;
                    let capacity = unsafe { page.as_ref().reserved() as usize };
                    assert!(capacity > 1, "the owner-exit page must have a remote-free route");
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the source page reaches its full queue");
                        assert_eq!(unsafe { allocator.test_page_for_block(block) }, page.as_ptr());
                        blocks.push(block);
                    }

                    // Keep every client free in the joined remote head. Normal
                    // collection is deliberately skipped: source thread exit
                    // must clear the fast slot and take `_mi_page_free_collect`
                    // with `force == true` before it can prove this page empty.
                    for block in blocks {
                        let producer = unsafe { allocator.begin_remote_free(block) }
                            .expect("the full later page admits each scoped remote free");
                        thread::scope(|scope| {
                            let worker = scope.spawn(move || producer.publish());
                            match worker.join().expect("the remote producer completes") {
                                Ok(()) => {}
                                Err((producer, error)) => {
                                    let _ = producer.cancel();
                                    panic!("the remote free publishes before thread exit: {error:?}");
                                }
                            }
                        });
                    }
                    assert_eq!(unsafe { page.as_ref().used() }, capacity);

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    assert!(matches!(drain.finish(), Ok(())));
                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "forced owner-exit collection unregisters the full PageMap span"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                        Some(true),
                        "all-free owner exit clears the shared main bitmap before slice release"
                    );
                    owner
                        .finish_after_page_drain()
                        .expect("the now-empty later owner completes source root/list/TLD teardown");
                });
                worker.join().expect("later owner-exit fixture remains current-thread local");
            });

            main.teardown()
                .expect("the static main owner retires after the page-bearing later exit");
        })
        .join()
        .expect("later owner-exit fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_collects_later_full_pages_before_retaining_an_earlier_live_page() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let arena = process_arena
                        .arena()
                        .expect("the paired arena stays published through thread exit");
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the owner-exit boundary");

                    let live = allocator
                        .allocate(16, false)
                        .expect("the fixture creates an earlier live small page");
                    let live_page = NonNull::new(unsafe { allocator.test_page_for_block(live) })
                        .expect("the small page stays PageMap-published");

                    let request = SMALL_MAX_OBJ_SIZE + 1;
                    let first = allocator
                        .allocate(request, false)
                        .expect("the fixture creates a later regular page");
                    let full_page = NonNull::new(unsafe { allocator.test_page_for_block(first) })
                        .expect("the later regular page stays PageMap-published");
                    assert_ne!(live_page, full_page);
                    let full_memory = unsafe { full_page.as_ref().memid() };
                    let full_slice = full_memory
                        .arena_memory()
                        .expect("the full page belongs to the paired arena")
                        .slice_index as usize;
                    let capacity = unsafe { full_page.as_ref().reserved() as usize };
                    assert!(capacity > 1, "the later page must reach the full queue");
                    let mut blocks = std::vec::Vec::with_capacity(capacity);
                    blocks.push(first);
                    while blocks.len() < capacity {
                        let block = allocator
                            .allocate(request, false)
                            .expect("the later regular page reaches its full queue");
                        assert_eq!(
                            unsafe { allocator.test_page_for_block(block) },
                            full_page.as_ptr()
                        );
                        blocks.push(block);
                    }
                    for block in blocks {
                        let producer = unsafe { allocator.begin_remote_free(block) }
                            .expect("the later full page admits each scoped remote free");
                        thread::scope(|scope| {
                            let worker = scope.spawn(move || producer.publish());
                            match worker.join().expect("the remote producer completes") {
                                Ok(()) => {}
                                Err((producer, error)) => {
                                    let _ = producer.cancel();
                                    panic!("the remote free publishes before thread exit: {error:?}");
                                }
                            }
                        });
                    }

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("thread exit clears the main fast slot before page collection: {error:?}");
                        }
                    };
                    let retained = match drain.finish() {
                        Err(MainHeapThreadProcessPageExitDrainFinishError::Retained(drain)) => {
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitDrainFinishError::PageMap(error)) => {
                            panic!("a retained live page cannot finish the PageMap lifecycle: {error:?}")
                        }
                        Ok(()) => panic!("the earlier live page must retain the thread-exit drain"),
                    };

                    assert!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(first.as_ptr()) }.is_null(),
                        "the drain force-collects and releases a later full page before retaining"
                    );
                    assert_eq!(
                        unsafe { arena.pages() }.unwrap().is_clear_range(full_slice, 1),
                        Some(true),
                        "the later all-free page clears the shared main bitmap before retention"
                    );
                    assert_eq!(
                        unsafe { page_map.page_map().unwrap().checked_lookup(live.as_ptr()) },
                        live_page.as_ptr(),
                        "the earlier live page remains registered for a future general abandonment route"
                    );

                    drop(retained);
                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "a retained post-fast-slot drain cannot imitate root/list/TLD teardown"
                    );
                    core::mem::forget(owner);
                });
                worker.join().expect("mixed owner-exit fixture remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("mixed owner-exit fixture remains current-thread local");
    }

    #[test]
    fn later_thread_exit_retains_a_nonempty_page_after_the_fast_slot_is_clear() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the owner-exit boundary");
                    let block = allocator
                        .allocate(SMALL_MAX_OBJ_SIZE + 1, false)
                        .expect("the fixture creates one still-live regular page");
                    let page = unsafe { allocator.test_page_for_block(block) };

                    let drain = match allocator.begin_thread_exit_drain() {
                        Ok(drain) => drain,
                        Err(MainHeapThreadProcessPageExitDrainFailure::Retained {
                            allocator,
                            error,
                        }) => {
                            core::mem::forget(allocator);
                            panic!("the attached owner must clear its fast slot before traversal: {error:?}");
                        }
                    };
                    let retained = match drain.finish() {
                        Err(MainHeapThreadProcessPageExitDrainFinishError::Retained(drain)) => {
                            drain
                        }
                        Err(MainHeapThreadProcessPageExitDrainFinishError::PageMap(error)) => {
                            panic!("a live page cannot reach PageMap release: {error:?}")
                        }
                        Ok(()) => panic!("the bounded all-free drain must not release a live page"),
                    };
                    drop(retained);

                    assert_eq!(
                        owner.finish_after_page_drain(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping a retained post-fast-slot drain cannot imitate list/TLD teardown"
                    );
                    assert!(matches!(
                        page_map.begin_page_lifecycle(),
                        Err(ProcessPageMapError::Poisoned)
                    ));
                    assert_eq!(
                        unsafe {
                            page_map
                                .test_retained_page_map()
                                .expect("the terminal root retains its process map image")
                                .checked_lookup(block.as_ptr())
                        },
                        page,
                        "the retained drain leaves the live PageMap registration intact"
                    );
                    // The source-complete abandonment path is intentionally
                    // absent; keep this isolated live owner terminal.
                    core::mem::forget(owner);
                });
                worker.join().expect("nonempty owner-exit fixture remains current-thread local");
            });
            core::mem::forget(main);
        })
        .join()
        .expect("nonempty owner-exit fixture remains current-thread local");
    }

    #[test]
    fn unfinished_later_page_engine_poison_retains_the_attachment_and_process_map() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected process owners match");
            let main = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("ticket zero attaches the source-static main images");
            let main_heap = main.shared_main_heap_lease().unwrap();

            thread::scope(|scope| {
                let worker = scope.spawn(move || {
                    let mut owner = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(owner) => owner,
                        Err(MainHeapThreadAttachmentBeginError::Rejected(error)) => {
                            panic!("later source thread attachment rejected: {error:?}")
                        }
                        Err(MainHeapThreadAttachmentBeginError::Retained { error, .. }) => {
                            panic!("later source thread attachment retained: {error:?}")
                        }
                    };
                    let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut owner, pair)
                        .expect("the matched process pair admits the retained-page fixture");
                    let block = allocator.allocate(37, false).expect("the fixture creates one live page");
                    let page = unsafe { allocator.test_page_for_block(block) };
                    drop(allocator);
                    assert_eq!(
                        owner.finish_after_user_destructors(),
                        Err(MainHeapThreadAttachmentError::Poisoned),
                        "dropping a live later page engine cannot imitate source thread teardown"
                    );
                    assert!(matches!(
                        page_map.begin_page_lifecycle(),
                        Err(ProcessPageMapError::Poisoned)
                    ));
                    assert_eq!(
                        unsafe {
                            page_map
                                .test_retained_page_map()
                                .expect("the terminal process root retains its map image")
                                .checked_lookup(block.as_ptr())
                        },
                        page,
                        "the terminal map retains the live later page registration"
                    );
                    core::mem::forget(owner);
                });
                worker.join().expect("retained later page fixture remains current-thread local");
            });
            // The static main Heap still contains the retained later Theap,
            // so no bounded source teardown exists for this intentionally
            // terminal test image.
            core::mem::forget(main);
        })
        .join()
        .expect("unfinished later page fixture remains current-thread local");
    }
}
