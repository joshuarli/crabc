// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:181-224,305-360`,
// `src/page-map.c:228-365`, and `src/arena.c:674-723,781-821,951-1114,
// 1240-1282`.

//! Page-bearing binding of the static main Theap to one process-owned arena.
//!
//! This module holds the first bounded page allocator which pairs the
//! already-published process PageMap with a caller-managed process arena and
//! borrows the ticket-zero static owner. It deliberately does not reserve an
//! arena, implement general process initialization, attach later threads, or
//! introduce pthread/TLS hooks.

use core::ptr::NonNull;

use crate::arena::ArenaId;
use crate::main_theap::{
    MainStaticPageSessionError, MainStaticTheapAttachment,
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

/// The one bounded main-thread allocator over a matched process map/arena.
///
/// Field order is intentional: if this owner is dropped unfinished, the page
/// engine first poisons the borrowed static attachment and then the process
/// map mutation lease poisons its root before releasing the private lock. A
/// successful [`Self::finish`] is the only path that leaves either owner ready
/// for a later bounded session.
#[must_use = "a main-static process page allocator must finish or retain its owner explicitly"]
pub(crate) struct MainStaticProcessPageAllocator<'main> {
    engine: PageAllocatorEngine<'static, 'static, crate::main_theap::MainStaticPageSession<'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// A pre-publication refusal while opening the bounded static page allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticProcessPageAllocatorBeginError {
    Pair(ProcessPageArenaLeaseError),
    /// The static ticket-zero attachment belongs to another process image.
    /// This is checked before it is borrowed as a page session or the PageMap
    /// lifecycle lock is acquired.
    SubprocessMismatch,
    Session(MainStaticPageSessionError),
    PageMap(ProcessPageMapError),
}

/// The only failure outcomes while consuming a bounded static page engine.
#[must_use = "a retained main-static page allocator still owns live page state"]
pub(crate) enum MainStaticProcessPageAllocatorFinishError<'main> {
    /// One page, queue, producer, or OS-release owner remains live. The exact
    /// engine and its PageMap mutation lease remain together for retry or a
    /// terminal owner decision.
    Retained(MainStaticProcessPageAllocator<'main>),
    /// The engine reached an empty source state, but releasing the private
    /// PageMap lifecycle lock reported a post-Release wake failure. The map
    /// owner is terminally poisoned; no engine state remains to retry.
    PageMap(ProcessPageMapError),
}

impl<'main> MainStaticProcessPageAllocator<'main> {
    /// Starts one source-shaped page lifecycle for the ticket-zero attachment.
    ///
    /// The paired lease proves a common root/configuration/subprocess before
    /// this function touches either static image. The map mutation lease then
    /// serializes every ordinary PageMap entry operation for the complete
    /// engine and any joined scoped remote producer lifetime.
    pub(crate) fn begin(
        attachment: &'main mut MainStaticTheapAttachment,
        pair: ProcessPageArenaLease,
    ) -> Result<Self, MainStaticProcessPageAllocatorBeginError> {
        let process = pair
            .subprocess()
            .map_err(MainStaticProcessPageAllocatorBeginError::Pair)?;
        if !attachment
            .subprocess()
            .map_or(false, |attachment_process| core::ptr::eq(attachment_process.as_ptr(), process.as_ptr()))
        {
            return Err(MainStaticProcessPageAllocatorBeginError::SubprocessMismatch);
        }
        let arena = pair
            .arena()
            .map_err(MainStaticProcessPageAllocatorBeginError::Pair)?;
        let session = attachment
            .page_session()
            .map_err(MainStaticProcessPageAllocatorBeginError::Session)?;
        let page_map_lifecycle = pair
            .begin_page_lifecycle()
            .map_err(MainStaticProcessPageAllocatorBeginError::Pair)?;
        let page_map = page_map_lifecycle
            .page_map()
            .map_err(MainStaticProcessPageAllocatorBeginError::PageMap)?;
        // SAFETY: `pair` validated the exact map/arena/process identity and
        // `page_map_lifecycle` remains stored beside the engine until finish
        // or terminal Drop. `session` is the uniquely borrowed ticket-zero
        // static owner for the same complete lifetime.
        let engine = unsafe {
            PageAllocatorEngine::activate_main_static(session, arena, ArenaId::none(), page_map)
        };
        Ok(Self {
            engine,
            page_map_lifecycle,
        })
    }

    /// Allocates one ordinary main-static block through the source page engine.
    #[inline]
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        self.engine.allocate(request, zero)
    }

    /// Frees one current main-static allocation.
    ///
    /// # Safety
    ///
    /// `block` must be one current allocation returned by this exact owner;
    /// it must not be freed, handed to a scoped remote producer, or accessed
    /// concurrently through another path.
    #[inline]
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), FreeError> {
        unsafe { self.engine.free(block) }
    }

    /// Runs the bounded local retired-page collector after any scoped remote
    /// producer has joined.
    #[inline]
    pub(crate) fn collect_retired(&mut self, force: bool) -> bool {
        self.engine.collect_retired(force)
    }

    /// Prepares one joined scoped remote free for a live regular or full page.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation in this engine. The returned
    /// producer must publish or cancel before this owner resumes allocation,
    /// collection, finish, or drop.
    #[inline]
    pub(crate) unsafe fn begin_remote_free<'owner>(
        &'owner mut self,
        block: NonNull<u8>,
    ) -> Result<RemoteFreeProducer<'owner>, RemoteFreePreparationError> {
        unsafe { self.engine.begin_remote_free(block) }
    }

    /// Finishes only after every source page/queue/map/arena transition is
    /// empty, then releases the process map mutation lifetime.
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainStaticProcessPageAllocatorFinishError<'main>> {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.finish() {
            Ok(()) => page_map_lifecycle
                .finish()
                .map_err(MainStaticProcessPageAllocatorFinishError::PageMap),
            Err(engine) => Err(MainStaticProcessPageAllocatorFinishError::Retained(Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
    use crate::main_theap::{MainStaticAttachmentStorage, MainStaticTheapAttachment};
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
    fn main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let arena = process_arena.arena().expect("the process arena remains published");
            let arena_index = arena.arena().arena_index;
            let expected_pages = NonNull::from(&arena.arena().pages_main);
            let expected_arena = core::ptr::from_ref(arena.arena()).cast_mut();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the ticket-zero static owner attaches before its page session");
            let expected_heap = owner.test_heap_pointer();
            let expected_theap = owner.test_theap_pointer();

            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit one static page engine");
            assert!(matches!(
                page_map.begin_page_lifecycle(),
                Err(ProcessPageMapError::LifecycleBusy)
            ), "the live engine owns the process map's sole plain-entry lifecycle");
            let block = allocator
                .allocate(37, false)
                .expect("a fresh static-main page allocates from the process arena");
            let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                .expect("the fresh block is PageMap-published");
            // SAFETY: the allocator holds the process map mutation lease and
            // the block/page remain live until the matching local free below.
            let memory = unsafe { page.as_ref().memid() };
            let slice = memory
                .arena_memory()
                .expect("the static page uses the paired arena")
                .slice_index as usize;
            assert_eq!(unsafe { page.as_ref().heap() }, expected_heap);
            assert_eq!(unsafe { page.as_ref().theap() }, expected_theap);
            assert_eq!(
                memory.arena_memory().unwrap().arena,
                expected_arena,
                "fresh page provenance stays in the paired process arena"
            );
            assert_eq!(
                unsafe { arena.pages() }.unwrap().is_set_range(slice, 1),
                Some(true),
                "the embedded main bitmap transitions before PageMap publication"
            );
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                page.as_ptr(),
                "the completed fresh page is visible through the release-published process root"
            );

            // SAFETY: `block` is the one current allocation owned by this
            // exact static page engine.
            unsafe { allocator.free(block) }.expect("the local static free succeeds");
            assert!(matches!(
                allocator.finish(),
                Ok(())
            ), "all-free collection unregisters the map and clears the main bitmap");
            let mutation = page_map
                .begin_page_lifecycle()
                .expect("a completed engine releases the map lifecycle boundary");
            mutation
                .finish()
                .expect("an empty follow-on lifecycle releases cleanly");

            let (heap, _) = owner.test_images();
            assert_eq!(heap.arena_pages_at(arena_index), Some(expected_pages));
            assert_eq!(
                unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                Some(true),
                "release clears the exact embedded main bitmap after PageMap unregistration"
            );
            assert!(
                unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) }.is_null(),
                "the release path removes the full PageMap span before teardown"
            );
            assert!(
                arena
                    .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                    .is_some_and(|claim| claim.release()),
                "the all-free static page returns its source arena slice"
            );
            owner
                .teardown()
                .expect("the empty static page owner tears down after page lifecycle completion");
        })
        .join()
        .expect("static page fixture remains current-thread local");
    }

    #[test]
    fn foreign_process_page_pair_rejects_before_static_heap_map_or_arena_mutation() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let static_subprocess = MainSubprocess::test_static_owner();
            let foreign_subprocess = MainSubprocess::test_static_owner();
            let (foreign_map, foreign_process_arena) =
                paired_process_owner(config, foreign_subprocess);
            let pair = ProcessPageArenaLease::join(foreign_map, foreign_process_arena)
                .expect("the foreign map and arena remain internally matched");
            let arena = foreign_process_arena
                .arena()
                .expect("the foreign arena is registry-published");
            let arena_index = arena.arena().arena_index;
            let map_base = arena.slice_start(0).expect("arena has an address-stable first slice");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, static_subprocess)
            }
            .expect("the independent static owner attaches");

            assert!(matches!(
                MainStaticProcessPageAllocator::begin(&mut owner, pair),
                Err(MainStaticProcessPageAllocatorBeginError::SubprocessMismatch)
            ));
            let (heap, theap) = owner.test_images();
            assert!(heap.arena_pages_at(arena_index).is_none());
            assert_eq!(theap.page_count(), 0);
            assert_eq!(
                unsafe { foreign_map.page_map().unwrap().checked_lookup(map_base) },
                core::ptr::null_mut(),
                "the foreign root receives no page publication"
            );
            assert_eq!(
                unsafe { arena.pages() }.unwrap().is_clear_range(0, arena.arena().slice_count),
                Some(true),
                "the foreign arena bitmap remains untouched"
            );
            let mutation = foreign_map
                .begin_page_lifecycle()
                .expect("mismatch never acquires or poisons the foreign map lifecycle");
            mutation.finish().expect("foreign map remains reusable");
            owner
                .teardown()
                .expect("a pre-mutation rejection leaves the static owner intact");
        })
        .join()
        .expect("foreign-pair rejection remains current-thread local");
    }

    #[test]
    fn preexisting_main_arena_bit_rolls_back_the_static_fresh_claim_without_map_publication() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let arena = process_arena.arena().expect("the process arena remains published");
            let probe = arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                .expect("one ordinary arena slice is available for the injected bitmap state");
            let slice = probe.slice_index();
            let slice_start = probe.start();
            assert!(probe.release());
            assert!(unsafe { arena.pages() }
                .and_then(|pages| pages.set_range(slice, 1))
                .is_some_and(|transition| transition.all_transitioned()));

            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the static owner attaches before its failed fresh-page attempt");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit the static page engine");
            assert!(allocator.allocate(37, false).is_none());
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(slice_start) },
                core::ptr::null_mut(),
                "a duplicate main bitmap bit rejects before PageMap registration"
            );
            assert!(matches!(allocator.finish(), Ok(())));
            assert_eq!(
                unsafe { arena.pages() }.unwrap().clear_range(slice, 1),
                Some(true),
                "the test removes only its preexisting invalid bitmap bit"
            );
            let reclaimed = arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                .expect("the failed static fresh claim returned its exact arena slice");
            assert_eq!(reclaimed.slice_index(), slice);
            assert!(reclaimed.release());
            owner
                .teardown()
                .expect("the failed fresh path leaves no static page state");
        })
        .join()
        .expect("main-bitmap rollback fixture remains current-thread local");
    }

    #[test]
    fn joined_remote_producer_is_collected_by_the_static_main_page_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the static owner attaches before its producer lifecycle");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit the static page engine");
            let block = allocator
                .allocate(37, false)
                .expect("the static owner has one regular source page");
            let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                .expect("the regular static block remains PageMap-published");
            let capacity = unsafe { page.as_ref().capacity() as usize };
            let mut local_blocks = std::vec::Vec::with_capacity(capacity);
            local_blocks.push(block);
            while unsafe { page.as_ref().used() } < capacity {
                let next = allocator
                    .allocate(37, false)
                    .expect("the current static direct page supplies its initialized capacity");
                assert_eq!(unsafe { allocator.test_page_for_block(next) }, page.as_ptr());
                local_blocks.push(next);
            }
            assert!(capacity < unsafe { page.as_ref().reserved() as usize });
            let producer = unsafe { allocator.begin_remote_free(block) }
                .expect("the active static regular page admits its bounded producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined.join().expect("the scoped producer remains live") {
                    Ok(()) => {}
                    Err((producer, _)) => {
                        let _ = producer.cancel();
                        panic!("the static remote producer must publish its exact live block");
                    }
                }
            });
            let reused = allocator
                .allocate(37, false)
                .expect("the regular source scan false-collects the joined remote block");
            assert_eq!(reused, block);
            // SAFETY: owner collection returned this exact remote block to
            // local static ownership once.
            unsafe { allocator.free(reused) }.expect("the reused static block frees");
            for local in local_blocks.into_iter().skip(1) {
                // SAFETY: sibling allocations were never transferred and
                // remain exact current blocks from the same static page.
                unsafe { allocator.free(local) }.expect("the static sibling frees");
            }
            assert!(matches!(allocator.finish(), Ok(())));
            owner
                .teardown()
                .expect("the joined producer leaves no static page owner behind");
        })
        .join()
        .expect("static remote-producer fixture remains current-thread local");
    }

    #[test]
    fn unfinished_static_page_engine_poison_retains_the_page_and_process_map_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the static owner attaches before its retained-page fixture");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit the static page engine");
            let block = allocator
                .allocate(37, false)
                .expect("the retained fixture creates one live static page");
            let page = unsafe { allocator.test_page_for_block(block) };
            drop(allocator);

            assert_eq!(
                owner.teardown(),
                Err(crate::main_theap::MainStaticTheapError::Poisoned),
                "dropping unfinished page state cannot imitate static thread teardown"
            );
            assert!(matches!(
                page_map.begin_page_lifecycle(),
                Err(ProcessPageMapError::Poisoned)
            ), "the PageMap root remains terminal instead of admitting another plain-entry owner");
            assert_eq!(
                unsafe {
                    page_map
                        .test_retained_page_map()
                        .expect("the terminal root still retains its final PageMap slot")
                        .checked_lookup(block.as_ptr())
                },
                page,
                "the retained terminal owner preserves the live PageMap registration"
            );
            // This intentionally leaves the isolated process image retained.
            // No bounded cleanup path can release a page after its engine was
            // discarded, so a test must not forge one merely to reclaim its
            // leaked fixture backing.
            core::mem::forget(owner);
        })
        .join()
        .expect("unfinished static page fixture remains current-thread local");
    }
}
