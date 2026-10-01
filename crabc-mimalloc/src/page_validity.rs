// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:43-148,724-729`
// (page-list containment, owner-list accounting, and the fresh committed
// area's initially-zero check). Queue and Heap/Theap membership validation
// remains at the caller's separately locked lifecycle boundary.

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

impl SourcePageInvariant {
    /// The exact C expression, for later delivery after observations end.
    /// A Rust observation-boundary failure has no invented source assertion.
    pub(crate) const fn assertion(self) -> Option<&'static CStr> {
        Some(match self {
            // The accessor asserts this field before the outer initialization
            // predicate can evaluate its returned block size.
            Self::BlockSize => c"page->block_size > 0",
            Self::UsedCapacity => c"page->used <= page->capacity",
            Self::CapacityReserved => c"page->capacity <= page->reserved",
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

/// Checks the source scalar/list assertions without taking ownership or
/// invoking diagnostic callbacks. Remote blocks remain included in `used`.
///
/// # Safety
/// The snapshot's live metadata and complete block backing must remain
/// retained. The caller excludes ordinary owner mutation and every remote
/// producer/collector for this entire operation, not merely the head load.
/// Each contained list node has an initialized readable link word. The map
/// stays active and no overlapping registration changes during the reads.
/// These obligations provide observation permission, never release rights.
pub(crate) unsafe fn source_page_lists_valid(
    state: &PageValiditySnapshot,
    map: &PageMap,
) -> Result<(), SourcePageInvariant> {
    if state.block_size == 0 { return Err(SourcePageInvariant::BlockSize); }
    if state.used > usize::from(state.capacity) { return Err(SourcePageInvariant::UsedCapacity); }
    if state.capacity > state.reserved { return Err(SourcePageInvariant::CapacityReserved); }
    // SAFETY: the caller supplies stable backing and initialized list links
    // with all producers excluded; each walk checks containment before read.
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
        // excludes every producer that could rewrite this word.
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
/// Above debug level two, the caller exclusively retains the actual fresh committed region from
/// `area`, with every byte initialized and readable. For on-demand pages the
/// actual OS page size and source committed-prefix count describe that same
/// region, which can extend beyond `reserved * block_size`. No concurrent
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
            let address = block.as_ptr().expose_provenance();
            std::thread::spawn(move || {
                let block = NonNull::new(core::ptr::with_exposed_provenance_mut(address)).unwrap();
                crate::remote_free::push(producer, block).unwrap();
            }).join().unwrap();
            let state = Page::validity_snapshot_at(page);
            assert_eq!(state.used, 1);
            assert!(!state.remote.is_null());
            assert_eq!(source_page_lists_valid(&state, map), Ok(()));
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
