// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0
// - `src/heap.c:149-157` (`mi_heap_new_in_arena`, `mi_heap_new`) and
//   `src/heap.c:228-261` (`mi_heap_delete`, `mi_heap_destroy`);
// - `src/subproc.c:113-115` (`mi_heap_main`);
// - `src/alloc.c:213-304,357-360` (`mi_heap_malloc_small`, `mi_heap_malloc`,
//   `mi_heap_zalloc_small`, `mi_heap_zalloc`, `mi_heap_calloc`,
//   `mi_heap_mallocn`) and `src/alloc-aligned.c:318-340` (the
//   `mi_heap_*_aligned[_at]` allocation entries);
// - `src/arena.c:1886-1922` (`mi_reserve_os_memory_ex2`,
//   `mi_reserve_os_memory_ex`, `mi_reserve_os_memory`).

//! Pinned mimalloc first-class Heap and OS-reservation public entries over
//! the native runtime.
//!
//! Each function is the source entry of the same `mi_` name. A Heap is the
//! source `mi_heap_t*`, passed as an opaque pointer. A calling thread of the
//! process main subprocess uses `subproc::main_heaps`; a thread admitted to a
//! child subprocess uses that child's Heap lifecycle. As in [`crate::source_api`], each
//! allocation reports the errno effect of its source path as data.
//!
//! Not provided: an exclusive-arena Heap (`mi_heap_new_in_arena` with an
//! arena), reservation from a thread of a child subprocess (refused with
//! `ENOMEM`), and the `_mi_verbose_message` reservation reports.

use core::ffi::{c_int, c_void};
use core::ptr::{null_mut, NonNull};

use crabc_core::Errno;

use crate::diagnostic_output::{SourceErrorReport, SourceFormattedMessage};
use crate::source_api::{Block, SourceErrno, Sourced};
use crate::subproc::main_heaps;
use crate::subproc::MainSubprocess;
use crate::types::heap_registry::lifecycle::HeapReleaseOutcome;
use crate::types::{Heap, Page};

/// `mi_heap_main()`: the calling thread's subprocess main Heap.
pub fn heap_main() -> *mut c_void {
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return crate::subproc::lifecycle::current_child_main_heap().map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    MainSubprocess::global().ready_main_heap_pointer().cast()
}

/// `mi_heap_new()`: null when the Heap cannot be created.
pub fn heap_new() -> *mut c_void {
    if let Some(created) = crate::subproc::lifecycle::native_child_heap_new() {
        return created.ok().and_then(Result::ok).map_or(null_mut(), |heap| heap.as_ptr().cast());
    }
    main_heaps::native_heap_new().map_or(null_mut(), |heap| heap.as_ptr().cast())
}

/// `mi_heap_of`: the Heap currently named by the page containing `pointer`.
/// An interior pointer has the same Heap as its containing live block.
///
/// # Safety
/// `pointer` is null, inside a live allocation held through this call, or
/// inside memory the caller owns that this allocator never mapped. The
/// caller excludes a concurrent Heap move for the containing page.
pub unsafe fn heap_of(pointer: *const u8) -> *mut c_void {
    // SAFETY: forwarded slice and Heap-transition exclusions.
    unsafe { main_heaps::heap_of_pointer(pointer) }.map_or(null_mut(), |heap| heap.as_ptr().cast())
}

/// `mi_any_heap_contains`: whether the safe PageMap lookup finds a page.
///
/// # Safety
/// The obligations of [`heap_of`].
pub unsafe fn any_heap_contains(pointer: *const u8) -> bool {
    // SAFETY: forwarded PageMap slice-exclusion obligation.
    unsafe { crate::source_api::check_owned(pointer) }
}

/// `mi_is_in_heap_region`: whether the safe PageMap lookup finds a page.
///
/// # Safety
/// The obligations of [`any_heap_contains`].
pub unsafe fn is_in_heap_region(pointer: *const u8) -> bool {
    // SAFETY: the same safe PageMap lookup answers both public queries.
    unsafe { any_heap_contains(pointer) }
}

/// `mi_heap_contains`: a null Heap selects this thread's subprocess main
/// Heap before comparing it with the pointer's page Heap.
///
/// # Safety
/// The obligations of [`heap_of`]; `heap` is null or a live Heap identity.
pub unsafe fn heap_contains(heap: *mut c_void, pointer: *const u8) -> bool {
    let heap = if heap.is_null() { heap_main() } else { heap };
    // SAFETY: forwarded pointer and Heap-lifetime obligations.
    !heap.is_null() && heap == unsafe { heap_of(pointer) }
}

/// `mi_unsafe_heap_page_is_under_utilized`: checks one page's ordinary
/// queue, commitment, Heap identity, and used-block count without collecting.
///
/// # Safety
/// `pointer` is null, inside a live allocation retained through this call,
/// or in caller-owned memory this allocator never mapped. The containing
/// page and its PageMap slice must remain registered and stable, with no
/// concurrent allocation, free, collection, queue move, or Heap move. `heap`
/// is null or a live Heap identity retained through this call.
pub unsafe fn heap_page_is_under_utilized(
    heap: *mut c_void,
    pointer: *mut u8,
    percentage: usize,
) -> bool {
    let Some(pointer) = NonNull::new(pointer) else { return false };
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return false;
    };
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return false };
    // SAFETY: the caller excludes PageMap entry mutation for this exact slice.
    let Some(page) = (unsafe { binding.page_map().lookup_registered_page(pointer.as_ptr()) }).ok().flatten() else {
        return false;
    };
    // SAFETY: the caller keeps this page and all of its ordinary fields
    // stable until the utilization predicate has copied its scalar values.
    unsafe { page.as_ref() }.is_under_utilized_for_heap(heap.cast(), percentage)
}

#[cfg(test)]
mod heap_membership_tests {
    extern crate std;

    use super::*;
    use crate::runtime_lifecycle::{
        attach_current_thread, finish_current_thread_native_after_user_destructors, native_free,
        NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    };
    use crate::subproc::main_heaps::{native_heap_allocate, native_heap_new, native_heap_release};
    use std::vec::Vec;

    unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

    fn initialize_test_owner() {
        assert!(crate::runtime_lifecycle::test_initialize_process_from_host_environment(4096, unsafe {
            crate::__crabc_runtime::RuntimeStderrOutput::new(no_output)
        }));
        assert!(crate::runtime_lifecycle::prepare_native_later_thread_arena());
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn live_interior_foreign_and_moved_page_queries_follow_page_identity() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::live_interior_foreign_and_moved_page_queries_follow_page_identity",
            || {
                initialize_test_owner();
                let heap = native_heap_new().expect("a non-main Heap");
                // SAFETY: this newly created Heap stays live until its page
                // has moved to the main Heap.
                let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("a live block");
                let pointer = block.as_ptr();
                let interior = pointer.wrapping_add(1);
                let foreign = 0u8;
                let selected = heap.as_ptr().cast();
                // SAFETY: the allocation and its PageMap slice stay live,
                // and no other thread can mutate this page in the fixture.
                unsafe {
                    assert_eq!(heap_of(pointer), selected);
                    assert_eq!(heap_of(interior), selected);
                    assert!(heap_contains(selected, pointer));
                    assert!(any_heap_contains(interior));
                    assert!(is_in_heap_region(interior));
                    assert!(!heap_contains(core::ptr::null_mut(), pointer));
                    assert!(!heap_page_is_under_utilized(selected, pointer, 100));
                    assert!(heap_of(core::ptr::null()).is_null());
                    assert!(!any_heap_contains(core::ptr::null()));
                    assert!(!is_in_heap_region(core::ptr::null()));
                    assert!(heap_of(&foreign).is_null());
                    assert!(!any_heap_contains(&foreign));
                    assert!(!is_in_heap_region(&foreign));
                    assert!(!heap_contains(selected, &foreign));
                    assert!(!heap_page_is_under_utilized(selected, (&foreign as *const u8).cast_mut(), 100));
                }
                // SAFETY: the Heap is live, its only page and block stay
                // mapped, and this thread alone performs the move.
                assert_eq!(unsafe { native_heap_release(heap, false) }, Ok(HeapReleaseOutcome::Released));
                let main = heap_main();
                // SAFETY: the moved block still retains its registered page;
                // no concurrent owner may move or retire it during the query.
                unsafe {
                    assert_eq!(heap_of(pointer), main);
                    assert_eq!(heap_of(interior), main);
                    assert!(heap_contains(core::ptr::null_mut(), interior));
                    assert!(any_heap_contains(pointer));
                    assert!(is_in_heap_region(interior));
                    assert!(!heap_page_is_under_utilized(main, pointer, 100));
                }
                // SAFETY: `block` remains exact and live after its Heap move.
                assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
            },
        );
    }

    struct UtilizationPages {
        blocks: Vec<usize>,
        pairs: Vec<(usize, usize)>,
    }

    unsafe extern "C" fn find_utilization_pages(
        _: *const c_void,
        area: *const HeapArea,
        block: *mut c_void,
        _: usize,
        argument: *mut c_void,
    ) -> bool {
        if !block.is_null() || area.is_null() || argument.is_null() { return true; }
        // SAFETY: the test owns both the callback argument and this borrowed
        // area image until the callback returns; neither outlives this call.
        let probe = unsafe { &mut *argument.cast::<UtilizationPages>() };
        let area = unsafe { &*area };
        let start = area.blocks.addr();
        let end = start.saturating_add(area.committed);
        let mut found = probe.blocks.iter().copied().filter(|address| *address >= start && *address < end);
        if let (Some(victim), Some(survivor)) = (found.next(), found.next()) {
            probe.pairs.push((victim, survivor));
        }
        true
    }

    unsafe extern "C" fn collect_utilization_page(
        _: *const c_void,
        _: *const HeapArea,
        _: *mut c_void,
        _: usize,
        _: *mut c_void,
    ) -> bool {
        true
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn joined_remote_free_exposes_non_head_page_utilization() {
        crate::test_process::run_in_fresh_process(
            "source_heap_api::heap_membership_tests::joined_remote_free_exposes_non_head_page_utilization",
            || {
                initialize_test_owner();
                let heap = native_heap_new().expect("a non-main Heap");
                let selected = heap.as_ptr().cast();
                let mut probe = UtilizationPages { blocks: Vec::with_capacity(10_000), pairs: Vec::new() };
                for _ in 0..10_000 {
                    // SAFETY: the creating thread holds this Heap until its
                    // worker has joined and all queries have completed.
                    let block = unsafe { native_heap_allocate(heap, 64, None, false) }.expect("a page block");
                    probe.blocks.push(block.as_ptr().addr());
                }
                // SAFETY: all pages and the callback's borrowed probe remain
                // stable while this sole owner identifies page-local pairs.
                assert!(unsafe { heap_visit_blocks(selected, false, Some(find_utilization_pages),
                    (&mut probe as *mut UtilizationPages).cast()) });
                assert!(probe.pairs.len() >= 3);
                let victims: Vec<usize> = probe.pairs.iter().map(|pair| pair.0).collect();
                std::thread::spawn(move || {
                    let descriptor = crate::__crabc_runtime::current_native_allocator_thread_descriptor();
                    // SAFETY: this new worker registers its own descriptor once.
                    assert!(unsafe {
                        crate::__crabc_runtime::register_current_native_allocator_worker_descriptor(descriptor)
                    });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    for address in victims {
                        let block = NonNull::new(address as *mut u8).expect("a retained victim");
                        // SAFETY: each exact block is transferred once to
                        // this worker; its Heap stays live until the join.
                        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
                    }
                    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
                }).join().expect("the remote producer finished");
                // SAFETY: the producer has joined, the Heap and pages remain
                // live, and the visitor only collects and observes them.
                assert!(unsafe { heap_visit_blocks(selected, true, Some(collect_utilization_page),
                    core::ptr::null_mut()) });
                let main = heap_main();
                let mut positives = 0usize;
                for (_, survivor) in &probe.pairs {
                    let pointer = *survivor as *mut u8;
                    // SAFETY: the survivor is an exact live block. The only
                    // remote producer joined before collection and queries.
                    if unsafe { heap_page_is_under_utilized(selected, pointer, 100) } {
                        positives += 1;
                        let interior = pointer.wrapping_add(1);
                        // SAFETY: the same retained block and quiescent page
                        // back every threshold and Heap-identity observation.
                        unsafe {
                            assert!(!heap_page_is_under_utilized(selected, pointer, 50));
                            assert!(!heap_page_is_under_utilized(main, pointer, 100));
                            assert!(heap_page_is_under_utilized(selected, interior, 100));
                            assert_eq!(heap_of(interior), selected);
                            assert!(is_in_heap_region(interior));
                        }
                    }
                }
                assert!(positives > 0, "a collected non-head page is observable");
                // SAFETY: no worker remains and this live Heap owns all
                // retained pages until destruction finishes.
                assert_eq!(unsafe { native_heap_release(heap, true) }, Ok(HeapReleaseOutcome::Released));
            },
        );
    }
}

/// The C `mi_heap_area_t` image passed only while one visitor call runs.
#[repr(C)]
pub struct HeapArea {
    blocks: *mut c_void,
    reserved: usize,
    committed: usize,
    used: usize,
    block_size: usize,
    full_block_size: usize,
    reserved1: *mut c_void,
}

/// The C `mi_block_visit_fun` callback.
///
/// # Safety
/// `heap`, `area`, and `block` belong to the current live visitor step;
/// the callee may inspect them only before returning. `argument` is the
/// caller-supplied pointer and must be used under that caller's contract.
pub type HeapBlockVisitor = unsafe extern "C" fn(
    heap: *const c_void,
    area: *const HeapArea,
    block: *mut c_void,
    block_size: usize,
    argument: *mut c_void,
) -> bool;

/// Marks one free block in the page-local visit bitmap.
fn mark_heap_visit_free_block(bitmap: &mut [usize], index: usize) -> bool {
    let word = index / usize::BITS as usize;
    let mask = 1usize << (index % usize::BITS as usize);
    if bitmap[word] & mask != 0 { return false; }
    bitmap[word] |= mask;
    true
}

/// Copies a stable page's immediate free-list membership into a visit bitmap.
///
/// # Safety
/// `free` is null or points inside the retained, exclusively owned `blocks`
/// area; every free-list link is an initialized unencoded block pointer.
unsafe fn heap_visit_free_map(
    mut free: *mut crate::types::Block,
    blocks: *mut u8,
    committed: usize,
    block_size: usize,
    capacity: usize,
    bitmap: &mut [usize],
) -> Option<usize> {
    let mut free_count = 0usize;
    while !free.is_null() {
        let offset = (free as usize).checked_sub(blocks as usize)?;
        if offset >= committed || offset % block_size != 0 || free_count >= capacity { return None; }
        let index = offset / block_size;
        if !mark_heap_visit_free_block(bitmap, index) { return None; }
        free_count += 1;
        // SAFETY: the validated node is in the caller-retained free block
        // area, whose unencoded next word remains stable during visitation.
        free = unsafe { core::ptr::read(free.cast::<*mut crate::types::Block>()) };
    }
    Some(free_count)
}

/// Visits one page's area before any of its live blocks.
///
/// # Safety
/// `page` is a live page of `heap`, and no callback may retire or move that
/// page, mutate its free lists, or race its ordinary-field owner. The caller
/// keeps the page's arena slice registered for the whole call.
unsafe fn visit_heap_page(
    heap: NonNull<Heap>,
    page: NonNull<Page>,
    visit_blocks: bool,
    visitor: HeapBlockVisitor,
    argument: *mut c_void,
) -> bool {
    let (blocks, area, full_block_size) = {
        // SAFETY: the caller holds the live page and excludes ordinary-field
        // mutation while these source geometry scalars are copied.
        let page_ref = unsafe { page.as_ref() };
        if page_ref.heap() != heap.as_ptr() { return false; }
        let full_block_size = page_ref.block_size();
        let Some(reserved) = full_block_size.checked_mul(page_ref.reserved() as usize) else { return false };
        let Some(committed) = full_block_size.checked_mul(page_ref.capacity() as usize) else { return false };
        // SAFETY: the caller's live page geometry covers the complete area.
        let blocks = unsafe { page_ref.start() };
        let area = HeapArea {
            blocks: blocks.cast(), reserved, committed, used: page_ref.used(),
            block_size: full_block_size, full_block_size, reserved1: page.as_ptr().cast(),
        };
        (blocks, area, full_block_size)
    };
    // SAFETY: the C caller supplied a live callback and argument; the area
    // image stays on this stack until it returns.
    if !unsafe { visitor(heap.as_ptr().cast(), &area, null_mut(), area.block_size, argument) } {
        return false;
    }
    if !visit_blocks { return true; }
    const MAX_BLOCKS: usize = crate::config::SMALL_PAGE_SIZE / core::mem::size_of::<usize>();
    const WORD_BITS: usize = usize::BITS as usize;
    // SAFETY: the callback left this page and its ordinary fields stable.
    let page_ref = unsafe { page.as_ref() };
    let capacity = page_ref.capacity() as usize;
    let used = page_ref.used();
    if capacity > MAX_BLOCKS || full_block_size == 0 { return false; }
    let mut free_map = [0usize; MAX_BLOCKS.div_ceil(WORD_BITS)];
    // SAFETY: the caller excludes mutation of every page free-list node.
    let Some(mut free_count) = (unsafe {
        heap_visit_free_map(page_ref.free_list_head(), blocks, area.committed, full_block_size, capacity, &mut free_map)
    }) else { return false };
    // When the immediate free list accounts for every unused block and no
    // remote head is published, forced collection cannot change this page's
    // live-block image. This also covers a page whose owner has exited.
    if free_count + used != capacity || page_ref.has_published_remote_free() {
        // SAFETY: the caller owns the stable page and its block area through
        // the remote and local collection steps for this page identity.
        if !unsafe { Page::collect_for_heap_visit_at(page) } { return false; }
        free_map.fill(0);
        // SAFETY: collection left the same page and block area live.
        let Some(collected_count) = (unsafe {
            heap_visit_free_map(page.as_ref().free_list_head(), blocks, area.committed, full_block_size, capacity, &mut free_map)
        }) else { return false };
        free_count = collected_count;
    }
    // SAFETY: any collection has finished before this ordinary-field read.
    let used = unsafe { page.as_ref() }.used();
    if free_count + used != capacity { return false; }
    if used == 0 { return true; }
    if capacity == 1 {
        // SAFETY: the one live block is the page area's first block.
        return unsafe { visitor(heap.as_ptr().cast(), &area, blocks.cast(), area.block_size, argument) };
    }
    for index in 0..capacity {
        if free_map[index / WORD_BITS] & (1usize << (index % WORD_BITS)) != 0 { continue; }
        // SAFETY: every index below capacity names a live block in the
        // caller-retained page area, and the callback cannot retire it.
        let block = unsafe { blocks.add(index * full_block_size) };
        if !unsafe { visitor(heap.as_ptr().cast(), &area, block.cast(), area.block_size, argument) } {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod heap_visit_tests {
    #[test]
    fn cyclic_free_list_is_rejected_before_a_live_callback() {
        let mut blocks = [0usize; 2];
        let block_size = core::mem::size_of::<usize>();
        let second = blocks.as_mut_ptr().wrapping_add(1);
        // SAFETY: the second block is retained for this call and its next
        // word deliberately points back to itself to model a malformed list.
        unsafe { second.write(second.addr()) };
        let mut bitmap = [0usize; 1];
        // SAFETY: both blocks and the cyclic next word stay initialized and
        // exclusively owned through the bounded traversal.
        assert_eq!(unsafe {
            super::heap_visit_free_map(
                second.cast(), blocks.as_mut_ptr().cast(), 2 * block_size,
                block_size, 2, &mut bitmap,
            )
        }, None);
        assert_eq!(bitmap, [1usize << 1]);
    }
}

/// `mi_heap_visit_blocks` for a quiescent Heap of the process main subprocess.
/// A null visitor is refused before Heap selection.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
/// Every page of the selected Heap, its arena bitmap, and its block area stay
/// mapped and stable throughout traversal; no other thread owns or mutates
/// their ordinary fields or publishes remote frees during traversal. The
/// callback and `argument` remain callable, and the callback does not free,
/// move, or mutate a visited page or its blocks.
pub unsafe fn heap_visit_blocks(
    heap: *mut c_void,
    visit_blocks: bool,
    visitor: Option<HeapBlockVisitor>,
    argument: *mut c_void,
) -> bool {
    let Some(visitor) = visitor else { return false };
    let selected = if heap.is_null() { heap_main() } else { heap };
    let Some(heap) = NonNull::new(selected.cast::<Heap>()) else { return false };
    // SAFETY: caller keeps the Heap live and traversal quiescent.
    let heap_ref = unsafe { heap.as_ref() };
    if !heap_ref.is_bound_to_main_subprocess(MainSubprocess::global()) {
        return false;
    }
    let Some((binding, _)) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs() else { return false };
    let registry = MainSubprocess::global().identity().arena_backing().registry();
    for index in 0..registry.count() {
        // SAFETY: the caller excludes arena retirement for this traversal.
        let Some(arena) = (unsafe { registry.arena_at(index) }) else { continue };
        // SAFETY: the registered arena remains mapped and published.
        let Some(view) = (unsafe { crate::arena::ArenaView::from_ptr(core::ptr::from_ref(arena).cast_mut()) }) else {
            return false;
        };
        let pages = if heap_ref.is_subprocess_main() {
            if heap_ref.arena_pages_at(index) != Some(NonNull::from(&view.arena().pages_main)) {
                continue;
            }
            // SAFETY: the installed main Heap slot retains this arena's
            // embedded bitmap, and the caller excludes its retirement.
            unsafe { view.pages() }
        } else {
            // SAFETY: the installed Heap bitmap and arena remain live.
            unsafe { heap_ref.non_main_arena_pages_bitmap(&view, 0) }
        };
        let Some(pages) = pages else { continue };
        let complete = pages.visit_set_bits(|slice, _| {
            let Some(start) = view.slice_start(slice) else { return false };
            // SAFETY: a set Heap bit retains the registered page at this
            // slice; caller exclusion keeps its mapping stable.
            let Some(page) = (unsafe { binding.page_map().lookup_registered_page(start) }).ok().flatten() else {
                return false;
            };
            // SAFETY: forwarded Heap, page, and callback stability.
            unsafe { visit_heap_page(heap, page, visit_blocks, visitor, argument) }
        });
        if !complete { return false; }
    }
    // Source visits the Heap's OS-abandoned list after all arena bitmaps.
    // SAFETY: caller exclusion keeps the private list stable.
    let mut current = unsafe { Heap::os_abandoned_head_at(heap) };
    while let Some(page) = NonNull::new(current) {
        // SAFETY: read the successor before invoking the callback.
        current = unsafe { Page::next_at(page) };
        // SAFETY: forwarded stable Heap and page obligations.
        if !unsafe { visit_heap_page(heap, page, visit_blocks, visitor, argument) } { return false; }
    }
    true
}

fn is_main_heap(heap: NonNull<Heap>) -> bool {
    core::ptr::eq(heap.as_ptr(), MainSubprocess::global().ready_main_heap_pointer())
}

/// The shape of one Heap allocation request.
#[derive(Clone, Copy)]
enum Request {
    Plain,
    Aligned { alignment: usize, offset: usize },
}

/// `_mi_heap_theap(heap)` then the Theap allocation of `request`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
unsafe fn heap_allocate(heap: *mut c_void, size: usize, request: Request, zero: bool) -> Sourced<Block> {
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    };
    if is_main_heap(heap) {
        main_heaps::select_main_heap_theap();
        return match (request, zero) {
            (Request::Plain, false) => crate::source_api::malloc(size),
            (Request::Plain, true) => crate::source_api::zalloc(size),
            (Request::Aligned { alignment, offset }, false) => crate::source_api::malloc_aligned_at(size, alignment, offset),
            (Request::Aligned { alignment, offset }, true) => crate::source_api::zalloc_aligned_at(size, alignment, offset),
        };
    }
    if let Request::Aligned { alignment, offset } = request {
        // `mi_theap_malloc_zero_aligned_at`'s refusals before any Theap work.
        if let Some(report) = SourceErrorReport::aligned_precheck(size, alignment, offset) {
            let _ = crate::process_init::process_error_message(report);
            return Sourced { value: None, errno: SourceErrno::error_message(report.error()) };
        }
    }
    let child_member = crate::subproc::lifecycle::current_thread_is_child_member();
    let child_page_alignment_refusal = match request {
        Request::Aligned { alignment, offset: 0 }
            if child_member && alignment >= crate::config::PAGE_META_ALIGNMENT => Some(alignment),
        _ => None,
    };
    if child_page_alignment_refusal.is_some() {
        // `_mi_heap_theap` precedes the allocation attempt even when the OS
        // page geometry later refuses this alignment.
        // SAFETY: forwarded Heap and current-child obligations.
        if !unsafe { crate::subproc::lifecycle::native_child_heap_select_theap(heap) } {
            return Sourced { value: None, errno: report_failure(size, request) };
        }
    }
    let block = if child_member {
        let aligned = match request {
            Request::Plain => None,
            Request::Aligned { alignment, offset } => Some((alignment, offset)),
        };
        // SAFETY: forwarded Heap contract.
        unsafe { crate::subproc::lifecycle::native_child_heap_allocate_variant(heap, size, aligned, zero) }.flatten()
    } else {
        let aligned = match request {
            Request::Plain => None,
            Request::Aligned { alignment, offset } => Some((alignment, offset)),
        };
        // SAFETY: forwarded Heap contract.
        unsafe { main_heaps::native_heap_allocate(heap, size, aligned, zero) }
    };
    if block.is_some() {
        return Sourced { value: block, errno: SourceErrno::Unchanged };
    }
    let prior_errno = if let Some(alignment) = child_page_alignment_refusal {
        // Each of `mi_find_page`'s two attempts reaches the same OS-page
        // alignment refusal before the generic fallback reports OOM.
        for _ in 0..2 {
            crate::process_init::process_warning_message(
                SourceFormattedMessage::page_alignment_too_large(alignment),
            );
        }
        SourceErrno::Store(Errno::INVAL)
    } else {
        SourceErrno::Unchanged
    };
    Sourced { value: None, errno: prior_errno.then(report_failure(size, request)) }
}

/// The failed `_mi_malloc_generic`'s reports: `mi_find_page` refuses a
/// too-large request before and after its forced collection, then the
/// generic fallback reports out of memory.
fn report_failure(size: usize, request: Request) -> SourceErrno {
    let mut errno = SourceErrno::Unchanged;
    if matches!(request, Request::Plain) && size > crate::config::MAX_ALLOC_SIZE {
        for _ in 0..2 {
            let report = SourceErrorReport::AllocationTooLarge { size };
            let _ = crate::process_init::process_error_message(report);
            errno = errno.then(SourceErrno::error_message(report.error()));
        }
    }
    let report = SourceErrorReport::OutOfMemory { size };
    let _ = crate::process_init::process_error_message(report);
    errno.then(SourceErrno::error_message(Errno::NOMEM))
}

/// `mi_heap_malloc`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
pub unsafe fn heap_malloc(heap: *mut c_void, size: usize) -> Sourced<Block> {
    // SAFETY: forwarded.
    unsafe { heap_allocate(heap, size, Request::Plain, false) }
}

/// `mi_heap_zalloc`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_zalloc(heap: *mut c_void, size: usize) -> Sourced<Block> {
    // SAFETY: forwarded.
    unsafe { heap_allocate(heap, size, Request::Plain, true) }
}

/// `mi_heap_calloc`: an overflowing product fails before any allocation.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_calloc(heap: *mut c_void, count: usize, size: usize) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_zalloc(heap, total) },
        None => Sourced { value: None, errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_mallocn`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_mallocn(heap: *mut c_void, count: usize, size: usize) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_malloc(heap, total) },
        None => Sourced { value: None, errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_malloc_aligned_at` and `mi_heap_zalloc_aligned_at`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_malloc_aligned_at(
    heap: *mut c_void,
    size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<Block> {
    // SAFETY: forwarded.
    unsafe { heap_allocate(heap, size, Request::Aligned { alignment, offset }, zero) }
}

/// `mi_heap_calloc_aligned_at`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_calloc_aligned_at(
    heap: *mut c_void,
    count: usize,
    size: usize,
    alignment: usize,
    offset: usize,
) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_malloc_aligned_at(heap, total, alignment, offset, true) },
        None => Sourced { value: None, errno: SourceErrno::Unchanged },
    }
}

/// `mi_heap_delete` or, with `destroy`, `mi_heap_destroy`. `false` when a
/// legal release could not complete (its owners are retained).
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess that no
/// other thread uses during the call; after a destroy no block of it is used
/// again.
pub unsafe fn heap_release(heap: *mut c_void, destroy: bool) -> bool {
    let Some(heap) = NonNull::new(heap.cast::<Heap>()) else { return true };
    // SAFETY: forwarded; the child route checks its own membership.
    if let Some(released) = unsafe { crate::subproc::lifecycle::native_child_heap_release(heap, destroy) } {
        return match released {
            Ok(Ok(HeapReleaseOutcome::MainHeapRefused)) => {
                warn_main_heap(destroy);
                true
            }
            Ok(Ok(_)) => true,
            _ => false,
        };
    }
    if is_main_heap(heap) {
        warn_main_heap(destroy);
        return true;
    }
    // SAFETY: forwarded.
    match unsafe { main_heaps::native_heap_release(heap, destroy) } {
        Ok(HeapReleaseOutcome::MainHeapRefused) => {
            warn_main_heap(destroy);
            true
        }
        Ok(_) => true,
        Err(_) => false,
    }
}

/// The `_mi_warning_message` of a main-Heap delete or destroy.
fn warn_main_heap(destroy: bool) {
    let message = if destroy { c"cannot destroy the main heap\n" } else { c"cannot delete the main heap\n" };
    if let Some(binding) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .map(|(binding, _)| binding)
    {
        binding.process().policy().source_warning(SourceFormattedMessage::from_source_formatted(message));
    }
}

/// `mi_reserve_os_memory_ex`: `0` or `ENOMEM`, writing the reserved arena's
/// id (or none) through `arena_id` when it is not null. The errno effect is
/// that of the failing step: a too-large report, or the failed `mmap` or
/// `munmap` code musl leaves in `errno`.
///
/// # Safety
/// `arena_id` is null or writable.
pub unsafe fn reserve_os_memory_ex(
    size: usize,
    commit: bool,
    allow_large: bool,
    exclusive: bool,
    arena_id: *mut *mut c_void,
) -> Sourced<c_int> {
    use crate::arena::ReserveOsMemoryFailure;
    if !arena_id.is_null() {
        // SAFETY: the caller's writable output.
        unsafe { arena_id.write(null_mut()) };
    }
    if crate::subproc::lifecycle::current_thread_is_child_member() {
        return Sourced { value: Errno::NOMEM.raw(), errno: SourceErrno::Unchanged };
    }
    match main_heaps::native_reserve_os_memory(size, commit, allow_large, exclusive) {
        Ok(id) => {
            if !arena_id.is_null() {
                // SAFETY: as above.
                unsafe { arena_id.write(id.as_ptr().cast()) };
            }
            Sourced { value: 0, errno: SourceErrno::Unchanged }
        }
        Err(failure) => Sourced {
            value: Errno::NOMEM.raw(),
            errno: match failure {
                ReserveOsMemoryFailure::TooLarge => SourceErrno::error_message(Errno::OVERFLOW),
                ReserveOsMemoryFailure::Os(error) => SourceErrno::Store(error),
                ReserveOsMemoryFailure::Unmanaged => SourceErrno::Unchanged,
            },
        },
    }
}

/// `mi_reserve_os_memory`.
pub fn reserve_os_memory(size: usize, commit: bool, allow_large: bool) -> Sourced<c_int> {
    // SAFETY: a null output is never written.
    unsafe { reserve_os_memory_ex(size, commit, allow_large, false, null_mut()) }
}

// ---------------------------------------------------------------------------
// Heap reallocation (`alloc.c:379-530`, `alloc-aligned.c:344-424`)
// ---------------------------------------------------------------------------

use crate::source_api::{FreeOutcome, SourceCRuntime};

const WORD: usize = core::mem::size_of::<usize>();

/// The Heap argument of a reallocation entry: the main Heap (handled by the
/// default-Theap entries, whose Theap is that Heap's), or a non-main Heap.
enum Target {
    Main,
    NonMain(NonNull<Heap>),
}

fn target(heap: *mut c_void) -> Option<Target> {
    let heap = NonNull::new(heap.cast::<Heap>())?;
    if is_main_heap(heap) {
        main_heaps::select_main_heap_theap();
        return Some(Target::Main);
    }
    Some(Target::NonMain(heap))
}

/// Heap realloc wrappers resolve their Theap before the realloc kernel can
/// reuse a block, reject an alignment, or reject a multiplied size.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
unsafe fn realloc_target(heap: *mut c_void) -> Option<Target> {
    match target(heap) {
        Some(Target::NonMain(heap)) if crate::subproc::lifecycle::current_thread_is_child_member() => {
            // SAFETY: the public Heap wrapper holds its live Heap argument.
            unsafe { crate::subproc::lifecycle::native_child_heap_select_theap(heap) }.then_some(Target::NonMain(heap))
        }
        Some(Target::NonMain(heap)) if !main_heaps::native_heap_select_theap(heap) => None,
        other => other,
    }
}

fn freed_with(result: Sourced<Block>) -> Sourced<(Block, FreeOutcome)> {
    Sourced { value: (result.value, FreeOutcome::Freed), errno: result.errno }
}

/// `mi_theap_realloc_zero_ex` through a non-main Heap's Theap. The block is
/// reused only when it fits with at most half waste and its page belongs to
/// that Heap; otherwise a block of the Heap replaces it (its expanded part
/// zeroed from the last copied word when `zero`) and the old block is freed.
///
/// # Safety
/// `block` is null or an exact live block no other thread uses; on a
/// non-null result it is consumed.
unsafe fn heap_realloc_zero(heap: NonNull<Heap>, block: *mut u8, new_size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    let Some(live) = NonNull::new(block) else {
        // SAFETY: forwarded Heap contract.
        return freed_with(unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Plain, zero) });
    };
    // `mi_validate_ptr_page`: an unregistered pointer returns null.
    // SAFETY: forwarded live-block contract.
    let Some(page_heap) = (unsafe { main_heaps::heap_of_block(live) }) else {
        return Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged };
    };
    // SAFETY: as above.
    let size = unsafe { crate::source_api::usable_size(block) };
    if new_size <= size && new_size >= size / 2 && new_size > 0 && page_heap == heap {
        return Sourced { value: (Some(live), FreeOutcome::Freed), errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded Heap contract.
    let result = unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Plain, false) };
    let Some(replacement) = result.value else { return freed_with(result) };
    let copy = new_size.min(size);
    let zero_start = (if copy >= WORD { copy - WORD } else { 0 }) & !(WORD - 1);
    // SAFETY: the fresh block is live and exclusively ours; `block` holds at
    // least `copy` usable bytes and does not overlap it.
    unsafe {
        let usable = crate::source_api::usable_size(replacement.as_ptr());
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        } else if new_size == 0 {
            replacement.as_ptr().write(0);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
    }
    // SAFETY: the old block is freed once, after the copy.
    let freed = unsafe { crate::source_api::free(block) };
    Sourced { value: (Some(replacement), freed), errno: result.errno }
}

/// `mi_theap_realloc_zero_aligned_at` through a non-main Heap's Theap.
///
/// # Safety
/// As [`heap_realloc_zero`].
unsafe fn heap_realloc_zero_aligned_at(
    heap: NonNull<Heap>,
    block: *mut u8,
    new_size: usize,
    alignment: usize,
    offset: usize,
    zero: bool,
) -> Sourced<(Block, FreeOutcome)> {
    if !crate::size_class::alignment_is_valid(alignment) {
        let report = SourceErrorReport::BadAlignment { size: new_size, alignment, offset };
        let _ = crate::process_init::process_error_message(report);
        return Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::error_message(report.error()) };
    }
    if alignment <= WORD && offset == 0 {
        // SAFETY: forwarded.
        return unsafe { heap_realloc_zero(heap, block, new_size, zero) };
    }
    if block.is_null() {
        // SAFETY: forwarded Heap contract.
        return freed_with(unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Aligned { alignment, offset }, zero) });
    }
    // SAFETY: forwarded live-block contract.
    let size = unsafe { crate::source_api::usable_size(block) };
    if new_size <= size && new_size >= size - size / 2 && (block.addr().wrapping_add(offset) & (alignment - 1)) == 0 {
        return Sourced { value: (NonNull::new(block), FreeOutcome::Freed), errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded Heap contract.
    let result = unsafe { heap_allocate(heap.as_ptr().cast(), new_size, Request::Aligned { alignment, offset }, false) };
    let Some(replacement) = result.value else { return freed_with(result) };
    let copy = new_size.min(size);
    let zero_start = if copy >= WORD { copy - WORD } else { 0 };
    // SAFETY: as in `heap_realloc_zero`.
    unsafe {
        let usable = crate::source_api::usable_size(replacement.as_ptr());
        if zero && usable > zero_start {
            replacement.as_ptr().add(zero_start).write_bytes(0, usable - zero_start);
        }
        core::ptr::copy_nonoverlapping(block, replacement.as_ptr(), copy);
    }
    // SAFETY: the old block is freed once, after the copy.
    let freed = unsafe { crate::source_api::free(block) };
    Sourced { value: (Some(replacement), freed), errno: result.errno }
}

/// `mi_heap_realloc` or, with `zero`, `mi_heap_rezalloc`. The free outcome
/// is that of the replaced block.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess; `block`
/// is null or an exact live block no other thread uses, consumed on a
/// non-null result.
pub unsafe fn heap_realloc(heap: *mut c_void, block: *mut u8, new_size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    // SAFETY: forwarded public Heap contract.
    match unsafe { realloc_target(heap) } {
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
        // SAFETY: forwarded.
        Some(Target::Main) if zero => freed_with(unsafe { crate::source_api::rezalloc(block, new_size) }),
        // SAFETY: forwarded.
        Some(Target::Main) => freed_with(unsafe { crate::source_api::realloc(block, new_size) }),
        // SAFETY: forwarded.
        Some(Target::NonMain(heap)) => unsafe { heap_realloc_zero(heap, block, new_size, zero) },
    }
}

/// `mi_heap_reallocn` or, with `zero`, `mi_heap_recalloc`.
///
/// # Safety
/// As [`heap_realloc`].
pub unsafe fn heap_reallocn(heap: *mut c_void, block: *mut u8, count: usize, size: usize, zero: bool) -> Sourced<(Block, FreeOutcome)> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_realloc(heap, block, total, zero) },
        None => {
            // SAFETY: forwarded public Heap contract.
            let _ = unsafe { realloc_target(heap) };
            Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged }
        }
    }
}

/// `mi_heap_reallocf`: `block` is freed when the reallocation fails.
///
/// # Safety
/// As [`heap_realloc`], except that `block` is consumed on every path.
pub unsafe fn heap_reallocf(heap: *mut c_void, block: *mut u8, new_size: usize) -> Sourced<(Block, FreeOutcome)> {
    // SAFETY: forwarded.
    let result = unsafe { heap_realloc(heap, block, new_size, false) };
    if result.value.0.is_none() && !block.is_null() {
        // SAFETY: the failed reallocation left `block` live.
        let freed = unsafe { crate::source_api::free(block) };
        return Sourced { value: (None, freed), errno: result.errno };
    }
    result
}

/// `mi_heap_realloc_aligned_at` and, with `zero`, `mi_heap_rezalloc_aligned_at`.
/// `offset: None` is the `_aligned` form, whose word-sized or smaller
/// alignment takes the ordinary kernel before any validation.
///
/// # Safety
/// As [`heap_realloc`].
pub unsafe fn heap_realloc_aligned(
    heap: *mut c_void,
    block: *mut u8,
    new_size: usize,
    alignment: usize,
    offset: Option<usize>,
    zero: bool,
) -> Sourced<(Block, FreeOutcome)> {
    if offset.is_none() && alignment <= WORD {
        // SAFETY: forwarded.
        return unsafe { heap_realloc(heap, block, new_size, zero) };
    }
    let offset = offset.unwrap_or(0);
    // SAFETY: forwarded public Heap contract.
    match unsafe { realloc_target(heap) } {
        None => Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged },
        // SAFETY: forwarded.
        Some(Target::Main) if zero => freed_with(unsafe { crate::source_api::rezalloc_aligned_at(block, new_size, alignment, offset) }),
        // SAFETY: forwarded.
        Some(Target::Main) => freed_with(unsafe { crate::source_api::realloc_aligned_at(block, new_size, alignment, offset) }),
        // SAFETY: forwarded.
        Some(Target::NonMain(heap)) => unsafe { heap_realloc_zero_aligned_at(heap, block, new_size, alignment, offset, zero) },
    }
}

/// `mi_heap_recalloc_aligned[_at]`.
///
/// # Safety
/// As [`heap_realloc`].
pub unsafe fn heap_recalloc_aligned(
    heap: *mut c_void,
    block: *mut u8,
    count: usize,
    size: usize,
    alignment: usize,
    offset: Option<usize>,
) -> Sourced<(Block, FreeOutcome)> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_realloc_aligned(heap, block, total, alignment, offset, true) },
        None => {
            // SAFETY: forwarded public Heap contract.
            let _ = unsafe { realloc_target(heap) };
            Sourced { value: (None, FreeOutcome::Freed), errno: SourceErrno::Unchanged }
        }
    }
}

// ---------------------------------------------------------------------------
// Heap strings and `new` (`alloc.c:540-676,771-810`)
// ---------------------------------------------------------------------------

/// `mi_theap_strndup` after its length is known.
///
/// # Safety
/// `text` has `length` readable bytes; `heap` as for [`heap_malloc`].
unsafe fn heap_duplicate(heap: *mut c_void, text: *const core::ffi::c_char, length: usize) -> Sourced<Block> {
    if length > crate::config::MAX_ALLOC_SIZE - 1 {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded Heap contract.
    let result = unsafe { heap_malloc(heap, length + 1) };
    if let Some(copy) = result.value {
        // SAFETY: a fresh block of `length + 1` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(text.cast::<u8>(), copy.as_ptr(), length);
            copy.as_ptr().add(length).write(0);
        }
    }
    result
}

/// `mi_heap_strdup`.
///
/// # Safety
/// `text` is null or NUL-terminated; `heap` as for [`heap_malloc`].
pub unsafe fn heap_strdup(heap: *mut c_void, text: *const core::ffi::c_char) -> Sourced<Block> {
    if text.is_null() {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded.
    unsafe { heap_duplicate(heap, text, crate::source_api::strnlen(text, usize::MAX)) }
}

/// `mi_heap_strndup`.
///
/// # Safety
/// `text` is null or readable up to its terminator or `max` bytes.
pub unsafe fn heap_strndup(heap: *mut c_void, text: *const core::ffi::c_char, max: usize) -> Sourced<Block> {
    if text.is_null() {
        return Sourced { value: None, errno: SourceErrno::Unchanged };
    }
    // SAFETY: forwarded.
    unsafe { heap_duplicate(heap, text, crate::source_api::strnlen(text, max)) }
}

/// `mi_heap_realpath`: the resolution buffer comes from the default Theap
/// (`mi_zalloc`), the result from the Heap.
///
/// # Safety
/// `name` is null or NUL-terminated; `resolved` is null or writable for the
/// system `PATH_MAX` bytes.
pub unsafe fn heap_realpath(
    runtime: &impl SourceCRuntime,
    heap: *mut c_void,
    name: *const core::ffi::c_char,
    resolved: *mut core::ffi::c_char,
) -> Sourced<*mut core::ffi::c_char> {
    if !resolved.is_null() {
        // SAFETY: forwarded.
        return Sourced { value: unsafe { runtime.realpath(name, resolved) }, errno: SourceErrno::Unchanged };
    }
    let limit = crate::source_api::path_max(runtime);
    let buffer = crate::source_api::zalloc(limit + 1);
    let Some(buffer) = buffer.value else {
        return Sourced { value: null_mut(), errno: buffer.errno.then(SourceErrno::Store(Errno::NOMEM)) };
    };
    // SAFETY: a fresh zeroed buffer of `limit + 1` bytes.
    let rname = unsafe { runtime.realpath(name, buffer.as_ptr().cast()) };
    // SAFETY: `rname` is null or the NUL-terminated result in `buffer`.
    let result = unsafe { heap_strndup(heap, rname, limit) };
    // SAFETY: this call's own buffer.
    let _ = unsafe { crate::source_api::free(buffer.as_ptr()) };
    Sourced { value: result.value.map_or(null_mut(), |copy| copy.as_ptr().cast()), errno: result.errno }
}

/// `mi_heap_alloc_new`: `mi_heap_malloc`, then `mi_theap_try_new`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_alloc_new(runtime: &impl SourceCRuntime, heap: *mut c_void, size: usize) -> Sourced<Block> {
    // SAFETY: forwarded.
    let first = unsafe { heap_malloc(heap, size) };
    if first.value.is_some() {
        return first;
    }
    let mut errno = first.errno;
    for _ in 0..crate::source_api::TRY_NEW_MAX {
        let (retry, effect) = crate::source_api::try_new_handler(runtime, false);
        errno = errno.then(effect);
        if !retry {
            break;
        }
        // The handler runs at least once before this size refusal.
        if size > crate::config::MAX_ALLOC_SIZE {
            return Sourced { value: None, errno };
        }
        // SAFETY: forwarded.
        let result = unsafe { heap_malloc(heap, size) };
        errno = errno.then(result.errno);
        if result.value.is_some() {
            return Sourced { value: result.value, errno };
        }
    }
    Sourced { value: None, errno }
}

/// `mi_heap_alloc_new_n`.
///
/// # Safety
/// As [`heap_malloc`].
pub unsafe fn heap_alloc_new_n(runtime: &impl SourceCRuntime, heap: *mut c_void, count: usize, size: usize) -> Sourced<Block> {
    match crate::size_class::count_size(count, size) {
        // SAFETY: forwarded.
        Some(total) => unsafe { heap_alloc_new(runtime, heap, total) },
        None => {
            let (_, errno) = crate::source_api::try_new_handler(runtime, false);
            Sourced { value: None, errno }
        }
    }
}

/// `mi_heap_collect(heap, force)`.
///
/// # Safety
/// `heap` is null or a live Heap of the calling thread's subprocess.
pub unsafe fn heap_collect(heap: *mut c_void, force: bool) {
    match target(heap) {
        Some(Target::Main) => crate::source_api::collect(force),
        // A child-subprocess thread's Theaps are collected at its finish.
        Some(Target::NonMain(_)) if crate::subproc::lifecycle::current_thread_is_child_member() => {}
        // SAFETY: forwarded.
        Some(Target::NonMain(heap)) => unsafe { main_heaps::native_heap_collect(heap, force) },
        None => {}
    }
}

// ---------------------------------------------------------------------------
// Subprocesses (`subproc.c:113-133,158-313`)
// ---------------------------------------------------------------------------

use crate::subproc::lifecycle::{NativeChildThreadAdd, NativeSubprocessId};

/// A Heap visitor (`mi_heap_visit_fun`).
pub type HeapVisitor = unsafe extern "C" fn(heap: *mut c_void, argument: *mut c_void) -> bool;

/// The outcome of `mi_subproc_add_current_thread`, for the embedding boundary
/// that binds threads to the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubprocAddCurrentThread {
    /// The thread now belongs to the child and allocates from it.
    Added,
    /// Nothing changed (the thread was already initialized, or the id is
    /// null or the main subprocess).
    Unchanged,
    /// Admission failed; the thread is unchanged.
    Failed,
}

fn main_id() -> *mut c_void {
    MainSubprocess::global().identity().as_ptr().cast()
}

/// `mi_subproc_main()`.
pub fn subproc_main() -> *mut c_void {
    main_id()
}

/// `mi_subproc_current()`.
pub fn subproc_current() -> *mut c_void {
    crate::subproc::lifecycle::current_child_id().map_or_else(main_id, NativeSubprocessId::as_ptr)
}

/// `mi_subproc_new()`: null when the child cannot be created.
pub fn subproc_new() -> *mut c_void {
    crate::subproc::lifecycle::native_subproc_new().map_or(null_mut(), NativeSubprocessId::as_ptr)
}

/// `mi_subproc_destroy(id)`: the main subprocess and null are ignored; a
/// child that threads still belong to is destroyed under them. `false` when
/// a step retained the child.
///
/// # Safety
/// `id` is null, the main id, or a live child id from [`subproc_new`]; no
/// block of the child is used again, and a thread that still belongs to it
/// makes no allocator call afterwards other than its own thread finish.
pub unsafe fn subproc_destroy(id: *mut c_void) -> bool {
    let Some(pointer) = NonNull::new(id) else { return true };
    if pointer.as_ptr() == main_id() {
        return true;
    }
    let Some(_operation) = crate::runtime_lifecycle::NativeSubprocessOperation::enter() else {
        return false;
    };
    // SAFETY: forwarded live-id contract.
    if unsafe { crate::subproc::lifecycle::native_subproc_destroy(NativeSubprocessId::from_ptr(pointer)) }.is_err() {
        return false;
    }
    // Source releases the destroying thread's regular TLS table while
    // destroying the child's main Heap. Keep the whole public operation
    // admitted so terminal shutdown cannot pass between these two steps.
    main_heaps::release_current_thread_locals_after_child_destroy()
}

/// The source warning of a thread that already belongs to another
/// subprocess (`subproc.c:292-294`).
fn warn_other_subprocess(other: *mut c_void) {
    let mut text = [0u8; 128];
    let prefix = b"unable to add thread to the subprocess as it was already in another subprocess (at 0x";
    let mut length = prefix.len();
    text[..length].copy_from_slice(prefix);
    // `%p` as `_mi_vsnprintf` renders it: uppercase, 8, 12, or 16 digits.
    let address = other.addr();
    let digits = if address <= u32::MAX as usize { 8 } else if address >> 16 <= u32::MAX as usize { 12 } else { 16 };
    for index in (0..digits).rev() {
        text[length] = b"0123456789ABCDEF"[(address >> (index * 4)) & 0xf];
        length += 1;
    }
    text[length] = b')';
    text[length + 1] = b'\n';
    let Ok(message) = core::ffi::CStr::from_bytes_until_nul(&text[..length + 3]) else { return };
    if let Some(binding) = crate::process_init::ProcessMainInitializationStorage::global()
        .ready_child_subprocess_inputs()
        .map(|(binding, _)| binding)
    {
        binding.process().policy().source_warning(SourceFormattedMessage::from_source_formatted(message));
    }
}

/// `mi_subproc_add_current_thread(id)`.
///
/// # Safety
/// `id` is null, the main id, or a live child id; the calling thread has
/// registered with the runtime but made no allocation, and owns its
/// thread roots until it finishes.
pub unsafe fn subproc_add_current_thread(id: *mut c_void) -> SubprocAddCurrentThread {
    let Some(pointer) = NonNull::new(id) else { return SubprocAddCurrentThread::Unchanged };
    if pointer.as_ptr() == main_id() {
        // A thread of the main subprocess is initialized on its first
        // operation; a child member is already initialized elsewhere.
        if let Some(child) = crate::subproc::lifecycle::current_child_id() {
            warn_other_subprocess(child.as_ptr());
        }
        return SubprocAddCurrentThread::Unchanged;
    }
    // SAFETY: forwarded live-id and current-thread contracts.
    match unsafe { crate::subproc::lifecycle::native_subproc_add_current_thread(NativeSubprocessId::from_ptr(pointer)) } {
        Ok(NativeChildThreadAdd::Added) => SubprocAddCurrentThread::Added,
        Ok(NativeChildThreadAdd::AlreadyInitialized { in_other_subprocess }) => {
            if in_other_subprocess {
                warn_other_subprocess(subproc_current());
            }
            SubprocAddCurrentThread::Unchanged
        }
        _ => SubprocAddCurrentThread::Failed,
    }
}

/// `mi_subproc_visit_heaps(id, visitor, argument)`: visits the subprocess's
/// Heaps in list order until the visitor returns `false`.
///
/// # Safety
/// `id` is null, the main id, or a live child id; `visitor` is a valid C
/// function that does not operate on that subprocess's Heap list.
pub unsafe fn subproc_visit_heaps(id: *mut c_void, visitor: HeapVisitor, argument: *mut c_void) -> bool {
    let Some(pointer) = NonNull::new(id) else { return false };
    // SAFETY: the visitor's C contract.
    let mut visit = |heap: NonNull<Heap>| unsafe { visitor(heap.as_ptr().cast(), argument) };
    if pointer.as_ptr() == main_id() {
        return MainSubprocess::global().identity().heap_list().visit_heaps(&mut visit).unwrap_or(false);
    }
    // SAFETY: forwarded live-id contract.
    unsafe { crate::subproc::lifecycle::native_subproc_visit_heaps(NativeSubprocessId::from_ptr(pointer), visit) }
        .unwrap_or(false)
}
