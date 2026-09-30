#![cfg(target_arch = "x86_64")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use core::ptr::null_mut;
use crabc_mimalloc::__crabc_runtime::{
    source_api as api, source_heap_api as heaps, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors,
};

struct Visit {
    heap: *mut c_void,
    clients: [(usize, usize); 3],
    areas: usize,
    blocks: usize,
    seen: u8,
    previous: usize,
    valid: bool,
    stop_after: usize,
    reentry_heap: *mut c_void,
    reentered: bool,
}

impl Visit {
    fn new(heap: *mut c_void, clients: [(usize, usize); 3], stop_after: usize) -> Self {
        Self { heap, clients, areas: 0, blocks: 0, seen: 0, previous: 0,
            valid: true, stop_after, reentry_heap: null_mut(), reentered: false }
    }
}

unsafe extern "C" fn observe(
    heap: *const c_void,
    area: *const heaps::HeapArea,
    block: *mut c_void,
    block_size: usize,
    argument: *mut c_void,
) -> bool {
    // SAFETY: the synchronous traversal retains this one exclusive capture.
    // It never escapes the callback and is disjoint from allocator metadata.
    let visit = unsafe { &mut *argument.cast::<Visit>() };
    visit.valid &= heap == visit.heap.cast_const() && !area.is_null() && block_size > 0;
    if block.is_null() {
        visit.areas += 1;
        visit.previous = 0;
        if !visit.reentry_heap.is_null() && !visit.reentered {
            visit.reentered = true;
            let default = heaps::theap_get_default();
            // SAFETY: this distinct Heap remains live through traversal.
            // Allocation/free on it cannot mutate any visited page or client.
            let allocation = unsafe { heaps::heap_malloc(visit.reentry_heap, 33) };
            if let Some(client) = allocation.value {
                visit.valid &= unsafe { heaps::heap_of(client.as_ptr()) } == visit.reentry_heap;
                visit.valid &= unsafe { api::free(client.as_ptr()) } == api::FreeOutcome::Freed;
            } else {
                visit.valid = false;
            }
            visit.valid &= heaps::theap_get_default() == default;
        }
    } else {
        visit.blocks += 1;
        let address = block as usize;
        visit.valid &= visit.areas > 0 && address > visit.previous;
        visit.previous = address;
        if let Some(index) = visit.clients.iter().position(|(client, _)| *client == address) {
            visit.valid &= visit.seen & (1 << index) == 0;
            visit.seen |= 1 << index;
            // SAFETY: matching the retained client identifies an exact live
            // allocation. These metadata queries neither free nor modify it.
            visit.valid &= unsafe { heaps::heap_of(block.cast()) } == visit.heap;
            visit.valid &= unsafe { api::usable_size(block.cast()) } >= visit.clients[index].1;
        } else {
            visit.valid = false;
        }
    }
    visit.stop_after == 0 || visit.areas + visit.blocks < visit.stop_after
}

unsafe fn visit(heap: *mut c_void, blocks: bool, capture: &mut Visit) -> bool {
    // SAFETY: the caller retains this Heap and all its clients quiescent;
    // the callback only observes clients and updates its separate capture.
    unsafe { heaps::heap_visit_blocks(heap, blocks, Some(observe), (capture as *mut Visit).cast()) }
}

unsafe extern "C" fn observe_calloc(
    heap: *const c_void, area: *const heaps::HeapArea, block: *mut c_void,
    block_size: usize, argument: *mut c_void,
) -> bool {
    // SAFETY: the synchronous visitor retains the initialized area and the
    // capture for this callback; no allocator metadata is mutated.
    unsafe {
        let geometry = block_size;
        let expected = if cfg!(feature = "mi-debug-1") { 104 } else { 96 };
        (*argument.cast::<Visit>()).valid &= geometry == expected;
        observe(heap, area, block, block_size, argument)
    }
}

#[test]
fn public_theap_visitation_finds_one_live_calloc_block() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let heap = heaps::heap_new();
    assert!(!heap.is_null());
    // SAFETY: the test owns this Heap and retains its only live client until
    // synchronous visitation finishes; the callback never mutates its page.
    unsafe {
        let theap = heaps::heap_theap(heap);
        assert!(!theap.is_null());
        let client = api::theap_calloc(theap, 7, 13).value.unwrap();
        assert_eq!(api::usable_size(client.as_ptr()),
                   if cfg!(feature = "mi-debug-1") { 91 } else { 96 });
        assert!(core::slice::from_raw_parts(client.as_ptr().cast::<u8>(), 91)
            .iter().all(|byte| *byte == 0));
        let mut capture = Visit::new(heap, [(client.as_ptr() as usize, 91), (0, 0), (0, 0)], 0);
        let completed = api::theap_visit_blocks(theap, true, Some(observe_calloc),
            (&mut capture as *mut Visit).cast());
        assert_eq!((completed, capture.areas, capture.blocks, capture.seen, capture.valid),
                   (true, 1, 1, 1, true));
        assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
        assert!(heaps::heap_release(heap, true));
    }
}

#[test]
fn public_heap_visitation_tracks_live_population_early_stop_and_collection() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    let default = heaps::theap_get_default();
    let heap = heaps::heap_new();
    let reentry_heap = heaps::heap_new();
    assert!(!default.is_null() && !heap.is_null() && !reentry_heap.is_null());
    // SAFETY: this test retains its public Heap handle until final release.
    // Allocation, freeing and collection finish before every traversal.
    unsafe {
        let mut empty = Visit::new(heap, [(0, 0); 3], 0);
        assert!(visit(heap, true, &mut empty));
        assert_eq!((empty.areas, empty.blocks), (0, 0));
        assert!(!heaps::heap_visit_blocks(heap, true, None, null_mut()));

        let first = heaps::heap_malloc(heap, 64).value.unwrap();
        let remote = heaps::heap_malloc(heap, 64).value.unwrap();
        let second = heaps::heap_malloc(heap, 64).value.unwrap();
        let third = heaps::heap_malloc(heap, 256).value.unwrap();
        let clients = [(first.as_ptr() as usize, 64), (second.as_ptr() as usize, 64),
                       (third.as_ptr() as usize, 256)];
        let remote_address = remote.as_ptr() as usize;
        // Only the exact client's address is handed off, never a borrowed
        // Heap or Theap. Joining establishes that no remote producer remains
        // active when the owner inspects or collects the Heap.
        std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            assert_eq!(api::free(remote_address as *mut u8), api::FreeOutcome::Freed);
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        }).join().expect("the remote free completes before visitation");

        let mut full = Visit::new(heap, clients, 0);
        full.reentry_heap = reentry_heap;
        assert!(visit(heap, true, &mut full));
        assert!(full.valid && full.reentered);
        assert_eq!((full.blocks, full.seen), (3, 0b111));
        assert!(full.areas >= 2);

        let mut areas = Visit::new(heap, clients, 0);
        assert!(visit(heap, false, &mut areas));
        assert!(areas.valid);
        assert_eq!((areas.areas, areas.blocks), (full.areas, 0));
        let mut stop_area = Visit::new(heap, clients, 1);
        assert!(!visit(heap, false, &mut stop_area));
        assert!(stop_area.valid);
        assert_eq!((stop_area.areas, stop_area.blocks), (1, 0));
        let mut stop_block = Visit::new(heap, clients, 2);
        assert!(!visit(heap, true, &mut stop_block));
        assert!(stop_block.valid);
        assert_eq!((stop_block.areas, stop_block.blocks), (1, 1));
        let mut repeated = Visit::new(heap, clients, 0);
        assert!(visit(heap, true, &mut repeated));
        assert!(repeated.valid);
        assert_eq!((repeated.blocks, repeated.seen), (3, 0b111));

        assert_eq!(api::free(first.as_ptr()), api::FreeOutcome::Freed);
        assert_eq!(api::free(second.as_ptr()), api::FreeOutcome::Freed);
        heaps::heap_collect(heap, true);
        let mut collected = Visit::new(heap, [(0, 0), (0, 0), clients[2]], 0);
        assert!(visit(heap, true, &mut collected));
        assert!(collected.valid);
        assert_eq!((collected.blocks, collected.seen), (1, 0b100));
        assert_eq!(api::free(third.as_ptr()), api::FreeOutcome::Freed);
        heaps::heap_collect(heap, true);
        let mut drained = Visit::new(heap, [(0, 0); 3], 0);
        assert!(visit(heap, true, &mut drained));
        assert!(drained.valid);
        assert_eq!((drained.areas, drained.blocks), (0, 0));
        assert_eq!(heaps::theap_get_default(), default);
        assert!(heaps::heap_release(heap, true));
        assert!(heaps::heap_release(reentry_heap, true));
    }
}
