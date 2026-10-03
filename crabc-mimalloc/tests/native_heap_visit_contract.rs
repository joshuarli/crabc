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
            // This visited Heap is non-main. Creating and releasing a sibling
            // changes its subprocess list links and main-Heap metadata, while
            // leaving every visited page and retained client untouched.
            let sibling = heaps::heap_new();
            if sibling.is_null() { visit.valid = false; }
            else { visit.valid &= unsafe { heaps::heap_release(sibling, true) }; }
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

fn public_theap_visitation_finds_one_live_calloc_block() {
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

fn public_heap_visitation_tracks_live_population_early_stop_and_collection() {
    let default = heaps::theap_get_default();
    let reentry_heap = heaps::heap_new();
    let heap = heaps::heap_new();
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
        stop_area.reentry_heap = reentry_heap;
        assert!(!visit(heap, false, &mut stop_area));
        assert!(stop_area.valid);
        assert!(stop_area.reentered);
        assert_eq!((stop_area.areas, stop_area.blocks), (1, 0));
        let mut stop_block = Visit::new(heap, clients, 2);
        stop_block.reentry_heap = reentry_heap;
        assert!(!visit(heap, true, &mut stop_block));
        assert!(stop_block.valid);
        assert!(stop_block.reentered);
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

fn abandoned_heap_visitation_keeps_reentrant_callbacks_outside_owner_views() {
    let reentry_heap = heaps::heap_new();
    let heap = heaps::heap_new();
    assert!(!heap.is_null() && !reentry_heap.is_null());
    let heap_address = heap as usize;
    let clients = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let heap = heap_address as *mut c_void;
        let clients = [64, 64, 256].map(|size| {
            // SAFETY: the coordinator retains the Heap through worker exit,
            // subsequent quiescent traversal, client frees and final release.
            let client = unsafe { heaps::heap_malloc(heap, size) }.value.unwrap();
            (client.as_ptr() as usize, size)
        });
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        clients
    }).join().unwrap();
    // Joining ends all owner and remote producers. The callback only changes
    // a distinct sibling Heap; these retained abandoned pages stay quiescent.
    unsafe {
        for (blocks, stop_after, completed) in [(true, 0, true), (false, 1, false), (true, 2, false)] {
            let mut capture = Visit::new(heap, clients, stop_after);
            capture.reentry_heap = reentry_heap;
            assert_eq!(heaps::heap_visit_abandoned_blocks(heap, blocks, Some(observe),
                (&mut capture as *mut Visit).cast()), completed);
            assert!(capture.valid && capture.reentered);
            if completed { assert_eq!((capture.blocks, capture.seen), (3, 0b111)); }
            else { assert_eq!((capture.areas, capture.blocks), (1, usize::from(blocks))); }
        }
        let mut repeated = Visit::new(heap, clients, 0);
        assert!(visit(heap, true, &mut repeated));
        assert!(repeated.valid);
        assert_eq!((repeated.blocks, repeated.seen), (3, 0b111));
        for (client, _) in clients { assert_eq!(api::free(client as *mut u8), api::FreeOutcome::Freed); }
        assert!(heaps::heap_release(heap, true));
        assert!(heaps::heap_release(reentry_heap, true));
    }
}

#[test]
fn public_heap_and_theap_visitation_preserve_live_population_after_prior_heap_history() {
    // Process startup owns the initial thread's allocator descriptor. Keep
    // both histories on that same live thread instead of treating a later
    // libtest worker as another initial process thread.
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ).unwrap();
    assert!(native_runtime_test_support::initialize(page_size));
    abandoned_visitation_rotates_arenas_with_captured_heap_population();
    public_heap_visitation_tracks_live_population_early_stop_and_collection();
    std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        public_theap_visitation_finds_one_live_calloc_block();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    }).join().unwrap();
    public_theap_visitation_finds_one_live_calloc_block();
    public_heap_visitation_tracks_live_population_early_stop_and_collection();
    abandoned_heap_visitation_keeps_reentrant_callbacks_outside_owner_views();
}

fn abandoned_visitation_rotates_arenas_with_captured_heap_population() {
    struct Rotation {
        heap: *mut c_void,
        other: *mut c_void,
        arenas: [*mut c_void; 3],
        clients: Vec<usize>,
        seen: Vec<bool>,
        order: Vec<usize>,
        siblings: Vec<*mut c_void>,
        reenter: bool,
        stop: bool,
        count: usize,
    }
    unsafe extern "C" fn observe_rotation(
        heap: *const c_void, area: *const heaps::HeapArea, block: *mut c_void,
        block_size: usize, argument: *mut c_void,
    ) -> bool {
        // SAFETY: this synchronous callback has the unique capture. Its
        // allocations use another retained Heap and never change visited
        // pages or clients. All arena mappings stay published through it.
        unsafe {
            let capture = &mut *argument.cast::<Rotation>();
            assert_eq!(heap, capture.heap.cast_const());
            assert!(!area.is_null() && block_size > 0);
            if block.is_null() {
                if capture.reenter {
                    capture.reenter = false;
                    let client = heaps::heap_malloc(capture.other, 33).value.unwrap();
                    assert_eq!(api::free(client.as_ptr()), api::FreeOutcome::Freed);
                    for _ in 0..5 {
                        let sibling = heaps::heap_new();
                        assert!(!sibling.is_null());
                        capture.siblings.push(sibling);
                    }
                }
                return true;
            }
            let index = capture.clients.iter().position(|client| *client == block as usize).unwrap();
            assert!(!capture.seen[index]);
            capture.seen[index] = true;
            let arena = capture.arenas.iter().position(|arena| heaps::arena_contains(*arena, block)).unwrap();
            if !capture.order.contains(&arena) { capture.order.push(arena); }
            capture.count += 1;
            !capture.stop
        }
    }
    // SAFETY: all reserved arenas, both Heaps, and every live allocation
    // remain retained until the joined owner and every callback finish.
    unsafe {
        let mut arenas = [null_mut(); 3];
        for arena in &mut arenas {
            assert_eq!(heaps::reserve_os_memory_ex(64 * 1024 * 1024, true, false, false, arena).value, 0);
            assert!(!arena.is_null());
        }
        let other = heaps::heap_new();
        let heap = heaps::heap_new();
        assert!(!other.is_null() && !heap.is_null());
        let selected = heap as usize;
        let clients = std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            let mut clients = Vec::new();
            // Keep the same full source block class when its padding word
            // is enabled, so each medium page has sixteen client slots.
            let padding = if cfg!(any(feature = "mi-debug-1", feature = "mi-secure-3")) { 8 } else { 0 };
            for _ in 0..4096 {
                clients.push(heaps::heap_malloc(selected as *mut c_void, 32 * 1024 - padding).value.unwrap().as_ptr() as usize);
            }
            // Leave ordinary source pages partially occupied: full arena
            // pages are deliberately absent from abandoned-bin visitation.
            for index in (0..clients.len()).step_by(16) {
                assert_eq!(api::free(clients[index] as *mut u8), api::FreeOutcome::Freed);
                clients[index] = 0;
            }
            assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            clients
        }).join().unwrap();
        let mut capture = Rotation { heap, other, arenas, clients, seen: vec![false; 4096],
            order: Vec::new(), siblings: Vec::new(), reenter: false, stop: false, count: 0 };
        let run = |capture: &mut Rotation, reenter: bool, stop: bool, expected: &[usize]| {
            capture.seen.fill(false);
            capture.order.clear();
            capture.count = 0;
            capture.reenter = reenter;
            capture.stop = stop;
            assert_eq!(heaps::heap_visit_abandoned_blocks(heap, true, Some(observe_rotation),
                (capture as *mut Rotation).cast()), !stop);
            assert_eq!(capture.order, expected);
            assert_eq!(capture.count, if stop { 1 } else { 3840 });
            if !stop {
                for (client, seen) in capture.clients.iter().zip(&capture.seen) {
                    assert_eq!(*seen, *client != 0);
                }
            }
        };
        // The fresh Heap sequences and live Heap population place this Heap
        // in the middle of the source's cycle below the final arena. Changes
        // made by its callback affect the next traversal, not the current one.
        run(&mut capture, false, false, &[1, 0, 2]);
        run(&mut capture, true, true, &[1]);
        run(&mut capture, false, false, &[0, 1, 2]);
        for sibling in capture.siblings.drain(..) { assert!(heaps::heap_release(sibling, true)); }
        run(&mut capture, false, false, &[1, 0, 2]);
        run(&mut capture, true, false, &[1, 0, 2]);
        run(&mut capture, false, false, &[0, 1, 2]);
        run(&mut capture, false, true, &[0]);
        for sibling in capture.siblings.drain(..) { assert!(heaps::heap_release(sibling, true)); }
        run(&mut capture, false, false, &[1, 0, 2]);
        for client in capture.clients.into_iter().filter(|client| *client != 0) {
            assert_eq!(api::free(client as *mut u8), api::FreeOutcome::Freed);
        }
        assert!(heaps::heap_release(heap, true));
        assert!(heaps::heap_release(other, true));
    }
}
