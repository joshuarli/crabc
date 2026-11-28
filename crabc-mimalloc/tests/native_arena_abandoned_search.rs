// Rust half of the pinned abandoned-page search differential in
// `compat/allocator/m2_arena_abandoned_search_x86_64.{c,py}`. Three reserved
// arenas and two non-main Heaps reach the source search through the public
// Heap entry points; each observation prints the same field as the C oracle.
#![cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "native-runtime-test-audit"))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ffi::c_void;
use core::ptr::null_mut;

use crabc_mimalloc::__crabc_runtime::{
    NativeRuntimeArenaSpanTestAudit, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_runtime_arena_span_state_test_audit,
    native_runtime_live_client_arena_span_test_audit,
};
use crabc_mimalloc::source_api as api;
use crabc_mimalloc::source_heap_api as heaps;

const ARENA_SIZE: usize = 64 * 1024 * 1024;
const REQUEST: usize = 32 * 1024;
const CLIENTS: usize = 4096;
const STRIDE: usize = 16;
const SIBLINGS: usize = 5;
const PAGE_BLOCKS: usize = 16;

fn emit(name: &str, value: i64) {
    println!("m2.arena_abandoned_search.{name}={value}");
}

fn on_worker<R: Send + 'static>(work: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let result = work();
        assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
        result
    })
    .join()
    .expect("the worker completes")
}

struct Search {
    arenas: [usize; 3],
    freed: Vec<usize>,
}

impl Search {
    fn arena_of(&self, block: usize) -> i64 {
        self.arenas.iter()
            // SAFETY: every reserved arena stays published for the test.
            .position(|arena| unsafe { heaps::arena_contains(*arena as *mut c_void, block as *const c_void) })
            .map_or(-1, |index| index as i64)
    }

    fn take_freed(&mut self, block: usize) -> i64 {
        match self.freed.iter().position(|freed| *freed == block) {
            Some(index) => {
                self.freed.swap_remove(index);
                1
            }
            None => 0,
        }
    }
}

fn heap_allocate(heap: usize) -> usize {
    // SAFETY: the Heap stays live until the final release below.
    let block = unsafe { heaps::heap_malloc(heap as *mut c_void, REQUEST) }.value
        .expect("a medium Heap request allocates");
    block.as_ptr() as usize
}

fn probe(heap: Option<usize>) -> usize {
    on_worker(move || match heap {
        Some(heap) => heap_allocate(heap),
        None => api::malloc(REQUEST).value.expect("a medium request allocates").as_ptr() as usize,
    })
}

fn step(search: &mut Search, heap: usize, name: &str) -> usize {
    let block = probe(Some(heap));
    emit(&format!("{name}.reclaimed"), search.take_freed(block));
    emit(&format!("{name}.arena"), search.arena_of(block));
    block
}

fn free(block: usize) {
    // SAFETY: every caller passes one exact live client exactly once.
    assert_eq!(unsafe { api::free(block as *mut u8) }, api::FreeOutcome::Freed);
}

fn registry_count(block: usize) -> i64 {
    // SAFETY: the client is live and every worker has joined.
    let span: NativeRuntimeArenaSpanTestAudit = unsafe {
        native_runtime_live_client_arena_span_test_audit(core::ptr::NonNull::new(block as *mut u8).unwrap())
    }.expect("a live medium client names an arena span");
    // SAFETY: as above; no allocator operation runs concurrently.
    unsafe { native_runtime_arena_span_state_test_audit(span) }
        .expect("the published span remains auditable")
        .arena_registry_count as i64
}

#[test]
fn abandoned_page_search_follows_the_source_arena_and_heap_order() {
    let page_size = crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ");
    assert!(native_runtime_test_support::initialize(page_size));
    let mut arenas = [0usize; 3];
    for arena in &mut arenas {
        let mut id = null_mut();
        // SAFETY: the output is this local slot; the arena stays published.
        assert_eq!(unsafe { heaps::reserve_os_memory_ex(ARENA_SIZE, true, false, false, &mut id) }.value, 0);
        assert!(!id.is_null());
        *arena = id as usize;
    }
    let other = heaps::heap_new() as usize;
    let heap = heaps::heap_new() as usize;
    assert!(other != 0 && heap != 0);

    let (mut clients, freed) = on_worker(move || {
        let mut clients: Vec<usize> = (0..CLIENTS).map(|_| heap_allocate(heap)).collect();
        let mut freed = Vec::new();
        for index in (0..CLIENTS).step_by(STRIDE) {
            freed.push(clients[index]);
            free(clients[index]);
            clients[index] = 0;
        }
        (clients, freed)
    });
    let mut search = Search { arenas, freed };
    let mut placement = [0i64; 3];
    for block in &search.freed {
        let arena = search.arena_of(*block);
        assert!(arena >= 0);
        placement[arena as usize] += 1;
    }
    let live = *clients.iter().find(|client| **client != 0).expect("a live client remains");
    emit("registry", registry_count(live));
    emit("placement.0", placement[0]);
    emit("placement.1", placement[1]);
    emit("placement.2", placement[2]);

    let mut other_clients = on_worker(move || {
        let clients: Vec<usize> = (0..PAGE_BLOCKS).map(|_| heap_allocate(other)).collect();
        free(clients[0]);
        clients
    });
    let other_freed = core::mem::take(&mut other_clients[0]);
    emit("other.placement", search.arena_of(other_freed));
    let main_block = probe(None);
    emit("main.reclaimed", search.take_freed(main_block));

    let mut steps = vec![step(&mut search, heap, "first")];
    let siblings: Vec<usize> = (0..SIBLINGS).map(|_| heaps::heap_new() as usize).collect();
    assert!(siblings.iter().all(|sibling| *sibling != 0));
    steps.push(step(&mut search, heap, "siblings"));
    for sibling in siblings {
        // SAFETY: each sibling is empty, live and used by no other thread.
        assert!(unsafe { heaps::heap_release(sibling as *mut c_void, false) });
    }
    steps.push(step(&mut search, heap, "released"));

    let freed = core::mem::take(&mut search.freed);
    let (drained, fresh, remaining) = on_worker(move || {
        let mut freed = freed;
        let mut drained = Vec::new();
        let fresh = loop {
            let block = heap_allocate(heap);
            match freed.iter().position(|candidate| *candidate == block) {
                Some(index) => {
                    freed.swap_remove(index);
                    drained.push(block);
                }
                None => break block,
            }
        };
        (drained, fresh, freed)
    });
    let arenas: Vec<i64> = drained.iter().map(|block| search.arena_of(*block)).collect();
    let mut segments = 0;
    let mut index = 0;
    while index < arenas.len() {
        let run = arenas[index..].iter().take_while(|arena| **arena == arenas[index]).count();
        emit(&format!("drain.{segments}.arena"), arenas[index]);
        emit(&format!("drain.{segments}.count"), run as i64);
        segments += 1;
        index += run;
    }
    emit("drain.segments", segments);
    emit("drain.fresh", 1);
    emit("drain.remaining", remaining.len() as i64);
    let foreign = probe(Some(other));
    emit("other.reclaimed", i64::from(foreign == other_freed));
    emit("other.arena", search.arena_of(foreign));

    free(fresh);
    for block in drained.into_iter().chain(steps).chain([foreign, main_block]) {
        free(block);
    }
    for client in clients.drain(..).chain(other_clients).filter(|client| *client != 0) {
        free(client);
    }
    // SAFETY: both Heaps are live, every client has been freed and no other
    // thread uses them.
    assert!(unsafe { heaps::heap_release(heap as *mut c_void, false) });
    assert!(unsafe { heaps::heap_release(other as *mut c_void, false) });
}
