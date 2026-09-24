#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_usable_size, prepare_native_later_thread_arena,
    register_current_native_allocator_worker_descriptor,
};

// Larger than the 4 MiB `MI_LARGE_PAGE_SIZE` and smaller than the 32 MiB
// arena chunk object limit: pinned `mi_arenas_page_singleton_alloc` places
// this ordinary request in an arena, and `mi_page_map_get_idx` registers
// only the clipped `MI_LARGE_PAGE_SIZE - MI_ARENA_SLICE_SIZE` interior range
// rather than every arena slice of the singleton span.
const HUGE_ARENA_SINGLETON_REQUEST: usize = 5 * 1024 * 1024;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// One live C ABI client moved by value between test threads. It carries no
/// allocator ownership or release capability.
#[repr(transparent)]
struct LiveCClient(core::ptr::NonNull<u8>);

// SAFETY: A publishes the client before exiting and the initial thread frees
// it exactly once after joining A. No thread accesses it concurrently.
unsafe impl Send for LiveCClient {}

/// A worker allocates a huge arena singleton, exits, and is joined; the
/// initial thread then frees the surviving block. Pinned `free.c` claims the
/// abandoned singleton and `_mi_arenas_page_free` unregisters exactly the
/// PageMap range registered at allocation, so the terminal release completes
/// rather than retaining the page as an unreleasable terminal owner.
#[test]
fn initial_thread_releases_an_exited_workers_huge_arena_singleton() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the huge-singleton witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial owner prepares the later-owner source arena"
    );

    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        // SAFETY: this test thread's TLS descriptor stays mapped through its
        // allocator finish below, and no terminal writer runs in this process.
        assert!(unsafe {
            register_current_native_allocator_worker_descriptor(
                current_native_allocator_thread_descriptor(),
            )
        });
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(HUGE_ARENA_SINGLETON_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A allocates the huge arena singleton"),
        };
        // SAFETY: `block` is A's live client of at least the requested size.
        unsafe {
            block.as_ptr().write(0x5a);
            block.as_ptr().add(HUGE_ARENA_SINGLETON_REQUEST - 1).write(0xa5);
        }
        sender
            .send(LiveCClient(block))
            .expect("A publishes its surviving client before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon with its singleton still live"
        );
    });
    let client = receiver.recv().expect("the initial thread receives A's client");
    owner.join().expect("A reaches its completed owner-exit boundary");

    let block = client.0;
    // SAFETY: the abandoned client stays live until the free below.
    unsafe {
        assert_eq!(block.as_ptr().read(), 0x5a);
        assert_eq!(block.as_ptr().add(HUGE_ARENA_SINGLETON_REQUEST - 1).read(), 0xa5);
        assert!(
            native_usable_size(block).is_some_and(|size| size >= HUGE_ARENA_SINGLETON_REQUEST),
            "the abandoned singleton stays PageMap-queryable before its free"
        );
        assert_eq!(
            native_free(block),
            NativePageFreeResult::Freed,
            "the terminal free releases the abandoned huge arena singleton"
        );
    }

    let after = match native_allocate_aligned(53, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the initial owner remains usable after the terminal release"),
    };
    assert_eq!(
        unsafe { native_free(after) },
        NativePageFreeResult::Freed,
        "the process was not retained by the huge-singleton release"
    );
}
