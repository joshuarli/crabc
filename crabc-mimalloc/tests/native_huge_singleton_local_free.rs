#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, current_native_allocator_thread_descriptor,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_usable_size, prepare_native_later_thread_arena,
    register_current_native_allocator_worker_descriptor,
};

// A singleton page area larger than `MI_LARGE_PAGE_SIZE` (4 MiB) is the case
// where pinned `mi_page_map_get_idx` clips the registered PageMap range to
// the furthest interior pointer. The 2 MiB request stays below that clip.
const REQUESTS: [usize; 3] = [2 * 1024 * 1024, 4 * 1024 * 1024, 5 * 1024 * 1024];

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Allocates, touches, queries, and frees each huge request on the calling
/// owner. A legal free of a live block must never be refused or retained.
fn allocate_and_free_locally(owner: &str) {
    for size in REQUESTS {
        let block = match native_allocate_aligned(size, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("{owner} allocates {size} bytes"),
        };
        // SAFETY: `block` is this owner's live client of at least `size` bytes.
        unsafe {
            block.as_ptr().write(0x3c);
            block.as_ptr().add(size - 1).write(0xc3);
            assert!(
                native_usable_size(block).is_some_and(|usable| usable >= size),
                "{owner} queries its live {size}-byte singleton"
            );
            assert_eq!(
                native_free(block),
                NativePageFreeResult::Freed,
                "{owner} frees its live {size}-byte singleton"
            );
        }
    }
}

#[test]
fn initial_and_worker_owners_free_their_own_huge_singletons() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the huge-singleton witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial owner prepares the later-owner source arena"
    );

    allocate_and_free_locally("the initial owner");

    std::thread::spawn(|| {
        // SAFETY: this test thread's TLS descriptor stays mapped through its
        // allocator finish below, and no terminal writer runs in this process.
        assert!(unsafe {
            register_current_native_allocator_worker_descriptor(
                current_native_allocator_thread_descriptor(),
            )
        });
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        allocate_and_free_locally("a worker owner");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished
        );
    })
    .join()
    .expect("the worker frees its huge singletons and finishes");

    allocate_and_free_locally("the initial owner after the worker exit");
}
