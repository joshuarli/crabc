// Rust half of the pinned `mi_abandoned_page_try_reclaim` differential in
// `compat/allocator/reclaim_on_free.{c,py}`. Each case runs on attached
// worker threads, frees through `native_free`, and prints the same fields as
// the C oracle: whether the freeing thread now owns the page, its `used`
// count, and the length of that thread's regular queue for the page's bin.
#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use core::ptr::NonNull;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors, native_allocate_aligned, native_free,
    native_runtime_current_local_page_test_audit, native_runtime_live_client_page_test_audit,
    prepare_native_later_thread_arena,
};

/// `native_runtime_current_local_page_test_audit`'s refusals for a thread
/// that has no page engine yet and for a page it does not own.
const NO_PAGE_ENGINE: i32 = -3;
const NOT_CURRENT_OWNER: i32 = -6;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate(size: usize) -> NonNull<u8> {
    match native_allocate_aligned(size, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the attached worker allocates a {size}-byte client"),
    }
}

fn free(block: NonNull<u8>) {
    // SAFETY: every caller passes one exact live client exactly once.
    assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
}

fn page_address(block: NonNull<u8>) -> usize {
    // SAFETY: `block` is live and its owner is not mutating it concurrently.
    unsafe { native_runtime_live_client_page_test_audit(block) }
        .expect("a live regular client has an arena page")
        .page_address()
}

fn is_abandoned_for_current_thread(block: NonNull<u8>) -> bool {
    // SAFETY: `block` is live; the observation is serialized with its page.
    matches!(
        unsafe { native_runtime_current_local_page_test_audit(block) },
        Err(NO_PAGE_ENGINE | NOT_CURRENT_OWNER)
    )
}

/// Prints the freeing thread's view of the page of one of its live blocks.
fn emit_page(name: &str, live: NonNull<u8>) {
    // SAFETY: `live` is still allocated and only this thread touches its page.
    let (reclaimed, used, queue_count) =
        match unsafe { native_runtime_current_local_page_test_audit(live) } {
            Ok(audit) => (1, audit.used, audit.regular_queue_count),
            Err(NO_PAGE_ENGINE | NOT_CURRENT_OWNER) => (0, 0, 0),
            Err(error) => panic!("{name}: the page audit failed with {error}"),
        };
    println!("reclaim.{name}.reclaimed={reclaimed}");
    println!("reclaim.{name}.used={used}");
    println!("reclaim.{name}.queue_count={queue_count}");
}

fn on_worker<R: Send + 'static>(work: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::spawn(move || {
        assert_eq!(
            native_runtime_test_support::attach_current_thread(),
            ThreadAttachResult::Attached
        );
        let result = work();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished
        );
        result
    })
    .join()
    .expect("the worker completes")
}

/// The worker allocates until a search moves its first page to full (after
/// `page_full_retain` newer full pages), which abandons it; the worker's own
/// free then meets that page's originating Theap.
fn own_full() {
    let first = allocate(64);
    let page = page_address(first);
    let mut blocks = vec![first];
    while !is_abandoned_for_current_thread(first) {
        blocks.push(allocate(64));
    }
    assert_eq!(page_address(blocks[1]), page);
    free(blocks[1]);
    emit_page("own_full", first);
    for block in blocks.drain(2..).rev() {
        free(block);
    }
    free(first);
}

/// Raw client addresses handed from an exited owner to the freeing worker.
struct Blocks([usize; 3]);

/// The freeing worker optionally owns one block of the same size class, runs
/// a foreign owner that allocates three blocks to its exit, and then frees
/// one of those three.
fn foreign(name: &'static str, size: usize, own_block_first: bool) {
    let own = own_block_first.then(|| allocate(size));
    let Blocks(addresses) = on_worker(move || {
        Blocks([0, 1, 2].map(|_| allocate(size).as_ptr() as usize))
    });
    let blocks = addresses.map(|address| NonNull::new(address as *mut u8).expect("a client"));
    assert!(is_abandoned_for_current_thread(blocks[0]), "the exited owner abandoned its page");
    free(blocks[2]);
    emit_page(name, blocks[0]);
    free(blocks[1]);
    free(blocks[0]);
    if let Some(own) = own {
        free(own);
    }
}

#[test]
fn reclaim_on_free_decisions_match_the_pinned_source() {
    assert!(native_runtime_test_support::initialize(current_page_size()));
    assert!(prepare_native_later_thread_arena());
    on_worker(own_full);
    on_worker(|| foreign("foreign_empty_queue", 80, false));
    on_worker(|| foreign("foreign_nonempty_queue", 96, true));
    on_worker(|| foreign("foreign_large", 86_699, false));
}
