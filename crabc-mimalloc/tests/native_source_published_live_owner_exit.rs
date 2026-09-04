use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, prepare_native_later_thread_arena,
};

const SOURCE_PUBLISHED_REQUEST: usize = 37;
const LIVE_SIBLING_REQUEST: usize = 64 * 1024;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn joined_source_publication_collects_before_live_sibling_owner_exit() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the source-publication witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner publishes the later-owner state"
    );

    let (live_sender, live_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let source_published = match native_allocate_aligned(SOURCE_PUBLISHED_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the source-published direct-small client"),
        };
        let live_sibling = match native_allocate_aligned(LIVE_SIBLING_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A retains the independent live medium sibling"),
        };

        let source_published = source_published.as_ptr().addr();
        std::thread::scope(|scope| {
            let publisher = scope.spawn(move || {
                assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                // SAFETY: A keeps this exact direct-small client live until
                // the joined publisher has completed its pointer-first free.
                let source_published = unsafe {
                    core::ptr::NonNull::new_unchecked(source_published as *mut u8)
                };
                assert_eq!(
                    unsafe { native_free(source_published) },
                    NativePageFreeResult::Freed,
                    "the joined publisher records A's source-page remote free"
                );
                assert_eq!(
                    finish_current_thread_native_after_user_destructors(),
                    ThreadFinishResult::Finished,
                    "the joined publisher completes its own lifecycle before A exits"
                );
            });
            publisher
                .join()
                .expect("the source publisher remains joined to A's live owner");
        });

        live_sender
            .send(live_sibling.as_ptr().addr())
            .expect("the coordinator receives only A's surviving medium client");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A collects the joined source publication and abandons its live sibling"
        );
    });

    let live_sibling = live_receiver
        .recv()
        .expect("the coordinator receives A's surviving client before owner exit");
    owner
        .join()
        .expect("A completes source collect-abandon before the post-exit free");

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A supplied this exact still-live medium address before its
        // collect-abandon exit. The fresh releaser must use pointer-derived
        // PageMap/page facts; it receives no source route or client ledger.
        let live_sibling = unsafe {
            core::ptr::NonNull::new_unchecked(live_sibling as *mut u8)
        };
        assert_eq!(
            unsafe { native_free(live_sibling) },
            NativePageFreeResult::Freed,
            "the fresh releaser frees A's abandoned sibling through pointer state"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the fresh releaser finishes independently of the exited owner"
        );
    });
    releaser
        .join()
        .expect("the fresh releaser completes the post-exit lifecycle");
}
