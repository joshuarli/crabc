use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, prepare_native_later_thread_arena,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// The initial thread is an ordinary foreign producer when the pointer names
/// a live later-worker page. Pointer-first `free` must therefore publish to
/// that page's source remote head before it considers ticket-zero ownership.
#[test]
fn native_free_dispatches_a_live_worker_pointer_before_caller_identity() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its pointer-first free witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before the live worker starts"
    );

    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (published_sender, published_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("the live worker creates the initial thread's remote client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("the live worker retains one local client while main publishes"),
        };
        remote_sender
            .send(remote.as_ptr().addr())
            .expect("the initial thread receives only the live C-shaped address");
        published_receiver
            .recv()
            .expect("the worker resumes only after the initial publication succeeds");
        let probe = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("the live worker resumes after the initial publication"),
        };
        // SAFETY: the probe and local client remain current in this owner;
        // its final source drain collects the initial thread publication.
        assert_eq!(unsafe { native_free(probe) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the live worker finishes after the remote client is consumed"
        );
    });

    let remote = remote_receiver
        .recv()
        .expect("the live worker publishes its client before main frees it");
    // SAFETY: the worker keeps this exact allocation live until this source
    // free attempt returns and sends the result back to the owner.
    let remote = unsafe { core::ptr::NonNull::new_unchecked(remote as *mut u8) };
    let free_result = unsafe { native_free(remote) };
    assert_eq!(
        free_result,
        NativePageFreeResult::Freed,
        "pointer-first free treats the initial thread as a foreign producer for a live worker page"
    );
    published_sender
        .send(())
        .expect("the owner resumes after the source publication succeeds");
    owner
        .join()
        .expect("the live worker cleans up after the initial free attempt");
}
