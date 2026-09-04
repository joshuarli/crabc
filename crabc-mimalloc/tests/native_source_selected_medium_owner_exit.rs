use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, prepare_native_later_thread_arena,
};

// These ordinary, naturally aligned requests select distinct pinned regular
// classes: the first becomes a large source page and the later two stay in one
// medium source page. They intentionally do not select singleton geometry.
const RETIRED_LARGE_REQUEST: usize = 128 * 1024;
const LIVE_MEDIUM_REQUEST: usize = 64 * 1024;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_owner_exit_selects_live_medium_after_retired_large_prepass() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the source-selected medium witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner publishes the later-owner state"
    );

    let (live_sender, live_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let retired_large = match native_allocate_aligned(RETIRED_LARGE_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the regular-large source page"),
        };
        let live_medium = match native_allocate_aligned(LIVE_MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the live medium source page"),
        };
        let medium_spare = match native_allocate_aligned(LIVE_MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the medium local-free witness"),
        };

        assert_eq!(
            unsafe { native_free(medium_spare) },
            NativePageFreeResult::Freed,
            "A returns one exact local medium block before owner exit"
        );
        assert_eq!(
            unsafe { native_free(retired_large) },
            NativePageFreeResult::Freed,
            "A leaves the distinct regular-large page for source retirement"
        );
        live_sender
            .send(live_medium.as_ptr().addr())
            .expect("the coordinator receives only the still-live medium client");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A releases its retired large page before abandoning the source-selected live medium"
        );
    });

    let live_medium = live_receiver
        .recv()
        .expect("the coordinator receives A's live medium before owner exit");
    owner
        .join()
        .expect("A completes the source-ordered owner-exit traversal");

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A completed source owner exit after sending this exact live
        // client. B has no former-Theap or geometry capability; it exercises
        // only the normal pointer-derived post-exit free.
        let live_medium = unsafe {
            core::ptr::NonNull::new_unchecked(live_medium as *mut u8)
        };
        assert_eq!(
            unsafe { native_free(live_medium) },
            NativePageFreeResult::Freed,
            "B releases the one source-selected medium through PageMap state"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes independently after the post-exit medium free"
        );
    });
    releaser
        .join()
        .expect("B completes the source-selected medium release");
}
