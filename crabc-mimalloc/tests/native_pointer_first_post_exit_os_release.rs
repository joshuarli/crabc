// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. Keep the narrow audit and fault-only witness inert unless
// its existing direct-test features are explicitly selected.
#![cfg(all(
    feature = "native-runtime-test-audit",
    feature = "native-runtime-test-fault"
))]

use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_post_exit_registry_test_audit,
    native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, native_runtime_test_fail_next_unmap,
    prepare_native_later_thread_arena,
};

const OS_ALIGNMENT: usize = 128 * 1024;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// General pointer-first no-registry evidence: consuming an exited worker's
/// PageMap-owned source must not resurrect the retired exact-client route
/// bridge.
fn assert_general_pointer_first_no_registry(context: &str) {
    let audit = native_post_exit_registry_test_audit();
    assert_eq!(
        audit.published_entry_count, 0,
        "{context}: pointer-first dispatch publishes no post-exit route metadata"
    );
    assert_eq!(
        audit.live_entry_count, 0,
        "{context}: pointer-first dispatch keeps no route storage live"
    );
    assert_eq!(
        audit.retained_entry_count, 0,
        "{context}: pointer-first dispatch retains no route storage"
    );
}

/// Builds the source-shaped mixed exit image but returns only its OS client.
/// The other members keep this regression on the pinned aggregate source
/// drain rather than declaring a standalone geometry route. The later free
/// receives no owner, route, client ledger, scheduler, PageMap, or release
/// capability: it starts only with the exact C-shaped client address.
fn allocate_mixed_owner_exit_aggregate_os_singleton() -> usize {
    for (request, alignment, name) in [
        (37, 16, "direct-small"),
        (1025, 16, "non-direct-small"),
        (64 * 1024, 16, "medium"),
        (128 * 1024, 16, "large"),
        (1024 * 1024, 16, "arena singleton"),
    ] {
        assert!(
            matches!(
                native_allocate_aligned(request, alignment, false),
                NativePageAllocationResult::Allocated(_)
            ),
            "A allocates the mixed aggregate's {name} member"
        );
    }
    let block = match native_allocate_aligned(7, OS_ALIGNMENT, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates the mixed aggregate's OS-aligned singleton"),
    };
    assert_eq!(
        block.as_ptr().addr() % OS_ALIGNMENT,
        0,
        "the exact C-shaped input is backed by the selected OS singleton tail"
    );
    block.as_ptr().addr()
}

/// Pinned v3.5.0 `free.c` lets the producer that claims an abandoned remote
/// head run collection before the `arena.c` OS-list/bitmap/PageMap/backing
/// tail. A failed unmap therefore retains that exact post-CAS source owner;
/// it cannot retry through a former worker or a second pointer publication.
#[test]
fn native_free_pointer_first_post_exit_os_release_is_terminal_without_retry() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the pointer-first post-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the source arena before A creates the mixed exit image"
    );

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        owner_sender
            .send(allocate_mixed_owner_exit_aggregate_os_singleton())
            .expect("A gives the later free only an exact C-shaped address");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before the pointer free"
        );
    });
    let os_singleton = owner_receiver
        .recv()
        .expect("the initial thread receives A's one exact C-shaped input");
    owner
        .join()
        .expect("A completes the source Theap/TLD owner-exit boundary");

    assert_general_pointer_first_no_registry(
        "A's direct collect-abandon exit leaves only PageMap/process ownership",
    );

    let after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("the exited source leaves a quiescent PageMap audit");
    assert!(
        after_owner_exit.page_map_registered_entry_count >= 1,
        "the source exit leaves the OS singleton registered for pointer-to-page dispatch"
    );
    assert_eq!(
        after_owner_exit.main_heap_os_abandoned_pages_empty,
        0,
        "the selected OS source page remains on its page-owned abandoned list"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "source owner exit releases its worker admission before a later pointer free"
    );

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        // B first owns and releases an unrelated local client. Its later
        // foreign free receives only A's raw C-shaped address: no A owner,
        // route, ledger, scheduler token, PageMap capability, or terminal
        // release capability crosses this thread boundary.
        let local = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B establishes an independent local owner before the foreign free"),
        };
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B's own pointer remains a local free before it submits A's address"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B owns only its own active admission before the foreign pointer dispatch"
        );

        // SAFETY: A supplied this exact current native client before its
        // source owner exited. The PageMap registration keeps it
        // lookup-visible through this source-state dispatch attempt.
        let os_singleton = unsafe { core::ptr::NonNull::new_unchecked(os_singleton as *mut u8) };
        let unmap_failure = native_runtime_test_fail_next_unmap();
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Retained,
            "the PageMap-derived OS terminal release retains its exact failed source owner"
        );
        assert_eq!(
            unmap_failure.observed(),
            1,
            "the terminal PageMap-owned tail attempts exactly one injected munmap"
        );
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Retained,
            "the retained terminal owner is not reopened into a second source publication"
        );
        assert_eq!(
            unmap_failure.observed(),
            1,
            "a second pointer free does not retry the failed terminal unmap"
        );
        (
            unmap_failure.observed(),
            finish_current_thread_native_after_user_destructors(),
        )
    });
    let (unmap_attempts, releaser_finish) = releaser
        .join()
        .expect("B releases only its independent local owner after A's terminal failure");
    assert_eq!(
        unmap_attempts,
        1,
        "B's teardown cannot reopen A's terminal release for a second munmap"
    );
    assert_eq!(
        releaser_finish,
        ThreadFinishResult::Finished,
        "A's retained source claim does not retain B's independently empty owner"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's finished teardown releases its own admission without reviving A's retained claim"
    );
    assert_general_pointer_first_no_registry(
        "B's failed pointer-first terminal release does not create a route completion",
    );
}
