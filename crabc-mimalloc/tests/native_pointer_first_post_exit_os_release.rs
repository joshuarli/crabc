// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. Keep the narrow audit and fault-only witness inert unless
// its existing direct-test features are explicitly selected.
#![cfg(all(
    feature = "native-runtime-test-audit",
    feature = "native-runtime-test-fault"
))]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;



use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    native_collect, native_runtime_terminal_vm_current_test_audit,
    finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_free, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, native_runtime_test_fail_next_unmap,
    prepare_native_later_thread_arena,
};

const OS_ALIGNMENT: usize = 128 * 1024;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}
fn assert_failed_range_stays_mapped(range: (usize, usize)) {
    let page_size = current_page_size();
    assert_eq!(range.0 % page_size, 0);
    assert_eq!(range.1 % page_size, 0);
    assert!(range.1 > 0);
    for offset in (0..range.1).step_by(page_size) {
        let mut residency = 0u8;
        // SAFETY: this kernel observation uses the captured raw mapping extent
        // and a live output byte; it never dereferences the consumed client.
        assert!(unsafe { crabc_core::mm::mincore_raw(
            (range.0 + offset) as *mut u8, page_size, &mut residency,
        ) }.is_ok(), "every page of the refused source release stays mapped");
    }
}

fn vm_current() -> (i64, i64) {
    let state = native_runtime_terminal_vm_current_test_audit()
        .expect("the source subprocess retains its VM counters");
    (state.reserved, state.committed)
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
/// tail. A failed raw unmap consumes the source Page after its retirement;
/// the refused mapping cannot retry through a former worker or a second publication.
#[test]
fn native_free_pointer_first_post_exit_os_release_is_terminal_without_retry() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the pointer-first post-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the source arena before A creates the mixed exit image"
    );

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
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
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);

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
        let before_map = native_runtime_lifecycle_test_audit().unwrap();
        let before_vm = vm_current();
        let unmap_failure = native_runtime_test_fail_next_unmap();
        let capture = unmap_failure.capture_range();
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Freed,
            "the source Page free consumes its client despite the refused raw unmap"
        );
        let failed_range = capture.single().expect("one exact refused source unmap");
        let after_vm = vm_current();
        assert_eq!(before_vm.0 - after_vm.0, failed_range.1 as i64,
            "source release retires reserved bytes even when raw unmap fails");
        // This alignment-forced singleton begins at the source slice start.
        // Its reservation also includes a preceding uncommitted alignment area.
        let committed_extent = failed_range.0 + failed_range.1 - os_singleton.as_ptr().addr();
        assert!(committed_extent > 0 && committed_extent < failed_range.1);
        assert_eq!(before_vm.1 - after_vm.1, committed_extent as i64,
            "source release retires the committed Page extent, excluding its alignment prefix");
        let after_map = native_runtime_lifecycle_test_audit().unwrap();
        assert!(after_map.page_map_registered_entry_count < before_map.page_map_registered_entry_count,
            "consumed source Page release removes its PageMap coverage");
        assert_eq!(after_map.main_heap_os_abandoned_pages_empty, 1,
            "unabandon removes the consumed source Page from the OS list");
        assert_failed_range_stays_mapped(failed_range);
        native_collect(true);
        assert_eq!(vm_current(), after_vm, "collection cannot retire the failed source free twice");
        assert_failed_range_stays_mapped(failed_range);
        let recovery = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("an independent client remains allocatable after consumed source release"),
        };
        assert_ne!(recovery, os_singleton);
        // SAFETY: this distinct successful client is exclusively owned here.
        unsafe { recovery.as_ptr().write_bytes(0x5a, 73) };
        assert_eq!(unsafe { native_free(recovery) }, NativePageFreeResult::Freed);
        native_collect(true);
        assert_failed_range_stays_mapped(failed_range);
        assert_eq!(
            unmap_failure.observed(),
            1,
            "the terminal PageMap-owned tail attempts exactly one injected munmap"
        );
        // PageMap removal completed before the failed unmap. The refused
        // raw range has no live client registration or automatic retry owner.
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::InvalidPointer,
            "the completed PageMap removal rejects a second source publication"
        );
        assert_eq!(
            unmap_failure.observed(),
            1,
            "a second pointer free does not retry the failed terminal unmap"
        );
        (
            unmap_failure.observed(),
            finish_current_thread_native_after_user_destructors(),
            failed_range,
        )
    });
    let (unmap_attempts, releaser_finish, failed_range) = releaser
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
        "A's consumed source Page free does not retain B's independently empty owner"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's finished teardown releases its own admission without reviving A's consumed Page"
    );
    assert_failed_range_stays_mapped(failed_range);
}
