#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    native_collect, native_block_size, native_runtime_terminal_vm_current_test_audit, native_runtime_lifecycle_test_audit,
    TicketZeroPageAllocationResult, finish_current_thread_native_after_user_destructors, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, native_runtime_test_fail_next_unmap,
    prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
    TicketZeroPageFreeResult,
};

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


/// Allocates a source-shaped mixed exit image, but returns only its
/// OS-aligned client. The other live members make A follow normal
/// collect-abandon before B supplies the exact client to PageMap dispatch.
fn allocate_mixed_owner_exit_aggregate() -> usize {
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
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates the mixed aggregate's OS-aligned singleton"),
    };
    assert_eq!(
        os_singleton.as_ptr().addr() % (128 * 1024),
        0,
        "the exact source client reaches the OS-backed terminal-release path"
    );
    os_singleton.as_ptr().addr()
}

#[test]
fn native_post_exit_failed_os_release_is_terminal_without_retaining_worker_admission() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the failed-OS-release witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before A borrows the dormant pair"
    );

    let (owner_sender, owner_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        owner_sender
            .send(allocate_mixed_owner_exit_aggregate())
            .expect("A gives B only the exact OS client before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A's persistent owner completes collect-abandon before B's pointer free"
        );
    });
    let os_singleton = owner_receiver
        .recv()
        .expect("the coordinator receives B's one exact source client");
    owner
        .join()
        .expect("A completes the source Theap/TLD teardown before B starts");
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A's persistent owner releases its worker admission at the owner-exit boundary"
    );

    let consumer = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "B owns the one current worker admission before its foreign pointer free"
        );
        // SAFETY: A supplied this exact still-live OS-aligned client before
        // its source owner exited. B has no owner or release capability for
        // this address; `native_free` must begin with the PageMap lookup.
        let os_singleton = unsafe { core::ptr::NonNull::new_unchecked(os_singleton as *mut u8) };
        let before_map = native_runtime_lifecycle_test_audit().unwrap();
        let before_vm = vm_current();
        // SAFETY: the joined former owner left this exact singleton client live.
        let committed_extent = unsafe { native_block_size(os_singleton) }.unwrap();
        let unmap_failure = native_runtime_test_fail_next_unmap();
        let capture = unmap_failure.capture_range();
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Freed,
            "the failed raw unmap does not reopen the consumed source Page free"
        );
        let failed_range = capture.single().expect("one exact refused source unmap");
        let after_vm = vm_current();
        assert_eq!(before_vm.0 - after_vm.0, failed_range.1 as i64,
            "source release retires reserved bytes even when raw unmap fails");
        assert_eq!(failed_range.0 + failed_range.1 - os_singleton.as_ptr().addr(), committed_extent,
            "this singleton follows the uncommitted alignment prefix in its raw reservation");
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
            "B attempts exactly the one injected terminal source unmap"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "the consumed source does not manufacture a second worker admission"
        );
        // The failed unmap leaves its raw range after consuming PageMap removal, so
        // this stale client can neither resolve a page nor retry the tail.
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::InvalidPointer,
            "the completed PageMap removal rejects a retry through the old pointer"
        );
        let finish = finish_current_thread_native_after_user_destructors();
        (unmap_failure.observed(), finish, failed_range)
    });
    let (unmap_attempts, consumer_finish, failed_range) = consumer
        .join()
        .expect("B finishes independently of A's consumed terminal source");
    assert_eq!(
        unmap_attempts,
        1,
        "neither the repeated pointer free nor B's teardown retries the failed terminal unmap"
    );
    assert_eq!(
        consumer_finish,
        ThreadFinishResult::Finished,
        "A's consumed source Page free does not retain B's independent owner"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's finish releases its own admission without reconstructing A's"
    );

    // The refused raw mapping holds no source Page owner or PageMap mutation lease. An unrelated
    // initial owner can still allocate and free through its own page state.
    let independent = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("a retained OS mapping leaves the independent initial owner usable"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(independent) },
        TicketZeroPageFreeResult::Freed,
        "the independent owner still releases its local client"
    );
    assert_failed_range_stays_mapped(failed_range);
}
