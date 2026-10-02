// This is a direct process-lifetime regression. The scalar audit and one-shot
// unmap fault are both intentionally absent from ordinary allocator builds.
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
    TicketZeroPageAllocationResult, finish_current_thread_native_after_user_destructors, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, native_runtime_lifecycle_test_audit,
    native_runtime_test_fail_next_unmap, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free, TicketZeroPageFreeResult,
};

const OS_ALIGNMENT: usize = 128 * 1024;

/// One live C ABI client that crosses the test-thread boundary by value.
///
/// This is not allocator ownership, a route, or a release capability. The
/// synchronized test lifetime keeps its one allocation live through B's one
/// generic pointer-first free, which is the same input a C caller provides.
#[repr(transparent)]
struct ExactLiveCClient(core::ptr::NonNull<u8>);

// SAFETY: the test moves this one C client only after A has published it and
// before B's exactly-once free. No thread accesses the client concurrently.
unsafe impl Send for ExactLiveCClient {}

impl ExactLiveCClient {
    #[inline]
    fn into_block(self) -> core::ptr::NonNull<u8> { self.0 }
}

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


fn publish_exact_os_singleton_before_owner_exit() -> ExactLiveCClient {
    let block = match native_allocate_aligned(7, OS_ALIGNMENT, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A allocates the exact alignment-forced OS singleton"),
    };
    assert_eq!(
        block.as_ptr().addr() % OS_ALIGNMENT,
        0,
        "the exact C-shaped client selects the normal-OS singleton terminal tail"
    );
    ExactLiveCClient(block)
}

/// Pinned `free.c` retains the low-bit claim through collection. Its terminal
/// all-free branch calls `arena.c`'s unabandon/list removal before page-map,
/// metadata, and backing release. A failing `munmap` leaves its raw range mapped
/// after consuming those predecessor transitions; it must not reopen
/// A's exited owner, leave a stale OS-list member, or retain B's worker owner.
#[test]
fn post_exit_failed_os_release_consumes_page_without_raw_retry() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the terminal-owner witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero prepares the source arena before A creates its exact live client"
    );

    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(publish_exact_os_singleton_before_owner_exit())
            .expect("A supplies only the exact live C-shaped client");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before B begins pointer dispatch"
        );
    });
    let client = receiver
        .recv()
        .expect("the coordinator receives A's exact client before owner exit");
    owner
        .join()
        .expect("A reaches its completed persistent-owner exit boundary");

    let after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("A's abandoned singleton remains process-PageMap auditable");
    assert!(
        after_owner_exit.page_map_registered_entry_count >= 1,
        "the exact live client remains registered until its pointer-first terminal free"
    );
    assert_eq!(
        after_owner_exit.main_heap_os_abandoned_pages_empty,
        0,
        "A's non-arena singleton is retained by source OS-abandonment state"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A releases its worker admission before B's independent attachment"
    );

    let releaser = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let os_singleton = client.into_block();
        let before_map = native_runtime_lifecycle_test_audit().unwrap();
        let before_vm = vm_current();
        let failure = native_runtime_test_fail_next_unmap();
        let capture = failure.capture_range();
        // SAFETY: A published this exact still-live C client before its owner
        // exited. B holds no A owner, page, list, map, or release capability;
        // the generic pointer dispatcher derives all source facts itself.
        assert_eq!(
            unsafe { native_free(os_singleton) },
            NativePageFreeResult::Freed,
            "terminal source Page release consumes the client before the refused raw unmap"
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
            failure.observed(),
            1,
            "the exact terminal owner reaches the injected source munmap once"
        );
        // SAFETY: the dispatcher diagnoses the old address without accessing
        // client storage after PageMap coverage has been removed.
        assert_eq!(unsafe { native_free(os_singleton) }, NativePageFreeResult::InvalidPointer,
            "consumed PageMap coverage rejects a second client publication");
        assert_eq!(failure.observed(), 1, "invalid-pointer diagnosis cannot retry raw release");
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "consuming A's source does not manufacture another worker owner for B"
        );
        (failure.observed(), finish_current_thread_native_after_user_destructors(), failed_range)
    });
    let (unmap_attempts, releaser_finish, failed_range) = releaser
        .join()
        .expect("B completes independently after the consumed terminal release");
    assert_eq!(
        unmap_attempts,
        1,
        "B's normal finish does not reopen the consumed terminal backing release"
    );
    assert_eq!(
        releaser_finish,
        ThreadFinishResult::Finished,
        "B releases only its own independent worker owner"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "B's normal finish leaves no worker admission behind"
    );
    // The failed unmap left one raw mapping after consuming PageMap removal.
    // It holds no mutation lease or client registration for the initial owner.
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
