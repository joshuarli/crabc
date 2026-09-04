// This is a direct process-lifetime regression. The scalar audit and one-shot
// unmap fault are both intentionally absent from ordinary allocator builds.
#![cfg(all(
    feature = "native-runtime-test-audit",
    feature = "native-runtime-test-fault"
))]

use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, native_runtime_lifecycle_test_audit,
    native_runtime_test_fail_next_unmap, prepare_native_later_thread_arena, ticket_zero_allocate,
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
/// metadata, and backing release. A failing `munmap` must therefore retain one
/// opaque source owner after those predecessor transitions; it must not reopen
/// A's exited owner, leave a stale OS-list member, or retain B's worker owner.
#[test]
fn post_exit_failed_os_release_seals_one_terminal_source_owner() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the terminal-owner witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero prepares the source arena before A creates its exact live client"
    );

    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
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
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let failure = native_runtime_test_fail_next_unmap();
        // SAFETY: A published this exact still-live C client before its owner
        // exited. B holds no A owner, page, list, map, or release capability;
        // the generic pointer dispatcher derives all source facts itself.
        assert_eq!(
            unsafe { native_free(client.into_block()) },
            NativePageFreeResult::Retained,
            "the failed terminal OS release keeps the exact source fail-closed"
        );
        assert_eq!(
            failure.observed(),
            1,
            "the exact terminal owner reaches the injected source munmap once"
        );
        assert_eq!(
            native_runtime_fork_admission_test_audit().active_later_thread_count,
            1,
            "retaining A's source does not manufacture another worker owner for B"
        );
        (failure.observed(), finish_current_thread_native_after_user_destructors())
    });
    let (unmap_attempts, releaser_finish) = releaser
        .join()
        .expect("B completes independently after the terminal source retention");
    assert_eq!(
        unmap_attempts,
        1,
        "B's normal finish does not reopen the retained terminal backing release"
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
    assert!(
        matches!(
            ticket_zero_allocate(73, false),
            TicketZeroPageAllocationResult::Retained
        ),
        "the retained terminal source closes the process state without a retry or fallback route"
    );
}
