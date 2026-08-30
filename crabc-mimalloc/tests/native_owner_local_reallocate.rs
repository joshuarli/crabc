use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_reallocate, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_owner_local_reallocate_preserves_prefix_then_releases_the_same_session() {
    assert!(
        initialize_process(current_page_size()),
        "this isolated process initializes the private native runtime"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves the native first arena dormant before the worker attaches"
    );

    let worker = std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let original = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the attached worker creates its owner-local native client")
            }
        };
        // SAFETY: `original` remains this worker's exact current client until
        // the owner-local reallocation below consumes it.
        unsafe {
            original.as_ptr().write(0x4d);
            original.as_ptr().add(36).write(0xa7);
        }

        let replacement = match unsafe { native_reallocate(Some(original), 97) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the same worker reenters its owner-local reallocation boundary")
            }
        };
        // SAFETY: the successful reallocation returned the one live local
        // replacement, which still belongs to this worker's session.
        unsafe {
            assert_eq!(replacement.as_ptr().read(), 0x4d);
            assert_eq!(replacement.as_ptr().add(36).read(), 0xa7);
        }
        assert_eq!(
            unsafe { native_free(replacement) },
            NativePageFreeResult::Freed,
            "the replacement returns through the same owner-local session"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the all-free owner reaches its normal source teardown"
        );
    });
    worker
        .join()
        .expect("the owner-local reallocation worker joins");

    let resumed = match ticket_zero_allocate(41, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("the worker teardown returns ticket zero to the dormant pair")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero remains usable after the owner-local reallocation lifecycle"
    );
}
