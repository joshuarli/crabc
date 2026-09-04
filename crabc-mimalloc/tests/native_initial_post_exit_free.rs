use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn initial_thread_frees_exact_client_after_worker_owner_exit() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the selected owner-exit regression"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial thread primes the source dormant pair before the worker starts"
    );

    let worker = std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(16, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("worker allocation must succeed")
            }
        };
        let address = block.as_ptr().addr();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the worker must publish its surviving allocation through source collect-abandon"
        );
        address
    });
    let address = worker
        .join()
        .expect("the worker exits after publishing its surviving allocation");
    let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };

    assert_eq!(
        unsafe { native_free(block) },
        NativePageFreeResult::Freed,
        "the initial caller must resolve the exited worker's PageMap source state before its own owner"
    );

    let resumed = match ticket_zero_allocate(16, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero reactivates after the pointer-derived source state is consumed")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed initial owner keeps its ordinary free behavior"
    );
}
