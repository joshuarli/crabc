use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn publish_one_detached_worker_client(request: usize) -> usize {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the sequential worker creates its one surviving native client")
            }
        };
        let address = block.as_ptr().addr();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the sequential worker publishes its surviving client before exit"
        );
        address
    })
    .join()
    .expect("the sequential detached worker completes its source exit")
}

#[test]
fn initial_free_scans_past_newer_detached_route_for_an_older_worker_client() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before detached routes are inserted"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero primes the dormant pair before the sequential workers start"
    );

    let older_address = publish_one_detached_worker_client(37);
    let newer_address = publish_one_detached_worker_client(53);
    assert_ne!(
        older_address, newer_address,
        "each sequential exited owner leaves one distinct live native client"
    );

    // The second owner was published most recently, so its registry entry is
    // encountered first. The initial thread owns neither worker attachment:
    // this first free can succeed only if the Phase-A pointer bridge restores
    // that nonmatching newer route and continues to the older exact client.
    let older = unsafe { core::ptr::NonNull::new_unchecked(older_address as *mut u8) };
    assert_eq!(
        unsafe { native_free(older) },
        NativePageFreeResult::Freed,
        "the pointer-only bridge releases the older client without caller identity"
    );

    // A skipped route must remain routable after the older one completes.
    let newer = unsafe { core::ptr::NonNull::new_unchecked(newer_address as *mut u8) };
    assert_eq!(
        unsafe { native_free(newer) },
        NativePageFreeResult::Freed,
        "the restored newer route releases from the same initial caller"
    );

    let resumed = match ticket_zero_allocate(61, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("ticket zero reactivates after both out-of-order detached frees")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the initial owner remains usable after the pointer-only route scan"
    );
}
