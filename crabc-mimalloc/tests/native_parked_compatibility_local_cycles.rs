use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, prepare_native_later_thread_arena, ticket_zero_allocate,
    ticket_zero_free,
};

const LOCAL_COMPATIBILITY_CYCLES: &[(usize, usize, u8)] = &[
    (37, 97, 0x31),
    (53, 193, 0x64),
    (1025, 4097, 0xa2),
];

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_local_compatibility_block(request: usize) -> core::ptr::NonNull<u8> {
    match native_allocate_aligned(request, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the attached worker creates its private compatibility client")
        }
    }
}

#[test]
fn parked_compatibility_worker_repeats_local_cycles_then_returns_ticket_zero_to_baseline() {
    assert!(
        initialize_process(current_page_size()),
        "the private native runtime initializes before the compatibility lifecycle"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves its first arena dormant before the worker attaches"
    );

    std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        for &(request, replacement_request, seed) in LOCAL_COMPATIBILITY_CYCLES {
            let original = allocate_local_compatibility_block(request);
            // SAFETY: `original` is this worker's exact current private block
            // until the following local replacement consumes it.
            unsafe {
                for offset in 0..request {
                    original
                        .as_ptr()
                        .add(offset)
                        .write(seed.wrapping_add(offset as u8));
                }
            }

            let replacement = match unsafe { native_reallocate(Some(original), replacement_request) } {
                NativePageAllocationResult::Allocated(block) => block,
                NativePageAllocationResult::Unavailable
                | NativePageAllocationResult::AllocationFailed
                | NativePageAllocationResult::Retained => {
                    panic!("the parked compatibility worker reenters its local replacement route")
                }
            };
            // SAFETY: a successful local replacement retains the initialized
            // prefix exclusively on this worker until the matching free.
            unsafe {
                for offset in 0..request {
                    assert_eq!(
                        replacement.as_ptr().add(offset).read(),
                        seed.wrapping_add(offset as u8),
                        "cycle {request}->{replacement_request} preserves initialized prefix byte {offset}"
                    );
                }
            }
            assert_eq!(
                unsafe { native_free(replacement) },
                NativePageFreeResult::Freed,
                "each compatibility replacement returns through the worker-local free route"
            );
        }

        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the all-free compatibility worker reaches normal source teardown"
        );
    })
    .join()
    .expect("the one compatibility worker joins after every local cycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable
        | TicketZeroPageAllocationResult::AllocationFailed
        | TicketZeroPageAllocationResult::Retained => {
            panic!("worker teardown restores the ticket-zero baseline")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the restored ticket-zero owner returns its baseline client"
    );
}
