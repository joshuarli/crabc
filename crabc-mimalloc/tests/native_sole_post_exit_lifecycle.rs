use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, native_reallocate, native_usable_size,
    prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_sole_post_exit_replacement_releases_the_dormant_pair_while_b_remains_attached() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its shadow owner-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before a native worker borrows it"
    );

    let (block_sender, block_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let returned_medium = match native_allocate_aligned(64 * 1024, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives its first native medium client"),
        };
        let medium = match native_allocate_aligned(64 * 1024, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("owner receives its surviving native medium client"),
        };
        unsafe {
            medium.as_ptr().write(0x52);
            medium.as_ptr().add(4095).write(0x53);
            medium.as_ptr().add(64 * 1024 - 1).write(0x54);
        }
        // The source sole-page result is not a one-live-block shortcut. It
        // requires one still-live medium client and a current immediate local
        // free head in that same otherwise sole mapped regular page.
        assert_eq!(
            unsafe { native_free(returned_medium) },
            NativePageFreeResult::Freed,
            "the owner returns the source immediate local medium block"
        );
        // The fresh B receives only the C-shaped address. The exact client,
        // mapped page route, and A's admission remain private to the typed
        // post-exit capability.
        block_sender
            .send(medium.as_ptr().addr())
            .expect("the fresh B receives the exact medium address");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A transfers one source-valid sole mapped-regular route"
        );
    });
    let medium = block_receiver
        .recv()
        .expect("the owner publishes its client before exit");
    owner
        .join()
        .expect("A completes after the sole route owns its detached page");

    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(0);
    let release_b = Arc::new(Barrier::new(2));
    let b_release = Arc::clone(&release_b);
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A has completed its typed sole-page route, and the test
        // passes B the exact C-shaped client address it is allowed to free.
        let medium = unsafe { core::ptr::NonNull::new_unchecked(medium as *mut u8) };
        assert!(
            unsafe { native_usable_size(medium) }.is_some_and(|size| size >= 64 * 1024),
            "the PageMap pointer query preserves the source-recorded usable extent"
        );
        assert!(
            matches!(
                unsafe { native_reallocate(Some(medium), usize::MAX) },
                NativePageAllocationResult::AllocationFailed
            ),
            "an invalid request leaves A's exact client live"
        );
        assert_eq!(unsafe { medium.as_ptr().read() }, 0x52);
        assert_eq!(unsafe { medium.as_ptr().add(4095).read() }, 0x53);
        assert_eq!(unsafe { medium.as_ptr().add(64 * 1024 - 1).read() }, 0x54);
        // This sole route is detached from A's TLS, but its surviving page
        // has the source abandoned-mapped identity. It is not the special
        // `Detached` PageMap state with no nonlocal-free producer.
        let replacement = match unsafe { native_reallocate(Some(medium), 4096) } {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable => {
                panic!("B finds A's sole abandoned-mapped source through PageMap facts")
            }
            NativePageAllocationResult::AllocationFailed => {
                panic!("B creates its sole-route replacement through its persistent owner")
            }
            NativePageAllocationResult::Retained => {
                panic!("the source-valid sole abandoned-mapped tail consumes A's old client")
            }
        };
        assert_eq!(unsafe { replacement.as_ptr().read() }, 0x52);
        assert_eq!(unsafe { replacement.as_ptr().add(4095).read() }, 0x53);
        assert_eq!(
            unsafe { native_free(replacement) },
            NativePageFreeResult::Freed,
            "B releases its successful replacement without touching A's consumed source"
        );
        let continued = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!(
                "B resumes only its independent local session after A's terminal sole-route completion"
            ),
        };
        // SAFETY: this exact allocation belongs to B's local session, not the
        // opaque completed sole route that still holds A's admission proof.
        unsafe {
            continued.as_ptr().write(0x55);
            continued.as_ptr().add(72).write(0x56);
            assert_eq!(continued.as_ptr().read(), 0x55);
            assert_eq!(continued.as_ptr().add(72).read(), 0x56);
        }
        assert_eq!(
            unsafe { native_free(continued) },
            NativePageFreeResult::Freed,
            "B can free its continued local client before its normal finish"
        );
        terminal_sender
            .send(())
            .expect("B reports its terminal sole-route free before finish");
        b_release.wait();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its own local session before releasing A's completion"
        );
    });

    terminal_receiver
        .recv()
        .expect("B reaches the sole-route-terminal pre-finish state");
    // The source-valid sole replacement consumed A's PageMap source before
    // this point. B remains attached with its own persistent target owner,
    // while ticket zero can independently resume its dormant pair.
    let while_b_attached = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable => {
            panic!("the consumed sole source no longer blocks ticket zero while B is attached")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("the fixed small ticket-zero request remains allocatable")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("the successful sole replacement leaves the process owner usable")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(while_b_attached) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its independent client while B remains attached"
    );
    release_b.wait();
    releaser
        .join()
        .expect("B completes the typed sole-route lifecycle");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes only after B finishes"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to the dormant pair"
    );
}
