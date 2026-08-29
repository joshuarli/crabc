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
fn native_sole_mapped_regular_route_keeps_the_dormant_pair_busy_until_b_finishes() {
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
            medium.as_ptr().add(64 * 1024 - 1).write(0x53);
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
            "the opaque sole route preserves the source-recorded usable extent"
        );
        assert!(
            matches!(
                unsafe { native_reallocate(Some(medium), 4096) },
                NativePageAllocationResult::Unavailable
            ),
            "the post-exit sole route declines realloc without opening a B-side allocator"
        );
        assert_eq!(unsafe { medium.as_ptr().read() }, 0x52);
        assert_eq!(unsafe { medium.as_ptr().add(64 * 1024 - 1).read() }, 0x53);
        assert_eq!(unsafe { native_free(medium) }, NativePageFreeResult::Freed);
        assert!(
            matches!(
                native_allocate_aligned(73, 16, false),
                NativePageAllocationResult::Unavailable
            ),
            "B stays a no-page finisher after the sole route releases until it consumes A's proof"
        );
        terminal_sender
            .send(())
            .expect("B reports its terminal sole-route free before finish");
        b_release.wait();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its no-page attachment before releasing A's completion"
        );
    });

    terminal_receiver
        .recv()
        .expect("B reaches the sole-route-terminal pre-finish state");
    assert!(
        matches!(ticket_zero_allocate(73, false), TicketZeroPageAllocationResult::Unavailable),
        "the dormant pair stays unavailable after the sole route releases until B finishes"
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
