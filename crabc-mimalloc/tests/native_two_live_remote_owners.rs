use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_usable_size, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Two independent native workers keep live persistent owners before either
/// address crosses a thread boundary. Each fresh B worker receives only one
/// exact C-shaped address, and pointer-first PageMap lookup must locate the
/// matching A without a process-wide client table.
#[test]
fn two_live_native_owners_accept_independent_pointer_first_remote_frees() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before two live owners begin"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero readies the first arena before both native owners begin"
    );

    let (owner_ready_sender, owner_ready_receiver) = mpsc::sync_channel(0);
    let first_owner_ready_sender = owner_ready_sender.clone();
    let (first_resume_sender, first_resume_receiver) = mpsc::sync_channel(0);
    let (second_resume_sender, second_resume_receiver) = mpsc::sync_channel(0);

    let first_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A1 creates its live native remote client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A1 retains one local client while B1 publishes"),
        };
        // SAFETY: A1 owns both clients until the exact B1 publication below.
        unsafe {
            remote.as_ptr().write(0x41);
            remote.as_ptr().add(36).write(0x42);
            local.as_ptr().write(0x43);
            local.as_ptr().add(72).write(0x44);
        }
        first_owner_ready_sender
            .send((remote.as_ptr().addr(), 37usize, 0x41u8, 0x42u8))
            .expect("the coordinator receives only A1's exact C address");
        first_resume_receiver
            .recv()
            .expect("A1 continues only after B1 completes its pointer-first free");

        let probe = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A1 resumes after its exact remote publication"),
        };
        // SAFETY: A1 owns its resumed probe and retained local client. Its
        // all-free drain later collects B1's source remote-head publication.
        unsafe {
            assert_eq!(local.as_ptr().read(), 0x43);
            assert_eq!(local.as_ptr().add(72).read(), 0x44);
            assert_eq!(native_free(probe), NativePageFreeResult::Freed);
            assert_eq!(native_free(local), NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A1 collects its remote publication before its normal native finish"
        );
    });

    // A1 remains live before A2 creates its independent allocation. The
    // witness begins once both PageMap-published owners have supplied their
    // exact client addresses, before either B begins.
    let first = owner_ready_receiver
        .recv()
        .expect("A1 remains live before A2 creates its independent live client");

    let second_owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A2 creates its independently live remote client"),
        };
        let local = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A2 retains one local client while B2 publishes"),
        };
        // SAFETY: A2 owns both clients until the exact B2 publication below.
        unsafe {
            remote.as_ptr().write(0x51);
            remote.as_ptr().add(52).write(0x52);
            local.as_ptr().write(0x53);
            local.as_ptr().add(88).write(0x54);
        }
        owner_ready_sender
            .send((remote.as_ptr().addr(), 53usize, 0x51u8, 0x52u8))
            .expect("the coordinator receives only A2's exact C address");
        second_resume_receiver
            .recv()
            .expect("A2 continues only after B2 completes its pointer-first free");

        let probe = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A2 resumes after its exact remote publication"),
        };
        // SAFETY: A2 owns its resumed probe and retained local client. Its
        // all-free drain later collects B2's source remote-head publication.
        unsafe {
            assert_eq!(local.as_ptr().read(), 0x53);
            assert_eq!(local.as_ptr().add(88).read(), 0x54);
            assert_eq!(native_free(probe), NativePageFreeResult::Freed);
            assert_eq!(native_free(local), NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A2 collects its remote publication before its normal native finish"
        );
    });

    let second = owner_ready_receiver
        .recv()
        .expect("A2 remains live before either B worker starts");
    let first_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let (address, request, first_byte, last_byte) = first;
        // SAFETY: A1 keeps this exact allocation live until B1 finishes its
        // source-shaped pointer-first remote free.
        let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
        // SAFETY: B1 observes the still-live C client before publishing it.
        unsafe {
            assert_eq!(block.as_ptr().read(), first_byte);
            assert_eq!(block.as_ptr().add(request - 1).read(), last_byte);
        }
        assert!(
            unsafe { native_usable_size(block) }.is_some_and(|size| size >= request),
            "B1 reads A1's captured PageMap usable extent"
        );
        assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B1 publishes its exact A1 client through matching PageMap state"
        );
        assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "B1 finishes its independent attachment after its exact source publication"
        );
    });

    let second_releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let (address, request, first_byte, last_byte) = second;
        // SAFETY: A2 keeps this exact allocation live until B2 finishes its
        // source-shaped pointer-first remote free.
        let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
        // SAFETY: B2 observes the still-live C client before publishing it.
        unsafe {
            assert_eq!(block.as_ptr().read(), first_byte);
            assert_eq!(block.as_ptr().add(request - 1).read(), last_byte);
        }
        assert!(
            unsafe { native_usable_size(block) }.is_some_and(|size| size >= request),
            "B2 reads A2's captured PageMap usable extent"
        );
        assert_eq!(
                unsafe { native_free(block) },
                NativePageFreeResult::Freed,
                "B2 finds A2 even while A1's independent PageMap state remains live"
        );
        assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "B2 finishes its independent attachment after its exact source publication"
        );
    });

    first_releaser
        .join()
        .expect("B1 completes A1's independent remote publication");
    second_releaser
        .join()
        .expect("B2 completes A2's independent remote publication");
    first_resume_sender
        .send(())
        .expect("A1 may continue after B1 completes its pointer-first free");
    second_resume_sender
        .send(())
        .expect("A2 may continue after B2 completes its pointer-first free");
    first_owner
        .join()
        .expect("A1 finishes after collecting its exact remote publication");
    second_owner
        .join()
        .expect("A2 finishes after collecting its exact remote publication");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes after both live persistent owners finish"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the dormant ticket-zero pair receives its local client after both owners finish"
    );
}
