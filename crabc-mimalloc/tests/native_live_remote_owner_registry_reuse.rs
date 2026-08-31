use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_usable_size, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

const EPOCH_COUNT: usize = 4;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn spawn_live_persistent_owner(
    remote_request: usize,
    local_request: usize,
    ready: mpsc::SyncSender<usize>,
    resume: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(remote_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates its exact live remote client"),
        };
        let local = match native_allocate_aligned(local_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A retains one private local client while B frees remotely"),
        };
        ready
            .send(remote.as_ptr().addr())
            .expect("the coordinator receives only A's exact remote client");
        resume
            .recv()
            .expect("A resumes only after its matching B free completes");

        // A's next ordinary operation collects its source remote head before
        // its local all-free drain. The local allocation keeps this a normal
        // persistent-owner lifecycle rather than an all-free shortcut.
        let probe = match native_allocate_aligned(remote_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A resumes after B completes its PageMap-derived remote free"),
        };
        // SAFETY: A owns its probe and local client; B has already published
        // only the distinct exact remote client to A's source remote head.
        unsafe {
            assert_eq!(native_free(probe), NativePageFreeResult::Freed);
            assert_eq!(native_free(local), NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes its persistent owner only through normal native finish"
        );
    })
}

fn release_exact_live_client(address: usize, request: usize) {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: the paired A keeps this exact client live in its persistent
        // owner until B's PageMap-derived operation finishes.
        let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
        assert!(
            unsafe { native_usable_size(block) }.is_some_and(|size| size >= request),
            "B reads the matching A client's captured PageMap usable extent"
        );
        assert_eq!(
            unsafe { native_free(block) },
            NativePageFreeResult::Freed,
            "B frees only its exact A client through the foreign PageMap path"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B settles its own no-page attachment after the foreign publication"
        );
    })
    .join()
    .expect("the exact live-owner B finishes normally")
}

/// Each epoch holds two independent persistent owners live before either B
/// receives an address. The repeated sequence proves that exact foreign
/// PageMap queries and frees remain valid across completed owner lifecycles.
#[test]
fn native_live_remote_frees_repeat_across_persistent_owner_epochs() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the repeated live-remote witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent initial owner readies the first arena before workers begin"
    );

    for epoch in 0..EPOCH_COUNT {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let first_ready_sender = ready_sender.clone();
        let (first_resume_sender, first_resume_receiver) = mpsc::sync_channel(0);
        let (second_resume_sender, second_resume_receiver) = mpsc::sync_channel(0);

        let first_owner = spawn_live_persistent_owner(
            37 + epoch,
            73 + epoch,
            first_ready_sender,
            first_resume_receiver,
        );
        let first_address = ready_receiver
            .recv()
            .expect("A1 keeps its persistent owner live before A2 begins");
        let second_owner = spawn_live_persistent_owner(
            53 + epoch,
            89 + epoch,
            ready_sender,
            second_resume_receiver,
        );
        let second_address = ready_receiver
            .recv()
            .expect("A2 keeps its persistent owner live before either B receives an address");

        release_exact_live_client(first_address, 37 + epoch);
        release_exact_live_client(second_address, 53 + epoch);

        first_resume_sender
            .send(())
            .expect("A1 resumes after B1 completed its exact publication");
        first_owner
            .join()
            .expect("A1 completes its persistent owner through normal finish");
        second_resume_sender
            .send(())
            .expect("A2 resumes after B2 completed its exact publication");
        second_owner
            .join()
            .expect("A2 completes its persistent owner through normal finish");

        let resumed = match ticket_zero_allocate(113 + epoch, false) {
            TicketZeroPageAllocationResult::Allocated(block) => block,
            _ => panic!("the persistent initial owner remains usable after each live-owner epoch"),
        };
        assert_eq!(
            unsafe { ticket_zero_free(resumed) },
            TicketZeroPageFreeResult::Freed,
            "the resumed ticket-zero client returns to its dormant pair"
        );
    }
}
