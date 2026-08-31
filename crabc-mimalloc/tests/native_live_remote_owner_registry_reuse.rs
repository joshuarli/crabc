use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_live_remote_owner_registry_test_audit,
    native_usable_size, prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const LIVE_OWNER_COUNT: usize = 2;
const EPOCH_COUNT: usize = 4;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn spawn_parked_owner(
    remote_request: usize,
    local_request: usize,
    ready: mpsc::SyncSender<usize>,
    resume: mpsc::Receiver<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(remote_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates its exact live registry client"),
        };
        let local = match native_allocate_aligned(local_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A retains one private local client while B publishes"),
        };
        ready
            .send(remote.as_ptr().addr())
            .expect("the coordinator receives only A's exact remote client");
        resume
            .recv()
            .expect("A resumes only after its matching B free completes");

        // A's next ordinary operation collects its source remote head before
        // its local all-free drain. The local allocation ensures this stays a
        // normal parked-session lifecycle rather than a C-specific shortcut.
        let probe = match native_allocate_aligned(remote_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A resumes after B restored its registry entry"),
        };
        // SAFETY: A owns its probe and local client; B has already published
        // only the distinct exact remote client through the source route.
        unsafe {
            assert_eq!(native_free(probe), NativePageFreeResult::Freed);
            assert_eq!(native_free(local), NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A removes its live registry entry only through normal native finish"
        );
    })
}

fn release_exact_live_client(address: usize, request: usize) {
    std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: the paired A remains parked with this exact client live
        // until this source-shaped B operation finishes.
        let block = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
        assert!(
            unsafe { native_usable_size(block) }.is_some_and(|size| size >= request),
            "B reads the matching A client's captured PageMap usable extent"
        );
        assert_eq!(
            unsafe { native_free(block) },
            NativePageFreeResult::Freed,
            "B publishes only its exact A client through the matched entry"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B settles its own no-page lifecycle after the source publication"
        );
    })
    .join()
    .expect("the exact live-owner B finishes normally")
}

/// Stable metadata nodes must follow concurrent live-owner high-water, not
/// the number of sequential worker lifecycles. Every epoch first parks A1,
/// then A2, so the source scheduler admits one setup transition at a time;
/// both registry entries are nevertheless simultaneously active before any B
/// receives an address.
#[test]
fn native_live_owner_registry_reuses_its_warm_two_owner_high_water() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the live-owner registry witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before live owners begin"
    );
    assert_eq!(
        native_live_remote_owner_registry_test_audit().published_entry_count,
        0,
        "this isolated test process begins without a live-owner registry entry"
    );

    let mut warm_entry_count = None;
    for epoch in 0..EPOCH_COUNT {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
        let first_ready_sender = ready_sender.clone();
        let (first_resume_sender, first_resume_receiver) = mpsc::sync_channel(0);
        let (second_resume_sender, second_resume_receiver) = mpsc::sync_channel(0);

        let first_owner = spawn_parked_owner(
            37 + epoch,
            73 + epoch,
            first_ready_sender,
            first_resume_receiver,
        );
        let first_address = ready_receiver
            .recv()
            .expect("A1 parks before A2 enters its setup transition");
        let second_owner = spawn_parked_owner(
            53 + epoch,
            89 + epoch,
            ready_sender,
            second_resume_receiver,
        );
        let second_address = ready_receiver
            .recv()
            .expect("A2 parks before either B receives an address");

        let live = native_live_remote_owner_registry_test_audit();
        assert_eq!(
            live.live_entry_count, LIVE_OWNER_COUNT,
            "epoch {epoch} has one active entry for each parked A"
        );
        assert_eq!(
            live.retained_entry_count, 0,
            "epoch {epoch} has no terminal live-owner entry"
        );
        match warm_entry_count {
            Some(warm) => assert_eq!(
                live.published_entry_count, warm,
                "epoch {epoch} reuses the warm live-owner metadata high-water"
            ),
            None => {
                assert_eq!(
                    live.published_entry_count, LIVE_OWNER_COUNT,
                    "the first epoch creates exactly one stable node per parked A"
                );
                warm_entry_count = Some(live.published_entry_count);
            }
        }

        release_exact_live_client(first_address, 37 + epoch);
        release_exact_live_client(second_address, 53 + epoch);

        first_resume_sender
            .send(())
            .expect("A1 resumes after B1 completed its exact publication");
        first_owner
            .join()
            .expect("A1 removes its entry through normal finish");
        second_resume_sender
            .send(())
            .expect("A2 resumes after B2 completed its exact publication");
        second_owner
            .join()
            .expect("A2 removes its entry through normal finish");

        let quiescent = native_live_remote_owner_registry_test_audit();
        assert_eq!(
            quiescent.published_entry_count,
            warm_entry_count.expect("the first epoch records the warm high-water"),
            "epoch {epoch} keeps the stable metadata nodes for reuse"
        );
        assert_eq!(
            quiescent.live_entry_count, 0,
            "epoch {epoch} returns every live-owner entry to empty"
        );
        assert_eq!(
            quiescent.retained_entry_count, 0,
            "epoch {epoch} leaves no hidden terminal entry"
        );

        let resumed = match ticket_zero_allocate(113 + epoch, false) {
            TicketZeroPageAllocationResult::Allocated(block) => block,
            _ => panic!("ticket zero reactivates after each complete live-owner epoch"),
        };
        assert_eq!(
            unsafe { ticket_zero_free(resumed) },
            TicketZeroPageFreeResult::Freed,
            "the resumed ticket-zero client returns to its dormant pair"
        );
    }
}
