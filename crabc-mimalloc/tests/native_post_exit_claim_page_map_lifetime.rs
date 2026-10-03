#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;

use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_free, native_usable_size, prepare_native_later_thread_arena,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_lifecycle_test_audit;

const PRODUCER_COUNT: usize = 4;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// A source owner leaves four exact clients live after exit.
///
/// The first foreign free must claim the unowned low bit and complete its
/// source tail while the other three clients keep their pages PageMap-published.
/// Regular-page clients share a page; OS-singleton clients retain independent
/// spans. They then race their own `allow_collect=true` frees. A remaining
/// exact client stays queryable after the first tail, and every application
/// registration disappears only after all clients complete their frees.
#[test]
fn post_exit_claim_tail_keeps_page_map_live_for_late_same_page_producers() {
    // Requests span regular, medium, large, and OS-singleton pages. The
    // aligned row also requires canonical-block recovery from the client.
    for (request, alignment) in [(37, 16), (79, 256), (12_289, 16),
        (131_073, 16), (524_289, 16)] {
        assert_post_exit_claim_lifetime(request, alignment);
    }
}

fn assert_post_exit_claim_lifetime(request: usize, alignment: usize) {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the claimed-page lifetime witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial owner prepares the source arena"
    );
    #[cfg(feature = "native-runtime-test-audit")]
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared process exposes a PageMap scalar baseline");
    // SAFETY: no worker has started; this thread performs only the observation.
    #[cfg(feature = "native-runtime-test-audit")]
    let baseline_application_entries = unsafe { native_runtime_test_support::quiescent_application_page_map_entry_count() };

    let clients = publish_exited_owner_clients(request, alignment);
    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after_owner_exit = native_runtime_lifecycle_test_audit()
            .expect("the exited source clients remain PageMap-auditable");
        assert!(
            after_owner_exit.page_map_registered_entry_count
                > baseline.page_map_registered_entry_count,
            "the owner's exact live source clients keep their PageMap registration after owner exit"
        );
    }

    let source_ready = Arc::new(Barrier::new(PRODUCER_COUNT + 1));
    let follower_start = Arc::new(Barrier::new(PRODUCER_COUNT));
    let (leader_start_sender, leader_start_receiver) = mpsc::sync_channel(0);
    let (leader_result_sender, leader_result_receiver) = mpsc::sync_channel(0);
    let (leader_finish_sender, leader_finish_receiver) = mpsc::sync_channel(0);

    let leader_address = clients[0];
    let leader_ready = Arc::clone(&source_ready);
    let leader = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let leader_client = exact_client(leader_address);
        assert_live_source_client(leader_client, 0, request);
        leader_ready.wait();

        leader_start_receiver
            .recv()
            .expect("the coordinator starts the first low-bit claimant");
        let free = unsafe { native_free(leader_client) };
        leader_result_sender
            .send(free)
            .expect("the first claimant reports after its complete source tail");

        leader_finish_receiver
            .recv()
            .expect("the coordinator holds the completed claimant attachment until followers finish");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the completed claimant releases only its own attachment"
        );
        free
    });

    let mut followers = Vec::with_capacity(PRODUCER_COUNT - 1);
    for (index, address) in clients.into_iter().enumerate().skip(1) {
        let source_ready = Arc::clone(&source_ready);
        let follower_start = Arc::clone(&follower_start);
        followers.push(std::thread::spawn(move || {
            assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
            let client = exact_client(address);
            assert_live_source_client(client, index, request);
            source_ready.wait();

            follower_start.wait();
            let free = unsafe { native_free(client) };
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "late producer {index} releases only its own attachment"
            );
            free
        }));
    }

    // Every producer has confirmed its own exact client remains PageMap
    // queryable while all four clients are live. Only then may the first CAS
    // run.
    source_ready.wait();
    leader_start_sender
        .send(())
        .expect("the first low-bit claimant receives its source-CAS release");
    assert_eq!(
        leader_result_receiver
            .recv()
            .expect("the first claimant reports its source disposition"),
        NativePageFreeResult::Freed,
        "the first producer completes the low-bit claim and source tail"
    );

    #[cfg(feature = "native-runtime-test-audit")]
    {
        let after_claim_tail = native_runtime_lifecycle_test_audit()
            .expect("the complete first claim tail leaves the remaining source page auditable");
        assert!(
            after_claim_tail.page_map_registered_entry_count
                > baseline.page_map_registered_entry_count,
            "the first claimant cannot begin terminal PageMap release while exact late clients remain live"
        );
    }
    let late_client = exact_client(clients[1]);
    assert!(
        unsafe { native_usable_size(late_client) }.is_some_and(|size| size >= request),
        "a late producer's exact client remains PageMap-queryable after the winning claim tail"
    );

    // The remaining exact clients now compete normally. Their completed
    // source tails may release the page only after the final client is gone.
    follower_start.wait();
    for (index, follower) in followers.into_iter().enumerate() {
        assert_eq!(
            follower
                .join()
                .expect("each late producer completes its source operation"),
            NativePageFreeResult::Freed,
            "late producer {} publishes or claims exactly once",
            index + 1
        );
    }

    leader_finish_sender
        .send(())
        .expect("the completed first claimant may now finish its attachment");
    assert_eq!(
        leader
            .join()
            .expect("the first claimant finishes after all late source clients"),
        NativePageFreeResult::Freed,
        "the first claimant retains no retryable source authority"
    );

    #[cfg(feature = "native-runtime-test-audit")]
    {
        assert!(native_runtime_lifecycle_test_audit().is_some(),
            "all source producers joined before the terminal PageMap audit");
        assert_eq!(
            // SAFETY: every source producer joined before this observation.
            unsafe { native_runtime_test_support::quiescent_application_page_map_entry_count() },
            baseline_application_entries,
            "the terminal release begins only after every exact source client has completed"
        );
    }
}

fn publish_exited_owner_clients(request: usize, alignment: usize) -> [usize; PRODUCER_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let mut clients = [0; PRODUCER_COUNT];
        for (index, client) in clients.iter_mut().enumerate() {
            let block = match native_allocate_aligned(request, alignment, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("the source owner allocates exact source client {index}"),
            };
            // SAFETY: the owner transfers each distinct, still-live client to
            // exactly one foreign producer after source owner exit.
            unsafe {
                block.as_ptr().write((0x30 + index) as u8);
                block.as_ptr().add(request - 1).write((0x90 + index) as u8);
            }
            *client = block.as_ptr().addr();
        }
        sender
            .send(clients)
            .expect("the owner publishes only exact C-shaped source clients");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the source owner abandons its still-live source pages before foreign frees"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives every exact source client");
    owner
        .join()
        .expect("the source owner completes its owner-exit boundary");
    clients
}

fn exact_client(address: usize) -> core::ptr::NonNull<u8> {
    // SAFETY: every address is produced from one exact current native client
    // and transferred to one unique producer before that producer frees it.
    unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) }
}

fn assert_live_source_client(client: core::ptr::NonNull<u8>, index: usize, request: usize) {
    // SAFETY: the caller holds its unique exact client and has not entered its
    // consuming source free yet.
    unsafe {
        assert_eq!(client.as_ptr().read(), (0x30 + index) as u8);
        assert_eq!(client.as_ptr().add(request - 1).read(), (0x90 + index) as u8);
    }
    assert!(
        unsafe { native_usable_size(client) }.is_some_and(|size| size >= request),
        "producer {index} completes a checked PageMap observation before its source CAS"
    );
}
