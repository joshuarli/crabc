use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_usable_size, prepare_native_later_thread_arena,
};

#[cfg(feature = "native-runtime-test-audit")]
use crabc_mimalloc::__crabc_runtime::native_runtime_lifecycle_test_audit;

const PRODUCER_COUNT: usize = 4;
const REQUEST: usize = 37;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// A source owner leaves four exact direct-small clients live after exit.
///
/// The first foreign free must claim the unowned low bit and complete its
/// source tail while the other three clients still keep the same source page
/// PageMap-published.  They then race their own `allow_collect=true` frees.
/// This proves that terminal PageMap release cannot begin at the first claim:
/// a remaining exact client is still queryable after that tail completes.
#[test]
fn post_exit_claim_tail_keeps_page_map_live_for_late_same_page_producers() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the claimed-page lifetime witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial owner prepares the direct-small source arena"
    );
    #[cfg(feature = "native-runtime-test-audit")]
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared process exposes a PageMap scalar baseline");

    let clients = publish_exited_owner_clients();
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
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let leader_client = exact_client(leader_address);
        assert_live_source_client(leader_client, 0);
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
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            let client = exact_client(address);
            assert_live_source_client(client, index);
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
        unsafe { native_usable_size(late_client) }.is_some_and(|size| size >= REQUEST),
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
        let after = native_runtime_lifecycle_test_audit()
            .expect("all source producers joined before the terminal PageMap audit");
        assert_eq!(
            after.page_map_registered_entry_count,
            baseline.page_map_registered_entry_count,
            "the terminal release begins only after every exact source client has completed"
        );
    }
}

fn publish_exited_owner_clients() -> [usize; PRODUCER_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let mut clients = [0; PRODUCER_COUNT];
        for (index, client) in clients.iter_mut().enumerate() {
            let block = match native_allocate_aligned(REQUEST, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("the source owner allocates exact direct-small client {index}"),
            };
            // SAFETY: the owner transfers each distinct, still-live client to
            // exactly one foreign producer after source owner exit.
            unsafe {
                block.as_ptr().write((0x30 + index) as u8);
                block.as_ptr().add(REQUEST - 1).write((0x90 + index) as u8);
            }
            *client = block.as_ptr().addr();
        }
        sender
            .send(clients)
            .expect("the owner publishes only exact C-shaped source clients");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the source owner abandons its still-live direct-small page before foreign frees"
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

fn assert_live_source_client(client: core::ptr::NonNull<u8>, index: usize) {
    // SAFETY: the caller holds its unique exact client and has not entered its
    // consuming source free yet.
    unsafe {
        assert_eq!(client.as_ptr().read(), (0x30 + index) as u8);
        assert_eq!(client.as_ptr().add(REQUEST - 1).read(), (0x90 + index) as u8);
    }
    assert!(
        unsafe { native_usable_size(client) }.is_some_and(|size| size >= REQUEST),
        "producer {index} completes a checked PageMap observation before its source CAS"
    );
}
