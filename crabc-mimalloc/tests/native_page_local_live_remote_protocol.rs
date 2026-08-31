use std::sync::{Arc, Barrier, mpsc};

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

/// Each foreign worker receives one exact live source pointer. The owner keeps
/// allocating while their PageMap lookup and page-local remote publication
/// race its ordinary collection path, then finishes only after every producer
/// has discharged its source operation. This checks the source lifetime rule:
/// a live block keeps its PageMap registration and page metadata valid through
/// the producer CAS or the owner's concurrent collection.
#[test]
fn page_local_live_remote_free_handles_one_two_four_and_eight_producers() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the page-local remote-free protocol"
    );

    for producer_count in [1usize, 2, 4, 8] {
        assert!(
            prepare_native_later_thread_arena(),
            "ticket zero prepares the source arena before the {producer_count}-producer epoch"
        );
        run_live_remote_epoch(producer_count);
    }
}

fn run_live_remote_epoch(producer_count: usize) {
    let start = Arc::new(Barrier::new(producer_count + 1));
    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (publisher_done_sender, publisher_done_receiver) = mpsc::channel();

    let owner_start = Arc::clone(&start);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

        let mut remote_clients = Vec::with_capacity(producer_count);
        for index in 0..producer_count {
            let remote = match native_allocate_aligned(37, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!(
                    "the owner creates exact live client {index} for {producer_count} publishers"
                ),
            };
            // SAFETY: the owner keeps each client live until exactly one
            // foreign producer completes the source PageMap operation below.
            unsafe {
                remote.as_ptr().write((0x40 + index) as u8);
                remote.as_ptr().add(36).write((0x80 + index) as u8);
            }
            remote_clients.push(remote.as_ptr().addr());
        }
        remote_sender
            .send(remote_clients)
            .expect("the publishers receive only exact C-shaped client addresses");

        owner_start.wait();

        // Keep the owner in ordinary source allocation work while the remote
        // producers are resolving and publishing. Filling this bounded batch
        // requires normal page collection when a source page becomes full;
        // it does not borrow a producer or take a PageMap mutation lease.
        let mut local_clients = Vec::with_capacity(256);
        for index in 0..256usize {
            let local = match native_allocate_aligned(37, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!(
                    "the live owner continues local allocation {index} while {producer_count} publishers race"
                ),
            };
            local_clients.push(local);
        }

        for _ in 0..producer_count {
            publisher_done_receiver
                .recv()
                .expect("every foreign producer completes its exact source publication");
        }

        for local in local_clients {
            // SAFETY: each local client remains current in this owner until
            // this one ordinary source free.
            assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the owner force-collects every remote publication before its PageMap entries can release"
        );
    });

    let remote_clients = remote_receiver
        .recv()
        .expect("the owner remains live while the foreign publishers start");
    assert_eq!(remote_clients.len(), producer_count);

    let mut publishers = Vec::with_capacity(producer_count);
    for (index, address) in remote_clients.into_iter().enumerate() {
        let start = Arc::clone(&start);
        let publisher_done_sender = publisher_done_sender.clone();
        publishers.push(std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            // SAFETY: the owner has published one exact current source client
            // and waits for this producer to consume it before teardown.
            let remote = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };

            start.wait();
            // SAFETY: source PageMap lookup runs while the exact client still
            // contributes to the owner's `used` count. It must therefore
            // recover the same page/extent even while owner collection runs.
            unsafe {
                assert_eq!(remote.as_ptr().read(), (0x40 + index) as u8);
                assert_eq!(remote.as_ptr().add(36).read(), (0x80 + index) as u8);
            }
            assert!(
                unsafe { native_usable_size(remote) }.is_some_and(|size| size >= 37),
                "producer {index} reads the source PageMap extent before its atomic publication"
            );
            assert_eq!(
                unsafe { native_free(remote) },
                NativePageFreeResult::Freed,
                "producer {index} publishes its canonical source block exactly once"
            );
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "producer {index} finishes its independent no-page attachment"
            );
            publisher_done_sender
                .send(())
                .expect("the source owner observes this completed publication");
        }));
    }
    drop(publisher_done_sender);

    for publisher in publishers {
        publisher
            .join()
            .expect("each source-page remote publisher completes without a route lookup");
    }
    owner
        .join()
        .expect("the owner collects all page-local remote publications");

    let resumed = match ticket_zero_allocate(37, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!(
            "ticket zero resumes after the {producer_count}-producer PageMap lifetime epoch"
        ),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed static owner remains independent of the completed remote-free epoch"
    );
}
