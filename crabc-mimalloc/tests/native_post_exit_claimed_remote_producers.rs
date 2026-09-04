use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, TicketZeroPageAllocationResult, TicketZeroPageFreeResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_usable_size, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

const REQUEST: usize = 37;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// Each producer owns one exact client from one source direct-small page after
/// its owner has published abandonment. Their simultaneous `native_free`
/// calls must elect one `allow_collect=true` low-bit claimant, preserve every
/// later producer on the source remote list, and finish without retaining the
/// source PageMap lifetime.
#[test]
fn post_exit_low_bit_claim_collects_exact_same_page_remote_producers() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the post-exit low-bit claim witness"
    );

    for producer_count in [1usize, 2, 4, 8] {
        assert!(
            prepare_native_later_thread_arena(),
            "ticket zero restores the source arena before the {producer_count}-producer epoch"
        );
        run_claim_epoch(producer_count);
    }
}

fn run_claim_epoch(producer_count: usize) {
    let (clients_sender, clients_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let mut clients = Vec::with_capacity(producer_count);
        for index in 0..producer_count {
            let client = match native_allocate_aligned(REQUEST, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!(
                    "the source owner allocates exact direct-small client {index} for {producer_count} producers"
                ),
            };
            // SAFETY: the exact client remains live until its one foreign
            // producer consumes it after this owner has published abandonment.
            unsafe {
                client.as_ptr().write((0x30 + index) as u8);
                client.as_ptr().add(REQUEST - 1).write((0x90 + index) as u8);
            }
            clients.push(client.as_ptr().addr());
        }
        clients_sender
            .send(clients)
            .expect("the post-exit producers receive only exact C-shaped clients");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the source owner publishes the still-live same-page clients before any producer frees"
        );
    });

    let clients = clients_receiver
        .recv()
        .expect("the owner publishes the complete exact source client set");
    owner
        .join()
        .expect("the source owner completes its abandon/unown boundary");
    assert_eq!(clients.len(), producer_count);

    let start = Arc::new(Barrier::new(producer_count + 1));
    let mut producers = Vec::with_capacity(producer_count);
    for (index, address) in clients.into_iter().enumerate() {
        let start = Arc::clone(&start);
        producers.push(std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            // SAFETY: this is the one exact current client allocated by the
            // finished owner; no other producer receives the same address.
            let client = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            // SAFETY: the client remains live until this producer's one
            // source pointer operation completes.
            unsafe {
                assert_eq!(client.as_ptr().read(), (0x30 + index) as u8);
                assert_eq!(client.as_ptr().add(REQUEST - 1).read(), (0x90 + index) as u8);
            }
            assert!(
                unsafe { native_usable_size(client) }.is_some_and(|size| size >= REQUEST),
                "producer {index} resolves its exact PageMap client before the shared low-bit CAS"
            );
            // Every producer has now completed its pointer-first PageMap
            // observation while every source client is still live. The shared
            // release begins competing `allow_collect=true` publications from
            // the same abandoned page rather than serializing lookups behind
            // a prior terminal free.
            start.wait();
            assert_eq!(
                unsafe { native_free(client) },
                NativePageFreeResult::Freed,
                "producer {index} publishes or collects its exact source block once"
            );
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "producer {index} finishes its independent attachment after the page-local source operation"
            );
        }));
    }

    start.wait();
    for producer in producers {
        producer
            .join()
            .expect("each source-page producer completes its pointer-first free");
    }

    let resumed = match ticket_zero_allocate(REQUEST, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!(
            "ticket zero remains usable after the {producer_count}-producer claimed-page epoch"
        ),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the complete same-page claim/collection epoch leaves no retained source lifetime"
    );
}
