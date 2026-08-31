use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult,
    ThreadFinishResult, attach_current_thread, finish_current_thread_native_after_user_destructors,
    initialize_process, native_allocate_aligned, native_free, prepare_native_later_thread_arena,
    native_usable_size, ticket_zero_allocate, ticket_zero_free, TicketZeroPageAllocationResult,
    TicketZeroPageFreeResult,
};

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

#[test]
fn native_live_owner_remote_free_returns_a_parked_worker_to_its_owner() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its live-owner remote-free witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero parks the first arena before A owns a persistent session"
    );

    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (query_sender, query_receiver) = mpsc::sync_channel(0);
    let (free_sender, free_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives the remote C-shaped client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A retains a second local client while B publishes"),
        };
        remote_sender
            .send(remote.as_ptr().addr())
            .expect("B receives only the C-shaped remote address");
        query_receiver
            .recv()
            .expect("A resumes only after B has restored the read-only handoff");

        let query_probe = match native_allocate_aligned(29, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A resumes its parked session after B's read-only usable-size query"),
        };
        // SAFETY: the probe remains current only in A's resumed session.
        assert_eq!(unsafe { native_free(query_probe) }, NativePageFreeResult::Freed);
        free_sender
            .send(())
            .expect("B publishes only after A proves the read-only route restored PARKED");
        resume_receiver
            .recv()
            .expect("A resumes only after B has returned the parked scheduler state");

        let reused = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A resumes its exact parked native session"),
        };
        // A may still have an ordinary local free-list entry ahead of B's
        // atomic remote head. The important C boundary is that this ordinary
        // owner operation resumes safely; its later all-free source drain
        // force-collects B's published client before it releases A's pages.
        assert_ne!(reused.as_ptr(), core::ptr::null_mut());
        // SAFETY: both blocks remain current only in A's resumed session.
        assert_eq!(unsafe { native_free(reused) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A's all-free native finish returns ticket zero after collecting B's publication"
        );
    });

    let remote = remote_receiver
        .recv()
        .expect("A parks its live source engine before B enters");
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A keeps this exact native allocation live and parked until
        // B publishes its source-shaped remote free and finishes its own
        // complete interleaving operation.
        let remote = unsafe { core::ptr::NonNull::new_unchecked(remote as *mut u8) };
        assert!(
            unsafe { native_usable_size(remote) }.is_some_and(|size| size >= 37),
            "B reads A's captured PageMap usable extent before it publishes the exact remote free"
        );
        query_sender
            .send(())
            .expect("A may resume before B takes the separate source publication operation");
        free_receiver
            .recv()
            .expect("B waits for A to restore its live parked session before the source publication");
        assert_eq!(
            unsafe { native_free(remote) },
            NativePageFreeResult::Freed,
            "B publishes the exact A-owned C client while A remains live"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B returns the scheduler to A's parked persistent session"
        );
    });
    releaser
        .join()
        .expect("B finishes its complete no-page lifecycle");
    resume_sender
        .send(())
        .expect("A may resume after B restored the parked state");
    owner
        .join()
        .expect("A collects the remote publication and finishes normally");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes after A's all-free finish"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the resumed ticket-zero client returns to its dormant pair"
    );

    native_live_owner_serializes_two_exact_remote_publishers_before_collection();
    native_live_owner_remote_free_from_parked_worker_keeps_b_local_session();
}

fn native_live_owner_serializes_two_exact_remote_publishers_before_collection() {
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero restores its dormant arena before A owns the two-publisher persistent session"
    );

    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let first = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives the first remote C-shaped client"),
        };
        let second = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A receives the second remote C-shaped client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A retains one local client while both publishers run"),
        };
        // SAFETY: each client is current only in A's just-created native
        // session until an exact B/C route publishes it to A's remote head.
        unsafe {
            first.as_ptr().write(0x51);
            first.as_ptr().add(36).write(0x52);
            second.as_ptr().write(0x53);
            second.as_ptr().add(52).write(0x54);
            local.as_ptr().write(0x55);
            local.as_ptr().add(72).write(0x56);
        }
        remote_sender
            .send([first.as_ptr().addr(), second.as_ptr().addr()])
            .expect("B and C receive only the two C-shaped client addresses");
        resume_receiver
            .recv()
            .expect("A resumes only after both exact remote publications finish");

        let first_probe = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A resumes after both publishers restored its parked session"),
        };
        let second_probe = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A performs a second ordinary operation after both publications"),
        };
        // SAFETY: the probes and local client remain current only in A's
        // resumed session. A's all-free drain will force-collect both remote
        // head entries before its source pages can release.
        unsafe {
            first_probe.as_ptr().write(0x57);
            first_probe.as_ptr().add(36).write(0x58);
            second_probe.as_ptr().write(0x59);
            second_probe.as_ptr().add(52).write(0x5a);
            assert_eq!(local.as_ptr().read(), 0x55);
            assert_eq!(local.as_ptr().add(72).read(), 0x56);
        }
        assert_eq!(unsafe { native_free(first_probe) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(second_probe) }, NativePageFreeResult::Freed);
        assert_eq!(unsafe { native_free(local) }, NativePageFreeResult::Freed);
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A's all-free native finish collects both remote publications before ticket zero returns"
        );
    });

    let [first, second] = remote_receiver
        .recv()
        .expect("A parks its live source engine before B and C enter");
    let start = Arc::new(Barrier::new(3));
    let publishers = [
        (first, 37usize, 0x51u8, 0x52u8),
        (second, 53usize, 0x53u8, 0x54u8),
    ]
    .map(|(address, request, first_byte, last_byte)| {
        let start = Arc::clone(&start);
        std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            // SAFETY: A keeps this exact allocation live and parked until
            // this publisher completes its source-shaped remote-free route.
            let remote = unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) };
            // SAFETY: B/C read only their supplied live C-shaped client
            // before atomically publishing its canonical block to A.
            unsafe {
                assert_eq!(remote.as_ptr().read(), first_byte);
                assert_eq!(remote.as_ptr().add(request - 1).read(), last_byte);
            }
            assert!(
                unsafe { native_usable_size(remote) }.is_some_and(|size| size >= request),
                "each publisher reads its exact captured PageMap usable extent"
            );
            start.wait();
            assert_eq!(
                unsafe { native_free(remote) },
                NativePageFreeResult::Freed,
                "the static live-owner route serializes one exact source publication per publisher"
            );
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "each no-page publisher finishes after returning the scheduler to A's parked session"
            );
        })
    });
    start.wait();
    for publisher in publishers {
        publisher
            .join()
            .expect("both independent publishers complete their exact remote-free routes");
    }
    resume_sender
        .send(())
        .expect("A may resume only after both publishers restored its parked scheduler state");
    owner
        .join()
        .expect("A collects both remote publications and finishes normally");

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes after A's two-publisher all-free finish"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its fresh client to the dormant pair after both publishers finish"
    );
}

/// A source-shaped transfer receiver commonly has already allocated its own
/// local bookkeeping and payload before it consumes a foreign pointer. Its
/// parked session must therefore stay accounted while it atomically publishes
/// A's exact live client to A's remote head.
fn native_live_owner_remote_free_from_parked_worker_keeps_b_local_session() {
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero restores its dormant arena before the parked receiver begins"
    );

    let (owner_ready_sender, owner_ready_receiver) = mpsc::sync_channel(0);
    let (remote_sender, remote_receiver) = mpsc::sync_channel(0);
    let (resume_sender, resume_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let remote = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A creates the exact live source client"),
        };
        let local = match native_allocate_aligned(73, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A retains a local client while B owns a parked session"),
        };
        // SAFETY: A owns both clients until B publishes only `remote` below.
        unsafe {
            remote.as_ptr().write(0x61);
            remote.as_ptr().add(36).write(0x62);
            local.as_ptr().write(0x63);
            local.as_ptr().add(72).write(0x64);
        }
        owner_ready_sender
            .send(())
            .expect("B starts only after A parks the source session");
        remote_sender
            .send(remote.as_ptr().addr())
            .expect("B receives only A's exact C-shaped address after its local session parks");
        resume_receiver
            .recv()
            .expect("A waits until B restored both parked sessions");

        let probe = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A resumes after B's parked-session publication"),
        };
        // SAFETY: the probe and local block remain current in A's session;
        // its source all-free drain collects B's remote-head publication.
        unsafe {
            assert_eq!(local.as_ptr().read(), 0x63);
            assert_eq!(local.as_ptr().add(72).read(), 0x64);
            assert_eq!(native_free(probe), NativePageFreeResult::Freed);
            assert_eq!(native_free(local), NativePageFreeResult::Freed);
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A finishes after collecting B's exact source publication"
        );
    });

    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        owner_ready_receiver
            .recv()
            .expect("B waits for A's live route before creating its local session");
        let local = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B creates its independent parked local session"),
        };
        let remote = remote_receiver
            .recv()
            .expect("B receives A's pointer only after B parks its local session");
        // SAFETY: A retains this exact client live and parked; B receives no
        // source route beyond the raw C-shaped address.
        let remote = unsafe { core::ptr::NonNull::new_unchecked(remote as *mut u8) };
        assert_eq!(
            unsafe { native_free(remote) },
            NativePageFreeResult::Freed,
            "B publishes A's exact client while restoring B's own parked session"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B retains and frees its local client after publishing A's pointer"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B's all-free finish releases only B's own parked session"
        );
    });
    releaser
        .join()
        .expect("B publishes A's pointer and finishes its local session");
    resume_sender
        .send(())
        .expect("A may resume after B restores its parked state");
    owner
        .join()
        .expect("A collects the publication and finishes normally");

    let resumed = match ticket_zero_allocate(89, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes after A and B complete their parked sessions"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the dormant ticket-zero pair receives its local client after the transfer"
    );
}
