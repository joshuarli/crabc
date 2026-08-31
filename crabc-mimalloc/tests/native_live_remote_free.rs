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
fn native_live_owner_remote_free_uses_pointer_first_page_map() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its live-owner remote-free witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero readies the first arena before A owns a persistent page engine"
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
            .expect("A continues after B completes the read-only PageMap query");

        let query_probe = match native_allocate_aligned(29, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A continues its persistent owner after B's read-only usable-size query"),
        };
        // SAFETY: the probe remains current only in A's persistent owner.
        assert_eq!(unsafe { native_free(query_probe) }, NativePageFreeResult::Freed);
        free_sender
            .send(())
            .expect("B publishes only after A completes its normal local operation");
        resume_receiver
            .recv()
            .expect("A continues only after B completes its pointer-first free");

        let reused = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A continues its exact persistent native owner"),
        };
        // A may still have an ordinary local free-list entry ahead of B's
        // atomic remote head. The important C boundary is that this ordinary
        // owner operation resumes safely; its later all-free source drain
        // force-collects B's published client before it releases A's pages.
        assert_ne!(reused.as_ptr(), core::ptr::null_mut());
        // SAFETY: both blocks remain current only in A's persistent owner.
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
        .expect("A keeps its live persistent source engine before B enters");
    let releaser = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // SAFETY: A keeps this exact native allocation live until B publishes
        // its source-shaped remote free and finishes its own operation.
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
            .expect("B waits for A to complete its local operation before the source publication");
        assert_eq!(
            unsafe { native_free(remote) },
            NativePageFreeResult::Freed,
            "B publishes the exact A-owned C client while A remains live"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B finishes its independent no-page attachment after the PageMap publication"
        );
    });
    releaser
        .join()
        .expect("B finishes its complete no-page lifecycle");
    resume_sender
        .send(())
        .expect("A may continue after B completes the pointer-first free");
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
    native_live_owner_remote_free_from_worker_keeps_b_local_owner();
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
            _ => panic!("A continues after both publishers complete their PageMap frees"),
        };
        let second_probe = match native_allocate_aligned(53, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A performs a second ordinary operation after both publications"),
        };
        // SAFETY: the probes and local client remain current only in A's
        // persistent owner. A's all-free drain will force-collect both remote
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
        .expect("A keeps its live source engine before B and C enter");
    let start = Arc::new(Barrier::new(3));
    let publishers = [
        (first, 37usize, 0x51u8, 0x52u8),
        (second, 53usize, 0x53u8, 0x54u8),
    ]
    .map(|(address, request, first_byte, last_byte)| {
        let start = Arc::clone(&start);
        std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            // SAFETY: A keeps this exact allocation live until this publisher
            // completes its source-shaped PageMap remote free.
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
                "the page's atomic remote head serializes one exact publication per publisher"
            );
            assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "each no-page publisher finishes after its independent PageMap publication"
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
        .expect("A may continue only after both publishers complete their PageMap frees");
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

/// A foreign-pointer releaser may already own local bookkeeping and payload.
/// Its independent persistent owner must therefore remain usable while it
/// atomically publishes A's exact live client to A's remote head.
fn native_live_owner_remote_free_from_worker_keeps_b_local_owner() {
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero restores its dormant arena before the independent receiver begins"
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
            _ => panic!("A retains a local client while B owns an independent persistent owner"),
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
            .expect("B starts only after A keeps its source owner live");
        remote_sender
            .send(remote.as_ptr().addr())
            .expect("B receives only A's exact C-shaped address after it owns local state");
        resume_receiver
            .recv()
            .expect("A waits until B completes both of its pointer operations");

        let probe = match native_allocate_aligned(37, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("A continues after B's pointer-first publication"),
        };
        // SAFETY: the probe and local block remain current in A's owner;
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
            .expect("B waits for A's live owner before creating its local state");
        let local = match native_allocate_aligned(89, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => panic!("B creates its independent persistent local owner"),
        };
        let remote = remote_receiver
            .recv()
            .expect("B receives A's pointer only after B owns its local state");
        // SAFETY: A retains this exact client live; B receives no source
        // capability beyond the raw C-shaped address.
        let remote = unsafe { core::ptr::NonNull::new_unchecked(remote as *mut u8) };
        assert_eq!(
                unsafe { native_free(remote) },
                NativePageFreeResult::Freed,
                "B publishes A's exact client while retaining B's own local owner"
        );
        assert_eq!(
            unsafe { native_free(local) },
            NativePageFreeResult::Freed,
            "B retains and frees its local client after publishing A's pointer"
        );
        assert_eq!(
                finish_current_thread_native_after_user_destructors(),
                ThreadFinishResult::Finished,
                "B's all-free finish releases only B's own persistent owner"
        );
    });
    releaser
        .join()
        .expect("B publishes A's pointer and finishes its local owner");
    resume_sender
        .send(())
        .expect("A may continue after B finishes its independent owner");
    owner
        .join()
        .expect("A collects the publication and finishes normally");

    let resumed = match ticket_zero_allocate(89, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        _ => panic!("ticket zero resumes after A and B complete their persistent owners"),
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "the dormant ticket-zero pair receives its local client after the transfer"
    );
}
