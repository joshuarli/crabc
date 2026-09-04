use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_usable_size, prepare_native_later_thread_arena,
};

const RELEASER_COUNT: usize = 16;
const LIVE_BLOCK_COUNT: usize = RELEASER_COUNT;
// A 2 MiB alignment forces an OS-backed singleton for this 1 MiB request.
// Its multi-slice PageMap source range gives simultaneous terminal frees a
// real structural lifecycle to serialize, without making this a large-memory
// stress test.
const OS_SINGLETON_REQUEST: usize = 1024 * 1024;
const OS_ALIGNMENT: usize = 2 * 1024 * 1024;

#[derive(Debug)]
struct ReleaseObservation {
    index: usize,
    sentinels_intact: bool,
    usable_size: Option<usize>,
    free: NativePageFreeResult,
}

#[derive(Debug)]
struct ReleaserObservation {
    releases: Vec<ReleaseObservation>,
    finish: ThreadFinishResult,
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn source_client_request(index: usize) -> usize {
    assert!(
        index < LIVE_BLOCK_COUNT,
        "each fresh releaser owns one exact OS-singleton source client"
    );
    OS_SINGLETON_REQUEST
}

/// Publishes distinct large OS-singleton source ranges. Their wide PageMap
/// spans make the terminal structural release contention observable without
/// giving any B a route, page, owner, or mutation capability.
fn publish_concurrent_post_exit_os_singletons() -> [usize; LIVE_BLOCK_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let mut clients = [0; LIVE_BLOCK_COUNT];

        for (index, client) in clients.iter_mut().enumerate() {
            let size = source_client_request(index);
            let block = match native_allocate_aligned(size, OS_ALIGNMENT, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!("A allocates every concurrent OS-singleton source client"),
            };
            assert_eq!(
                block.as_ptr().addr() % OS_ALIGNMENT,
                0,
                "each source OS-singleton retains its requested alignment"
            );
            // SAFETY: `block` is A's exact live native client until the fresh
            // releaser later consumes it. The distinct sentinels prove that
            // every pointer-first observation names its exact live client.
            unsafe {
                block.as_ptr().write((0x20 + index) as u8);
                block.as_ptr().add(size - 1).write((0x80 + index) as u8);
            }
            *client = block.as_ptr().addr();
        }

        sender
            .send(clients)
            .expect("A publishes only exact source clients before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before any B begins a free"
        );
    });
    let clients = receiver
        .recv()
        .expect("the coordinator receives the complete source image");
    owner
        .join()
        .expect("A reaches its completed native owner-exit boundary");
    clients
}

#[test]
fn concurrent_distinct_post_exit_page_releases_complete_without_retention() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the concurrent owner-exit witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent initial owner prepares the later-owner source arena"
    );

    let clients = Arc::new(publish_concurrent_post_exit_os_singletons());
    let release_barrier = Arc::new(Barrier::new(RELEASER_COUNT + 1));
    let terminal_free_barrier = Arc::new(Barrier::new(RELEASER_COUNT));
    let mut releasers = Vec::with_capacity(RELEASER_COUNT);

    for releaser in 0..RELEASER_COUNT {
        let clients = Arc::clone(&clients);
        let release_barrier = Arc::clone(&release_barrier);
        let terminal_free_barrier = Arc::clone(&terminal_free_barrier);
        releasers.push(std::thread::spawn(move || {
            assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
            release_barrier.wait();

            let index = releaser;
            let size = source_client_request(index);
            // SAFETY: A published this exact still-live native client before
            // completing source collect-abandon. This fresh B receives
            // neither an owner, a route, a source page, nor a release
            // capability; it must use pointer-first state.
            let block = unsafe { core::ptr::NonNull::new_unchecked(clients[index] as *mut u8) };
            // SAFETY: no other B receives this index, so the exact client
            // remains live through its sentinel and usable-size observations
            // until this B's following terminal free.
            let sentinels_intact = unsafe {
                block.as_ptr().read() == (0x20 + index) as u8
                    && block.as_ptr().add(size - 1).read() == (0x80 + index) as u8
            };
            let usable_size = unsafe { native_usable_size(block) };
            // Every B has now completed its immutable source observation.
            // Releasing this barrier makes the next operation sixteen distinct
            // terminal pointer-first frees, rather than an accidental race
            // between one free and another B's setup query.
            terminal_free_barrier.wait();
            let free = unsafe { native_free(block) };
            let finish = finish_current_thread_native_after_user_destructors();
            ReleaserObservation {
                releases: vec![ReleaseObservation {
                    index,
                    sentinels_intact,
                    usable_size,
                    free,
                }],
                finish,
            }
        }));
    }

    release_barrier.wait();
    for releaser in releasers {
        let observation = releaser
            .join()
            .expect("each fresh B returns its own post-exit release observations");
        assert_eq!(
            observation.finish,
            ThreadFinishResult::Finished,
            "each B completes only its own ordinary native finish"
        );
        for release in observation.releases {
            let size = source_client_request(release.index);
            assert!(
                release.sentinels_intact,
                "B observes intact sentinels for source client {}",
                release.index
            );
            assert_eq!(
                release.free,
                NativePageFreeResult::Freed,
                "concurrent B frees distinct source client {} without retention",
                release.index
            );
            assert!(
                release.usable_size.is_some_and(|usable_size| usable_size >= size),
                "B keeps source client {} PageMap-queryable before its free",
                release.index
            );
        }
    }

    let after = match native_allocate_aligned(53, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("the initial owner remains usable after every B finishes"),
    };
    // SAFETY: `after` is the initial owner's exact local client, proving
    // that completion of A's terminal proof did not retain the process.
    unsafe {
        after.as_ptr().write(0x51);
        after.as_ptr().add(52).write(0x52);
        assert_eq!(after.as_ptr().read(), 0x51);
        assert_eq!(after.as_ptr().add(52).read(), 0x52);
    }
    assert_eq!(
        unsafe { native_free(after) },
        NativePageFreeResult::Freed,
        "the initial owner returns its independent post-epoch client"
    );
}
