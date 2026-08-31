#![cfg(feature = "native-runtime-test-audit")]

use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_runtime_fork_admission_test_audit, native_runtime_lifecycle_test_audit,
    native_usable_size, prepare_native_later_thread_arena, ticket_zero_allocate, ticket_zero_free,
};

const OS_SINGLETON_COUNT: usize = 16;
const OS_SINGLETON_REQUEST: usize = 7;

/// Returns the fixed alternating high-alignment source shape. Both alignments
/// are strictly on the OS-singleton side of the arena-alignment boundary.
const fn os_singleton_alignment(index: usize) -> usize {
    if index % 2 == 0 {
        32 * 1024 * 1024
    } else {
        64 * 1024 * 1024
    }
}

const fn source_head(index: usize) -> u8 {
    0x20 + index as u8
}

const fn source_tail(index: usize) -> u8 {
    0x80 + index as u8
}

/// One raw C-shaped source pointer for exactly one fresh B. Its index is only
/// test identity for the fixed sentinels; it is not an owner, a route, a
/// PageMap lease, or a client-collection/release capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OsSingletonInput {
    index: usize,
    address: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OsSingletonObservation {
    input: OsSingletonInput,
    attachment: ThreadAttachResult,
    source_usable_size: Option<usize>,
    copied_head: Option<u8>,
    copied_tail: Option<u8>,
    free_result: Option<NativePageFreeResult>,
    finish_result: Option<ThreadFinishResult>,
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn exact_post_exit_block(address: usize) -> core::ptr::NonNull<u8> {
    // SAFETY: the caller receives A's one exact live C-shaped client before
    // A completes source collect-abandon. It holds no source-owner or route
    // capability; native pointer-first dispatch must rediscover PageMap state.
    unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) }
}

fn publish_os_singleton_sources() -> [OsSingletonInput; OS_SINGLETON_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let inputs: [OsSingletonInput; OS_SINGLETON_COUNT] = core::array::from_fn(|index| {
            let alignment = os_singleton_alignment(index);
            let block = match native_allocate_aligned(OS_SINGLETON_REQUEST, alignment, false) {
                NativePageAllocationResult::Allocated(block) => block,
                _ => panic!(
                    "A allocates its distinct {alignment}-byte-aligned OS singleton {index}"
                ),
            };
            assert_eq!(
                block.as_ptr().addr() % alignment,
                0,
                "A's OS singleton {index} preserves its fixed high alignment"
            );
            // SAFETY: A owns this just-allocated seven-byte client until its
            // normal owner-exit transition below.
            unsafe {
                block.as_ptr().write(source_head(index));
                block
                    .as_ptr()
                    .add(OS_SINGLETON_REQUEST - 1)
                    .write(source_tail(index));
            }
            OsSingletonInput {
                index,
                address: block.as_ptr().addr(),
            }
        });
        for (left_index, left) in inputs.iter().enumerate() {
            for right in &inputs[(left_index + 1)..] {
                assert_ne!(
                    left.address, right.address,
                    "A publishes distinct OS singleton clients for distinct B survivors"
                );
            }
        }
        sender
            .send(inputs)
            .expect("A publishes only exact OS-singleton C pointers before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before any fresh B observes its source"
        );
    });
    let inputs = receiver
        .recv()
        .expect("the coordinator receives every exact high-alignment source pointer before A exits");
    owner
        .join()
        .expect("A reaches its completed native owner-exit boundary");
    inputs
}

fn release_os_singleton_source(
    input: OsSingletonInput,
    start: Arc<Barrier>,
    source_observed: Arc<Barrier>,
) -> OsSingletonObservation {
    let attachment = attach_current_thread();
    // Every fresh B reaches this source-operation boundary without a turn
    // scheduler or retry bridge. An attachment failure still joins the fixed
    // barriers so the regression fails boundedly instead of stranding peers.
    start.wait();
    let (source_usable_size, copied_head, copied_tail) = if attachment == ThreadAttachResult::Attached {
        let block = exact_post_exit_block(input.address);
        // SAFETY: this is B's one exact still-live client. No other B gets
        // this address, and source reads precede all terminal releases.
        unsafe {
            (
                native_usable_size(block),
                Some(block.as_ptr().read()),
                Some(
                    block
                        .as_ptr()
                        .add(OS_SINGLETON_REQUEST - 1)
                        .read(),
                ),
            )
        }
    } else {
        (None, None, None)
    };
    // All sixteen raw-pointer source observations complete before terminal
    // frees begin. The next calls are one free per B and may converge only
    // through the source-required PageMap/remote-free state.
    source_observed.wait();
    let (free_result, finish_result) = if attachment == ThreadAttachResult::Attached {
        let block = exact_post_exit_block(input.address);
        // SAFETY: this is B's one exact still-live source client.
        let free_result = unsafe { native_free(block) };
        let finish_result = finish_current_thread_native_after_user_destructors();
        (Some(free_result), Some(finish_result))
    } else {
        (None, None)
    };
    OsSingletonObservation {
        input,
        attachment,
        source_usable_size,
        copied_head,
        copied_tail,
        free_result,
        finish_result,
    }
}

fn assert_os_singleton_observation(observation: OsSingletonObservation) {
    assert_eq!(
        observation.attachment,
        ThreadAttachResult::Attached,
        "every fresh B attaches before its one OS-singleton operation: {observation:?}"
    );
    assert!(
        observation
            .source_usable_size
            .is_some_and(|usable_size| usable_size >= OS_SINGLETON_REQUEST),
        "B {} retains PageMap usable-size visibility for its exact OS singleton: {observation:?}",
        observation.input.index,
    );
    assert_eq!(
        observation.copied_head,
        Some(source_head(observation.input.index)),
        "B {} retains its source-head sentinel through A's owner exit: {observation:?}",
        observation.input.index,
    );
    assert_eq!(
        observation.copied_tail,
        Some(source_tail(observation.input.index)),
        "B {} retains its source-tail sentinel through A's owner exit: {observation:?}",
        observation.input.index,
    );
    assert_eq!(
        observation.free_result,
        Some(NativePageFreeResult::Freed),
        "B {} completes its post-exit OS-singleton terminal free without retention: {observation:?}",
        observation.input.index,
    );
    assert_eq!(
        observation.finish_result,
        Some(ThreadFinishResult::Finished),
        "B {} completes only its own later-thread lifecycle after its terminal free: {observation:?}",
        observation.input.index,
    );
}

/// Run this direct lifecycle regression with:
/// `cargo test -p crabc-mimalloc --features native-runtime-test-audit --test native_concurrent_post_exit_os_singletons -- --exact --test-threads=1`.
///
/// One exited A leaves sixteen distinct 32-/64-MiB-aligned OS singletons; all
/// sixteen fresh B threads synchronously query and free one distinct raw
/// pointer. Before the W03 exact post-owner-exit PageMap mutation boundary,
/// this contention shape could return `Retained` (or lose usable-size
/// visibility) for a valid source. No source owner, route, client ledger,
/// release capability, retry, or test turn schedule is available to B.
#[test]
fn concurrent_os_singleton_post_exit_frees_complete_without_retention() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the OS-singleton contention regression"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent initial owner prepares the native later-thread arena before A exits"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared initial owner exposes a quiescent lifecycle baseline");

    let inputs = publish_os_singleton_sources();
    let after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("A's completed OS-singleton owner exit remains PageMap-auditable");
    assert!(
        after_owner_exit.page_map_registered_entry_count
            > baseline.page_map_registered_entry_count,
        "every still-live OS singleton remains PageMap-registered after A exits"
    );
    assert_eq!(
        after_owner_exit.main_heap_os_abandoned_pages_empty,
        0,
        "A's high-alignment source pages enter OS-abandoned ownership before B frees"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A releases its admission before the sixteen fresh B threads attach"
    );

    let start = Arc::new(Barrier::new(OS_SINGLETON_COUNT));
    let source_observed = Arc::new(Barrier::new(OS_SINGLETON_COUNT));
    let workers: Vec<_> = inputs
        .into_iter()
        .map(|input| {
            let start = Arc::clone(&start);
            let source_observed = Arc::clone(&source_observed);
            std::thread::spawn(move || release_os_singleton_source(input, start, source_observed))
        })
        .collect();
    let observations: Vec<_> = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .expect("every synchronized OS-singleton B returns a bounded observation")
        })
        .collect();
    for observation in observations {
        assert_os_singleton_observation(observation);
    }

    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "every fresh B releases only its completed later-thread admission"
    );
    let after = native_runtime_lifecycle_test_audit()
        .expect("every synchronized B joins before the final OS-singleton lifecycle audit");
    assert_eq!(
        after.page_map_registered_entry_count, baseline.page_map_registered_entry_count,
        "all sixteen terminal frees return their PageMap registrations to baseline"
    );
    assert_eq!(
        after.arena_registry_count, baseline.arena_registry_count,
        "the OS-singleton contention run leaves no extra process arena registration"
    );
    assert_eq!(
        after.main_heap_abandoned_page_count, baseline.main_heap_abandoned_page_count,
        "the OS-singleton contention run leaves regular abandoned state at baseline"
    );
    assert_eq!(
        after.main_heap_os_abandoned_pages_empty, baseline.main_heap_os_abandoned_pages_empty,
        "all sixteen OS singletons leave the abandoned list at baseline"
    );
    assert_eq!(
        after.live_thread_count, baseline.live_thread_count,
        "A and every B leave no later-thread source identity behind"
    );
    assert_eq!(
        after.shared_later_theap_count, baseline.shared_later_theap_count,
        "no B retains A's former Theap or a shared successor"
    );
    assert_eq!(
        after
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "the exact PageMap completion path does not enter the legacy scheduler"
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "the exact PageMap completion path does not enter the parked compatibility bridge"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable => {
            panic!("ticket zero remains independently usable after OS-singleton convergence")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("the fixed ticket-zero request remains allocatable after OS-singleton convergence")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("healthy OS-singleton completion does not retain ticket zero")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its independent post-convergence allocation"
    );
}
