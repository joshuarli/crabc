#![cfg(feature = "native-runtime-test-audit")]

use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    TicketZeroPageAllocationResult, TicketZeroPageFreeResult, attach_current_thread,
    finish_current_thread_native_after_user_destructors, initialize_process, native_allocate_aligned,
    native_free, native_reallocate, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, native_usable_size, prepare_native_later_thread_arena,
    ticket_zero_allocate, ticket_zero_free,
};

const SOURCE_COUNT: usize = 6;
const MEDIUM_REQUEST: usize = 64 * 1024;
const MEDIUM_REALLOC_REQUEST: usize = 128 * 1024;
const MEDIUM_SENTINEL_HEAD: u8 = 0x61;
const MEDIUM_SENTINEL_MIDDLE: u8 = 0x62;
const MEDIUM_SENTINEL_TAIL: u8 = 0x63;
const SOURCE_CLASSES: [(&str, usize); SOURCE_COUNT] = [
    ("direct-small", 37),
    ("non-direct-small", 1025),
    ("medium", MEDIUM_REQUEST),
    ("regular-large", 128 * 1024),
    ("arena-singleton", 1024 * 1024),
    ("OS-singleton", 7),
];

/// The source-permitted terminal action for one exact raw C-shaped pointer.
/// This is test scheduling metadata only: a consumer receives neither A's
/// former owner nor a route, ledger, PageMap lease, or release capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MixedAction {
    Free,
    ReallocateMedium,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MixedInput {
    geometry: &'static str,
    minimum_usable_size: usize,
    address: usize,
    action: MixedAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReallocateOutcome {
    Allocated,
    Unavailable,
    AllocationFailed,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MixedOperation {
    Free(NativePageFreeResult),
    Reallocate {
        outcome: ReallocateOutcome,
        replacement_is_distinct: bool,
        replacement_usable_size: Option<usize>,
        copied_head: Option<u8>,
        copied_middle: Option<u8>,
        copied_tail: Option<u8>,
        replacement_free: Option<NativePageFreeResult>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MixedObservation {
    input: MixedInput,
    attachment: Option<ThreadAttachResult>,
    source_usable_size: Option<usize>,
    operation: Option<MixedOperation>,
    finish_result: Option<ThreadFinishResult>,
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn exact_post_exit_block(address: usize) -> core::ptr::NonNull<u8> {
    // SAFETY: A supplied this exact live C-shaped pointer before owner exit.
    // Pointer-first operations recover source state from the process PageMap.
    unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) }
}

fn allocate_mixed_sources() -> [usize; SOURCE_COUNT] {
    let direct_small = match native_allocate_aligned(37, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its direct-small native client"),
    };
    let non_direct_small = match native_allocate_aligned(1025, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its non-direct-small native client"),
    };
    let medium = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its medium native client"),
    };
    let large = match native_allocate_aligned(128 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its regular-large native client"),
    };
    let arena_singleton = match native_allocate_aligned(1024 * 1024, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its arena-singleton native client"),
    };
    let os_singleton = match native_allocate_aligned(7, 128 * 1024, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("A receives its OS-singleton native client"),
    };
    // The medium survivor must recover this source extent through PageMap
    // facts before copying it through a new B-owned replacement.
    unsafe {
        medium.as_ptr().write(MEDIUM_SENTINEL_HEAD);
        medium.as_ptr().add(4095).write(MEDIUM_SENTINEL_MIDDLE);
        medium
            .as_ptr()
            .add(MEDIUM_REQUEST - 1)
            .write(MEDIUM_SENTINEL_TAIL);
    }
    let sources = [
        direct_small.as_ptr().addr(),
        non_direct_small.as_ptr().addr(),
        medium.as_ptr().addr(),
        large.as_ptr().addr(),
        arena_singleton.as_ptr().addr(),
        os_singleton.as_ptr().addr(),
    ];
    for (left_index, left) in sources.iter().enumerate() {
        for right in &sources[(left_index + 1)..] {
            assert_ne!(
                left, right,
                "A publishes distinct mixed source clients for distinct survivor operations"
            );
        }
    }
    sources
}

fn publish_mixed_sources() -> [usize; SOURCE_COUNT] {
    let (sender, receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        sender
            .send(allocate_mixed_sources())
            .expect("A publishes only exact C-shaped mixed source pointers before owner exit");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before the concurrent B operations"
        );
    });
    let sources = receiver
        .recv()
        .expect("the coordinator receives every exact mixed source pointer before A exits");
    owner
        .join()
        .expect("A reaches its completed native owner-exit boundary");
    sources
}

fn consume_mixed_source(input: MixedInput) -> MixedOperation {
    let block = exact_post_exit_block(input.address);
    match input.action {
        MixedAction::Free => {
            // SAFETY: this exact source stays live after A's exit until this
            // one pointer-centered terminal free.
            MixedOperation::Free(unsafe { native_free(block) })
        }
        MixedAction::ReallocateMedium => {
            // SAFETY: this medium source stays live until reallocation either
            // preserves it on failure or consumes it through its PageMap tail.
            match unsafe { native_reallocate(Some(block), MEDIUM_REALLOC_REQUEST) } {
                NativePageAllocationResult::Allocated(replacement) => {
                    let replacement_usable_size = unsafe { native_usable_size(replacement) };
                    // SAFETY: the replacement covers the fixed medium source
                    // prefix, and it has not escaped B's current owner.
                    let (copied_head, copied_middle, copied_tail, replacement_free) = unsafe {
                        (
                            replacement.as_ptr().read(),
                            replacement.as_ptr().add(4095).read(),
                            replacement.as_ptr().add(MEDIUM_REQUEST - 1).read(),
                            native_free(replacement),
                        )
                    };
                    MixedOperation::Reallocate {
                        outcome: ReallocateOutcome::Allocated,
                        replacement_is_distinct: replacement != block,
                        replacement_usable_size,
                        copied_head: Some(copied_head),
                        copied_middle: Some(copied_middle),
                        copied_tail: Some(copied_tail),
                        replacement_free: Some(replacement_free),
                    }
                }
                NativePageAllocationResult::Unavailable => MixedOperation::Reallocate {
                    outcome: ReallocateOutcome::Unavailable,
                    replacement_is_distinct: false,
                    replacement_usable_size: None,
                    copied_head: None,
                    copied_middle: None,
                    copied_tail: None,
                    replacement_free: None,
                },
                NativePageAllocationResult::AllocationFailed => MixedOperation::Reallocate {
                    outcome: ReallocateOutcome::AllocationFailed,
                    replacement_is_distinct: false,
                    replacement_usable_size: None,
                    copied_head: None,
                    copied_middle: None,
                    copied_tail: None,
                    replacement_free: None,
                },
                NativePageAllocationResult::Retained => MixedOperation::Reallocate {
                    outcome: ReallocateOutcome::Retained,
                    replacement_is_distinct: false,
                    replacement_usable_size: None,
                    copied_head: None,
                    copied_middle: None,
                    copied_tail: None,
                    replacement_free: None,
                },
            }
        }
    }
}

fn mixed_worker(
    input: MixedInput,
    start: Arc<Barrier>,
    source_observed: Arc<Barrier>,
) -> MixedObservation {
    let attachment = attach_current_thread();
    // Every fresh survivor joins both barriers even on failed attachment so
    // the test has a bounded result rather than a stranded valid operation.
    start.wait();
    let source_usable_size = if attachment == ThreadAttachResult::Attached {
        // SAFETY: B has only this one exact still-live A client; the barrier
        // starts every pointer-first source observation from the same exit.
        unsafe { native_usable_size(exact_post_exit_block(input.address)) }
    } else {
        None
    };
    source_observed.wait();
    if attachment != ThreadAttachResult::Attached {
        return MixedObservation {
            input,
            attachment: Some(attachment),
            source_usable_size,
            operation: None,
            finish_result: None,
        };
    }
    let operation = consume_mixed_source(input);
    let finish_result = finish_current_thread_native_after_user_destructors();
    MixedObservation {
        input,
        attachment: Some(attachment),
        source_usable_size,
        operation: Some(operation),
        finish_result: Some(finish_result),
    }
}

fn assert_mixed_observation(observation: MixedObservation) {
    assert!(
        observation
            .source_usable_size
            .is_some_and(|usable_size| usable_size >= observation.input.minimum_usable_size),
        "{} remains PageMap-queryable before its concurrent post-exit operation: {observation:?}",
        observation.input.geometry,
    );
    match (observation.input.action, observation.operation) {
        (
            MixedAction::Free,
            Some(MixedOperation::Free(NativePageFreeResult::Freed)),
        ) => {}
        (
            MixedAction::ReallocateMedium,
            Some(MixedOperation::Reallocate {
                outcome: ReallocateOutcome::Allocated,
                replacement_is_distinct: true,
                replacement_usable_size,
                copied_head: Some(MEDIUM_SENTINEL_HEAD),
                copied_middle: Some(MEDIUM_SENTINEL_MIDDLE),
                copied_tail: Some(MEDIUM_SENTINEL_TAIL),
                replacement_free: Some(NativePageFreeResult::Freed),
            }),
        ) if replacement_usable_size
            .is_some_and(|usable_size| usable_size >= MEDIUM_REALLOC_REQUEST) => {}
        _ => panic!(
            "{} completes its source-permitted pointer operation without a route or ledger: {observation:?}",
            observation.input.geometry,
        ),
    }
    if observation.attachment.is_some() {
        assert_eq!(
            observation.attachment,
            Some(ThreadAttachResult::Attached),
            "every fresh B attaches before its pointer operation: {observation:?}"
        );
        assert_eq!(
            observation.finish_result,
            Some(ThreadFinishResult::Finished),
            "each fresh B completes independently after its one pointer operation: {observation:?}"
        );
    }
}

/// Run this direct behavior test with:
/// `cargo test -p crabc-mimalloc --features native-runtime-test-audit --test native_concurrent_mixed_post_exit_completions -- --exact --test-threads=1`.
///
/// A exits with six deliberately distinct classes. The initial survivor and
/// five fresh B threads each receive one exact pointer, all observe
/// PageMap-derived usable size, and then free or grow the source-permitted
/// client concurrently. No client ledger, route token, or test turn schedule
/// may supply the former A state.
#[test]
fn concurrent_mixed_post_exit_pointer_operations_complete_through_page_state() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the concurrent mixed pointer witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the persistent initial owner prepares the shared source arena before A exits"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared initial owner exposes a quiescent lifecycle baseline");

    let sources = publish_mixed_sources();
    let after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("A's completed owner exit leaves its live sources PageMap-visible");
    assert!(
        after_owner_exit.page_map_registered_entry_count
            > baseline.page_map_registered_entry_count,
        "A's live mixed sources stay registered until their exact operations consume them"
    );
    assert!(
        after_owner_exit.main_heap_abandoned_page_count > baseline.main_heap_abandoned_page_count
            || after_owner_exit.main_heap_os_abandoned_pages_empty
                < baseline.main_heap_os_abandoned_pages_empty,
        "A's source ownership is represented by abandoned page/process state before survivors begin"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A releases its own admission before any survivor attaches"
    );

    let actions = [
        MixedAction::Free,
        MixedAction::Free,
        MixedAction::ReallocateMedium,
        MixedAction::Free,
        MixedAction::Free,
        MixedAction::Free,
    ];
    let inputs: [MixedInput; SOURCE_COUNT] = core::array::from_fn(|index| MixedInput {
        geometry: SOURCE_CLASSES[index].0,
        minimum_usable_size: SOURCE_CLASSES[index].1,
        address: sources[index],
        action: actions[index],
    });

    // The persistent initial thread is one survivor; the other five are
    // fresh B threads. Each has only its exact C-shaped input.
    let start = Arc::new(Barrier::new(SOURCE_COUNT));
    let source_observed = Arc::new(Barrier::new(SOURCE_COUNT));
    let initial_input = inputs[0];
    let workers: Vec<_> = inputs
        .into_iter()
        .skip(1)
        .map(|input| {
            let start = Arc::clone(&start);
            let source_observed = Arc::clone(&source_observed);
            std::thread::spawn(move || mixed_worker(input, start, source_observed))
        })
        .collect();
    start.wait();
    // SAFETY: the initial owner has only this exact live A client and no
    // other survivor gets its address.
    let initial_source_usable_size = unsafe { native_usable_size(exact_post_exit_block(initial_input.address)) };
    source_observed.wait();
    let initial_observation = MixedObservation {
        input: initial_input,
        attachment: None,
        source_usable_size: initial_source_usable_size,
        operation: Some(consume_mixed_source(initial_input)),
        finish_result: None,
    };

    let mut observations = vec![initial_observation];
    for worker in workers {
        observations.push(
            worker
                .join()
                .expect("every fixed mixed survivor returns a bounded observation"),
        );
    }
    for observation in observations {
        assert_mixed_observation(observation);
    }

    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "every fresh survivor releases only its own completed attachment"
    );
    let after = native_runtime_lifecycle_test_audit()
        .expect("every concurrent survivor joins before the final lifecycle audit");
    assert_eq!(
        after.page_map_registered_entry_count, baseline.page_map_registered_entry_count,
        "every exact source and the medium replacement release PageMap registrations"
    );
    assert_eq!(
        after.arena_registry_count, baseline.arena_registry_count,
        "concurrent mixed completion leaves no extra process arena registration"
    );
    assert_eq!(
        after.main_heap_abandoned_page_count, baseline.main_heap_abandoned_page_count,
        "every regular source leaves static-main abandoned state at baseline"
    );
    assert_eq!(
        after.main_heap_os_abandoned_pages_empty, baseline.main_heap_os_abandoned_pages_empty,
        "the OS singleton leaves no abandoned-list member after concurrent release"
    );
    assert_eq!(
        after.live_thread_count, baseline.live_thread_count,
        "A and every fresh survivor leave no later-thread source identity behind"
    );
    assert_eq!(
        after.shared_later_theap_count, baseline.shared_later_theap_count,
        "no survivor retains A's former Theap or a shared successor"
    );
    assert_eq!(
        after
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "pointer-centered post-exit operations do not enter the legacy scheduler"
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "pointer-centered post-exit operations do not enter the parked compatibility bridge"
    );

    let resumed = match ticket_zero_allocate(73, false) {
        TicketZeroPageAllocationResult::Allocated(block) => block,
        TicketZeroPageAllocationResult::Unavailable => {
            panic!("ticket zero remains independently usable after concurrent source completion")
        }
        TicketZeroPageAllocationResult::AllocationFailed => {
            panic!("the fixed ticket-zero request remains allocatable after concurrent completion")
        }
        TicketZeroPageAllocationResult::Retained => {
            panic!("healthy concurrent source completion does not retain ticket zero")
        }
    };
    assert_eq!(
        unsafe { ticket_zero_free(resumed) },
        TicketZeroPageFreeResult::Freed,
        "ticket zero returns its independent post-convergence allocation"
    );
}
