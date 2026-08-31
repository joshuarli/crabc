// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The scalar auditor is deliberately default-off and exposes
// no owner, route, raw page, remote-head address, allocator, or release
// capability.
#![cfg(feature = "native-runtime-test-audit")]

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_reallocate, native_runtime_lifecycle_test_audit,
    native_usable_size, prepare_native_later_thread_arena,
};

const OLD_REQUEST: usize = 64 * 1024;
const REPLACEMENT_REQUEST: usize = 128 * 1024;
const LOCAL_ANCHOR_REQUEST: usize = 53;
const SENTINEL_HEAD: u8 = 0x71;
const SENTINEL_MIDDLE: u8 = 0x72;
const SENTINEL_TAIL: u8 = 0x73;

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

/// The scalar test auditor intentionally has no raw remote-head accessor.
/// These are the stable, quiescent consequences it can expose after every
/// participating worker has joined: PageMap coverage, arena registration, and
/// page-owned abandoned-list state. The exact live client's usable extent and
/// copied sentinels are the corresponding PageMap-derived page facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuiescentPageState {
    page_map_registered_entry_count: usize,
    page_map_published_submap_count: usize,
    arena_registry_count: usize,
    main_heap_abandoned_page_count: usize,
    main_heap_os_abandoned_pages_empty: usize,
    live_thread_count: usize,
    shared_later_theap_count: usize,
}

fn quiescent_page_state() -> QuiescentPageState {
    let audit = native_runtime_lifecycle_test_audit()
        .expect("all participating workers joined before the scalar state audit");
    QuiescentPageState {
        page_map_registered_entry_count: audit.page_map_registered_entry_count,
        page_map_published_submap_count: audit.page_map_published_submap_count,
        arena_registry_count: audit.arena_registry_count,
        main_heap_abandoned_page_count: audit.main_heap_abandoned_page_count,
        main_heap_os_abandoned_pages_empty: audit.main_heap_os_abandoned_pages_empty,
        live_thread_count: audit.live_thread_count,
        shared_later_theap_count: audit.shared_later_theap_count,
    }
}

/// PageMap submap publication is a retained capacity high-water, so a later
/// replacement may legitimately retain it. These are the source-liveness facts
/// that must return to the pre-worker baseline after the old client has been
/// consumed exactly once and B has finished its own independent owner.
fn assert_released_to_baseline(
    baseline: QuiescentPageState,
    after: QuiescentPageState,
    context: &str,
) {
    assert_eq!(
        after.page_map_registered_entry_count, baseline.page_map_registered_entry_count,
        "{context}: all old and replacement PageMap entries return to baseline"
    );
    assert_eq!(
        after.arena_registry_count, baseline.arena_registry_count,
        "{context}: replacement leaves no extra arena registration"
    );
    assert_eq!(
        after.main_heap_abandoned_page_count, baseline.main_heap_abandoned_page_count,
        "{context}: no abandoned page remains after the old client is consumed"
    );
    assert_eq!(
        after.main_heap_os_abandoned_pages_empty, baseline.main_heap_os_abandoned_pages_empty,
        "{context}: replacement leaves the page-owned OS abandoned list unchanged"
    );
    assert_eq!(
        after.live_thread_count, baseline.live_thread_count,
        "{context}: no worker lifetime remains attached"
    );
    assert_eq!(
        after.shared_later_theap_count, baseline.shared_later_theap_count,
        "{context}: B finishes its own Theap instead of retaining A's owner"
    );
}

fn allocate_owner_exit_client() -> usize {
    std::thread::spawn(|| {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let block = match native_allocate_aligned(OLD_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("A creates one source-owned medium client before it exits")
            }
        };
        // SAFETY: this exact worker owns `block` until source owner exit
        // transfers its live page to process-visible abandoned state.
        unsafe {
            block.as_ptr().write(SENTINEL_HEAD);
            block.as_ptr().add(4095).write(SENTINEL_MIDDLE);
            block.as_ptr().add(OLD_REQUEST - 1).write(SENTINEL_TAIL);
        }
        let address = block.as_ptr().addr();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A completes source collect-abandon before a nonlocal pointer operation"
        );
        address
    })
    .join()
    .expect("A joins before the quiescent state auditor reads its page facts")
}

fn live_block(address: usize) -> core::ptr::NonNull<u8> {
    // SAFETY: the test passes only the exact live native client A created;
    // its PageMap registration keeps the pointer lookup-visible until the one
    // valid free or successful replacement consumes it.
    unsafe { core::ptr::NonNull::new_unchecked(address as *mut u8) }
}

fn assert_old_client_facts(block: core::ptr::NonNull<u8>, expected_usable: usize) {
    assert_eq!(
        // SAFETY: the caller has not yet consumed this exact live client.
        unsafe { native_usable_size(block) },
        Some(expected_usable),
        "the PageMap still resolves the exact old allocation to its same usable extent"
    );
    // SAFETY: the same exact old client remains live after the failed attempt.
    unsafe {
        assert_eq!(block.as_ptr().read(), SENTINEL_HEAD);
        assert_eq!(block.as_ptr().add(4095).read(), SENTINEL_MIDDLE);
        assert_eq!(block.as_ptr().add(OLD_REQUEST - 1).read(), SENTINEL_TAIL);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplacementResult {
    Allocated,
    AllocationFailed,
    Unavailable,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplacementObservation {
    result: ReplacementResult,
    replacement_is_distinct: bool,
    replacement_usable_size: Option<usize>,
    copied_head: Option<u8>,
    copied_middle: Option<u8>,
    copied_tail: Option<u8>,
    replacement_free_result: Option<NativePageFreeResult>,
    anchor_free_result: NativePageFreeResult,
    finish_result: ThreadFinishResult,
}

/// Pinned `src/alloc.c:379-451` allocates a replacement through the current
/// owner, copies the old usable prefix, then sends the old pointer through the
/// general pointer-first free path. A's owner has already exited here, so B
/// can never reuse A's page in place. The current head intentionally returns
/// `Unavailable` at that PageMap-derived nonlocal branch; this assertion is a
/// red-before-core regression for the W01 connector rather than a claim that
/// the current refusal is a successful replacement.
#[test]
fn native_pointer_first_nonlocal_reallocate_audits_failure_and_one_old_consumption() {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before its nonlocal realloc state audit"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves its source arena dormant before A attaches"
    );
    let baseline = quiescent_page_state();

    // First establish the source failure contract while the initial thread is
    // quiescent enough to sample the public scalar auditor on both sides of
    // the rejected operation.
    let failed_address = allocate_owner_exit_client();
    let failed_old = live_block(failed_address);
    let failed_old_usable = unsafe { native_usable_size(failed_old) }
        .expect("A's exited live client remains PageMap-visible before replacement");
    assert!(
        failed_old_usable >= OLD_REQUEST,
        "the exact old page has a normal medium usable extent"
    );
    let before_failure = quiescent_page_state();
    assert!(
        before_failure.page_map_registered_entry_count
            > baseline.page_map_registered_entry_count,
        "A's live post-exit page remains registered before a nonlocal replacement attempt"
    );
    assert_eq!(
        before_failure.arena_registry_count, baseline.arena_registry_count,
        "the old page uses the already retained process arena rather than a synthetic test arena"
    );

    assert!(matches!(
        // SAFETY: `failed_old` remains the exact live A client and the invalid
        // size preflight must not consume it.
        unsafe { native_reallocate(Some(failed_old), usize::MAX) },
        NativePageAllocationResult::AllocationFailed
    ));
    let after_failure = quiescent_page_state();
    assert_eq!(
        after_failure, before_failure,
        "the failed replacement does not change PageMap, page-owned arena, or abandoned-head facts"
    );
    assert_old_client_facts(failed_old, failed_old_usable);
    assert_eq!(
        // SAFETY: the failed replacement left this exact old client live; the
        // generic pointer-first free is its sole subsequent consumption.
        unsafe { native_free(failed_old) },
        NativePageFreeResult::Freed,
        "failure leaves one valid old client for the normal post-exit free path"
    );
    assert_released_to_baseline(
        baseline,
        quiescent_page_state(),
        "the rejected replacement's later generic old-pointer free",
    );

    // Build a fresh A source so B's successful-path assertion can prove that
    // it consumes one different old client, rather than reusing the failed
    // case's generic free.
    let successful_address = allocate_owner_exit_client();
    let successful_old = live_block(successful_address);
    let successful_old_usable = unsafe { native_usable_size(successful_old) }
        .expect("the new A client remains PageMap-visible before B attaches");
    assert!(
        successful_old_usable >= OLD_REQUEST,
        "the second exact old page retains the source medium extent before replacement"
    );
    let before_success = quiescent_page_state();
    assert!(
        before_success.page_map_registered_entry_count
            > baseline.page_map_registered_entry_count,
        "the fresh old page remains registered until B's replacement consumes it"
    );

    let observation = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let successful_old = live_block(successful_address);
        let anchor = match native_allocate_aligned(LOCAL_ANCHOR_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("B establishes its own current owner for replacement allocation")
            }
        };
        let outcome = match unsafe { native_reallocate(Some(successful_old), REPLACEMENT_REQUEST) } {
            NativePageAllocationResult::Allocated(replacement) => {
                let replacement_usable_size = unsafe { native_usable_size(replacement) };
                let copied_head = unsafe { replacement.as_ptr().read() };
                let copied_middle = unsafe { replacement.as_ptr().add(4095).read() };
                let copied_tail = unsafe { replacement.as_ptr().add(OLD_REQUEST - 1).read() };
                let replacement_free_result = unsafe { native_free(replacement) };
                ReplacementObservation {
                    result: ReplacementResult::Allocated,
                    replacement_is_distinct: replacement != successful_old,
                    replacement_usable_size,
                    copied_head: Some(copied_head),
                    copied_middle: Some(copied_middle),
                    copied_tail: Some(copied_tail),
                    replacement_free_result: Some(replacement_free_result),
                    anchor_free_result: unsafe { native_free(anchor) },
                    finish_result: finish_current_thread_native_after_user_destructors(),
                }
            }
            NativePageAllocationResult::AllocationFailed => ReplacementObservation {
                result: ReplacementResult::AllocationFailed,
                replacement_is_distinct: false,
                replacement_usable_size: None,
                copied_head: None,
                copied_middle: None,
                copied_tail: None,
                replacement_free_result: None,
                anchor_free_result: unsafe { native_free(anchor) },
                finish_result: finish_current_thread_native_after_user_destructors(),
            },
            NativePageAllocationResult::Unavailable => ReplacementObservation {
                result: ReplacementResult::Unavailable,
                replacement_is_distinct: false,
                replacement_usable_size: None,
                copied_head: None,
                copied_middle: None,
                copied_tail: None,
                replacement_free_result: None,
                anchor_free_result: unsafe { native_free(anchor) },
                finish_result: finish_current_thread_native_after_user_destructors(),
            },
            NativePageAllocationResult::Retained => ReplacementObservation {
                result: ReplacementResult::Retained,
                replacement_is_distinct: false,
                replacement_usable_size: None,
                copied_head: None,
                copied_middle: None,
                copied_tail: None,
                replacement_free_result: None,
                anchor_free_result: unsafe { native_free(anchor) },
                finish_result: finish_current_thread_native_after_user_destructors(),
            },
        };
        outcome
    })
    .join()
    .expect("B joins before the post-replacement scalar state audit");
    let after_success_attempt = quiescent_page_state();

    assert_eq!(
        observation.result,
        ReplacementResult::Allocated,
        "W01 pointer-first nonlocal realloc must allocate through B, copy, and free A's old page exactly once; before={before_success:?}; after={after_success_attempt:?}; observation={observation:?}"
    );
    assert!(
        observation.replacement_is_distinct,
        "a larger B-side replacement cannot reuse A's exited source page in place"
    );
    assert!(
        observation
            .replacement_usable_size
            .is_some_and(|usable_size| usable_size >= REPLACEMENT_REQUEST),
        "the returned B replacement has a PageMap-derived usable extent"
    );
    assert_eq!(observation.copied_head, Some(SENTINEL_HEAD));
    assert_eq!(observation.copied_middle, Some(SENTINEL_MIDDLE));
    assert_eq!(observation.copied_tail, Some(SENTINEL_TAIL));
    assert_eq!(
        observation.replacement_free_result,
        Some(NativePageFreeResult::Freed),
        "B frees only its valid replacement after realloc consumed the old client"
    );
    assert_eq!(
        observation.anchor_free_result,
        NativePageFreeResult::Freed,
        "B's independent local anchor remains separately freeable"
    );
    assert_eq!(
        observation.finish_result,
        ThreadFinishResult::Finished,
        "B finishes its own owner without retaining A's exited Theap"
    );
    assert_released_to_baseline(
        baseline,
        after_success_attempt,
        "the successful nonlocal replacement and B-side cleanup",
    );
}
