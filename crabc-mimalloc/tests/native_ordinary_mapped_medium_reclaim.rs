// This direct regression is compiled only with the default-off scalar audit.
// It observes lifecycle counts after joined source boundaries, but never
// exposes A's client, page, PageMap, arena, or post-exit route to B.
#![cfg(feature = "native-runtime-test-audit")]

use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, prepare_native_later_thread_arena,
};

// This rounds to one normal 64 KiB medium queue block. The pinned default
// medium page has eight such blocks, so A's one live client is non-full and
// maps exactly one reclaimable regular page at owner exit.
const MEDIUM_REQUEST: usize = 64 * 1024;
const CHILD_SOURCE_IMAGE: &str = "CRABC_NATIVE_ORDINARY_MAPPED_MEDIUM_RECLAIM_CHILD";

#[derive(Clone, Copy)]
enum SourceMediumImage {
    /// A's only allocation consumes the page's initial block. Reclaim must
    /// extend before B can allocate from it.
    ExtensionRequired,
    /// A leaves one block locally free while retaining another. Owner exit
    /// publishes that block as the inherited immediate free head.
    InheritedImmediateHead,
}

impl SourceMediumImage {
    const fn child_mode(self) -> &'static str {
        match self {
            Self::ExtensionRequired => "extension-required",
            Self::InheritedImmediateHead => "inherited-immediate-head",
        }
    }
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn assert_reclaimed_lifecycle_baseline(
    baseline: crabc_mimalloc::__crabc_runtime::NativeRuntimeLifecycleAudit,
    after: crabc_mimalloc::__crabc_runtime::NativeRuntimeLifecycleAudit,
) {
    assert_eq!(after.process_active, baseline.process_active);
    assert_eq!(after.page_owner_ready, baseline.page_owner_ready);
    assert_eq!(
        after.page_map_registered_entry_count, baseline.page_map_registered_entry_count,
        "B's ordinary allocation and free release A's exact reclaimed PageMap span"
    );
    assert_eq!(after.arena_registry_count, baseline.arena_registry_count);
    assert_eq!(after.live_thread_count, baseline.live_thread_count);
    assert_eq!(
        after.metadata_live_capability_count, baseline.metadata_live_capability_count
    );
    assert_eq!(after.shared_later_theap_count, baseline.shared_later_theap_count);
    assert_eq!(
        after.main_heap_abandoned_page_count, baseline.main_heap_abandoned_page_count,
        "B consumes the one source bitmap/count publication instead of leaving A mapped-abandoned"
    );
    assert_eq!(
        after.main_heap_os_abandoned_pages_empty, baseline.main_heap_os_abandoned_pages_empty
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "ordinary allocation-time reclaim does not enter the parked compatibility bridge"
    );
    assert_eq!(
        after
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "ordinary allocation-time reclaim does not enter the legacy scheduler"
    );
}

#[test]
fn ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_medium_page() {
    run_source_image_in_fresh_process(
        SourceMediumImage::ExtensionRequired,
        "ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_medium_page",
    );
}

/// A allocates two 64 KiB blocks from one normal medium page, frees one while
/// retaining the other, and exits. Owner-exit collection must publish A's
/// locally freed block as the page's immediate inherited head. B receives no
/// A address or route; its ordinary same-bin allocation must return that exact
/// coordinator-known free block before any extension or fresh span is needed.
#[test]
fn ordinary_same_bin_allocation_claims_inherited_mapped_abandoned_medium_head() {
    run_source_image_in_fresh_process(
        SourceMediumImage::InheritedImmediateHead,
        "ordinary_same_bin_allocation_claims_inherited_mapped_abandoned_medium_head",
    );
}

/// The process-static native runtime intentionally promotes its source arena
/// only once. Each image therefore runs in a fresh child, so one witness's
/// completed initial persistent owner cannot turn the next setup attempt into
/// the deliberately retained live-transfer case.
fn run_source_image_in_fresh_process(source_image: SourceMediumImage, test_name: &'static str) {
    if std::env::var(CHILD_SOURCE_IMAGE).ok().as_deref() == Some(source_image.child_mode()) {
        reclaim_one_mapped_abandoned_medium_page(source_image);
        return;
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .arg("--exact")
    .arg(test_name)
    .env(CHILD_SOURCE_IMAGE, source_image.child_mode())
    .status()
    .expect("the isolated mapped-medium witness starts");
    assert_eq!(
        status.code(),
        Some(0),
        "the isolated {test_name} child completes its native lifecycle witness"
    );
}

/// A exits with exactly one normal non-full medium page mapped-abandoned. B
/// receives no A address, attaches independently, and makes one ordinary
/// same-bin allocation. There is one candidate and no transferred A pointer
/// or route: if the fresh path skips the source arena bitmap claim, B creates
/// a second medium span. B deliberately leaves its own client live through
/// its owner exit, so the joined snapshot distinguishes one reused
/// mapped-abandoned span from two fresh-fallback spans. Only the coordinator
/// holds the eventual live client addresses and pointer-frees them afterward,
/// proving the normal all-free lifecycle returns to baseline.
fn reclaim_one_mapped_abandoned_medium_page(source_image: SourceMediumImage) {
    assert!(
        initialize_process(current_page_size()),
        "the native runtime initializes before the ordinary mapped-medium witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner prepares the later-owner arena before A attaches"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared native runtime exposes a quiescent lifecycle baseline");

    let (owner_ready_sender, owner_ready_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        let source_medium = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("A creates one normal medium source page")
            }
        };
        // SAFETY: A alone owns this current source client through its owner
        // exit. The contents distinguish a real writable source allocation
        // from a fixture-only page-state transition.
        unsafe {
            source_medium.as_ptr().write(0x41);
            source_medium.as_ptr().add(MEDIUM_REQUEST - 1).write(0x42);
            assert_eq!(source_medium.as_ptr().read(), 0x41);
            assert_eq!(source_medium.as_ptr().add(MEDIUM_REQUEST - 1).read(), 0x42);
        }
        let inherited_immediate_head = match source_image {
            SourceMediumImage::ExtensionRequired => None,
            SourceMediumImage::InheritedImmediateHead => {
                let source_free = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    NativePageAllocationResult::Unavailable
                    | NativePageAllocationResult::AllocationFailed
                    | NativePageAllocationResult::Retained => {
                        panic!("A creates the source block that it publishes as B's immediate head")
                    }
                };
                // SAFETY: A owns this second allocation until it returns it
                // locally below. The distinct contents prove it is a normal
                // writable allocation rather than a fixture-only page shape.
                unsafe {
                    source_free.as_ptr().write(0x43);
                    source_free.as_ptr().add(MEDIUM_REQUEST - 1).write(0x44);
                    assert_eq!(source_free.as_ptr().read(), 0x43);
                    assert_eq!(source_free.as_ptr().add(MEDIUM_REQUEST - 1).read(), 0x44);
                }
                assert_eq!(
                    // SAFETY: A alone owns the second source client and frees
                    // it before its owner-exit collection publishes the local
                    // free list as the inherited immediate page head.
                    unsafe { native_free(source_free) },
                    NativePageFreeResult::Freed,
                    "A locally frees the block B must later pop as the inherited head"
                );
                Some(source_free.as_ptr().addr())
            }
        };
        owner_ready_sender
            .send((source_medium.as_ptr().addr(), inherited_immediate_head))
            .expect("only the coordinator retains A's client addresses for terminal cleanup");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A abandons its one non-full medium through the ordinary owner-exit path"
        );
    });
    let (source_medium, inherited_immediate_head) = owner_ready_receiver
        .recv()
        .expect("A publishes its client addresses only to the coordinator");
    owner
        .join()
        .expect("A completes owner exit before B begins its independent allocation");

    let after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("A's completed owner exit leaves an auditable mapped-medium source");
    assert_eq!(
        after_owner_exit.main_heap_abandoned_page_count,
        baseline.main_heap_abandoned_page_count + 1,
        "A leaves exactly one mapped-abandoned regular candidate for B's source bitmap search"
    );
    assert!(
        after_owner_exit.page_map_registered_entry_count
            > baseline.page_map_registered_entry_count,
        "A's live medium remains PageMap-registered while its source owner is gone"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A releases its later-thread admission before B independently attaches"
    );

    // B sends only after its normal owner-exit boundary. A one-slot channel
    // lets that post-exit handoff complete before the coordinator joins B;
    // the coordinator still does not receive or use the client until after
    // the joined one-page reuse audit below.
    let (consumer_finished_sender, consumer_finished_receiver) = mpsc::sync_channel(1);
    let consumer = std::thread::spawn(move || {
        assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
        // B receives no A allocation address, source page, or post-exit
        // route. This is the ordinary generic native allocation path only.
        let reclaimed_medium = match native_allocate_aligned(MEDIUM_REQUEST, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("B reclaims A's one normal same-bin medium page before fresh allocation")
            }
        };
        // SAFETY: B owns the exact allocation returned by its ordinary native
        // allocation through this paired write/read sequence; coordinator
        // cleanup frees it only after B's owner exit.
        unsafe {
            reclaimed_medium.as_ptr().write(0x51);
            reclaimed_medium
                .as_ptr()
                .add(MEDIUM_REQUEST - 1)
                .write(0x52);
            assert_eq!(reclaimed_medium.as_ptr().read(), 0x51);
            assert_eq!(
                reclaimed_medium.as_ptr().add(MEDIUM_REQUEST - 1).read(),
                0x52
            );
        }
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "B maps its still-live same-bin client through its own normal owner exit"
        );
        consumer_finished_sender
            .send(reclaimed_medium.as_ptr().addr())
            .expect("only the coordinator retains B's client address for terminal cleanup");
    });
    consumer
        .join()
        .expect("B completes its independent ordinary allocation lifecycle");

    let after_consumer = native_runtime_lifecycle_test_audit()
        .expect("both workers joined before the one-page reuse audit");
    assert_eq!(
        after_consumer.page_map_registered_entry_count,
        after_owner_exit.page_map_registered_entry_count,
        "ordinary same-bin allocation reuses A's exact PageMap span instead of leaving a second fresh medium span"
    );
    assert_eq!(
        after_consumer.main_heap_abandoned_page_count,
        baseline.main_heap_abandoned_page_count + 1,
        "B reabandonments the same one-page source image while its own client stays live"
    );
    assert_eq!(
        after_consumer.shared_later_theap_count,
        baseline.shared_later_theap_count,
        "both detached later Theaps leave no shared-main list member behind"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "the source and consumer release their independent later-thread admissions"
    );

    let consumer_medium = consumer_finished_receiver
        .recv()
        .expect("B publishes its client address only after its owner exit");
    let consumer_medium = core::ptr::NonNull::new(consumer_medium as *mut u8)
        .expect("B's retained native client address stays non-null");
    if let Some(inherited_immediate_head) = inherited_immediate_head {
        assert_eq!(
            consumer_medium.as_ptr().addr(),
            inherited_immediate_head,
            "B pops A's owner-exit-published immediate free head instead of extending or allocating fresh"
        );
    }
    let source_medium = core::ptr::NonNull::new(source_medium as *mut u8)
        .expect("A's retained native client address stays non-null");
    assert_eq!(
        // SAFETY: B returned this exact live client to the coordinator only
        // after its owner exit; no worker or route retains a second free
        // capability for it.
        unsafe { native_free(consumer_medium) },
        NativePageFreeResult::Freed,
        "the coordinator frees B's post-exit client through the exact PageMap route"
    );
    assert_eq!(
        // SAFETY: A returned this exact still-live source client only to the
        // coordinator, and B never received its address or a free route.
        unsafe { native_free(source_medium) },
        NativePageFreeResult::Freed,
        "the coordinator frees A's post-exit client and reaches the all-free terminal tail"
    );

    let after_cleanup = native_runtime_lifecycle_test_audit()
        .expect("coordinator cleanup returns the joined lifecycle to quiescence");
    assert_reclaimed_lifecycle_baseline(baseline, after_cleanup);
}
