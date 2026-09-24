// This direct regression is compiled only with the default-off scalar audit.
// It observes lifecycle counts after joined source boundaries, but never
// exposes A's client, page, PageMap, arena, or post-exit route to B.
#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;



use std::sync::mpsc;

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_free, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit,
    native_runtime_live_client_page_map_span_test_audit,
    native_runtime_live_client_page_test_audit, prepare_native_later_thread_arena,
};

/// One normal-release regular page class reached through the public native
/// allocation entry. These fixed requests deliberately select ordinary
/// source sizes: direct Small, Medium, and the 64-slice regular Large page.
/// They never request an OS huge page or a singleton allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegularPageClass {
    DirectSmall,
    Medium,
    Large,
}

impl RegularPageClass {
    const fn request(self) -> usize {
        match self {
            Self::DirectSmall => 1024,
            // This rounds to one normal 64 KiB medium queue block. The
            // pinned default medium page has eight such blocks.
            Self::Medium => 64 * 1024,
            // The first ordinary large request: pinned good-size rounds it
            // to a 96 KiB block on the normal 64-slice 4 MiB page.
            Self::Large => 86_699,
        }
    }
}
const CHILD_SOURCE_IMAGE: &str = "CRABC_NATIVE_ORDINARY_MAPPED_REGULAR_RECLAIM_CHILD";
const TRACE_CHILD_CASE: &str = "CRABC_NATIVE_ORDINARY_MAPPED_REGULAR_RECLAIM_TRACE_CHILD";
const TRACE_TEST_NAME: &str = "regular_mapped_reclaim_trace_matches_pinned_c_protocol";
const TRACE_BEGIN: &str = "CRABC_MI_REGULAR_MAPPED_RECLAIM_TRACE_BEGIN";
const TRACE_END: &str = "CRABC_MI_REGULAR_MAPPED_RECLAIM_TRACE_END";
const TRACE_INITIAL_NATURAL_ALIGNMENT_SMALL: &str = "initial-natural-alignment-small";
const TRACE_LATER_NATURAL_ALIGNMENT_SMALL: &str = "later-natural-alignment-small";
const NATURAL_ALIGNMENT_CHILD_MODE: &str = "initial-persistent-natural-alignment-small";
const LATER_NATURAL_ALIGNMENT_CHILD_MODE: &str = "later-persistent-natural-alignment-small";
const NATURAL_ALIGNMENT_TEST_NAME: &str =
    "initial_persistent_natural_c_alignment_keeps_small_clients_live";
const LATER_NATURAL_ALIGNMENT_TEST_NAME: &str =
    "later_persistent_natural_c_alignment_keeps_small_clients_live";
const NATIVE_C_ALIGNMENT: usize = 16;

/// One actual Rust receiver route recorded by the closed C/Rust differential.
/// Each child owns a fresh process image, so the initial persistent route does
/// not reuse a prior source promotion.
#[derive(Clone, Copy)]
struct RegularMappedReclaimTraceCase {
    child_case: &'static str,
    source_class: RegularPageClass,
    consumer_owner: ConsumerOwner,
    consumer_class: RegularPageClass,
    expect_source_reuse: bool,
}

#[derive(Clone, Copy)]
enum SourceRegularImage {
    /// A's only allocation consumes the page's initial block. Reclaim must
    /// extend before B can allocate from it.
    ExtensionRequired,
    /// A leaves one block locally free while retaining another. Owner exit
    /// publishes that block as the inherited immediate free head.
    InheritedImmediateHead,
}

impl SourceRegularImage {
    const fn child_mode(self, class: RegularPageClass, consumer: ConsumerOwner) -> &'static str {
        match (self, class, consumer) {
            (Self::ExtensionRequired, RegularPageClass::DirectSmall, ConsumerOwner::LaterAttached) =>
                "direct-small-extension-required-later",
            (Self::ExtensionRequired, RegularPageClass::Medium, ConsumerOwner::LaterAttached) =>
                "medium-extension-required-later",
            (Self::ExtensionRequired, RegularPageClass::Large, ConsumerOwner::LaterAttached) =>
                "large-extension-required-later",
            (Self::InheritedImmediateHead, RegularPageClass::DirectSmall, ConsumerOwner::LaterAttached) =>
                "direct-small-inherited-immediate-head-later",
            (Self::InheritedImmediateHead, RegularPageClass::Medium, ConsumerOwner::LaterAttached) =>
                "medium-inherited-immediate-head-later",
            (Self::InheritedImmediateHead, RegularPageClass::Large, ConsumerOwner::LaterAttached) =>
                "large-inherited-immediate-head-later",
            (Self::ExtensionRequired, RegularPageClass::DirectSmall, ConsumerOwner::InitialPersistent) =>
                "direct-small-extension-required-initial",
            (Self::ExtensionRequired, RegularPageClass::Medium, ConsumerOwner::InitialPersistent) =>
                "medium-extension-required-initial",
            (Self::ExtensionRequired, RegularPageClass::Large, ConsumerOwner::InitialPersistent) =>
                "large-extension-required-initial",
            (Self::InheritedImmediateHead, _, ConsumerOwner::InitialPersistent) =>
                "inherited-immediate-head-initial-is-not-a-fixture-route",
        }
    }
}

/// B is either a later attached native owner or the actual reactivated
/// ticket-zero persistent owner. Both use the public ordinary allocation
/// entry; neither receives A's page, client, or a reclaim capability.
#[derive(Clone, Copy)]
enum ConsumerOwner {
    LaterAttached,
    InitialPersistent,
}

const TRACE_CASES: &[RegularMappedReclaimTraceCase] = &[
    RegularMappedReclaimTraceCase {
        child_case: "later-direct-small",
        source_class: RegularPageClass::DirectSmall,
        consumer_owner: ConsumerOwner::LaterAttached,
        consumer_class: RegularPageClass::DirectSmall,
        expect_source_reuse: true,
    },
    RegularMappedReclaimTraceCase {
        child_case: "later-medium",
        source_class: RegularPageClass::Medium,
        consumer_owner: ConsumerOwner::LaterAttached,
        consumer_class: RegularPageClass::Medium,
        expect_source_reuse: true,
    },
    RegularMappedReclaimTraceCase {
        child_case: "later-regular-large",
        source_class: RegularPageClass::Large,
        consumer_owner: ConsumerOwner::LaterAttached,
        consumer_class: RegularPageClass::Large,
        expect_source_reuse: true,
    },
    RegularMappedReclaimTraceCase {
        child_case: "initial-direct-small",
        source_class: RegularPageClass::DirectSmall,
        consumer_owner: ConsumerOwner::InitialPersistent,
        consumer_class: RegularPageClass::DirectSmall,
        expect_source_reuse: true,
    },
    RegularMappedReclaimTraceCase {
        child_case: "initial-medium",
        source_class: RegularPageClass::Medium,
        consumer_owner: ConsumerOwner::InitialPersistent,
        consumer_class: RegularPageClass::Medium,
        expect_source_reuse: true,
    },
    RegularMappedReclaimTraceCase {
        child_case: "initial-regular-large",
        source_class: RegularPageClass::Large,
        consumer_owner: ConsumerOwner::InitialPersistent,
        consumer_class: RegularPageClass::Large,
        expect_source_reuse: true,
    },
    RegularMappedReclaimTraceCase {
        child_case: "later-medium-to-regular-large-fallback",
        source_class: RegularPageClass::Medium,
        consumer_owner: ConsumerOwner::LaterAttached,
        consumer_class: RegularPageClass::Large,
        expect_source_reuse: false,
    },
];

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
    // The source-span audit below is the ownership proof for A's reclaimed
    // page. Other completed process-lifetime owners can retain unrelated
    // PageMap entries, so a process-wide count is not an exact source-page
    // release witness.
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
        RegularPageClass::Medium,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::LaterAttached,
        "ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_medium_page",
    );
}

/// A direct-small cache miss must enter the same generic selected-map search
/// before it creates a fresh page. This uses no pointer/route transfer from A
/// to B; only the normal allocation entry observes the mapped candidate.
#[test]
fn ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_direct_small_page() {
    run_source_image_in_fresh_process(
        RegularPageClass::DirectSmall,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::LaterAttached,
        "ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_direct_small_page",
    );
}

/// The normal 64-slice regular-large page takes the source's regular path,
/// not an OS huge-page or singleton path. Its ordinary same-bin consumer must
/// claim the existing mapped page before it creates a fresh large span.
#[test]
fn ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_regular_large_page() {
    run_source_image_in_fresh_process(
        RegularPageClass::Large,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::LaterAttached,
        "ordinary_same_bin_allocation_reclaims_one_mapped_abandoned_regular_large_page",
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
        RegularPageClass::Medium,
        SourceRegularImage::InheritedImmediateHead,
        ConsumerOwner::LaterAttached,
        "ordinary_same_bin_allocation_claims_inherited_mapped_abandoned_medium_head",
    );
}

/// The dormant ticket-zero owner must use the same selected regular reclaim
/// branch when it becomes the ordinary receiver after A has exited.
#[test]
fn initial_persistent_same_bin_allocation_reclaims_mapped_abandoned_direct_small_page() {
    run_source_image_in_fresh_process(
        RegularPageClass::DirectSmall,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::InitialPersistent,
        "initial_persistent_same_bin_allocation_reclaims_mapped_abandoned_direct_small_page",
    );
}

#[test]
fn initial_persistent_same_bin_allocation_reclaims_mapped_abandoned_medium_page() {
    run_source_image_in_fresh_process(
        RegularPageClass::Medium,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::InitialPersistent,
        "initial_persistent_same_bin_allocation_reclaims_mapped_abandoned_medium_page",
    );
}

#[test]
fn initial_persistent_same_bin_allocation_reclaims_mapped_abandoned_regular_large_page() {
    run_source_image_in_fresh_process(
        RegularPageClass::Large,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::InitialPersistent,
        "initial_persistent_same_bin_allocation_reclaims_mapped_abandoned_regular_large_page",
    );
}

/// A mapped-abandoned source only applies to its exact regular source bin.
/// B asks for the distinct regular-large bin after A's medium page is
/// published. Its ordinary allocation must leave A mapped-abandoned and make
/// a fresh page for B; a broad or wrong-bin source claim would violate both
/// page identities.
#[test]
fn ordinary_different_bin_allocation_keeps_mapped_medium_source_and_falls_back_fresh() {
    run_regular_image_in_fresh_process(
        RegularPageClass::Medium,
        SourceRegularImage::ExtensionRequired,
        ConsumerOwner::LaterAttached,
        RegularPageClass::Large,
        false,
        "medium-to-large-fresh-fallback-later",
        "ordinary_different_bin_allocation_keeps_mapped_medium_source_and_falls_back_fresh",
    );
}

/// The private C-facing entry carries an explicit sixteen-byte aligned
/// allocation requirement. Pinned ordinary one-word small blocks are only
/// eight-byte-strided, so this must reach the source-shaped aligned selector
/// instead of inferring the requirement from ordinary `mi_malloc` behavior.
/// Keep mixed one- and eight-byte clients live together so a first page block
/// cannot hide a smaller later stride. This reaches the actual reactivated
/// initial persistent owner rather than an aligned-fixture adapter.
#[test]
fn initial_persistent_natural_c_alignment_keeps_small_clients_live() {
    run_initial_natural_alignment_in_fresh_process(NATURAL_ALIGNMENT_TEST_NAME);
}

/// The later persistent receiver has the same C-facing alignment contract as
/// the reactivated initial owner. Keep a separate attached-worker witness so
/// its own source-aligned selector cannot quietly return to the old blanket
/// ordinary branch.
#[test]
fn later_persistent_natural_c_alignment_keeps_small_clients_live() {
    run_later_natural_alignment_in_fresh_process(LATER_NATURAL_ALIGNMENT_TEST_NAME);
}

/// Emits the finite, address-independent C/Rust differential trace only after
/// every source-shaped child has proved its real receiver outcome. The C
/// fixture's `later` rows use an independently initialized pthread Theap; its
/// `initial` rows use the pinned source's main-heap receiver. The Rust rows
/// bind those same source outcomes to the actual later persistent and
/// reactivated initial persistent runtime owners.
#[test]
fn regular_mapped_reclaim_trace_matches_pinned_c_protocol() {
    if let Ok(child_case) = std::env::var(TRACE_CHILD_CASE) {
        if child_case == TRACE_INITIAL_NATURAL_ALIGNMENT_SMALL {
            exercise_initial_natural_alignment_small_requests();
            return;
        }
        if child_case == TRACE_LATER_NATURAL_ALIGNMENT_SMALL {
            exercise_later_natural_alignment_small_requests();
            return;
        }
        let case = TRACE_CASES
            .iter()
            .copied()
            .find(|case| case.child_case == child_case)
            .unwrap_or_else(|| panic!("unknown regular mapped-reclaim trace child: {child_case}"));
        exercise_mapped_abandoned_regular_allocation(
            case.source_class,
            SourceRegularImage::ExtensionRequired,
            case.consumer_owner,
            case.consumer_class,
            case.expect_source_reuse,
        );
        return;
    }

    for case in TRACE_CASES {
        let output = std::process::Command::new(
            std::env::current_exe().expect("the focused test executable has a current path"),
        )
        .arg("--exact")
        .arg(TRACE_TEST_NAME)
        .env(TRACE_CHILD_CASE, case.child_case)
        .output()
        .expect("the isolated regular mapped-reclaim trace child starts");
        assert!(
            output.status.success(),
            "the {case_child} source-shaped trace child completes: stdout={stdout:?}; stderr={stderr:?}",
            case_child = case.child_case,
            stdout = String::from_utf8_lossy(&output.stdout),
            stderr = String::from_utf8_lossy(&output.stderr),
        );
    }
    for child_case in [
        TRACE_INITIAL_NATURAL_ALIGNMENT_SMALL,
        TRACE_LATER_NATURAL_ALIGNMENT_SMALL,
    ] {
        let output = std::process::Command::new(
            std::env::current_exe().expect("the focused test executable has a current path"),
        )
        .arg("--exact")
        .arg(TRACE_TEST_NAME)
        .env(TRACE_CHILD_CASE, child_case)
        .output()
        .expect("the isolated small natural-alignment trace child starts");
        assert!(
            output.status.success(),
            "the {child_case} natural-alignment trace child completes: stdout={stdout:?}; stderr={stderr:?}",
            stdout = String::from_utf8_lossy(&output.stdout),
            stderr = String::from_utf8_lossy(&output.stderr),
        );
    }

    println!("{TRACE_BEGIN}");
    println!("trace.regular_mapped_reclaim.later.direct_small.same_page=1");
    println!("trace.regular_mapped_reclaim.later.medium.same_page=1");
    println!("trace.regular_mapped_reclaim.later.large.same_page=1");
    println!("trace.regular_mapped_reclaim.initial.direct_small.same_page=1");
    println!("trace.regular_mapped_reclaim.initial.medium.same_page=1");
    println!("trace.regular_mapped_reclaim.initial.large.same_page=1");
    println!("trace.regular_mapped_reclaim.fallback.medium_to_large.fresh=1");
    println!("trace.regular_mapped_reclaim.later.medium.cleanup_release=1");
    println!("trace.regular_mapped_reclaim.initial.natural_alignment.request1.all_live=1");
    println!("trace.regular_mapped_reclaim.initial.natural_alignment.request8.all_live=1");
    println!("trace.regular_mapped_reclaim.later.natural_alignment.request1.all_live=1");
    println!("trace.regular_mapped_reclaim.later.natural_alignment.request8.all_live=1");
    println!("{TRACE_END}");
}

/// The process-static native runtime intentionally promotes its source arena
/// only once. Each image therefore runs in a fresh child, so one witness's
/// completed initial persistent owner cannot turn the next setup attempt into
/// the deliberately retained live-transfer case.
fn run_source_image_in_fresh_process(
    class: RegularPageClass,
    source_image: SourceRegularImage,
    consumer_owner: ConsumerOwner,
    test_name: &'static str,
) {
    run_regular_image_in_fresh_process(
        class,
        source_image,
        consumer_owner,
        class,
        true,
        source_image.child_mode(class, consumer_owner),
        test_name,
    );
}

/// Runs one source image in an isolated process. The initial persistent
/// receiver deliberately promotes only once, and the fallback case also must
/// begin before another witness can leave a mapped source in its selected
/// static-main arena.
fn run_regular_image_in_fresh_process(
    source_class: RegularPageClass,
    source_image: SourceRegularImage,
    consumer_owner: ConsumerOwner,
    consumer_class: RegularPageClass,
    expect_source_reuse: bool,
    child_mode: &'static str,
    test_name: &'static str,
) {
    if std::env::var(CHILD_SOURCE_IMAGE).ok().as_deref() == Some(child_mode) {
        exercise_mapped_abandoned_regular_allocation(
            source_class,
            source_image,
            consumer_owner,
            consumer_class,
            expect_source_reuse,
        );
        return;
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .arg("--exact")
    .arg(test_name)
    .env(CHILD_SOURCE_IMAGE, child_mode)
    .status()
    .expect("the isolated mapped-medium witness starts");
    assert_eq!(
        status.code(),
        Some(0),
        "the isolated {test_name} child completes its native lifecycle witness"
    );
}

fn run_initial_natural_alignment_in_fresh_process(test_name: &'static str) {
    if std::env::var(CHILD_SOURCE_IMAGE).ok().as_deref() == Some(NATURAL_ALIGNMENT_CHILD_MODE) {
        exercise_initial_natural_alignment_small_requests();
        return;
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .arg("--exact")
    .arg(test_name)
    .env(CHILD_SOURCE_IMAGE, NATURAL_ALIGNMENT_CHILD_MODE)
    .status()
    .expect("the isolated initial small natural-alignment witness starts");
    assert_eq!(
        status.code(),
        Some(0),
        "the isolated {test_name} child preserves every live small C-aligned client"
    );
}

fn run_later_natural_alignment_in_fresh_process(test_name: &'static str) {
    if std::env::var(CHILD_SOURCE_IMAGE).ok().as_deref()
        == Some(LATER_NATURAL_ALIGNMENT_CHILD_MODE)
    {
        exercise_later_natural_alignment_small_requests();
        return;
    }

    let status = std::process::Command::new(
        std::env::current_exe().expect("the focused test executable has a current path"),
    )
    .arg("--exact")
    .arg(test_name)
    .env(CHILD_SOURCE_IMAGE, LATER_NATURAL_ALIGNMENT_CHILD_MODE)
    .status()
    .expect("the isolated later small natural-alignment witness starts");
    assert_eq!(
        status.code(),
        Some(0),
        "the isolated {test_name} child preserves every live small C-aligned client"
    );
}

fn exercise_initial_natural_alignment_small_requests() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the initial small natural-alignment witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner prepares its dormant first-arena pair before small C-aligned clients"
    );

    exercise_natural_alignment_small_clients();
}

fn exercise_later_natural_alignment_small_requests() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the later small natural-alignment witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner prepares the later receiver's first-arena pair before small C-aligned clients"
    );
    let worker = std::thread::spawn(|| {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        exercise_natural_alignment_small_clients();
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "the later small natural-alignment receiver completes its normal owner exit"
        );
    });
    worker
        .join()
        .expect("the later small natural-alignment receiver completes");
}

fn exercise_natural_alignment_small_clients() {
    const REQUESTS: [usize; 12] = [1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8];

    let mut clients: [Option<core::ptr::NonNull<u8>>; REQUESTS.len()] = [None; REQUESTS.len()];
    for (index, request) in REQUESTS.into_iter().enumerate() {
        let client = match native_allocate_aligned(request, NATIVE_C_ALIGNMENT, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("the current persistent owner creates live {request}-byte C-aligned client {index}")
            }
        };
        assert_eq!(
            client.as_ptr().addr() & (NATIVE_C_ALIGNMENT - 1),
            0,
            "live {request}-byte C-aligned client {index} preserves the requested 16-byte boundary"
        );
        for earlier in clients[..index].iter().flatten() {
            assert_ne!(
                client.as_ptr(),
                earlier.as_ptr(),
                "live C-aligned clients stay distinct before any small client is freed"
            );
        }
        // SAFETY: this exact client remains live and locally owned through
        // the following all-live alignment observations and serial cleanup.
        unsafe {
            client.as_ptr().write((index as u8).wrapping_add(1));
            assert_eq!(client.as_ptr().read(), (index as u8).wrapping_add(1));
        }
        clients[index] = Some(client);
    }

    for (index, client) in clients.iter().enumerate() {
        let client = client.expect("every mixed small request remains live before cleanup");
        assert_eq!(
            client.as_ptr().addr() & (NATIVE_C_ALIGNMENT - 1),
            0,
            "all-live C-aligned client {index} remains 16-byte aligned after later small allocations"
        );
    }

    for client in clients.into_iter().flatten() {
        assert_eq!(
            // SAFETY: this is one exact live current-owner allocation; each
            // client is freed once after all address observations complete.
            unsafe { native_free(client) },
            NativePageFreeResult::Freed,
            "the current persistent owner releases each small C-aligned client"
        );
    }
}

/// A exits with exactly one normal non-full regular page mapped-abandoned. B
/// is either an independently attached later owner or the reactivated
/// persistent initial owner, and makes one ordinary same-bin allocation.
/// There is one candidate and no transferred A pointer or route: if the fresh
/// path skips the source arena bitmap claim, B creates a second regular span.
/// Only the coordinator holds the eventual live client addresses and
/// pointer-frees them afterward. The later-owner path reaches the source
/// all-free release; the persistent initial owner deliberately retains its
/// all-free active engine for a later local allocation.
fn exercise_mapped_abandoned_regular_allocation(
    source_class: RegularPageClass,
    source_image: SourceRegularImage,
    consumer_owner: ConsumerOwner,
    consumer_class: RegularPageClass,
    expect_source_reuse: bool,
) {
    let source_request = source_class.request();
    let consumer_request = consumer_class.request();
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the native runtime initializes before the ordinary mapped-regular witness"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial persistent owner prepares the later-owner arena before A attaches"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the prepared native runtime exposes a quiescent lifecycle baseline");

    let (owner_ready_sender, owner_ready_receiver) = mpsc::sync_channel(0);
    let owner = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let source_regular = match native_allocate_aligned(source_request, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            NativePageAllocationResult::Unavailable
            | NativePageAllocationResult::AllocationFailed
            | NativePageAllocationResult::Retained => {
                panic!("A creates one normal {source_class:?} source page")
            }
        };
        // SAFETY: A alone owns this current source client through its owner
        // exit. The contents distinguish a real writable source allocation
        // from a fixture-only page-state transition.
        unsafe {
            source_regular.as_ptr().write(0x41);
            source_regular.as_ptr().add(source_request - 1).write(0x42);
            assert_eq!(source_regular.as_ptr().read(), 0x41);
            assert_eq!(source_regular.as_ptr().add(source_request - 1).read(), 0x42);
        }
        let inherited_immediate_head = match source_image {
            SourceRegularImage::ExtensionRequired => None,
            SourceRegularImage::InheritedImmediateHead => {
                let source_free = match native_allocate_aligned(source_request, 16, false) {
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
                    source_free.as_ptr().add(source_request - 1).write(0x44);
                    assert_eq!(source_free.as_ptr().read(), 0x43);
                    assert_eq!(source_free.as_ptr().add(source_request - 1).read(), 0x44);
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
            .send((source_regular.as_ptr().addr(), inherited_immediate_head))
            .expect("only the coordinator retains A's client addresses for terminal cleanup");
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "A abandons its one non-full regular page through the ordinary owner-exit path"
        );
    });
    let (source_regular, inherited_immediate_head) = owner_ready_receiver
        .recv()
        .expect("A publishes its client addresses only to the coordinator");
    owner
        .join()
        .expect("A completes owner exit before B begins its independent allocation");

    let after_owner_exit = native_runtime_lifecycle_test_audit()
        .expect("A's completed owner exit leaves an auditable mapped-regular source");
    assert_eq!(
        after_owner_exit.main_heap_abandoned_page_count,
        baseline.main_heap_abandoned_page_count + 1,
        "A leaves exactly one mapped-abandoned regular candidate for B's source bitmap search"
    );
    assert!(
        after_owner_exit.page_map_registered_entry_count
            > baseline.page_map_registered_entry_count,
        "A's live regular page remains PageMap-registered while its source owner is gone"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "A releases its later-thread admission before B independently attaches"
    );
    let source_regular = core::ptr::NonNull::new(source_regular as *mut u8)
        .expect("A's retained native client address stays non-null");
    // SAFETY: A has joined after its owner-exit boundary; `source_regular`
    // remains live under this coordinator and no other native worker can
    // mutate its PageMap/page fields before B begins.
    let source_page = unsafe { native_runtime_live_client_page_test_audit(source_regular) }
        .expect("A's live source client exposes its exact mapped regular PageMap fingerprint");
    // SAFETY: the joined-A boundary above leaves the recorded source span
    // quiescent, and this coordinator starts no concurrent allocator work
    // until after this read completes.
    let source_span_before_consumer = unsafe {
        native_runtime_live_client_page_map_span_test_audit(source_page)
    }
    .expect("A's mapped source PageMap span remains auditable before B attaches");
    assert_eq!(
        source_span_before_consumer.matching_page_entry_count,
        source_page.registered_slice_count(),
        "every source PageMap slice names A's exact mapped-abandoned page"
    );
    assert_eq!(
        source_span_before_consumer.non_null_entry_count,
        source_page.registered_slice_count(),
        "A's recorded PageMap span contains no unrelated published page"
    );

    let consumer_regular = match consumer_owner {
        ConsumerOwner::LaterAttached => {
            // B sends only after its normal owner-exit boundary. A one-slot
            // channel lets that post-exit handoff complete before the
            // coordinator joins B; the coordinator still does not receive or
            // use the client until after the joined one-page reuse audit.
            let (consumer_finished_sender, consumer_finished_receiver) = mpsc::sync_channel(1);
            let consumer = std::thread::spawn(move || {
                assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
                // B receives no A allocation address, source page, or
                // post-exit route. This is the ordinary generic native
                // allocation path only.
                let reclaimed_regular = match native_allocate_aligned(consumer_request, 16, false) {
                    NativePageAllocationResult::Allocated(block) => block,
                    NativePageAllocationResult::Unavailable
                    | NativePageAllocationResult::AllocationFailed
                    | NativePageAllocationResult::Retained => {
                        panic!("B receives the ordinary {consumer_class:?} allocation before fresh fallback")
                    }
                };
                // SAFETY: B owns the exact allocation returned by its ordinary
                // native allocation through this paired write/read sequence;
                // coordinator cleanup frees it only after B's owner exit.
                unsafe {
                    reclaimed_regular.as_ptr().write(0x51);
                    reclaimed_regular
                        .as_ptr()
                        .add(consumer_request - 1)
                        .write(0x52);
                    assert_eq!(reclaimed_regular.as_ptr().read(), 0x51);
                    assert_eq!(
                        reclaimed_regular.as_ptr().add(consumer_request - 1).read(),
                        0x52
                    );
                }
                assert_eq!(
                    finish_current_thread_native_after_user_destructors(),
                    ThreadFinishResult::Finished,
                    "B maps its still-live same-bin client through its own normal owner exit"
                );
                consumer_finished_sender
                    .send(reclaimed_regular.as_ptr().addr())
                    .expect("only the coordinator retains B's client address for terminal cleanup");
            });
            consumer
                .join()
                .expect("B completes its independent ordinary allocation lifecycle");

            let consumer_regular = consumer_finished_receiver
                .recv()
                .expect("B publishes its client address only after its owner exit");
            core::ptr::NonNull::new(consumer_regular as *mut u8)
                .expect("B's retained native client address stays non-null")
        }
        ConsumerOwner::InitialPersistent => {
            // The process's initial thread has already prepared its dormant
            // first-arena pair. This ordinary public allocation reactivates
            // that installed persistent owner; it receives neither A's
            // client nor a page/arena reclaim capability.
            let reclaimed_regular = match native_allocate_aligned(consumer_request, 16, false) {
                NativePageAllocationResult::Allocated(block) => block,
                NativePageAllocationResult::Unavailable
                | NativePageAllocationResult::AllocationFailed
                | NativePageAllocationResult::Retained => {
                    panic!("the initial persistent owner receives the ordinary {consumer_class:?} allocation before fresh fallback")
                }
            };
            // SAFETY: the initial owner exclusively owns this exact ordinary
            // result until coordinator cleanup below. The paired write/read
            // observes the returned allocation without exposing A's route.
            unsafe {
                reclaimed_regular.as_ptr().write(0x51);
                reclaimed_regular
                    .as_ptr()
                    .add(consumer_request - 1)
                    .write(0x52);
                assert_eq!(reclaimed_regular.as_ptr().read(), 0x51);
                assert_eq!(
                    reclaimed_regular.as_ptr().add(consumer_request - 1).read(),
                    0x52
                );
            }
            reclaimed_regular
        }
    };
    // SAFETY: any later B has joined, while the initial B runs only on this
    // coordinator; both clients remain live and no native worker can mutate
    // their ordinary page fields during this identity observation.
    let consumer_page = unsafe { native_runtime_live_client_page_test_audit(consumer_regular) }
        .expect("B's live client exposes its exact ordinary PageMap fingerprint");
    if expect_source_reuse {
        assert_eq!(
            consumer_page.page_address(),
            source_page.page_address(),
            "B's ordinary allocation belongs to A's original mapped-abandoned page, not a coincidental fresh span"
        );
        assert_eq!(
            consumer_page.arena_slice_start(),
            source_page.arena_slice_start(),
            "B's ordinary allocation retains A's exact arena-span start"
        );
        assert_eq!(
            consumer_page.arena_slice_count(),
            source_page.arena_slice_count(),
            "B's ordinary allocation retains A's complete source arena claim"
        );
        assert_eq!(
            consumer_page.registered_slice_count(),
            source_page.registered_slice_count(),
            "B's ordinary allocation retains A's source PageMap-covered prefix"
        );
    } else {
        assert_ne!(
            consumer_page.page_address(),
            source_page.page_address(),
            "a distinct-bin ordinary allocation never claims A's mapped source page"
        );
        assert_ne!(
            consumer_page.arena_slice_start(),
            source_page.arena_slice_start(),
            "the no-candidate fallback owns a new regular arena span"
        );
    }
    // SAFETY: B's owner-exit boundary is complete and the coordinator holds
    // both live clients, so no owner or free path can mutate this source span.
    let source_span_after_consumer = unsafe {
        native_runtime_live_client_page_map_span_test_audit(source_page)
    }
    .expect("the source PageMap span remains auditable before terminal frees");
    assert_eq!(
        source_span_after_consumer.matching_page_entry_count,
        source_page.registered_slice_count(),
        "the complete recorded source PageMap range still names A whether B claims it or falls back"
    );
    assert_eq!(
        source_span_after_consumer.non_null_entry_count,
        source_page.registered_slice_count(),
        "B's separate fallback registration never overlaps A's source range"
    );

    let after_consumer = native_runtime_lifecycle_test_audit()
        .expect("both workers joined before the one-page reuse audit");
    if expect_source_reuse {
        assert_eq!(
            after_consumer.page_map_registered_entry_count,
            after_owner_exit.page_map_registered_entry_count,
            "ordinary same-bin allocation reuses A's exact PageMap span instead of leaving a second fresh regular span"
        );
        match consumer_owner {
            ConsumerOwner::LaterAttached => assert_eq!(
                after_consumer.main_heap_abandoned_page_count,
                baseline.main_heap_abandoned_page_count + 1,
                "B reabandons the same one-page source image while its own client stays live"
            ),
            ConsumerOwner::InitialPersistent => assert_eq!(
                after_consumer.main_heap_abandoned_page_count,
                baseline.main_heap_abandoned_page_count,
                "the persistent initial owner claims A's publication and keeps the live page locally owned"
            ),
        }
    } else {
        assert!(matches!(consumer_owner, ConsumerOwner::LaterAttached));
        assert!(
            after_consumer.page_map_registered_entry_count
                > after_owner_exit.page_map_registered_entry_count,
            "the no-candidate distinct-bin allocation registers one fresh regular span"
        );
        assert_eq!(
            after_consumer.main_heap_abandoned_page_count,
            baseline.main_heap_abandoned_page_count + 2,
            "A's unmatched source and B's fresh page independently publish two mapped-abandoned pages"
        );
    }
    assert_eq!(
        after_consumer.shared_later_theap_count,
        baseline.shared_later_theap_count,
        "both detached later Theaps leave no shared-main list member behind"
    );
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "the source and any later consumer release their independent later-thread admissions"
    );

    if let Some(inherited_immediate_head) = inherited_immediate_head {
        assert!(
            expect_source_reuse,
            "an inherited immediate head is only a same-bin source image"
        );
        assert_eq!(
            consumer_regular.as_ptr().addr(),
            inherited_immediate_head,
            "B pops A's owner-exit-published immediate free head instead of extending or allocating fresh"
        );
    }
    assert_eq!(
        // SAFETY: B returned this exact live client to the coordinator only
        // after its owner exit; no worker or route retains a second free
        // capability for it.
        unsafe { native_free(consumer_regular) },
        NativePageFreeResult::Freed,
        "the coordinator frees B's post-exit client through the exact PageMap route"
    );
    assert_eq!(
        // SAFETY: A returned this exact still-live source client only to the
        // coordinator, and B never received its address or a free route.
        unsafe { native_free(source_regular) },
        NativePageFreeResult::Freed,
        "the coordinator frees A's post-exit client and reaches the all-free terminal tail"
    );
    // SAFETY: coordinator cleanup has completed serially; no worker remains
    // that could mutate or release the recorded PageMap span during this
    // source-plain post-free observation.
    let source_span_after_cleanup = unsafe {
        native_runtime_live_client_page_map_span_test_audit(source_page)
    }
    .expect("the source PageMap range remains auditable after terminal frees");
    match (expect_source_reuse, consumer_owner) {
        (_, ConsumerOwner::LaterAttached) => {
            assert_eq!(
                source_span_after_cleanup.matching_page_entry_count,
                0,
                "the exact reclaimed source page no longer has a PageMap entry after its final free"
            );
            assert_eq!(
                source_span_after_cleanup.non_null_entry_count,
                0,
                "the exact recorded source PageMap range is unregistered after the terminal free"
            );
        }
        (true, ConsumerOwner::InitialPersistent) => {
            assert_eq!(
                source_span_after_cleanup.matching_page_entry_count,
                source_page.registered_slice_count(),
                "the initial persistent owner retains its exact all-free page for its next ordinary local allocation"
            );
            assert_eq!(
                source_span_after_cleanup.non_null_entry_count,
                source_page.registered_slice_count(),
                "the retained initial engine keeps only the reclaimed source PageMap range registered"
            );
        }
        (false, ConsumerOwner::InitialPersistent) => unreachable!(
            "the focused no-candidate image uses the independently attached later receiver"
        ),
    }

    if !expect_source_reuse {
        // SAFETY: the joined consumer and serial coordinator cleanup leave
        // the copied fresh-span geometry quiescent for this post-free read.
        let consumer_span_after_cleanup = unsafe {
            native_runtime_live_client_page_map_span_test_audit(consumer_page)
        }
        .expect("B's fresh PageMap span remains auditable after terminal frees");
        assert_eq!(
            consumer_span_after_cleanup.matching_page_entry_count,
            0,
            "B's fresh fallback page is also unregistered after its final free"
        );
        assert_eq!(
            consumer_span_after_cleanup.non_null_entry_count,
            0,
            "B's recorded fresh PageMap range contains no residual entry after cleanup"
        );
    }

    let after_cleanup = native_runtime_lifecycle_test_audit()
        .expect("coordinator cleanup returns the joined lifecycle to quiescence");
    match (expect_source_reuse, consumer_owner) {
        (_, ConsumerOwner::LaterAttached) => assert_reclaimed_lifecycle_baseline(baseline, after_cleanup),
        (true, ConsumerOwner::InitialPersistent) => {
            assert_eq!(
                after_cleanup.main_heap_abandoned_page_count,
                baseline.main_heap_abandoned_page_count,
                "the initial local engine does not republish the reclaimed page as mapped-abandoned"
            );
            assert_eq!(
                after_cleanup.shared_later_theap_count,
                baseline.shared_later_theap_count,
                "the initial receiver does not leave a later-owner list entry behind"
            );
            assert_eq!(
                after_cleanup.live_thread_count,
                baseline.live_thread_count,
                "both later source-worker lifecycles have completed before the initial local cleanup audit"
            );
        }
        (false, ConsumerOwner::InitialPersistent) => unreachable!(
            "the focused no-candidate image uses the independently attached later receiver"
        ),
    }
}
