#![cfg(feature = "native-runtime-test-audit")]

#[path = "support/native_runtime.rs"]
mod native_runtime_test_support;




use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    finish_current_thread_native_after_user_destructors,
    native_allocate_aligned, native_free, native_reallocate,
    native_runtime_current_thread_attachment_test_audit, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, native_runtime_metadata_page_map_test_audit,
    native_runtime_live_client_page_test_audit, native_runtime_live_client_page_map_span_test_audit,
    native_usable_size, prepare_native_later_thread_arena,
};

const CHILD_WIDTH_ENV: &str = "CRABC_NATIVE_PERSISTENT_WORKER_FASTPATH_WIDTH";
const CHILD_TEARDOWN_ENV: &str = "CRABC_NATIVE_PERSISTENT_WORKER_FASTPATH_TEARDOWN";
const WORKER_WIDTHS: [usize; 4] = [1, 2, 4, 8];
const LOCAL_CYCLES: usize = 4;
const ANCHOR_REQUEST: usize = 47;
const REALLOCATED_ANCHOR_REQUEST: usize = 191;
const CYCLE_REQUEST: usize = 61;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerTeardown {
    AllFree,
    CollectAbandon,
    CollectAbandonReclaim,
}

impl WorkerTeardown {
    fn child_value(self) -> &'static str {
        match self {
            Self::AllFree => "all-free",
            Self::CollectAbandon => "collect-abandon",
            Self::CollectAbandonReclaim => "collect-abandon-reclaim",
        }
    }

    fn parse_child_value(value: &std::ffi::OsStr) -> Self {
        match value.to_str() {
            Some("all-free") => Self::AllFree,
            Some("collect-abandon") => Self::CollectAbandon,
            Some("collect-abandon-reclaim") => Self::CollectAbandonReclaim,
            _ => panic!("the child teardown selects one direct persistent-worker mode"),
        }
    }
}

fn current_page_size() -> usize {
    crabc_core::param::auxv_value(crabc_core::param::AT_PAGESZ)
        .expect("the native Linux test process exposes AT_PAGESZ")
}

fn allocate_local(request: usize) -> core::ptr::NonNull<u8> {
    match native_allocate_aligned(request, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the attached worker creates an ordinary local client")
        }
    }
}

fn run_independent_local_worker(
    worker: usize,
    ready: mpsc::SyncSender<()>,
    start: Arc<Barrier>,
    teardown: WorkerTeardown,
    reclaim_turn: Option<Arc<(Mutex<usize>, Condvar)>>,
) -> Option<usize> {
    assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);

    let anchor = allocate_local(ANCHOR_REQUEST);
    // SAFETY: this worker has the only current-owner capability for its
    // anchor. The test neither transfers it nor begins a remote operation.
    unsafe {
        anchor.as_ptr().write(worker as u8);
        assert_eq!(anchor.as_ptr().read(), worker as u8);
        assert!(
            native_usable_size(anchor).is_some_and(|usable| usable >= ANCHOR_REQUEST),
            "each worker retains its own PageMap-described local anchor"
        );
    }

    ready
        .send(())
        .expect("the coordinator observes every attached local owner");
    start.wait();
    if let Some(turn) = &reclaim_turn {
        let (current, changed) = &**turn;
        let mut current = current.lock().unwrap();
        while *current != worker {
            current = changed.wait(current).unwrap();
        }
    }

    let anchor = match unsafe { native_reallocate(Some(anchor), REALLOCATED_ANCHOR_REQUEST) } {
        NativePageAllocationResult::Allocated(block) => block,
        NativePageAllocationResult::Unavailable
        | NativePageAllocationResult::AllocationFailed
        | NativePageAllocationResult::Retained => {
            panic!("the retained local engine reallocates its own anchor")
        }
    };
    // SAFETY: reallocation returned this worker's sole current replacement.
    unsafe {
        assert_eq!(anchor.as_ptr().read(), worker as u8);
        anchor.as_ptr().add(REALLOCATED_ANCHOR_REQUEST - 1).write((worker as u8) ^ 0x5a);
        assert_eq!(
            anchor.as_ptr().add(REALLOCATED_ANCHOR_REQUEST - 1).read(),
            (worker as u8) ^ 0x5a
        );
    }

    for cycle in 0..LOCAL_CYCLES {
        let block = allocate_local(CYCLE_REQUEST);
        // SAFETY: this local temporary has no aliases outside its exact
        // allocate/free pair and never leaves this worker.
        unsafe {
            block.as_ptr().write((worker as u8) ^ (cycle as u8));
            assert_eq!(block.as_ptr().read(), (worker as u8) ^ (cycle as u8));
            assert_eq!(native_free(block), NativePageFreeResult::Freed);
        }
    }

    if teardown == WorkerTeardown::AllFree {
        // SAFETY: the reallocated anchor remains this worker's exact local
        // allocation until this final ordinary free.
        unsafe {
            assert_eq!(native_free(anchor), NativePageFreeResult::Freed);
        }
    }
    assert_eq!(
        finish_current_thread_native_after_user_destructors(),
        ThreadFinishResult::Finished,
        "the persistent local engine follows normal source teardown"
    );
    if let Some(turn) = &reclaim_turn {
        let (current, changed) = &**turn;
        *current.lock().unwrap() += 1;
        changed.notify_all();
    }
    // The test transfers only the still-live client to its coordinator. This
    // is a test-owned pointer list, never a production owner/route registry.
    (teardown != WorkerTeardown::AllFree).then(|| anchor.as_ptr().expose_provenance())
}

fn run_width(width: usize, teardown: WorkerTeardown) {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the private native runtime initializes before the persistent-worker workload"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves its first arena dormant before workers attach"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the initialized runtime begins in a quiescent auditable state");
    // SAFETY: this fresh child has initialized its runtime but has not spawned
    // workers. Its sole runtime thread performs only these observations.
    let baseline_metadata_entries = unsafe { native_runtime_metadata_page_map_test_audit() }
        .expect("the live runtime retains its source metadata identity");

    let (ready_sender, ready_receiver) = mpsc::sync_channel(width);
    let start = Arc::new(Barrier::new(width + 1));
    // The additional schedule preserves the ordinary concurrent case and
    // deterministically lets a later realloc reclaim an earlier worker's
    // abandoned replacement-anchor page, as pinned page.c::mi_page_fresh_alloc
    // permits. Every worker has already attached and allocated its first bin.
    let reclaim_turn = (teardown == WorkerTeardown::CollectAbandonReclaim)
        .then(|| Arc::new((Mutex::new(0), Condvar::new())));
    let mut workers = Vec::with_capacity(width);
    for worker in 0..width {
        let ready = ready_sender.clone();
        let start = Arc::clone(&start);
        let reclaim_turn = reclaim_turn.clone();
        workers.push(std::thread::spawn(move || {
            run_independent_local_worker(worker, ready, start, teardown, reclaim_turn)
        }));
    }
    drop(ready_sender);

    for _ in 0..width {
        ready_receiver
            .recv()
            .expect("each worker publishes one attached local anchor");
    }
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        width,
        "each concurrent worker retains one independent later-thread attachment before local operations continue"
    );
    start.wait();

    let mut live_anchors = Vec::new();
    for (worker_index, worker) in workers.into_iter().enumerate() {
        let anchor = worker
            .join()
            .expect("each independent local persistent worker reaches normal teardown");
        if let Some(address) = anchor {
            live_anchors.push((worker_index, address));
        }
    }

    let after = native_runtime_lifecycle_test_audit()
        .expect("every worker joined before the quiescent lifecycle audit");
    // SAFETY: every participating worker has joined, and this sole runtime
    // thread keeps the process and all registered pages live without mutation.
    let after_metadata_entries = unsafe { native_runtime_metadata_page_map_test_audit() }
        .expect("joined workers leave a quiescent metadata registration audit");
    let expected_owner_local_operations = width
        * (LOCAL_CYCLES * 2
            + match teardown {
                WorkerTeardown::AllFree => 3,
                WorkerTeardown::CollectAbandon | WorkerTeardown::CollectAbandonReclaim => 2,
            });
    assert!(
        after
            .native_owner_local_operation_count
            .saturating_sub(baseline.native_owner_local_operation_count)
            >= expected_owner_local_operations,
        "every allocation, free, and realloc crosses its worker's retained local engine; first-page materialization may add source-local work"
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "independent persistent workers never use the per-call parked compatibility bridge"
    );
    assert_eq!(
        after
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "independent persistent workers never take a scheduler transition"
    );
    assert_eq!(
        after.shared_later_theap_count, 0,
        "normal worker teardown detaches every metadata Theap from the shared main heap"
    );
    match teardown {
        WorkerTeardown::AllFree => {
            // Pinned init.c::mi_tld_free returns TLD/Theap blocks through
            // _mi_meta_free; it does not destroy mi_process_theap_meta.
            // Its reusable pages remain registered. Account for only pages
            // positively identified by subproc.c::_mi_meta_is_meta_page, so
            // even one leaked application-page registration still fails.
            assert_eq!(
                after.page_map_registered_entry_count,
                after_metadata_entries,
                "all remaining registrations belong to the detached metadata Theap"
            );
            assert_eq!(
                after.metadata_live_capability_count,
                baseline.metadata_live_capability_count,
                "normal teardown returns every worker TLD/Theap metadata capability"
            );
        }
        WorkerTeardown::CollectAbandon | WorkerTeardown::CollectAbandonReclaim => {
            assert_eq!(live_anchors.len(), width);
            let mut client_addresses = BTreeSet::new();
            let mut live_pages = BTreeMap::new();
            for (worker, address) in live_anchors {
                assert!(client_addresses.insert(address), "live worker clients never alias");
                let anchor = core::ptr::NonNull::new(
                    core::ptr::with_exposed_provenance_mut::<u8>(address),
                ).expect("the joined worker transferred its nonnull live anchor");
                // SAFETY: all workers joined; each exact client was deliberately
                // left live and exclusively transferred to this coordinator.
                // No allocator operation can now mutate its page or ownership.
                let page = unsafe {
                    assert_eq!(anchor.as_ptr().read(), worker as u8);
                    assert_eq!(
                        anchor.as_ptr().add(REALLOCATED_ANCHOR_REQUEST - 1).read(),
                        (worker as u8) ^ 0x5a,
                    );
                    assert!(native_usable_size(anchor)
                        .is_some_and(|size| size >= REALLOCATED_ANCHOR_REQUEST));
                    native_runtime_live_client_page_test_audit(anchor)
                }.expect("every live anchor retains its actual source PageMap identity");
                if let Some(previous) = live_pages.insert(page.page_address(), page) {
                    assert_eq!(previous, page, "clients sharing a page agree on its exact span");
                }
            }
            let mut live_registered_slices = 0;
            for page in live_pages.values() {
                // SAFETY: the live anchors above retain every observed page;
                // workers remain joined and no free or ownership mutation runs.
                let span = unsafe { native_runtime_live_client_page_map_span_test_audit(*page) }
                    .expect("each retained page remains fully registered");
                assert_eq!(span.matching_page_entry_count, page.registered_slice_count());
                assert_eq!(span.non_null_entry_count, page.registered_slice_count());
                live_registered_slices += page.registered_slice_count();
            }
            // Pinned page.c::mi_page_fresh_alloc can reclaim an earlier
            // worker's abandoned page for a later realloc. Several live
            // anchors may therefore share one final source page; worker
            // count is not the net abandoned-page count. Preserve that legal
            // interleaving and account for every exact live page instead.
            assert_eq!(
                after.main_heap_abandoned_page_count,
                baseline.main_heap_abandoned_page_count + live_pages.len(),
                "all and only the distinct live client pages remain abandoned"
            );
            assert_eq!(
                after.page_map_registered_entry_count - after_metadata_entries,
                baseline.page_map_registered_entry_count - baseline_metadata_entries
                    + live_registered_slices,
                "all application registrations match the exact live client page spans"
            );
            if teardown == WorkerTeardown::CollectAbandonReclaim && width > 1 {
                assert!(
                    live_pages.len() < width,
                    "the scheduled source reclaim consolidates multiple live anchors onto fewer pages"
                );
            }
        }
    }
    assert_eq!(after.live_thread_count, baseline.live_thread_count);
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "normal teardown releases every later-worker admission after its own source owner finishes"
    );
}

/// Later-thread local allocation uses one persistent TLD/Theap page engine per
/// worker. The fresh-process widths exercise both all-free and live
/// collect-abandon teardown through the ordinary direct API only. The
/// concurrent schedule remains unconstrained; an additional source-reclaim
/// schedule makes net-page consolidation deterministic. After joining, the
/// coordinator verifies every live payload and exact PageMap page/span.
/// No test geometry route, PageMap mutation lease, scheduler transition, or
/// production client ledger participates in the workload.
#[test]
fn persistent_workers_keep_independent_local_engines_through_normal_teardown() {
    if let (Some(width), Some(teardown)) = (
        std::env::var_os(CHILD_WIDTH_ENV),
        std::env::var_os(CHILD_TEARDOWN_ENV),
    ) {
        let width = width
            .to_string_lossy()
            .parse::<usize>()
            .expect("the child width is a valid positive integer");
        assert!(WORKER_WIDTHS.contains(&width), "the child width is in the direct workload");
        run_width(width, WorkerTeardown::parse_child_value(&teardown));
        return;
    }

    for teardown in [WorkerTeardown::AllFree, WorkerTeardown::CollectAbandon, WorkerTeardown::CollectAbandonReclaim] {
        for width in WORKER_WIDTHS {
            let status = std::process::Command::new(
                std::env::current_exe().expect("the focused test executable has a current path"),
            )
            .arg("--exact")
            .arg("persistent_workers_keep_independent_local_engines_through_normal_teardown")
            .env(CHILD_WIDTH_ENV, width.to_string())
            .env(CHILD_TEARDOWN_ENV, teardown.child_value())
            .status()
            .expect("each fresh-process worker width starts");
            assert_eq!(
                status.code(),
                Some(0),
                "the {width}-worker {teardown:?} persistent local fast path reaches normal teardown"
            );
        }
    }
}

/// A successful source later-thread attach owns its TLD/Theap immediately,
/// before a first allocator request may lazily bind page-engine state. This
/// checks that ordinary pthread creation itself neither reserves an
/// application page nor needs the first-page arena/PageMap transition, and
/// that an all-free no-allocation worker follows the normal source teardown.
#[test]
fn attach_pins_a_page_empty_owner_until_normal_no_allocation_teardown() {
    assert!(
        native_runtime_test_support::initialize(current_page_size()),
        "the private native runtime initializes before the source attachment"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves the first arena dormant before a worker attaches"
    );
    let before = native_runtime_lifecycle_test_audit()
        .expect("the initialized process has a quiescent baseline");
    // SAFETY: the test runtime is initialized and no worker exists yet; this
    // sole runtime thread retains all source owners without concurrent mutation.
    let before_metadata_entries = unsafe { native_runtime_metadata_page_map_test_audit() }
        .expect("the initialized metadata identity remains live");

    let attached = std::thread::spawn(move || {
        assert_eq!(native_runtime_test_support::attach_current_thread(), ThreadAttachResult::Attached);
        let audit = native_runtime_current_thread_attachment_test_audit();
        assert_eq!(
            audit.persistent_owner_installed, 1,
            "source TLD/Theap attachment is pinned before the first native allocation"
        );
        assert_eq!(
            audit.page_engine_active, 0,
            "pthread attach does not eagerly create a page engine or application page"
        );
        assert_eq!(
            audit.owner_local_operation_count, before.native_owner_local_operation_count,
            "pthread attach itself does not enter the owner-local allocation path"
        );
        assert_eq!(
            finish_current_thread_native_after_user_destructors(),
            ThreadFinishResult::Finished,
            "a page-empty persistent owner reaches normal source TLD/Theap teardown"
        );
    });
    attached
        .join()
        .expect("the page-empty worker completes normal teardown");

    let after = native_runtime_lifecycle_test_audit()
        .expect("the completed no-allocation worker restores a quiescent audit");
    // SAFETY: the only worker has joined; this sole runtime thread retains
    // the process and registered page images and performs no concurrent work.
    let after_metadata_entries = unsafe { native_runtime_metadata_page_map_test_audit() }
        .expect("the completed worker leaves a quiescent metadata registration audit");
    // The source TLD/Theap constructor legitimately uses metadata and its
    // PageMap registrations are not application-page claims. The persistent
    // owner state above proves the page engine remains dormant; these existing
    // process-backing observations independently prove that attach did not
    // begin or publish an application arena before the no-allocation teardown.
    assert_eq!(
        after.process_backing_first_arena_begin_count,
        before.process_backing_first_arena_begin_count,
        "thread attach does not begin a first application arena"
    );
    assert_eq!(
        after.process_backing_published_os_arena_count,
        before.process_backing_published_os_arena_count,
        "thread attach does not publish an OS-backed application arena parent"
    );
    assert_eq!(
        after.arena_registry_count, before.arena_registry_count,
        "thread attach does not register an application arena owner"
    );
    assert_eq!(
        after.metadata_live_capability_count, before.metadata_live_capability_count,
        "normal teardown releases the worker TLD/Theap metadata ownership"
    );
    assert_eq!(
        after.page_map_registered_entry_count - after_metadata_entries,
        before.page_map_registered_entry_count - before_metadata_entries,
        "page-empty attachment retains no application-page registration"
    );
    assert_eq!(after.shared_later_theap_count, 0);
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "normal no-allocation teardown releases the worker admission"
    );
}
