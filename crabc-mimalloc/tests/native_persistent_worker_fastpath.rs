#![cfg(feature = "native-runtime-test-audit")]

use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_reallocate, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, native_usable_size, prepare_native_later_thread_arena,
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
}

impl WorkerTeardown {
    fn child_value(self) -> &'static str {
        match self {
            Self::AllFree => "all-free",
            Self::CollectAbandon => "collect-abandon",
        }
    }

    fn parse_child_value(value: &std::ffi::OsStr) -> Self {
        match value.to_str() {
            Some("all-free") => Self::AllFree,
            Some("collect-abandon") => Self::CollectAbandon,
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
) {
    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

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
}

fn run_width(width: usize, teardown: WorkerTeardown) {
    assert!(
        initialize_process(current_page_size()),
        "the private native runtime initializes before the persistent-worker workload"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "ticket zero leaves its first arena dormant before workers attach"
    );
    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the initialized runtime begins in a quiescent auditable state");

    let (ready_sender, ready_receiver) = mpsc::sync_channel(width);
    let start = Arc::new(Barrier::new(width + 1));
    let mut workers = Vec::with_capacity(width);
    for worker in 0..width {
        let ready = ready_sender.clone();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || {
            run_independent_local_worker(worker, ready, start, teardown)
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

    for worker in workers {
        worker
            .join()
            .expect("each independent local persistent worker reaches normal teardown");
    }

    let after = native_runtime_lifecycle_test_audit()
        .expect("every worker joined before the quiescent lifecycle audit");
    let expected_owner_local_operations = width
        * (LOCAL_CYCLES * 2
            + match teardown {
                WorkerTeardown::AllFree => 3,
                WorkerTeardown::CollectAbandon => 2,
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
            assert_eq!(after.page_map_registered_entry_count, 0);
        }
        WorkerTeardown::CollectAbandon => {
            assert!(
                after.main_heap_abandoned_page_count
                    >= baseline.main_heap_abandoned_page_count + width,
                "each worker's live local anchor crosses its own source collect-abandon traversal"
            );
            assert!(
                after.page_map_registered_entry_count
                    >= baseline.page_map_registered_entry_count + width,
                "each independently abandoned local page remains PageMap-addressable after normal owner teardown"
            );
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
/// collect-abandon teardown through the ordinary direct API only: no test
/// geometry route, PageMap mutation lease, scheduler transition, or client
/// ledger participates in the workload.
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

    for teardown in [WorkerTeardown::AllFree, WorkerTeardown::CollectAbandon] {
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
