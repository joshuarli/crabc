// Automatic integration-test discovery still compiles this file in ordinary
// allocator builds. The scalar audit is deliberately default-off and exposes
// no owner, route, PageMap, scheduler token, or allocation identity.
#![cfg(feature = "native-runtime-test-audit")]

use std::sync::{Arc, Barrier, mpsc};

use crabc_mimalloc::__crabc_runtime::{
    NativePageAllocationResult, NativePageFreeResult, ThreadAttachResult, ThreadFinishResult,
    attach_current_thread, finish_current_thread_native_after_user_destructors, initialize_process,
    native_allocate_aligned, native_free, native_runtime_fork_admission_test_audit,
    native_runtime_lifecycle_test_audit, prepare_native_later_thread_arena,
};

const CHILD_WIDTH_ENV: &str = "CRABC_NATIVE_OWNER_FIRST_ALLOCATION_DISPATCH_WIDTH";
const WORKER_WIDTHS: [usize; 4] = [1, 2, 4, 8];
const STEADY_LOCAL_ALLOCATIONS: usize = 6;
const INITIAL_REQUEST: usize = 71;
const WORKER_ANCHOR_REQUEST: usize = 47;
const WORKER_STEADY_REQUEST: usize = 59;

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
            panic!("the installed persistent owner creates its ordinary local client")
        }
    }
}

fn run_local_worker(worker: usize, ready: mpsc::SyncSender<()>, start: Arc<Barrier>) {
    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);

    // This first allocation creates and installs the later worker's persistent
    // compiler-TLS owner. The concurrent sequence below is therefore a
    // steady-state owner-selection witness rather than a cold attach test.
    let anchor = allocate_local(WORKER_ANCHOR_REQUEST);
    ready
        .send(())
        .expect("the coordinator observes every installed later owner");
    start.wait();

    let mut blocks = [None; STEADY_LOCAL_ALLOCATIONS];
    for (cycle, slot) in blocks.iter_mut().enumerate() {
        let block = allocate_local(WORKER_STEADY_REQUEST);
        // SAFETY: this worker retains exclusive access to its exact local
        // allocation until the matching local free below.
        unsafe {
            block.as_ptr().write((worker as u8) ^ (cycle as u8));
            assert_eq!(block.as_ptr().read(), (worker as u8) ^ (cycle as u8));
        }
        *slot = Some(block);
    }
    for block in blocks {
        let block = block.expect("every steady local slot receives one block");
        // SAFETY: `block` is this worker's exact unshared local allocation.
        assert_eq!(unsafe { native_free(block) }, NativePageFreeResult::Freed);
    }
    // SAFETY: the anchor remains this worker's exact local allocation until
    // this final ordinary free.
    assert_eq!(unsafe { native_free(anchor) }, NativePageFreeResult::Freed);
    assert_eq!(
        finish_current_thread_native_after_user_destructors(),
        ThreadFinishResult::Finished,
        "the all-free persistent worker follows normal source teardown"
    );
}

fn run_width(width: usize) {
    assert!(
        initialize_process(current_page_size()),
        "the private native runtime initializes before the owner-first allocation audit"
    );
    assert!(
        prepare_native_later_thread_arena(),
        "the initial source installs its persistent owner before steady-state allocation"
    );

    // `prepare_native_later_thread_arena` has already performed the one-time
    // initial-owner promotion. This allocation/free pair must select the
    // installed initial compiler-TLS owner directly, without reopening the
    // process-wide initial-thread admission branch.
    let before_initial = native_runtime_lifecycle_test_audit()
        .expect("the promoted initial source exposes a scalar audit");
    let initial = allocate_local(INITIAL_REQUEST);
    // SAFETY: the initial source owns its exact current client until this
    // matching ordinary local free.
    assert_eq!(unsafe { native_free(initial) }, NativePageFreeResult::Freed);
    let after_initial = native_runtime_lifecycle_test_audit()
        .expect("the completed initial local sequence remains auditable");
    assert_eq!(
        after_initial
            .native_scheduler_transition_count
            .saturating_sub(before_initial.native_scheduler_transition_count),
        0,
        "the installed initial owner never re-enters the scheduler"
    );
    assert_eq!(
        after_initial
            .native_parked_compatibility_operation_count
            .saturating_sub(before_initial.native_parked_compatibility_operation_count),
        0,
        "the installed initial owner never uses the parked compatibility bridge"
    );

    let baseline = native_runtime_lifecycle_test_audit()
        .expect("the worker owner-selection audit starts from a quiescent initial source");
    let (ready_sender, ready_receiver) = mpsc::sync_channel(width);
    let start = Arc::new(Barrier::new(width + 1));
    let mut workers = Vec::with_capacity(width);
    for worker in 0..width {
        let ready = ready_sender.clone();
        let start = Arc::clone(&start);
        workers.push(std::thread::spawn(move || run_local_worker(worker, ready, start)));
    }
    drop(ready_sender);

    for _ in 0..width {
        ready_receiver
            .recv()
            .expect("each worker publishes one installed persistent owner");
    }
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        width,
        "the concurrent local workers retain exactly their own later-owner admissions"
    );
    start.wait();
    for worker in workers {
        worker
            .join()
            .expect("each owner-local allocation worker reaches normal teardown");
    }

    let after = native_runtime_lifecycle_test_audit()
        .expect("every owner-local worker joins before the scalar audit");
    let expected_owner_local_operations = width * (STEADY_LOCAL_ALLOCATIONS + 1) * 2;
    assert!(
        after
            .native_owner_local_operation_count
            .saturating_sub(baseline.native_owner_local_operation_count)
            >= expected_owner_local_operations,
        "every 1/2/4/8-worker allocation and free stays in its installed owner"
    );
    assert_eq!(
        after
            .native_scheduler_transition_count
            .saturating_sub(baseline.native_scheduler_transition_count),
        0,
        "installed later owners never re-enter the scheduler for local allocation"
    );
    assert_eq!(
        after
            .native_parked_compatibility_operation_count
            .saturating_sub(baseline.native_parked_compatibility_operation_count),
        0,
        "installed later owners never use the parked compatibility bridge for local allocation"
    );
    assert_eq!(
        after.page_map_registered_entry_count, baseline.page_map_registered_entry_count,
        "every local worker releases its exact clients before the final audit"
    );
    assert_eq!(after.shared_later_theap_count, baseline.shared_later_theap_count);
    assert_eq!(after.live_thread_count, baseline.live_thread_count);
    assert_eq!(
        native_runtime_fork_admission_test_audit().active_later_thread_count,
        0,
        "normal worker teardown releases every later-owner admission"
    );
}

/// Pinned `mi_heap_malloc` consumes an already-selected heap/theap; it does
/// not classify the caller again for each allocation. Each fresh child first
/// installs its initial owner, then creates one persistent owner per later
/// worker before the synchronized steady-state allocation sequence. The
/// widths prove direct initial and later owner selection stays local without
/// scheduler or parked-bridge deltas.
#[test]
fn native_owner_first_allocation_dispatch_keeps_initial_and_later_workers_local() {
    if let Some(width) = std::env::var_os(CHILD_WIDTH_ENV) {
        let width = width
            .to_string_lossy()
            .parse::<usize>()
            .expect("the child width is a valid positive integer");
        assert!(
            WORKER_WIDTHS.contains(&width),
            "the child width belongs to the direct owner-local audit"
        );
        run_width(width);
        return;
    }

    for width in WORKER_WIDTHS {
        let status = std::process::Command::new(
            std::env::current_exe().expect("the focused test executable has a current path"),
        )
        .arg("--exact")
        .arg("native_owner_first_allocation_dispatch_keeps_initial_and_later_workers_local")
        .env(CHILD_WIDTH_ENV, width.to_string())
        .status()
        .expect("each fresh-process owner-local width starts");
        assert_eq!(
            status.code(),
            Some(0),
            "the {width}-worker owner-first allocation path remains local"
        );
    }
}
