// SPDX-License-Identifier: MIT
//! Process-isolated native source-owner fork repair regressions.
//!
//! Each fixture runs in a freshly exec'd instance of this test binary, because
//! it consumes the irreversible process-global native owner. The registry model
//! is the libc contract in miniature: the process-initial descriptor slot plus
//! the linked worker descriptors. A sole child models libc's post-repair
//! registry reset by unlinking every inherited worker, so later writers can
//! see a surviving worker only through the re-rooted initial slot.
//!
//! Children never panic: every check exits with a distinct status so a failed
//! allocator transition is located without unwinding through copied state.
extern crate std;
use super::*;
use super::admission::{
    NativeAllocatorForkTestFault, TestEpochMode, TestRegistration, native_allocator_arm_fork_test_fault,
    native_allocator_disarm_fork_test_fault, test_epoch_mode, test_registration,
};
use core::sync::atomic::{AtomicBool, AtomicPtr};

const WORKERS: usize = 4;

struct Registry {
    workers: [AtomicPtr<NativeAllocatorThreadDescriptor>; WORKERS],
}

impl Registry {
    const fn new() -> Self {
        Self { workers: [const { AtomicPtr::new(core::ptr::null_mut()) }; WORKERS] }
    }

    fn visit(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
        let initial = native_allocator_initial_thread_descriptor();
        if let Some(initial) = initial { visitor(initial); }
        for worker in &self.workers {
            if let Some(worker) = NonNull::new(worker.load(Ordering::Acquire)) {
                if Some(worker) != initial { visitor(worker); }
            }
        }
    }

    fn publish(&self, index: usize) -> NonNull<NativeAllocatorThreadDescriptor> {
        let current = current_native_allocator_thread_descriptor();
        self.workers[index].store(current.as_ptr(), Ordering::Release);
        current
    }

    /// Libc forgets inherited worker controls after child repair.
    fn reset_after_child_repair(&self) {
        for worker in &self.workers { worker.store(core::ptr::null_mut(), Ordering::Release); }
    }
}

// SAFETY: fixture threads publish before their first source entry, keep their
// TLS mappings live until joined, and never withdraw while a writer runs. The
// initial descriptor is process-lifetime. Visits are synchronous and allocate
// nothing.
unsafe impl NativeAllocatorPinnedThreadRegistry for Registry {
    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
        self.visit(visitor);
    }
}
// SAFETY: the sole child visits the unchanged copied graph with signals
// blocked, before its modeled registry reset.
unsafe impl NativeAllocatorChildRetainedThreadRegistry for Registry {
    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
        self.visit(visitor);
    }
}

static REGISTRY: Registry = Registry::new();

unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

static CHILD_CALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);
static CHILD_CALLBACK_FAILED: AtomicBool = AtomicBool::new(false);

/// A registered deferred-free callback reached through the repaired
/// survivor's ordinary source cadence. It must run in phase B (entry
/// withdrawn, callback marker published) and may itself allocate.
unsafe extern "C" fn repaired_child_callback(_: bool, _: u64, _: *mut core::ffi::c_void) {
    CHILD_CALLBACK_CALLS.fetch_add(1, Ordering::Relaxed);
    if admission::current_native_allocator_callback_boundary_state() != (false, true) {
        CHILD_CALLBACK_FAILED.store(true, Ordering::Relaxed);
    }
    match native_allocate_aligned(16, 16, false) {
        NativePageAllocationResult::Allocated(block) => {
            if unsafe { native_free(block) } != NativePageFreeResult::Freed {
                CHILD_CALLBACK_FAILED.store(true, Ordering::Relaxed);
            }
        }
        _ => CHILD_CALLBACK_FAILED.store(true, Ordering::Relaxed),
    }
}

/// `single_thread.c` advances generic administration once per request. These
/// 1,000 2048-byte round trips reach the Mini cadence of the ordinary native
/// deferred-free boundary regression without retaining a client.
fn drive_callback_cadence() -> bool {
    (0..1_000).all(|_| match native_allocate_aligned(2048, 16, false) {
        NativePageAllocationResult::Allocated(block) => {
            (unsafe { native_free(block) }) == NativePageFreeResult::Freed
        }
        _ => false,
    })
}

/// The repaired child's registered callback is delivered by its own source
/// operations, never on behalf of a vanished owner during repair.
fn child_callback_delivery(status_base: i32) {
    CHILD_CALLBACK_CALLS.store(0, Ordering::Relaxed);
    unsafe { register_native_deferred_free_callback(Some(repaired_child_callback), core::ptr::null_mut()); }
    check(drive_callback_cadence(), status_base, b"child: callback cadence allocation\n");
    check(CHILD_CALLBACK_CALLS.load(Ordering::Relaxed) != 0, status_base + 1,
        b"child: repaired survivor delivers its deferred-free callback\n");
    check(!CHILD_CALLBACK_FAILED.load(Ordering::Relaxed), status_base + 2,
        b"child: callback phase-B boundary and reentry\n");
    unsafe { register_native_deferred_free_callback(None, core::ptr::null_mut()); }
}

fn note(message: &[u8]) { let _ = crabc_core::io::write(2, message); }

/// Child-side assertion: never unwind through copied parent state.
fn check(condition: bool, status: i32, message: &[u8]) {
    if !condition {
        note(message);
        crabc_core::process::exit_immediately(status);
    }
}

fn allocate(size: usize, alignment: usize) -> Option<NonNull<u8>> {
    match native_allocate_aligned(size, alignment, false) {
        NativePageAllocationResult::Allocated(block) => Some(block),
        _ => None,
    }
}

fn allocate_filled(size: usize, byte: u8) -> Block {
    let block = allocate(size, 16).expect("fixture native allocation");
    unsafe { block.as_ptr().write_bytes(byte, size); }
    Block { address: block.as_ptr() as usize, size, byte }
}

/// One live client recorded before a copy. Addresses are process-image
/// values, so the copied child can verify and release the same client.
#[derive(Clone, Copy)]
struct Block { address: usize, size: usize, byte: u8 }

impl Block {
    fn pointer(self) -> NonNull<u8> { NonNull::new(self.address as *mut u8).unwrap() }
    fn intact(self) -> bool {
        unsafe { core::slice::from_raw_parts(self.pointer().as_ptr(), self.size) }
            .iter().all(|value| *value == self.byte)
    }
}

/// Ordinary small, medium, large and OS-singleton clients.
const CLASS_SIZES: [usize; 5] = [48, 3_000, 40_000, 300_000, 3 * 1024 * 1024];

fn allocate_classes(byte: u8) -> [Block; 5] {
    CLASS_SIZES.map(|size| allocate_filled(size, byte))
}

fn free_block(block: Block) -> bool {
    block.intact() && unsafe { native_free(block.pointer()) } == NativePageFreeResult::Freed
}

fn block_signals() -> u64 {
    let blocked = u64::MAX;
    let mut previous = 0u64;
    unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &blocked, &mut previous) }
        .expect("block signals across the prepared copy");
    previous
}

fn restore_signals(previous: u64) {
    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &previous, core::ptr::null_mut()) }
        .expect("restore the saved mask");
}

fn wait_status(child: i32) -> i32 {
    let mut status = 0;
    assert_eq!(unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }, Ok(child));
    status
}

/// The complete ordinary operation set a repaired child must support on its
/// surviving owner.
fn survivor_operations(status_base: i32) {
    let small = allocate(64, 16);
    check(small.is_some(), status_base, b"child: survivor allocation\n");
    let small = small.unwrap();
    let zeroed = match native_allocate_aligned(4000, 16, true) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => { check(false, status_base + 1, b"child: zeroed allocation\n"); unreachable!() }
    };
    check(unsafe { core::slice::from_raw_parts(zeroed.as_ptr(), 4000) }.iter().all(|byte| *byte == 0),
        status_base + 2, b"child: zeroed contents\n");
    let aligned = allocate(100, 4096);
    check(aligned.is_some_and(|block| block.as_ptr() as usize % 4096 == 0),
        status_base + 3, b"child: aligned allocation\n");
    unsafe { small.as_ptr().write_bytes(0x5a, 64); }
    let grown = match unsafe { native_reallocate(Some(small), 90_000) } {
        NativePageAllocationResult::Allocated(block) => block,
        _ => { check(false, status_base + 4, b"child: survivor reallocation\n"); unreachable!() }
    };
    check(unsafe { core::slice::from_raw_parts(grown.as_ptr(), 64) }.iter().all(|byte| *byte == 0x5a),
        status_base + 5, b"child: reallocation contents\n");
    check(unsafe { native_usable_size(grown) }.is_some_and(|size| size >= 90_000),
        status_base + 6, b"child: usable size\n");
    for block in [grown, zeroed, aligned.unwrap()] {
        check(unsafe { native_free(block) } == NativePageFreeResult::Freed,
            status_base + 7, b"child: survivor free\n");
    }
}

/// A new child worker must register, attach, allocate and finish normally.
fn child_worker_round_trip(slot: usize) -> bool {
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let descriptor = REGISTRY.publish(slot);
            let ok = unsafe { register_current_native_allocator_worker_descriptor(descriptor) }
                && attach_current_thread() == ThreadAttachResult::Attached
                && allocate(48, 16).is_some_and(|block| {
                    (unsafe { native_free(block) }) == NativePageFreeResult::Freed
                })
                && finish_current_thread_native_after_user_destructors() == ThreadFinishResult::Finished;
            REGISTRY.workers[slot].store(core::ptr::null_mut(), Ordering::Release);
            ok
        }).join().unwrap_or(false)
    })
}

/// Prepared copy from the current thread, followed by sole-child repair.
/// Returns the child PID to the parent and `0` to the repaired child.
///
/// The child checks the repair's admission edges before any source entry:
/// no callback ran for a vanished owner, copied callback tokens cannot
/// resume (a distinct nonzero generation), and exactly the survivor's own
/// later-thread claim remains.
fn prepared_fork(survivor_is_worker: bool) -> i32 {
    let previous = block_signals();
    let interval = unsafe { begin_native_allocator_source_fork_quiescence(&REGISTRY) }
        .expect("every quiescent source owner admits the prepared copy");
    let copied_generation = RUNTIME_FORK_ADMISSION.callback_claim_generation.load(Ordering::Acquire);
    let copied_calls = CHILD_CALLBACK_CALLS.load(Ordering::Relaxed);
    let child = crabc_core::process::fork_raw().expect("prepared native copy");
    if child == 0 {
        let continuation = unsafe { interval.into_child_repair().into_unlocked_continuation() };
        check(continuation.is_ok(), 10, b"child: continuation\n");
        let repaired = unsafe { continuation.unwrap().repair_source_owners(&REGISTRY) };
        check(repaired.is_ok(), 11, b"child: source repair\n");
        check(CHILD_CALLBACK_CALLS.load(Ordering::Relaxed) == copied_calls, 5,
            b"child: repair invokes no callback for a vanished owner\n");
        let generation = RUNTIME_FORK_ADMISSION.callback_claim_generation.load(Ordering::Acquire);
        check(generation != 0 && generation != copied_generation, 6,
            b"child: copied callback tokens are invalidated and rearmed\n");
        check(RUNTIME_FORK_ADMISSION.state.load(Ordering::Acquire) == usize::from(survivor_is_worker), 7,
            b"child: only the survivor's later-thread claim remains\n");
        // Canonical native engines own only their exact PageMap ranges; a
        // survivor must not carry a legacy global lifecycle lease.
        let lease = RUNTIME_PROCESS.page_map_for_live_native_allocation()
            .map(|map| map.begin_page_lifecycle().map(|lease| lease.finish().is_ok()));
        check(matches!(lease, Some(Ok(true))), 8, b"child: PageMap lifecycle is free\n");
        REGISTRY.reset_after_child_repair();
        restore_signals(previous);
        return 0;
    }
    unsafe { interval.resume_parent() }.expect("parent resumes the exact generation");
    restore_signals(previous);
    child
}

fn thread_counts() -> (i64, i64, i64) {
    let counts = crate::subproc::MainSubprocess::global().statistics().source_snapshot();
    (counts.threads_total, counts.threads_peak, counts.threads_current)
}

/// Complete repaired-child behavior shared by both origins. `copied_threads`
/// is the parent's thread-statistics total and peak at the copy.
fn repaired_child(inherited: &[Block], survivor: NonNull<NativeAllocatorThreadDescriptor>,
    survivor_is_worker: bool, copied_threads: (i64, i64)) -> ! {
    check(native_allocator_initial_thread_descriptor() == Some(survivor), 12,
        b"child: survivor is re-rooted as the initial descriptor\n");
    check(test_epoch_mode() == TestEpochMode::Open, 13, b"child: epoch reopened\n");
    check(crate::subproc::MainSubprocess::global().live_thread_count() == 1, 14,
        b"child: vanished TLD/Theap owners retired\n");
    check(thread_counts() == (copied_threads.0, copied_threads.1, 1), 9,
        b"child: each vanished owner is detached from statistics exactly once\n");
    // Inherited clients from every vanished owner and the survivor: verify,
    // reallocate one per class through the pointer-first path, and free.
    for (index, block) in inherited.iter().enumerate() {
        check(block.intact(), 15, b"child: inherited client contents\n");
        if index % 2 == 0 {
            check(unsafe { native_usable_size(block.pointer()) }.is_some_and(|size| size >= block.size),
                16, b"child: inherited usable size\n");
            let moved = match unsafe { native_reallocate(Some(block.pointer()), block.size + 17) } {
                NativePageAllocationResult::Allocated(moved) => moved,
                _ => { check(false, 17, b"child: inherited reallocation\n"); unreachable!() }
            };
            let copied = Block { address: moved.as_ptr() as usize, ..*block };
            check(free_block(copied), 18, b"child: reallocated inherited free\n");
        } else {
            check(free_block(*block), 19, b"child: inherited free\n");
        }
    }
    survivor_operations(20);
    child_callback_delivery(27);
    check(child_worker_round_trip(WORKERS - 1), 30, b"child: new worker\n");
    check(thread_counts() == (copied_threads.0 + 1, copied_threads.1, 1), 35,
        b"child: the new worker attaches and finishes normally\n");
    // A second-generation prepared fork from the re-rooted survivor.
    let grandchild = prepared_fork(survivor_is_worker);
    if grandchild == 0 {
        check(native_allocator_initial_thread_descriptor() == Some(survivor), 31,
            b"grandchild: survivor stays the initial descriptor\n");
        survivor_operations(40);
        check(finish_selected_default_release_process_after_user_atexit()
            == SelectedProcessDoneResult::Completed, 32, b"grandchild: process done\n");
        crabc_core::process::exit_immediately(0);
    }
    check(wait_status(grandchild) == 0, 33, b"child: grandchild status\n");
    survivor_operations(50);
    check(finish_selected_default_release_process_after_user_atexit()
        == SelectedProcessDoneResult::Completed, 34, b"child: process done\n");
    crabc_core::process::exit_immediately(0);
}

fn initialize() {
    assert!(initialize_process(4096, unsafe { RuntimeStderrOutput::new(no_output) }));
    assert!(prepare_native_later_thread_arena());
}

/// A worker publishes, attaches and allocates every class before `ready`.
fn attach_worker(index: usize, byte: u8) -> [Block; 5] {
    let descriptor = REGISTRY.publish(index);
    assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
    allocate_classes(byte)
}

/// Finishes a parent worker and withdraws it, as libc unlinks its control.
fn finish_worker(index: usize) {
    assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
    REGISTRY.workers[index].store(core::ptr::null_mut(), Ordering::Release);
}

/// Continuously allocates and frees through a ring while a writer drains.
/// Ring slots hold either zero or one live client, so a copied child can
/// release exactly the clients which were live at the copy.
fn churn(ring: &[AtomicUsize; 8], stop: &AtomicBool) {
    let mut round = 0usize;
    while !stop.load(Ordering::Acquire) {
        let slot = &ring[round % ring.len()];
        let old = slot.swap(0, Ordering::AcqRel);
        if let Some(old) = NonNull::new(old as *mut u8) {
            assert_eq!(unsafe { native_free(old) }, NativePageFreeResult::Freed);
        }
        let size = CLASS_SIZES[round % 3] + round % 64;
        let block = allocate(size, 16).expect("churn allocation");
        unsafe { block.as_ptr().write_bytes(0x77, 16); }
        slot.store(block.as_ptr() as usize, Ordering::Release);
        round = round.wrapping_add(1);
    }
    for slot in ring {
        if let Some(old) = NonNull::new(slot.swap(0, Ordering::AcqRel) as *mut u8) {
            assert_eq!(unsafe { native_free(old) }, NativePageFreeResult::Freed);
        }
    }
}

fn ring_blocks(ring: &[AtomicUsize; 8]) -> std::vec::Vec<Block> {
    ring.iter().filter_map(|slot| {
        let address = slot.load(Ordering::Acquire);
        (address != 0).then_some(Block { address, size: 16, byte: 0x77 })
    }).collect()
}

/// Two parent threads hold live clients of every class while a third churns;
/// the selected origin performs the prepared copy.
fn prepared_origin_fixture(worker_origin: bool) {
    std::thread::spawn(move || {
        initialize();
        let initial_blocks = allocate_classes(0x35);
        // Addresses cross the scoped threads; the descriptors stay pinned.
        let initial_descriptor = native_allocator_initial_thread_descriptor().unwrap().as_ptr() as usize;
        let worker_blocks: std::sync::Mutex<Option<[Block; 5]>> = std::sync::Mutex::new(None);
        let ready = AtomicUsize::new(0);
        let release = AtomicBool::new(false);
        let stop_churn = AtomicBool::new(false);
        let ring = [const { AtomicUsize::new(0) }; 8];
        let counts_before = std::thread::scope(|scope| {
            let churner = scope.spawn(|| {
                let descriptor = REGISTRY.publish(1);
                assert!(unsafe { register_current_native_allocator_worker_descriptor(descriptor) });
                assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                ready.fetch_add(1, Ordering::AcqRel);
                churn(&ring, &stop_churn);
                finish_worker(1);
            });
            let worker = scope.spawn(|| {
                let blocks = attach_worker(0, 0x63);
                *worker_blocks.lock().unwrap() = Some(blocks);
                ready.fetch_add(1, Ordering::AcqRel);
                if worker_origin {
                    while ready.load(Ordering::Acquire) != 2 { std::thread::yield_now(); }
                    let survivor = current_native_allocator_thread_descriptor();
                    let child = prepared_fork(true);
                    if child == 0 {
                        let mut inherited = std::vec::Vec::from(initial_blocks);
                        inherited.extend_from_slice(&blocks);
                        inherited.extend(ring_blocks(&ring));
                        repaired_child(&inherited, survivor, true, (3, 3));
                    }
                    assert_eq!(wait_status(child), 0, "worker-origin repaired child");
                    assert_eq!(native_allocator_initial_thread_descriptor().map(|pointer| pointer.as_ptr() as usize),
                        Some(initial_descriptor), "the parent keeps its own initial descriptor");
                } else {
                    while !release.load(Ordering::Acquire) { std::thread::yield_now(); }
                }
                for block in blocks { assert!(free_block(block), "worker frees its own clients"); }
                finish_worker(0);
            });
            while ready.load(Ordering::Acquire) != 2 { std::thread::yield_now(); }
            if !worker_origin {
                let survivor = current_native_allocator_thread_descriptor();
                let worker = worker_blocks.lock().unwrap().expect("worker clients");
                let child = prepared_fork(false);
                if child == 0 {
                    let mut inherited = std::vec::Vec::from(initial_blocks);
                    inherited.extend_from_slice(&worker);
                    inherited.extend(ring_blocks(&ring));
                    repaired_child(&inherited, survivor, false, (3, 3));
                }
                assert_eq!(wait_status(child), 0, "initial-origin repaired child");
                release.store(true, Ordering::Release);
            }
            worker.join().unwrap();
            stop_churn.store(true, Ordering::Release);
            churner.join().unwrap();
            crate::subproc::MainSubprocess::global().statistics().source_snapshot()
        });
        for block in initial_blocks { assert!(free_block(block), "initial frees its own clients"); }
        assert_eq!((counts_before.threads_total, counts_before.threads_peak, counts_before.threads_current),
            (3, 3, 1), "child repair never changes the parent's thread statistics");
        assert_eq!(test_epoch_mode(), TestEpochMode::Open);
    }).join().expect("isolated prepared-fork fixture");
}

#[test]
fn worker_origin_child_repairs_initial_owner_and_preserves_live_clients() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::worker_origin_child_repairs_initial_owner_and_preserves_live_clients",
        || prepared_origin_fixture(true),
    );
}

#[test]
fn initial_origin_child_repairs_worker_owner_and_preserves_live_clients() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::initial_origin_child_repairs_worker_owner_and_preserves_live_clients",
        || prepared_origin_fixture(false),
    );
}

/// The permanent legal-C regression across a prepared fork: a worker
/// allocates every class, exits and is joined, and both the parent and the
/// repaired child free its surviving clients. A deferred-free callback
/// registered before the copy is never run for a vanished owner and is
/// delivered afterward by the survivor's own operations.
#[test]
fn joined_worker_clients_survive_prepared_fork_in_parent_and_child() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::joined_worker_clients_survive_prepared_fork_in_parent_and_child",
        || std::thread::spawn(|| {
            initialize();
            let initial_blocks = allocate_classes(0x35);
            let worker_blocks = std::thread::spawn(|| {
                let blocks = attach_worker(0, 0x63);
                finish_worker(0);
                blocks
            }).join().expect("exited worker");
            let survivor = current_native_allocator_thread_descriptor();
            unsafe { register_native_deferred_free_callback(Some(repaired_child_callback), core::ptr::null_mut()); }
            let child = prepared_fork(false);
            if child == 0 {
                check(native_allocator_initial_thread_descriptor() == Some(survivor), 110,
                    b"child: initial survivor stays rooted\n");
                check(thread_counts() == (2, 2, 1), 111, b"child: no owner detached twice\n");
                for block in worker_blocks { check(free_block(block), 112, b"child: exited worker clients\n"); }
                for block in initial_blocks { check(free_block(block), 113, b"child: initial clients\n"); }
                survivor_operations(114);
                child_callback_delivery(122);
                check(child_worker_round_trip(1), 125, b"child: new worker\n");
                check(finish_selected_default_release_process_after_user_atexit()
                    == SelectedProcessDoneResult::Completed, 126, b"child: process done\n");
                crabc_core::process::exit_immediately(0);
            }
            assert_eq!(wait_status(child), 0, "repaired child of a joined-worker parent");
            unsafe { register_native_deferred_free_callback(None, core::ptr::null_mut()); }
            for block in worker_blocks { assert!(free_block(block), "parent frees the exited worker's clients"); }
            for block in initial_blocks { assert!(free_block(block)); }
            assert_eq!(thread_counts(), (2, 2, 1), "child repair never changes the parent's statistics");
        }).join().expect("isolated joined-worker fixture"),
    );
}

/// An injected preflight refusal happens after the drain and before any copy.
/// The same generation reopens, every owner stays uniquely registered with its
/// exact clients, and the next prepared copy succeeds.
#[test]
fn injected_preflight_failure_reopens_and_preserves_every_unique_owner() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::injected_preflight_failure_reopens_and_preserves_every_unique_owner",
        || std::thread::spawn(|| {
            initialize();
            let initial_blocks = allocate_classes(0x35);
            let ready = AtomicBool::new(false);
            let release = AtomicBool::new(false);
            let worker_descriptor = AtomicPtr::new(core::ptr::null_mut());
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    let blocks = attach_worker(0, 0x63);
                    worker_descriptor.store(current_native_allocator_thread_descriptor().as_ptr(), Ordering::Release);
                    ready.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) { std::thread::yield_now(); }
                    for block in blocks { assert!(free_block(block)); }
                    finish_worker(0);
                });
                while !ready.load(Ordering::Acquire) { std::thread::yield_now(); }
                let worker_pointer = NonNull::new(worker_descriptor.load(Ordering::Acquire)).unwrap();
                native_allocator_arm_fork_test_fault(NativeAllocatorForkTestFault::Preflight);
                let refused = unsafe { begin_native_allocator_source_fork_quiescence(&REGISTRY) };
                assert!(matches!(refused, Err(NativeAllocatorQuiescenceError::RetainedDescriptor)));
                assert_eq!(test_epoch_mode(), TestEpochMode::Open, "refusal reopens entry");
                for descriptor in [native_allocator_initial_thread_descriptor().unwrap(), worker_pointer] {
                    assert_eq!(unsafe { test_registration(descriptor) }, TestRegistration::Registered,
                        "refusal neither transfers nor retains an owner");
                }
                // Both owners keep serving their own clients and new work.
                let extra = allocate_filled(700, 0x11);
                assert!(free_block(extra));
                let child = prepared_fork(false);
                if child == 0 {
                    check(unsafe { test_registration(worker_pointer) } == TestRegistration::Transferred,
                        60, b"child: vanished worker retired exactly once\n");
                    for block in initial_blocks { check(free_block(block), 61, b"child: initial clients\n"); }
                    survivor_operations(62);
                    crabc_core::process::exit_immediately(0);
                }
                assert_eq!(wait_status(child), 0, "the next prepared copy repairs normally");
                release.store(true, Ordering::Release);
                worker.join().unwrap();
            });
            for block in initial_blocks { assert!(free_block(block)); }
        }).join().expect("isolated preflight fault fixture"),
    );
}

/// A child repair failure retains exactly one identifiable owner, never
/// reopens source entry, and leaves the parent untouched.
#[test]
fn injected_child_repair_failure_retains_one_owner_and_seals_the_child() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::injected_child_repair_failure_retains_one_owner_and_seals_the_child",
        || std::thread::spawn(|| {
            initialize();
            let initial_blocks = allocate_classes(0x35);
            let ready = AtomicUsize::new(0);
            let release = AtomicBool::new(false);
            let descriptors = [const { AtomicPtr::new(core::ptr::null_mut()) }; 2];
            std::thread::scope(|scope| {
                let workers = [0usize, 1].map(|index| {
                    let (ready, release, descriptors) = (&ready, &release, &descriptors);
                    scope.spawn(move || {
                        let blocks = attach_worker(index, 0x40 + index as u8);
                        descriptors[index].store(current_native_allocator_thread_descriptor().as_ptr(), Ordering::Release);
                        ready.fetch_add(1, Ordering::AcqRel);
                        while !release.load(Ordering::Acquire) { std::thread::yield_now(); }
                        for block in blocks { assert!(free_block(block)); }
                        finish_worker(index);
                    })
                });
                while ready.load(Ordering::Acquire) != 2 { std::thread::yield_now(); }
                let vanished = descriptors.each_ref().map(|slot| NonNull::new(slot.load(Ordering::Acquire)).unwrap());
                let previous = block_signals();
                let interval = unsafe { begin_native_allocator_source_fork_quiescence(&REGISTRY) }
                    .expect("prepared copy");
                native_allocator_arm_fork_test_fault(NativeAllocatorForkTestFault::ChildRepair);
                let child = crabc_core::process::fork_raw().expect("fault child");
                if child == 0 {
                    let continuation = unsafe { interval.into_child_repair().into_unlocked_continuation() };
                    check(continuation.is_ok(), 70, b"child: continuation\n");
                    let repaired = unsafe { continuation.unwrap().repair_source_owners(&REGISTRY) };
                    check(repaired == Err(NativeAllocatorQuiescenceError::RetainedDescriptor), 71,
                        b"child: injected repair failure reported\n");
                    let states = vanished.map(|descriptor| unsafe { test_registration(descriptor) });
                    let retained = states.iter().filter(|state| **state == TestRegistration::Retained).count();
                    check(retained == 1, 72, b"child: exactly one retained owner\n");
                    check(states.iter().all(|state| matches!(state,
                        TestRegistration::Retained | TestRegistration::Registered | TestRegistration::Transferred)),
                        73, b"child: no owner lost or duplicated\n");
                    check(test_epoch_mode() == TestEpochMode::Terminal, 74, b"child: entry sealed\n");
                    check(native_allocator_initial_thread_descriptor()
                        == Some(current_native_allocator_thread_descriptor()), 75,
                        b"child: no survivor re-root after failure\n");
                    check(!matches!(native_allocate_aligned(32, 16, false), NativePageAllocationResult::Allocated(_)),
                        76, b"child: sealed entry refuses allocation\n");
                    crabc_core::process::exit_immediately(0);
                }
                // The parent's copy of the armed point is never consumed.
                native_allocator_disarm_fork_test_fault();
                unsafe { interval.resume_parent() }.expect("parent resume");
                restore_signals(previous);
                assert_eq!(wait_status(child), 0, "fault child fail-stops with one retained owner");
                for descriptor in vanished {
                    assert_eq!(unsafe { test_registration(descriptor) }, TestRegistration::Registered);
                }
                release.store(true, Ordering::Release);
                for worker in workers { worker.join().unwrap(); }
            });
            for block in initial_blocks { assert!(free_block(block)); }
        }).join().expect("isolated child repair fault fixture"),
    );
}

/// An unprepared raw copy from a worker never repairs the vanished initial
/// owner. Its survivor keeps allocating, while later writers fail closed.
#[test]
fn unprepared_worker_raw_copy_retains_the_vanished_initial_owner() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::unprepared_worker_raw_copy_retains_the_vanished_initial_owner",
        || std::thread::spawn(|| {
            initialize();
            let initial_blocks = allocate_classes(0x35);
            let initial_address = native_allocator_initial_thread_descriptor().unwrap().as_ptr() as usize;
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let initial_descriptor = NonNull::new(initial_address as *mut NativeAllocatorThreadDescriptor).unwrap();
                    let blocks = attach_worker(0, 0x63);
                    let copy = unsafe { begin_native_allocator_raw_fork_copy() }.expect("raw copy admission");
                    let child = crabc_core::process::fork_raw().expect("raw copy");
                    if child == 0 {
                        check(unsafe { copy.complete_child() }.is_ok(), 80, b"child: raw completion\n");
                        check(unsafe { test_registration(initial_descriptor) } == TestRegistration::Retained,
                            81, b"child: vanished initial retained\n");
                        check(native_allocator_initial_thread_descriptor() == Some(initial_descriptor), 82,
                            b"child: unprepared image is not re-rooted\n");
                        // The survivor's own owner is intact and usable.
                        for block in blocks { check(free_block(block), 83, b"child: survivor clients\n"); }
                        survivor_operations(84);
                        REGISTRY.reset_after_child_repair();
                        REGISTRY.workers[0].store(current_native_allocator_thread_descriptor().as_ptr(), Ordering::Release);
                        check(matches!(unsafe { begin_native_allocator_source_fork_quiescence(&REGISTRY) },
                            Err(NativeAllocatorQuiescenceError::RetainedDescriptor)), 95,
                            b"child: later prepared writer fails closed\n");
                        check(test_epoch_mode() == TestEpochMode::Open, 96, b"child: refusal reopens\n");
                        check(allocate(32, 16).is_some_and(|block| unsafe { native_free(block) } == NativePageFreeResult::Freed),
                            97, b"child: survivor still allocates after refusal\n");
                        check(finish_selected_default_release_process_after_user_atexit()
                            == SelectedProcessDoneResult::Completed, 98, b"child: process done\n");
                        crabc_core::process::exit_immediately(0);
                    }
                    copy.complete_parent();
                    assert_eq!(wait_status(child), 0, "unprepared worker raw child");
                    assert_eq!(unsafe { test_registration(initial_descriptor) }, TestRegistration::Registered);
                    for block in blocks { assert!(free_block(block)); }
                    finish_worker(0);
                }).join().unwrap();
            });
            for block in initial_blocks { assert!(free_block(block)); }
        }).join().expect("isolated unprepared raw-copy fixture"),
    );
}

/// With no other allocator owner, an unprepared raw copy is a complete image:
/// the child may later take the prepared path and repair normally.
#[test]
fn unprepared_single_owner_raw_copy_permits_a_prepared_successor() {
    crate::test_process::run_in_fresh_process(
        "runtime_lifecycle::fork_repair_tests::unprepared_single_owner_raw_copy_permits_a_prepared_successor",
        || std::thread::spawn(|| {
            initialize();
            let initial_blocks = allocate_classes(0x35);
            let survivor = current_native_allocator_thread_descriptor();
            let copy = unsafe { begin_native_allocator_raw_fork_copy() }.expect("raw copy admission");
            let child = crabc_core::process::fork_raw().expect("raw copy");
            if child == 0 {
                check(unsafe { copy.complete_child() }.is_ok(), 90, b"child: raw completion\n");
                check(unsafe { test_registration(survivor) } == TestRegistration::Registered, 91,
                    b"child: sole initial owner stays registered\n");
                let successor = prepared_fork(false);
                if successor == 0 {
                    for block in initial_blocks { check(free_block(block), 92, b"grandchild: clients\n"); }
                    survivor_operations(100);
                    crabc_core::process::exit_immediately(0);
                }
                check(wait_status(successor) == 0, 93, b"child: prepared successor\n");
                for block in initial_blocks { check(free_block(block), 94, b"child: clients\n"); }
                crabc_core::process::exit_immediately(0);
            }
            copy.complete_parent();
            assert_eq!(wait_status(child), 0, "unprepared single-owner raw child");
            for block in initial_blocks { assert!(free_block(block)); }
        }).join().expect("isolated single-owner raw-copy fixture"),
    );
}
