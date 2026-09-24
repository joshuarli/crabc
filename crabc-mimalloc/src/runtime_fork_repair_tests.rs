// SPDX-License-Identifier: MIT
//! Isolated native source-owner fork repair; no libc product qualification.
extern crate std;
use super::*;
use core::sync::atomic::{AtomicBool, AtomicPtr};

struct Registry<'a> {
    initial: NonNull<NativeAllocatorThreadDescriptor>,
    worker: &'a AtomicPtr<NativeAllocatorThreadDescriptor>,
    new_worker: &'a AtomicPtr<NativeAllocatorThreadDescriptor>,
}
impl Registry<'_> {
    fn visit(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
        visitor(self.initial);
        if let Some(worker) = NonNull::new(self.worker.load(Ordering::Acquire)) { visitor(worker); }
        if let Some(worker) = NonNull::new(self.new_worker.load(Ordering::Acquire)) { visitor(worker); }
    }
}
// The parent initial thread and scoped worker remain mapped throughout the
// test. Publication completes before the epoch closes; neither can withdraw.
unsafe impl NativeAllocatorPinnedThreadRegistry for Registry<'_> {
    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) { self.visit(visitor); }
}
// The child uses the unchanged copied graph with signals blocked and no
// reset/adoption/hooks. No libc lock exists in this allocator-only fixture.
unsafe impl NativeAllocatorChildRetainedThreadRegistry for Registry<'_> {
    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) { self.visit(visitor); }
}

unsafe extern "C" fn no_output(_: *const core::ffi::c_char) {}

static CHILD_CALLBACK_CALLS: AtomicUsize = AtomicUsize::new(0);
static CHILD_CALLBACK_FAILED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn repaired_child_callback(_: bool, _: u64, _: *mut core::ffi::c_void) {
    CHILD_CALLBACK_CALLS.fetch_add(1, Ordering::Relaxed);
    if admission::current_native_allocator_callback_boundary_state() != (false, true) {
        CHILD_CALLBACK_FAILED.store(true, Ordering::Relaxed);
    }
    // Actual registered callback reentry uses the repaired survivor's source
    // owner. The ordinary recurse marker suppresses another user invocation;
    // no synthetic callback-claim test stands in for this allocator path.
    match native_allocate_aligned(16, 16, false) {
        NativePageAllocationResult::Allocated(block) => {
            if unsafe { native_free(block) } != NativePageFreeResult::Freed {
                CHILD_CALLBACK_FAILED.store(true, Ordering::Relaxed);
            }
        }
        _ => CHILD_CALLBACK_FAILED.store(true, Ordering::Relaxed),
    }
}

struct StopOnDrop<'a>(&'a AtomicBool);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) { self.0.store(true, Ordering::Release); }
}
struct PublishFailure<'a>(&'a AtomicUsize);
impl Drop for PublishFailure<'_> {
    fn drop(&mut self) { let _ = self.0.compare_exchange(0, usize::MAX, Ordering::Release, Ordering::Relaxed); }
}

fn allocate(size: usize) -> NonNull<u8> {
    match native_allocate_aligned(size, 16, false) {
        NativePageAllocationResult::Allocated(block) => block,
        _ => panic!("native source fixture allocation"),
    }
}

fn drive_repaired_child_callback_to_source_mini() -> bool {
    // `single_thread.c` advances generic administration once per request. A
    // standalone 64-byte allocation does not promise a callback; these exact
    // 1,000 2048-byte allocate/free round trips reach the same Mini cadence
    // as the ordinary native deferred-free boundary regression without
    // exhausting an arena or retaining a client through owner exit.
    for _ in 0..1_000 {
        let NativePageAllocationResult::Allocated(block) = native_allocate_aligned(2048, 16, false) else {
            return false;
        };
        if unsafe { native_free(block) } != NativePageFreeResult::Freed {
            return false;
        }
    }
    true
}

fn copy_and_repair(registry: &Registry<'_>, initial: usize, worker: usize) {
    unsafe { register_native_deferred_free_callback(Some(repaired_child_callback), core::ptr::null_mut()); }
    let copied_callback_generation = RUNTIME_FORK_ADMISSION.callback_claim_generation.load(Ordering::Acquire);
    let survivor_is_worker = current_native_allocator_thread_descriptor() != registry.initial;
    let _ = crabc_core::io::write(2, b"child-repair: close begin\n");
    let mask = u64::MAX;
    let mut old = 0u64;
    unsafe { crabc_core::signal::rt_sigprocmask_raw(0, &mask, &mut old) }.unwrap();
    let interval = unsafe { begin_native_allocator_source_fork_quiescence(registry) }
        .expect("all source owners preflight before the raw copy");
    let child = crabc_core::process::fork_raw().expect("source-owner child fixture");
    if child == 0 {
        let _ = crabc_core::io::write(2, b"child-repair: copied, continuation begin\n");
        let continuation = match unsafe { interval.into_child_repair().into_unlocked_continuation() } {
            Ok(value) => value,
            Err(_) => crabc_core::process::exit_immediately(10),
        };
        let _ = crabc_core::io::write(2, b"child-repair: source repair begin\n");
        if unsafe { continuation.repair_source_owners(registry) }.is_err() {
            crabc_core::process::exit_immediately(11);
        }
        let _ = crabc_core::io::write(2, b"child-repair: source repair complete\n");
        if CHILD_CALLBACK_CALLS.load(Ordering::Relaxed) != 0 {
            crabc_core::process::exit_immediately(23);
        }
        let callback_generation = RUNTIME_FORK_ADMISSION.callback_claim_generation.load(Ordering::Acquire);
        if callback_generation == 0 || callback_generation == copied_callback_generation
            || RUNTIME_FORK_ADMISSION.state.load(Ordering::Acquire) != usize::from(survivor_is_worker)
        { crabc_core::process::exit_immediately(25); }
        // Canonical native engines own only their exact PageMap ranges. A
        // surviving initial engine must not carry the legacy test scheduler's
        // global lease into W03's terminal free of an abandoned worker page.
        let map = RUNTIME_PROCESS.page_map_for_live_native_allocation().unwrap();
        match map.begin_page_lifecycle() {
            Ok(lease) => {
                if lease.finish().is_err() { crabc_core::process::exit_immediately(21); }
            }
            Err(crate::process_page_map::ProcessPageMapError::LifecycleBusy) => {
                let _ = crabc_core::io::write(2, b"child-repair: canonical survivor incorrectly retains global PageMap lease\n");
                crabc_core::process::exit_immediately(20);
            }
            Err(_) => crabc_core::process::exit_immediately(22),
        }
        if crate::subproc::MainSubprocess::global().live_thread_count() != 1 {
            crabc_core::process::exit_immediately(12);
        }
        let counts = crate::subproc::MainSubprocess::global().statistics().source_snapshot();
        if (counts.threads_total, counts.threads_peak, counts.threads_current) != (2, 2, 1) {
            crabc_core::process::exit_immediately(18);
        }
        for (address, size, byte) in [(initial, 80, 0x35u8), (worker, 96, 0x63u8)] {
            let _ = crabc_core::io::write(2, b"child-repair: inherited client free\n");
            let pointer = NonNull::new(address as *mut u8).unwrap();
            if !unsafe { core::slice::from_raw_parts(pointer.as_ptr(), size) }.iter().all(|value| *value == byte)
                || unsafe { native_free(pointer) } != NativePageFreeResult::Freed
            { crabc_core::process::exit_immediately(13); }
            let _ = crabc_core::io::write(2, b"child-repair: inherited client free complete\n");
        }
        let _ = crabc_core::io::write(2, b"child-repair: survivor allocation begin\n");
        let block = match native_allocate_aligned(64, 16, false) {
            NativePageAllocationResult::Allocated(block) => block,
            _ => crabc_core::process::exit_immediately(14),
        };
        let _ = crabc_core::io::write(2, b"child-repair: survivor allocation complete\n");
        if unsafe { native_free(block) } != NativePageFreeResult::Freed {
            crabc_core::process::exit_immediately(15);
        }
        let _ = crabc_core::io::write(2, b"child-repair: survivor free complete\n");
        if !drive_repaired_child_callback_to_source_mini() {
            crabc_core::process::exit_immediately(26);
        }
        if CHILD_CALLBACK_CALLS.load(Ordering::Relaxed) == 0 {
            // Distinguish an unselected source cadence from a callback that
            // did enter but violated its phase-B boundary or reentry contract.
            crabc_core::process::exit_immediately(24);
        }
        if CHILD_CALLBACK_FAILED.load(Ordering::Relaxed) {
            crabc_core::process::exit_immediately(27);
        }
        // std's pinned-musl thread is only the fixture carrier. Each new
        // allocator owner still registers/attaches/finishes through real APIs.
        let published = registry.new_worker;
        let _ = crabc_core::io::write(2, b"child-repair: new worker begin\n");
        let new_worker_ok = std::thread::scope(|scope| {
            scope.spawn(|| {
                let descriptor = current_native_allocator_thread_descriptor();
                published.store(descriptor.as_ptr(), Ordering::Release);
                if !unsafe { register_current_native_allocator_worker_descriptor(descriptor) }
                    || attach_current_thread() != ThreadAttachResult::Attached { return false; }
                let block = allocate(48);
                (unsafe { native_free(block) }) == NativePageFreeResult::Freed
                    && finish_current_thread_native_after_user_destructors() == ThreadFinishResult::Finished
            }).join().unwrap_or(false)
        });
        published.store(core::ptr::null_mut(), Ordering::Release);
        let _ = crabc_core::io::write(2, b"child-repair: new worker complete\n");
        if !new_worker_ok { crabc_core::process::exit_immediately(16); }
        let counts = crate::subproc::MainSubprocess::global().statistics().source_snapshot();
        if (counts.threads_total, counts.threads_peak, counts.threads_current) != (3, 2, 1) {
            crabc_core::process::exit_immediately(19);
        }
        let _ = crabc_core::io::write(2, b"child-repair: process done begin\n");
        if finish_selected_default_release_process_after_user_atexit() != SelectedProcessDoneResult::Completed {
            crabc_core::process::exit_immediately(17);
        }
        crabc_core::process::exit_immediately(0);
    }
    let _ = crabc_core::io::write(2, b"child-repair: parent resume\n");
    unsafe { interval.resume_parent() }.unwrap();
    unsafe { register_native_deferred_free_callback(None, core::ptr::null_mut()); }
    unsafe { crabc_core::signal::rt_sigprocmask_raw(2, &old, core::ptr::null_mut()) }.unwrap();
    let mut status = 0;
    assert_eq!(unsafe { crabc_core::process::wait4_raw(child, &mut status, 0) }, Ok(child));
    assert_eq!(status, 0, "repaired child frees inherited clients, allocates, starts a worker and completes process done");
}

fn fixture(worker_origin: bool) {
    // Keep the native initial TLS mapping alive until process exit. The test
    // harness parent never initializes this process-global allocator instance.
    let outer = crabc_core::process::fork_raw().expect("isolated native fixture");
    if outer == 0 {
        let _ = std::panic::catch_unwind(|| {
        assert!(initialize_process(4096, unsafe { RuntimeStderrOutput::new(no_output) }));
        assert!(prepare_native_later_thread_arena());
        let initial = allocate(80);
        unsafe { initial.as_ptr().write_bytes(0x35, 80); }
        let initial_address = initial.as_ptr() as usize;
        let initial_descriptor = native_allocator_initial_thread_descriptor().unwrap().as_ptr() as usize;
        let descriptor = AtomicPtr::new(core::ptr::null_mut());
        let new_descriptor = AtomicPtr::new(core::ptr::null_mut());
        let worker_address = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let _stop_on_failure = StopOnDrop(&stop);
            let worker = scope.spawn(|| {
                let _publish_failure = PublishFailure(&worker_address);
                let current = current_native_allocator_thread_descriptor();
                descriptor.store(current.as_ptr(), Ordering::Release);
                assert!(unsafe { register_current_native_allocator_worker_descriptor(current) });
                assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                let client = allocate(96);
                unsafe { client.as_ptr().write_bytes(0x63, 96); }
                worker_address.store(client.as_ptr() as usize, Ordering::Release);
                if worker_origin {
                    let registry = Registry { initial: NonNull::new(initial_descriptor as *mut NativeAllocatorThreadDescriptor).unwrap(), worker: &descriptor, new_worker: &new_descriptor };
                    copy_and_repair(&registry, initial_address, client.as_ptr() as usize);
                } else {
                    while !stop.load(Ordering::Acquire) { std::thread::yield_now(); }
                }
                assert!(unsafe { core::slice::from_raw_parts(client.as_ptr(), 96) }.iter().all(|byte| *byte == 0x63));
                assert_eq!(unsafe { native_free(client) }, NativePageFreeResult::Freed);
                assert_eq!(finish_current_thread_native_after_user_destructors(), ThreadFinishResult::Finished);
            });
            while worker_address.load(Ordering::Acquire) == 0 { std::thread::yield_now(); }
            assert_ne!(worker_address.load(Ordering::Acquire), usize::MAX, "worker source initialization completed");
            if !worker_origin {
                let registry = Registry { initial: native_allocator_initial_thread_descriptor().unwrap(), worker: &descriptor, new_worker: &new_descriptor };
                copy_and_repair(&registry, initial_address, worker_address.load(Ordering::Acquire));
                stop.store(true, Ordering::Release);
            }
            worker.join().unwrap();
        });
        assert!(unsafe { core::slice::from_raw_parts(initial.as_ptr(), 80) }.iter().all(|byte| *byte == 0x35));
        assert_eq!(unsafe { native_free(initial) }, NativePageFreeResult::Freed);
        let counts = crate::subproc::MainSubprocess::global().statistics().source_snapshot();
        assert_eq!((counts.threads_total, counts.threads_peak, counts.threads_current), (2, 2, 1),
            "child source retirement never changes the parent's thread statistics");
        crabc_core::process::exit_immediately(0);
        });
        crabc_core::process::exit_immediately(126);
    }
    let mut status = 0;
    assert_eq!(unsafe { crabc_core::process::wait4_raw(outer, &mut status, 0) }, Ok(outer));
    assert_eq!(status, 0, "isolated source-owner fixture completed");
}

#[test]
fn worker_origin_child_repairs_initial_owner_and_preserves_live_clients() { fixture(true); }

#[test]
fn initial_origin_child_repairs_worker_owner_and_preserves_live_clients() { fixture(false); }
