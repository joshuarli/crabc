// SPDX-License-Identifier: MIT
//! Native explicit process destruction: init.c:605,626-647 and subproc.c:202-255.
//! Default process-done remains the retaining path. This caller is selected
//! only by the signed source destroy option after full native admission closes.
//! External ownership tracking survives both successful bulk release and every
//! retained failure; the source main Heap deliberately does not free OS-only
//! client pages. No registry lock may span this module's physical successor.

use super::*;
use crate::arena::DestroyedArenas;
use crate::process_init::ProcessMainReadyLease;
use crate::types::heap_destroy::{MainHeapDestroyError, MainHeapDestroyTracking};

/// Source explicit `mi_process_done` and automatic `_mi_auto_process_done`
/// differ for signed destroy_on_exit values >= 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessDoneInvocation { Automatic, Explicit }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessDoneAction { SkipAutomatic, RetainBacking, DestroyBacking }

fn source_process_done_action(raw: i64, invocation: NativeProcessDoneInvocation) -> NativeProcessDoneAction {
    if invocation == NativeProcessDoneInvocation::Automatic && raw >= 2 {
        NativeProcessDoneAction::SkipAutomatic
    } else if raw == 0 {
        NativeProcessDoneAction::RetainBacking
    } else {
        NativeProcessDoneAction::DestroyBacking
    }
}

/// Reads the one process-owned signed option while its source entry is live.
/// Call before acquiring the registry pin; automatic >=2 runs no process-done
/// transition at all. Negative nonzero values retain the source enabled test.
pub fn native_process_done_action(invocation: NativeProcessDoneInvocation)
    -> Result<NativeProcessDoneAction, NativeProcessDestroyError> {
    let _operation = admission::NativeAllocatorOperationGuard::enter()
        .map_err(|_| NativeProcessDestroyError::Inactive)?;
    let process = RUNTIME_PROCESS.active_vm_process().ok_or(NativeProcessDestroyError::Inactive)?;
    Ok(source_process_done_action(process.policy().destroy_on_exit_raw(), invocation))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessDestroyError {
    Inactive,
    DefaultRetains,
    AlreadyCompleted,
    UnsupportedOwner,
    Admission(admission::NativeAllocatorQuiescenceError),
    SourceOwner,
    TrackingStorage,
    Subprocess,
    Heap,
    Metadata,
    Coordinator,
    Arena,
    PageMap,
}

/// Source-level failures remain stored beside their surviving owners. Public
/// dispatch reports the stage without exporting a capability to retired memory.
enum RetainedDestroyFailure {
    Storage(crabc_core::Errno),
    Subprocess(ProcessMainInitError),
    Heap(MainHeapDestroyError),
    Metadata(crate::meta::MetaCloseError),
    Coordinator(ProcessMainInitError),
    Arena(crate::arena::ArenaDestroyError),
    PageMap(crate::process_page_map::ProcessPageMapTerminalDestroyError),
}

struct ProcessDestroyOwners {
    // This anonymous mapping is external to all subprocess arenas and metadata.
    tracking_mapping: Option<Mapping>,
    tracking: *mut MainHeapDestroyTracking,
    tracking_len: usize,
    arenas: Option<DestroyedArenas<'static>>,
    failure: Option<RetainedDestroyFailure>,
}

struct ProcessDestroyStorage(UnsafeCell<ProcessDestroyOwners>);
// SAFETY: the unique permanent epoch capability is the only mutable accessor;
// no source/diagnostic API exposes these terminal retained capabilities.
unsafe impl Sync for ProcessDestroyStorage {}
static DESTROY_OWNERS: ProcessDestroyStorage = ProcessDestroyStorage(UnsafeCell::new(ProcessDestroyOwners {
    tracking_mapping: None, tracking: core::ptr::null_mut(), tracking_len: 0,
    arenas: None, failure: None,
}));

/// All TLS engines have relinquished source authority. This value borrows no
/// libc registry; return it out of the pinned visitor before physical work.
#[must_use = "physical destruction or exact retained failure must follow source transfer"]
pub struct NativePreparedProcessDestroy {
    ready: ProcessMainReadyLease,
    heap: MainStaticHeapLease<'static>,
    _owners: admission::NativeAllocatorTransferredProcessOwners,
}

/// Immutable process witnesses captured under ordinary entry before libc
/// acquires the registry pin. This grants no terminal source authority.
#[must_use = "capture outside the registry, then consume inside the pinned transfer"]
pub struct NativeProcessDestroyRequest {
    ready: ProcessMainReadyLease,
    heap: MainStaticHeapLease<'static>,
}

/// Captures the exact live process/Heap binding before registry pinning. It
/// allocates nothing and claims no process-done once state. Dropping a request
/// changes no source state; only its later transfer may close admission.
pub fn capture_native_process_destroy_request()
    -> Result<NativeProcessDestroyRequest, NativeProcessDestroyError> {
    let operation = admission::NativeAllocatorOperationGuard::enter()
        .map_err(|_| NativeProcessDestroyError::Inactive)?;
    if RUNTIME_PROCESS.logical_process_done_is_complete() {
        return Err(NativeProcessDestroyError::AlreadyCompleted);
    }
    if !RUNTIME_PROCESS.is_active()
        || RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) != PAGE_OWNER_INITIAL_PERSISTENT
        || RUNTIME_PROCESS.has_active_post_exit_route()
        || RUNTIME_PROCESS.has_pending_post_exit_completion()
        || RUNTIME_PROCESS.has_retained_post_exit_route()
    { return Err(NativeProcessDestroyError::UnsupportedOwner); }
    let owner = unsafe { RUNTIME_PROCESS.active_owner() }.ok_or(NativeProcessDestroyError::Inactive)?;
    let ready = owner.ready().map_err(|_| NativeProcessDestroyError::Inactive)?;
    if ready.vm_process().map_err(|_| NativeProcessDestroyError::Inactive)?.policy().destroy_on_exit_raw() == 0 {
        return Err(NativeProcessDestroyError::DefaultRetains);
    }
    let heap = unsafe { RUNTIME_PROCESS.active_main_heap() }.ok_or(NativeProcessDestroyError::Inactive)?;
    drop(operation);
    Ok(NativeProcessDestroyRequest { ready, heap })
}

/// Transfers every native TLS owner under the existing pinned registry.
///
/// # Safety
/// All native source entries, diagnostics, deferred callbacks and raw process
/// copies participate in the shared admission protocol. The registry pins all
/// descriptors until this function returns. No lower-level source reference
/// survives outside that protocol. The caller has completed user atexit and
/// holds no source borrow. Physical completion must occur only after releasing
/// the registry and every outer libc lock. Failures after epoch commit retain
/// source owners permanently and never reopen native allocation.
pub unsafe fn prepare_native_process_destroy(
    request: NativeProcessDestroyRequest,
    registry: &dyn admission::NativeAllocatorPinnedThreadRegistry,
) -> Result<NativePreparedProcessDestroy, NativeProcessDestroyError> {
    // This atomic once claim precedes epoch closure: a previously completed
    // retaining process_done must not accidentally become a permanent seal.
    RUNTIME_PROCESS.logical_process_done.compare_exchange(PROCESS_DONE_OPEN, PROCESS_DONE_TRANSITION,
        Ordering::AcqRel, Ordering::Acquire).map_err(|_| NativeProcessDestroyError::AlreadyCompleted)?;
    let quiescence = match unsafe { admission::begin_native_allocator_terminal_quiescence(registry) } {
        Ok(quiescence) => quiescence,
        Err(error) => {
            // A pre-commit refusal reopens a fresh epoch. Only this claimant
            // may roll back its not-yet-started process_done transition. An
            // irreversible seal or retained writer never permits retry.
            if !admission::native_source_entry_is_terminal() {
                let _ = RUNTIME_PROCESS.logical_process_done.compare_exchange(
                    PROCESS_DONE_TRANSITION, PROCESS_DONE_OPEN, Ordering::AcqRel, Ordering::Acquire);
            }
            return Err(NativeProcessDestroyError::Admission(error));
        }
    };
    let owners = quiescence.transfer_source_owners().map_err(|_| NativeProcessDestroyError::SourceOwner)?;
    let NativeProcessDestroyRequest { ready, heap } = request;
    // Source init.c:605 clears the current cache before subprocess destruction.
    // The TLS transfer sealed source ownership but did not release this local
    // cache slot or any Theap storage, so its final empty publication is valid.
    set_cached_theap(NonNull::from(empty_default_theap()));
    Ok(NativePreparedProcessDestroy { ready, heap, _owners: owners })
}

impl NativePreparedProcessDestroy {
    /// Executes the physical source successor outside the libc registry pin.
    ///
    /// # Safety
    /// The preparer's permanent exclusion still holds, with no outstanding
    /// source references or outer libc locks. This must be called after the
    /// scoped registry callback has returned. Its tracking mapping and every
    /// failed owner remain in process-static storage and are never projected
    /// as live allocation capabilities after metadata close.
    pub unsafe fn finish(self) -> Result<(), NativeProcessDestroyError> {
        let owners = unsafe { &mut *DESTROY_OWNERS.0.get() };
        let process = self.ready.vm_process().map_err(|_| NativeProcessDestroyError::Coordinator)?;
        let config = self.ready.memory_config().map_err(|_| NativeProcessDestroyError::Coordinator)?;
        let tracking_len = {
            let mut guard = self.heap.lock_heap().map_err(|_| NativeProcessDestroyError::Heap)?;
            unsafe { guard.heap_mut().terminal_tracking_len() }.map_err(|error| {
                owners.failure = Some(RetainedDestroyFailure::Heap(error)); NativeProcessDestroyError::Heap
            })?
        };
        let words = unsafe { process.subprocess().arena_backing().terminal_tracking_words() }
            .map_err(|error| { owners.failure = Some(RetainedDestroyFailure::Arena(error)); NativeProcessDestroyError::Arena })?;
        let entries_bytes = tracking_len.checked_mul(core::mem::size_of::<MainHeapDestroyTracking>())
            .ok_or(NativeProcessDestroyError::TrackingStorage)?;
        let words_offset = entries_bytes.checked_add(core::mem::align_of::<usize>() - 1)
            .map(|value| value & !(core::mem::align_of::<usize>() - 1))
            .ok_or(NativeProcessDestroyError::TrackingStorage)?;
        let bytes = words.checked_mul(core::mem::size_of::<usize>()).and_then(|value| value.checked_add(words_offset))
            .ok_or(NativeProcessDestroyError::TrackingStorage)?;
        let page = config.page_size().bytes();
        let length = bytes.max(1).checked_add(page - 1).map(|value| value & !(page - 1))
            .ok_or(NativeProcessDestroyError::TrackingStorage)?;
        // Existing Mapping::map_anonymous -> map_regular validates length,
        // then calls crabc_core::mm::mmap_raw directly. It neither enters the
        // native allocator nor invokes diagnostics/stdio. This is per-Theap
        // teardown ownership storage, never a per-client allocation registry.
        // On failure the transferred capabilities remain in the source graph
        // and every arena remains mapped under permanent Terminal exclusion.
        let mapping = Mapping::map_anonymous(StartupInput::new(config.page_size()), length, MapAccess::Committed)
            .map_err(|error| { owners.failure = Some(RetainedDestroyFailure::Storage(error)); NativeProcessDestroyError::TrackingStorage })?;
        // Publish the mapping owner before any typed capability is stored in it.
        owners.tracking_mapping = Some(mapping);
        let base = owners.tracking_mapping.as_ref().unwrap().base().map_err(|error| {
            owners.failure = Some(RetainedDestroyFailure::Storage(error)); NativeProcessDestroyError::TrackingStorage
        })?;
        owners.tracking = base.cast();
        owners.tracking_len = tracking_len;
        for index in 0..tracking_len {
            unsafe { owners.tracking.add(index).write(MainHeapDestroyTracking::empty()); }
        }
        let tracking = unsafe { core::slice::from_raw_parts_mut(owners.tracking, tracking_len) };
        let huge_tracking: &'static mut [usize] = unsafe {
            core::slice::from_raw_parts_mut(base.add(words_offset).cast(), words)
        };
        unsafe { self.ready.unlink_terminal_subprocess() }.map_err(|error| {
            owners.failure = Some(RetainedDestroyFailure::Subprocess(error)); NativeProcessDestroyError::Subprocess
        })?;
        unsafe { self.heap.force_destroy_source_owned_main_heap(crate::meta::MetaAllocator::global(), tracking) }
            .map_err(|error| { owners.failure = Some(RetainedDestroyFailure::Heap(error)); NativeProcessDestroyError::Heap })?;
        unsafe { crate::meta::MetaAllocator::global().close_process_engine_quiescent() }
            .map_err(|error| { owners.failure = Some(RetainedDestroyFailure::Metadata(error)); NativeProcessDestroyError::Metadata })?;
        unsafe { process.subprocess().clear_metadata_identity_terminal(); }
        // Metadata releases above still need the canonical ready binding.
        // Revoke it after that engine ends and before any backing is unmapped.
        let terminal = unsafe { self.ready.seal_terminal() }.map_err(|error| {
            owners.failure = Some(RetainedDestroyFailure::Coordinator(error)); NativeProcessDestroyError::Coordinator
        })?;
        let arenas = unsafe { process.subprocess().arena_backing().destroy_all(huge_tracking) }
            .map_err(|error| { owners.failure = Some(RetainedDestroyFailure::Arena(error)); NativeProcessDestroyError::Arena })?;
        let all_arenas_released = arenas.is_released();
        owners.arenas = Some(arenas);
        unsafe { terminal.page_map_storage.destroy_terminal_quiescent() }.map_err(|error| {
            owners.failure = Some(RetainedDestroyFailure::PageMap(error)); NativeProcessDestroyError::PageMap
        })?;
        process.policy().enter_process_done_preloading();
        RUNTIME_PROCESS.logical_process_done.store(PROCESS_DONE_COMPLETE, Ordering::Release);
        if all_arenas_released { Ok(()) } else { Err(NativeProcessDestroyError::Arena) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    struct PinnedFixtureRegistry<'a> {
        initial: NonNull<admission::NativeAllocatorThreadDescriptor>,
        worker: &'a core::sync::atomic::AtomicPtr<admission::NativeAllocatorThreadDescriptor>,
    }
    // SAFETY: exactly one initial and one registered worker participate. The
    // scoped worker cannot exit until physical completion releases its stop
    // flag. Descriptor publication precedes source entry and the main thread
    // waits for its ready flag; there is no concurrent registration/removal.
    unsafe impl admission::NativeAllocatorPinnedThreadRegistry for PinnedFixtureRegistry<'_> {
        fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<admission::NativeAllocatorThreadDescriptor>)) {
            visitor(self.initial);
            if let Some(worker) = NonNull::new(self.worker.load(Ordering::Acquire)) { visitor(worker); }
        }
    }

    unsafe extern "C" {
        fn fputs(message: *const core::ffi::c_char, stream: *mut core::ffi::c_void) -> core::ffi::c_int;
        static mut stderr: *mut core::ffi::c_void;
    }
    unsafe extern "C" fn fixture_stderr(message: *const core::ffi::c_char) {
        unsafe { admission::with_native_allocator_diagnostic_callback(|| { let _ = fputs(message, stderr); }) }
            .expect("native source diagnostics retain ordinary admission");
    }

    struct ReleaseFlag<'a>(&'a core::sync::atomic::AtomicBool);
    impl Drop for ReleaseFlag<'_> {
        fn drop(&mut self) { self.0.store(true, Ordering::Release); }
    }

    fn physical_destroy_fixture(os_only: bool, fail_tracking_map: bool) {
        // These filters run in separate native test processes: the process
        // owner and Terminal state intentionally cannot be reinitialized.
        unsafe {
            std::env::set_var("mimalloc_destroy_on_exit", "1");
            std::env::set_var("mimalloc_arena_reserve", "65536");
            std::env::set_var("mimalloc_disallow_arena_alloc", if os_only { "1" } else { "0" });
        }
        std::thread::spawn(move || {
            assert!(initialize_process(4096, unsafe { RuntimeStderrOutput::new(fixture_stderr) }));
            assert!(prepare_native_later_thread_arena());
            assert_eq!(native_process_done_action(NativeProcessDoneInvocation::Automatic),
                Ok(NativeProcessDoneAction::DestroyBacking));
            let NativePageAllocationResult::Allocated(initial_client) = native_allocate_aligned(80, 16, false)
                else { panic!("initial live client"); };
            unsafe { initial_client.as_ptr().write_bytes(0x35, 80); }
            let descriptor = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
            let ready = core::sync::atomic::AtomicBool::new(false);
            let stop = core::sync::atomic::AtomicBool::new(false);
            std::thread::scope(|scope| {
                // A failing main assertion must still release the parked
                // worker before std's scoped-thread join runs during unwind.
                let _release_worker = ReleaseFlag(&stop);
                let worker = scope.spawn(|| {
                    let _publish_failure = ReleaseFlag(&ready);
                    let current = admission::current_native_allocator_thread_descriptor();
                    descriptor.store(current.as_ptr(), Ordering::Release);
                    assert!(unsafe { admission::register_current_native_allocator_worker_descriptor(current) });
                    assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                    let NativePageAllocationResult::Allocated(client) = native_allocate_aligned(96, 16, false)
                        else { panic!("worker live client"); };
                    unsafe { client.as_ptr().write_bytes(0x63, 96); }
                    ready.store(true, Ordering::Release);
                    while !stop.load(Ordering::Acquire) { std::thread::yield_now(); }
                    // The foreign thread still runs after physical release.
                    // Its ordinary API must deny access before touching the
                    // transferred TLS cells or old cached source pointers.
                    assert!(matches!(native_allocate_aligned(32, 16, false), NativePageAllocationResult::Unavailable));
                });
                while !ready.load(Ordering::Acquire) { std::thread::yield_now(); }
                assert!(unsafe { core::slice::from_raw_parts(initial_client.as_ptr(), 80) }.iter().all(|byte| *byte == 0x35));
                let request = capture_native_process_destroy_request().expect("source capture precedes registry pin");
                let registry = PinnedFixtureRegistry { initial: admission::native_allocator_initial_thread_descriptor().unwrap(), worker: &descriptor };
                let thread_count_before = crate::subproc::MainSubprocess::global().live_thread_count();
                let mut before_resident = 0u8;
                let before_mapped = unsafe { crabc_core::mm::mincore_raw(
                    (initial_client.as_ptr().addr() & !4095) as *mut u8, 4096, &mut before_resident) }.is_ok();
                let prepared = unsafe { prepare_native_process_destroy(request, &registry) }
                    .expect("all source owners transfer while both TLS mappings are pinned");
                // This fixture's registry pin is the worker stop condition;
                // no registry/source lock spans the physical successor.
                let fault = if fail_tracking_map {
                    Some(crate::os::fault::install(crate::os::fault::Plan::at(
                        crate::os::fault::Point::Map, 1, crabc_core::Errno::NOMEM)))
                } else { None };
                let result = unsafe { prepared.finish() };
                drop(fault);
                if fail_tracking_map {
                    assert_eq!(result, Err(NativeProcessDestroyError::TrackingStorage));
                    assert!(!process_is_active());
                    assert!(!RUNTIME_PROCESS.logical_process_done_is_complete());
                    let owners = unsafe { &*DESTROY_OWNERS.0.get() };
                    assert!(owners.tracking_mapping.is_none());
                    assert!(owners.arenas.is_none());
                    assert!(matches!(owners.failure, Some(RetainedDestroyFailure::Storage(crabc_core::Errno::NOMEM))));
                    let mut resident = 0u8;
                    assert!(unsafe { crabc_core::mm::mincore_raw(
                        (initial_client.as_ptr().addr() & !4095) as *mut u8, 4096, &mut resident) }.is_ok());
                    // No Heap mutation occurred: the exact transferred Malloc
                    // Theap/TLD images remain linked and recoverable by their
                    // source ownership contract, not a dropped TLS wrapper.
                    let heap = unsafe { RUNTIME_PROCESS.active_main_heap() }.unwrap();
                    let mut guard = heap.lock_heap().unwrap();
                    let (dynamic, attached, total) = guard.heap_mut().test_destroy_graph_counts();
                    guard.unlock().unwrap();
                    assert_eq!((dynamic, attached, total), (1, 1, 3));
                    stop.store(true, Ordering::Release);
                    worker.join().expect("failure retains source backing but denies new worker entry");
                    return;
                }
                result.expect("source ordered physical retirement");
                assert!(!process_is_active());
                assert!(RUNTIME_PROCESS.logical_process_done_is_complete());
                assert!(matches!(native_allocate_aligned(32, 16, false), NativePageAllocationResult::Unavailable));
                let owners = unsafe { &*DESTROY_OWNERS.0.get() };
                assert!(owners.tracking_mapping.is_some());
                assert!(owners.arenas.as_ref().unwrap().is_released());
                assert!(owners.failure.is_none());
                let mut resident = 0u8;
                let page_address = initial_client.as_ptr().addr() & !4095;
                let mapping_observation = unsafe {
                    crabc_core::mm::mincore_raw(page_address as *mut u8, 4096, &mut resident)
                };
                if os_only {
                    assert!(mapping_observation.is_ok(), "source main Heap retains direct OS pages");
                } else {
                    assert!(mapping_observation.is_err(), "released arena no longer owns the client mapping");
                }
                assert!(unsafe { core::slice::from_raw_parts(owners.tracking, owners.tracking_len) }
                    .iter().any(MainHeapDestroyTracking::retains_tld));
                let subprocess = crate::subproc::MainSubprocess::global();
                let values = [thread_count_before, usize::from(before_mapped), usize::from(mapping_observation.is_ok()),
                    subprocess.arena_backing().registry().count(),
                    usize::from(!subprocess.test_has_published_metadata_theap()),
                    subprocess.heap_list().test_counts().0,
                    usize::from(!crate::process_page_map::ProcessPageMapStorage::global().test_has_published_root())];
                for (index, value) in values.into_iter().enumerate() {
                    std::println!("m2.process.destroy.{index}={value}");
                }
                stop.store(true, Ordering::Release);
                worker.join().expect("transferred worker returns without source access");
            });
        }).join().expect("the isolated initial owner completes physical destruction");
    }

    #[test]
    fn physical_destroy_transfers_live_worker_before_arena_and_page_map_release() {
        physical_destroy_fixture(false, false);
    }

    #[test]
    fn physical_destroy_os_only_retains_source_pages_but_seals_all_native_access() {
        physical_destroy_fixture(true, false);
    }

    #[test]
    fn physical_destroy_tracking_oom_retains_transferred_graph_and_permanent_seal() {
        physical_destroy_fixture(false, true);
    }

    #[test]
    fn source_destroy_option_keeps_signed_explicit_and_automatic_dispatch_distinct() {
        for raw in [-7, -1, 0, 1, 2, 9, i64::MAX] {
            let explicit = if raw == 0 { NativeProcessDoneAction::RetainBacking }
                else { NativeProcessDoneAction::DestroyBacking };
            let automatic = if raw >= 2 { NativeProcessDoneAction::SkipAutomatic } else { explicit };
            assert_eq!(source_process_done_action(raw, NativeProcessDoneInvocation::Explicit), explicit);
            assert_eq!(source_process_done_action(raw, NativeProcessDoneInvocation::Automatic), automatic);
        }
    }
}
