// SPDX-License-Identifier: MIT
//! Native explicit process destruction: init.c:605,626-647 and subproc.c:202-255.
//! Default process-done remains the retaining path. This caller is selected
//! only by the signed source destroy option after full native admission closes.
//! External ownership tracking survives both successful bulk release and every
//! retained failure; the source main Heap deliberately does not free OS-only
//! client pages. No registry lock may span this module's physical successor.

use super::*;
use crate::arena::DestroyedArenas;
use crate::os::{MapAccess, Mapping};
use crate::process_init::ProcessMainReadyLease;
use crate::types::heap_destroy::{MainHeapDestroyError, MainHeapDestroyTracking};

/// Source explicit `mi_process_done` and automatic `_mi_auto_process_done`
/// differ for signed destroy_on_exit values >= 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessDoneInvocation { Automatic, Explicit }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcessDoneAction { AlreadyCompleted, SkipAutomatic, RetainBacking, DestroyBacking }

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
    // The once result remains observable after physical retirement without
    // reentering source or consulting its sealed VM binding.
    if RUNTIME_PROCESS.logical_process_done_is_complete() {
        return Ok(NativeProcessDoneAction::AlreadyCompleted);
    }
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
    ProcessDoneInProgress,
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
    Diagnostic,
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
    Diagnostic(admission::NativeAllocatorTerminalDiagnosticError),
    Output(crate::diagnostic_output::FinalDiagnosticOutputError),
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
///
/// `ready` and the finish-local VmProcess retain immutable identities in
/// process-static storage outside retiring arenas. Coordinator sealing revokes
/// their checked ready projections; it does not invalidate Rust references.
/// These stored identities may span final output, but no Heap/Theap/metadata
/// projection, PageMap view, mutable retained-owner borrow or lock does. The
/// shared Terminal epoch denies callback reentry before any native source
/// access; only the permanent policy's atomic preloading flag is used after
/// the final message. Diagnostic permission never restores ready access.
#[must_use = "physical destruction or exact retained failure must follow source transfer"]
pub struct NativePreparedProcessDestroy {
    ready: ProcessMainReadyLease,
    heap: MainStaticHeapLease<'static>,
    _owners: admission::NativeAllocatorTransferredProcessOwners,
    diagnostics: Option<ProcessFinalDiagnosticIdentity>,
}

/// Only process-static output identity and a source scalar cross coordinator
/// sealing. This value owns no Theap, Heap, PageMap or metadata projection and
/// cannot authorize a callback without the transferred writer's scope.
#[derive(Clone, Copy)]
struct ProcessFinalDiagnosticIdentity {
    output: &'static crate::diagnostic_output::OutputOwner,
    subprocess_sequence: usize,
}

/// Immutable process witnesses captured under ordinary entry before libc
/// acquires the registry pin. This grants no terminal source authority.
#[must_use = "capture outside the registry, then consume inside the pinned transfer"]
pub struct NativeProcessDestroyRequest {
    ready: ProcessMainReadyLease,
    heap: MainStaticHeapLease<'static>,
    diagnostics: Option<ProcessFinalDiagnosticIdentity>,
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
    let diagnostics = ready.diagnostic_output().map_err(|_| NativeProcessDestroyError::Coordinator)?
        .map(|output| ready.subprocess_sequence().map(|subprocess_sequence|
            ProcessFinalDiagnosticIdentity { output, subprocess_sequence }))
        .transpose().map_err(|_| NativeProcessDestroyError::Coordinator)?;
    drop(operation);
    Ok(NativeProcessDestroyRequest { ready, heap, diagnostics })
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
        Ordering::AcqRel, Ordering::Acquire).map_err(|state| {
            if state == PROCESS_DONE_COMPLETE { NativeProcessDestroyError::AlreadyCompleted }
            else { NativeProcessDestroyError::ProcessDoneInProgress }
        })?;
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
    let NativeProcessDestroyRequest { ready, heap, diagnostics } = request;
    // Source init.c:605 clears the current cache before subprocess destruction.
    // The TLS transfer sealed source ownership but did not release this local
    // cache slot or any Theap storage, so its final empty publication is valid.
    set_cached_theap(NonNull::from(empty_default_theap()));
    Ok(NativePreparedProcessDestroy { ready, heap, _owners: owners, diagnostics })
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
        // Source subproc.c:244 prints after arena destruction and before
        // PageMap retirement. End the mutable retained-owner projection before
        // an option warning or output adapter can enter foreign libc code.
        let _ = owners;
        if let Some(diagnostics) = self.diagnostics {
            let permit = unsafe { self._owners.with_final_diagnostic_output(|| {
                unsafe { diagnostics.output.final_statistics_enabled() }
            }) }
                .map_err(retain_diagnostic_failure)?
                .map_err(retain_output_failure)?;
            if let Some(permit) = permit {
                let elapsed = crate::statistics::process_elapsed_msecs();
                let statistics = process.subprocess().statistics().final_output_snapshot();
                let nodes = process.policy().numa_node_count();
                let info = match crate::os::process_usage() {
                    Ok(usage) => crate::diagnostic_output::FinalProcessInfo::from_source_observations(
                        elapsed, usage, nodes),
                    Err(_) => crate::diagnostic_output::FinalProcessInfo::from_source_committed_defaults(
                        elapsed, statistics.process_info_committed_defaults(), nodes),
                };
                let view = crate::diagnostic_output::FinalProcessDiagnosticView::new(
                    diagnostics.subprocess_sequence, statistics, info);
                // Only scalar copies, the permanent output identity and the
                // exact writer authority enter this callback scope.
                unsafe { self._owners.with_final_diagnostic_output(|| unsafe { permit.emit(view) }) }
                    .map_err(retain_diagnostic_failure)?;
            }
        }
        unsafe { terminal.page_map_storage.destroy_terminal_quiescent() }.map_err(|error| {
            let owners = unsafe { &mut *DESTROY_OWNERS.0.get() };
            owners.failure = Some(RetainedDestroyFailure::PageMap(error)); NativeProcessDestroyError::PageMap
        })?;
        // Source init.c:646 is a separate phase after subprocess/PageMap work.
        // Preloading remains false until its final diagnostic has returned.
        if let Some(diagnostics) = self.diagnostics {
            let _emitted = unsafe { self._owners.with_final_diagnostic_output(|| unsafe {
                diagnostics.output.final_process_done_message(core::mem::size_of::<crate::types::Page>())
            }) }
                .map_err(retain_diagnostic_failure)?
                .map_err(retain_output_failure)?;
        }
        process.policy().enter_process_done_preloading();
        RUNTIME_PROCESS.logical_process_done.store(PROCESS_DONE_COMPLETE, Ordering::Release);
        if all_arenas_released { Ok(()) } else { Err(NativeProcessDestroyError::Arena) }
    }
}

fn retain_diagnostic_failure(error: admission::NativeAllocatorTerminalDiagnosticError)
    -> NativeProcessDestroyError {
    // The already committed terminal writer is the sole observer/mutator of
    // this process-static retained owner. No callback is active on this path.
    unsafe { (*DESTROY_OWNERS.0.get()).failure = Some(RetainedDestroyFailure::Diagnostic(error)); }
    NativeProcessDestroyError::Diagnostic
}

fn retain_output_failure(error: crate::diagnostic_output::FinalDiagnosticOutputError)
    -> NativeProcessDestroyError {
    // Source-disabled output is `Ok(None)`/`Ok(false)`. This path instead
    // records an unavailable source descriptor owner or private-lock failure
    // after Terminal transfer, so physical teardown remains permanently
    // retained instead of completing an output-incomplete source transition.
    unsafe { (*DESTROY_OWNERS.0.get()).failure = Some(RetainedDestroyFailure::Output(error)); }
    NativeProcessDestroyError::Diagnostic
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

    #[derive(Clone, Copy)]
    enum FinalOutputFixtureMode {
        Disabled,
        SignedShowStats,
        SignedVerbose,
    }

    impl FinalOutputFixtureMode {
        const fn show_stats(self) -> &'static str {
            match self {
                Self::Disabled | Self::SignedVerbose => "0",
                Self::SignedShowStats => "-7",
            }
        }

        const fn verbose(self) -> &'static str {
            match self {
                Self::Disabled => "0",
                Self::SignedShowStats => "-1",
                Self::SignedVerbose => "-3",
            }
        }

        const fn emits_final_output(self) -> bool {
            !matches!(self, Self::Disabled)
        }
    }

    /// Test-only observation owned outside the sealed PageMap. The C callback
    /// sees only raw address/atomic state: it cannot borrow a ready owner,
    /// source Heap/TLS image, PageMap view, or process lock after Terminal.
    struct FinalOutputObservation {
        page_map_root: core::sync::atomic::AtomicUsize,
        statistics_headers: core::sync::atomic::AtomicUsize,
        process_done_tails: core::sync::atomic::AtomicUsize,
        statistics_root_mapped: core::sync::atomic::AtomicBool,
        process_done_root_unmapped: core::sync::atomic::AtomicBool,
        statistics_native_allocation_denied: core::sync::atomic::AtomicBool,
        process_done_native_allocation_denied: core::sync::atomic::AtomicBool,
    }

    impl FinalOutputObservation {
        const fn new() -> Self {
            Self {
                page_map_root: core::sync::atomic::AtomicUsize::new(0),
                statistics_headers: core::sync::atomic::AtomicUsize::new(0),
                process_done_tails: core::sync::atomic::AtomicUsize::new(0),
                statistics_root_mapped: core::sync::atomic::AtomicBool::new(false),
                process_done_root_unmapped: core::sync::atomic::AtomicBool::new(false),
                statistics_native_allocation_denied: core::sync::atomic::AtomicBool::new(false),
                process_done_native_allocation_denied: core::sync::atomic::AtomicBool::new(false),
            }
        }

        fn page_map_root_is_mapped(&self) -> bool {
            let root = self.page_map_root.load(Ordering::Acquire);
            if root == 0 {
                return false;
            }
            let mut resident = 0_u8;
            // SAFETY: `root` was captured from the live source ready lease
            // before Terminal sealing. This raw observation touches one
            // aligned page only; it neither projects nor reopens PageMap.
            unsafe {
                crabc_core::mm::mincore_raw(
                    (root & !4095) as *mut u8,
                    4096,
                    &mut resident,
                )
            }
            .is_ok()
        }

        unsafe fn observe_source_message(&self, message: *const core::ffi::c_char) {
            // SAFETY: OutputOwner supplies a non-null, NUL-terminated source
            // fragment and calls synchronously while this fixture registration
            // retains the observation in process-external test storage.
            let message = unsafe { core::ffi::CStr::from_ptr(message) }.to_bytes();
            if message.starts_with(b"subproc ") {
                self.statistics_headers.fetch_add(1, Ordering::AcqRel);
                self.statistics_root_mapped
                    .store(self.page_map_root_is_mapped(), Ordering::Release);
                self.statistics_native_allocation_denied.store(
                    matches!(native_allocate_aligned(32, 16, false), NativePageAllocationResult::Unavailable),
                    Ordering::Release,
                );
            } else if message.starts_with(b"mimalloc: process done ") {
                self.process_done_tails.fetch_add(1, Ordering::AcqRel);
                self.process_done_root_unmapped
                    .store(!self.page_map_root_is_mapped(), Ordering::Release);
                self.process_done_native_allocation_denied.store(
                    matches!(native_allocate_aligned(32, 16, false), NativePageAllocationResult::Unavailable),
                    Ordering::Release,
                );
            }
        }

        fn assert_source_order(self: &Self, mode: FinalOutputFixtureMode) {
            let headers = self.statistics_headers.load(Ordering::Acquire);
            let tails = self.process_done_tails.load(Ordering::Acquire);
            if mode.emits_final_output() {
                assert_eq!(headers, 1, "source final statistics emits one header");
                assert_eq!(tails, 1, "source final verbose emits one common tail");
                assert!(self.statistics_root_mapped.load(Ordering::Acquire));
                assert!(self.process_done_root_unmapped.load(Ordering::Acquire));
                assert!(self.statistics_native_allocation_denied.load(Ordering::Acquire));
                assert!(self.process_done_native_allocation_denied.load(Ordering::Acquire));
            } else {
                assert_eq!(headers, 0, "disabled source statistics must not emit a header");
                assert_eq!(tails, 0, "disabled source verbose must not emit a common tail");
            }
        }
    }

    static FINAL_OUTPUT_OBSERVATION: core::sync::atomic::AtomicPtr<FinalOutputObservation> =
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

    /// Synchronously exposes exactly one live test sink to `fixture_stderr`.
    /// Tests run this physical owner in fresh processes, so concurrent output
    /// registrations would be a fixture bug rather than a supported mode.
    struct FinalOutputObservationRegistration;

    impl FinalOutputObservationRegistration {
        fn install(observation: &FinalOutputObservation) -> Self {
            assert!(FINAL_OUTPUT_OBSERVATION.compare_exchange(
                core::ptr::null_mut(),
                core::ptr::from_ref(observation).cast_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok());
            Self
        }
    }

    impl Drop for FinalOutputObservationRegistration {
        fn drop(&mut self) {
            FINAL_OUTPUT_OBSERVATION.store(core::ptr::null_mut(), Ordering::Release);
        }
    }

    unsafe extern "C" fn fixture_stderr(message: *const core::ffi::c_char) {
        unsafe {
            admission::with_native_allocator_diagnostic_callback(|| {
                let observation = FINAL_OUTPUT_OBSERVATION.load(Ordering::Acquire);
                if let Some(observation) = unsafe { observation.as_ref() } {
                    // SAFETY: the registration keeps this exact stack value
                    // live through the synchronous source callback.
                    unsafe { observation.observe_source_message(message) };
                }
                let _ = fputs(message, stderr);
            })
        }
        .expect("native source diagnostics retain ordinary admission");
    }

    struct ReleaseFlag<'a>(&'a core::sync::atomic::AtomicBool);
    impl Drop for ReleaseFlag<'_> {
        fn drop(&mut self) { self.0.store(true, Ordering::Release); }
    }

    fn physical_destroy_fixture(
        os_only: bool,
        fail_tracking_map: bool,
        final_output: FinalOutputFixtureMode,
    ) {
        // These filters run in separate native test processes: the process
        // owner, Terminal state, and the source environment are intentionally
        // not reinitialized. The three exact signed-output modes therefore
        // cannot leak descriptor state into one another.
        unsafe {
            std::env::set_var("mimalloc_destroy_on_exit", "1");
            std::env::set_var("mimalloc_arena_reserve", "65536");
            std::env::set_var("mimalloc_disallow_arena_alloc", if os_only { "1" } else { "0" });
            std::env::set_var("mimalloc_show_stats", final_output.show_stats());
            std::env::set_var("mimalloc_verbose", final_output.verbose());
        }
        std::thread::spawn(move || {
            let observation = FinalOutputObservation::new();
            let _observation_registration = FinalOutputObservationRegistration::install(&observation);
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
                let root = request.ready.root().expect("request captures PageMap root before sealing");
                observation.page_map_root.store(root.as_ptr().addr(), Ordering::Release);
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
                observation.assert_source_order(final_output);
                assert!(!process_is_active());
                assert!(RUNTIME_PROCESS.logical_process_done_is_complete());
                assert_eq!(native_process_done_action(NativeProcessDoneInvocation::Automatic),
                    Ok(NativeProcessDoneAction::AlreadyCompleted));
                assert_eq!(native_process_done_action(NativeProcessDoneInvocation::Explicit),
                    Ok(NativeProcessDoneAction::AlreadyCompleted));
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
    fn physical_destroy_refuses_pending_owner_exit_without_a_live_callback_marker() {
        crate::test_process::run_in_fresh_process(
            "runtime_lifecycle::destroy::tests::physical_destroy_refuses_pending_owner_exit_without_a_live_callback_marker",
            || {
            // A rejected transfer must retain the live TLS mapping, not join or
            // drop its pending owner. This child has a fresh process owner;
            // it exits while the parked worker remains mapped.
            unsafe { std::env::set_var("mimalloc_destroy_on_exit", "1"); }
            assert!(initialize_process(4096, unsafe { RuntimeStderrOutput::new(fixture_stderr) }));
            assert!(prepare_native_later_thread_arena());
            let NativePageAllocationResult::Allocated(initial_client) = native_allocate_aligned(80, 16, false)
                else { panic!("initial pending-owner fixture client"); };
            let descriptor = std::boxed::Box::leak(std::boxed::Box::new(
                core::sync::atomic::AtomicPtr::new(core::ptr::null_mut())));
            let ready = std::boxed::Box::leak(std::boxed::Box::new(
                core::sync::atomic::AtomicBool::new(false)));
            let descriptor: &'static core::sync::atomic::AtomicPtr<admission::NativeAllocatorThreadDescriptor> = descriptor;
            let ready: &'static core::sync::atomic::AtomicBool = ready;
            let worker = std::thread::spawn(move || {
                let current = admission::current_native_allocator_thread_descriptor();
                descriptor.store(current.as_ptr(), Ordering::Release);
                assert!(unsafe { admission::register_current_native_allocator_worker_descriptor(current) });
                assert_eq!(attach_current_thread(), ThreadAttachResult::Attached);
                assert!(matches!(native_allocate_aligned(96, 16, false), NativePageAllocationResult::Allocated(_)));
                let operation = admission::NativeAllocatorOperationGuard::enter().unwrap();
                let phase = begin_current_thread_native_owner_exit_deferred_free_phase()
                    .expect("real source phase A retains its engine");
                let NativeOwnerExitDeferredFreePhase::Call(call) = phase;
                assert!(!call.invokes_user_callback(), "no callback registration in this isolated process");
                assert!(with_current_thread_native_persistent_owner(|owner|
                    matches!(owner.state, NativePersistentThreadOwnerExitState::DeferredFreePending(_)))
                    .unwrap());
                drop(operation);
                assert_eq!(admission::current_native_allocator_callback_boundary_state(), (false, false));
                // The value-only phase remains on this stack; there is no
                // phase C and no lifetime release before the process exits.
                let _pending_call = call;
                ready.store(true, Ordering::Release);
                loop { std::thread::yield_now(); }
            });
            while !ready.load(Ordering::Acquire) {
                if worker.is_finished() { panic!("worker failed before its pending publication"); }
                std::thread::yield_now();
            }
            let request = capture_native_process_destroy_request().unwrap();
            let registry = PinnedFixtureRegistry {
                initial: admission::native_allocator_initial_thread_descriptor().unwrap(), worker: descriptor,
            };
            assert!(matches!(unsafe { prepare_native_process_destroy(request, &registry) },
                Err(NativeProcessDestroyError::SourceOwner)));
            assert!(admission::native_source_entry_is_terminal());
            assert!(!RUNTIME_PROCESS.logical_process_done_is_complete());
            assert_eq!(crate::subproc::MainSubprocess::global().live_thread_count(), 2);
            assert!(unsafe { (&*DESTROY_OWNERS.0.get()).tracking_mapping.is_none() });
            let mut resident = 0u8;
            assert!(unsafe { crabc_core::mm::mincore_raw(
                (initial_client.as_ptr().addr() & !4095) as *mut u8, 4096, &mut resident) }.is_ok());
            assert!(matches!(native_allocate_aligned(32, 16, false), NativePageAllocationResult::Unavailable));
            crabc_core::process::exit_immediately(0);
            },
        );
    }

    #[test]
    fn physical_destroy_transfers_live_worker_before_arena_and_page_map_release() {
        crate::test_process::run_in_fresh_process(
            "runtime_lifecycle::destroy::tests::physical_destroy_transfers_live_worker_before_arena_and_page_map_release",
            || physical_destroy_fixture(false, false, FinalOutputFixtureMode::Disabled),
        );
    }

    #[test]
    fn physical_destroy_os_only_retains_source_pages_but_seals_all_native_access() {
        crate::test_process::run_in_fresh_process(
            "runtime_lifecycle::destroy::tests::physical_destroy_os_only_retains_source_pages_but_seals_all_native_access",
            || physical_destroy_fixture(true, false, FinalOutputFixtureMode::Disabled),
        );
    }

    #[test]
    fn physical_destroy_tracking_oom_retains_transferred_graph_and_permanent_seal() {
        crate::test_process::run_in_fresh_process(
            "runtime_lifecycle::destroy::tests::physical_destroy_tracking_oom_retains_transferred_graph_and_permanent_seal",
            || physical_destroy_fixture(false, true, FinalOutputFixtureMode::Disabled),
        );
    }

    #[test]
    fn physical_destroy_final_output_keeps_page_map_live_for_signed_show_stats_then_releases_it() {
        crate::test_process::run_in_fresh_process(
            "runtime_lifecycle::destroy::tests::physical_destroy_final_output_keeps_page_map_live_for_signed_show_stats_then_releases_it",
            || physical_destroy_fixture(false, false, FinalOutputFixtureMode::SignedShowStats),
        );
    }

    #[test]
    fn physical_destroy_final_output_keeps_page_map_live_for_signed_verbose_then_releases_it() {
        crate::test_process::run_in_fresh_process(
            "runtime_lifecycle::destroy::tests::physical_destroy_final_output_keeps_page_map_live_for_signed_verbose_then_releases_it",
            || physical_destroy_fixture(false, false, FinalOutputFixtureMode::SignedVerbose),
        );
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
