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
    registry: &dyn admission::NativeAllocatorPinnedThreadRegistry,
) -> Result<NativePreparedProcessDestroy, NativeProcessDestroyError> {
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
    let quiescence = unsafe { admission::begin_native_allocator_terminal_quiescence(registry) }
        .map_err(NativeProcessDestroyError::Admission)?;
    let owners = quiescence.transfer_source_owners().map_err(|_| NativeProcessDestroyError::SourceOwner)?;
    RUNTIME_PROCESS.logical_process_done.compare_exchange(PROCESS_DONE_OPEN, PROCESS_DONE_TRANSITION,
        Ordering::AcqRel, Ordering::Acquire).map_err(|_| NativeProcessDestroyError::AlreadyCompleted)?;
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
