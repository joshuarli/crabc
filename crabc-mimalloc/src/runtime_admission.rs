// SPDX-License-Identifier: MIT
//! Native integration admission shared by prepared fork and terminal teardown.
//! This is runtime coordination, not a mimalloc allocator algorithm. Ordinary
//! operations write only their own TLS cache line; the shared epoch is read-only.
//! A registry writer pins existing libc thread records before scanning them.
//!
//! Production native entry guards cover startup, allocation/free/reallocation,
//! usable-size observations, attachment/finish, logical process-done, and the
//! source-reading audit adapters before any owner-presence or PageMap access.
//! They preserve ordinary default process-done allocation: only an explicitly
//! closed native epoch denies entry. Registration is not source admission.
//!
//! This module does not yet enable a physical destroy caller: foreign callback
//! sites must compose the suspended-borrow boundary, fork must share the epoch,
//! and terminal ownership transfer must consume or retain every TLS engine.
//! Standalone source fixtures which export raw page/owner capabilities retain
//! their separate lifetime contracts and cannot authorize native destruction.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};
use super::ThreadLifecycleSlot;

const MODE_MASK: usize = 3;
const OPEN: usize = 0;
const FORK_CLOSED: usize = 1;
const TERMINAL_CLOSING: usize = 2;
const TERMINAL: usize = 3;
const UNPUBLISHED: u8 = 0;
const REGISTERED: u8 = 1;
const RETIRED: u8 = 2;
const TRANSFERRED: u8 = 3;
const RETAINED: u8 = 4;

/// Opaque owner-image-local TLS descriptor. Its address is not a `'static`
/// reference. Libc's existing thread registry pins its containing mapping.
/// Only admission atomics may be inspected without source-entry exclusion.
#[repr(align(64))]
pub struct NativeAllocatorThreadDescriptor {
    entered: AtomicBool,
    callback: AtomicBool,
    registration: AtomicU8,
    owner_slot: AtomicPtr<ThreadLifecycleSlot>,
    // These two fields belong only to the running thread, including while a
    // terminal writer consumes other, disjoint source-owner fields remotely.
    nesting: UnsafeCell<usize>,
    callback_nesting: UnsafeCell<usize>,
}

// SAFETY: foreign access is restricted to atomics. Current-thread nesting is
// never read or changed by a registry writer; it has no source-owner payload.
unsafe impl Sync for NativeAllocatorThreadDescriptor {}

impl NativeAllocatorThreadDescriptor {
    const fn new() -> Self {
        Self { entered: AtomicBool::new(false), callback: AtomicBool::new(false),
            registration: AtomicU8::new(UNPUBLISHED), owner_slot: AtomicPtr::new(core::ptr::null_mut()),
            nesting: UnsafeCell::new(0), callback_nesting: UnsafeCell::new(0) }
    }
}

#[thread_local]
static DESCRIPTOR: NativeAllocatorThreadDescriptor = NativeAllocatorThreadDescriptor::new();
static INITIAL_DESCRIPTOR: AtomicPtr<NativeAllocatorThreadDescriptor> = AtomicPtr::new(core::ptr::null_mut());
static EPOCH: NativeAllocatorEpoch = NativeAllocatorEpoch::new();

/// Obtains only the current TLS record's identity. Libc publishes this pointer
/// before worker registration/attachment; it must never dereference it itself.
pub fn current_native_allocator_thread_descriptor() -> NonNull<NativeAllocatorThreadDescriptor> {
    let pointer = NonNull::from(&DESCRIPTOR);
    DESCRIPTOR.owner_slot.store(super::current_thread_slot_pointer().as_ptr(), Ordering::Relaxed);
    pointer
}

/// Registers the current descriptor after libc has published it in the existing
/// ThreadControl graph. A false return never admits an allocator operation.
///
/// # Safety
/// The same allocator image owns `descriptor`. Its containing TLS mapping is
/// already visible in the locked libc registry and remains pinned through
/// allocator finish, cancellation, registry withdrawal and kernel retirement.
/// Publication must precede every source entry, including rejected attachment.
pub unsafe fn register_current_native_allocator_worker_descriptor(
    descriptor: NonNull<NativeAllocatorThreadDescriptor>,
) -> bool {
    if descriptor != current_native_allocator_thread_descriptor() { return false; }
    register_worker_at(&EPOCH, &DESCRIPTOR, || {})
}

fn register_worker_at(
    epoch: &NativeAllocatorEpoch,
    record: &NativeAllocatorThreadDescriptor,
    before_registration: impl FnOnce(),
) -> bool {
    if epoch.state.load(Ordering::SeqCst) & MODE_MASK >= TERMINAL_CLOSING { return false; }
    before_registration();
    let newly_registered = match record.registration.compare_exchange(UNPUBLISHED, REGISTERED, Ordering::Release, Ordering::Acquire) {
        Ok(_) => true,
        Err(REGISTERED) => false,
        Err(_) => return false,
    };
    // A terminal scan may have observed this already-published record while
    // it was still UNPUBLISHED. Registration grants no source authority: the
    // post-publication epoch check rejects that race, and attach independently
    // publishes ordinary entry and rechecks the same epoch before TLS access.
    if epoch.state.load(Ordering::SeqCst) & MODE_MASK >= TERMINAL_CLOSING {
        if newly_registered {
            // This exact fresh worker has never entered source. A failed
            // idempotent registration must not retire an existing live owner.
            let _ = record.registration.compare_exchange(REGISTERED, RETIRED, Ordering::Release, Ordering::Acquire);
        }
        return false;
    }
    true
}

/// Returns the initial process-owned TLS record for exactly-once inclusion in
/// the pinned registry visitor. Initial TLS remains mapped after pthread_exit.
pub fn native_allocator_initial_thread_descriptor() -> Option<NonNull<NativeAllocatorThreadDescriptor>> {
    NonNull::new(INITIAL_DESCRIPTOR.load(Ordering::Acquire))
}

pub(super) fn register_initial_descriptor() -> bool {
    let descriptor = current_native_allocator_thread_descriptor();
    match INITIAL_DESCRIPTOR.compare_exchange(core::ptr::null_mut(), descriptor.as_ptr(), Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {},
        Err(existing) if existing == descriptor.as_ptr() => {},
        Err(_) => return false,
    }
    // The initial mapping is process-owned, not a reclaimable child control.
    match DESCRIPTOR.registration.compare_exchange(UNPUBLISHED, REGISTERED, Ordering::Release, Ordering::Acquire) {
        Ok(_) | Err(REGISTERED) => true,
        Err(_) => false,
    }
}

/// Borrowed access to the existing libc thread registry; this owns no new list.
///
/// # Safety
/// For the complete borrow, the implementation pins every listed descriptor's
/// TLS mapping and owner image, includes all registered workers and the initial
/// descriptor exactly once, and prevents publication/removal races. Descriptors
/// must come from this exact allocator image. Visiting allocates nothing, invokes
/// no user code and only calls the supplied internal visitor synchronously.
/// Registry locking must respect the documented native fork/terminal lock order.
pub unsafe trait NativeAllocatorPinnedThreadRegistry {
    fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAllocatorCallbackBoundaryError { NoOperation, Closed, InvalidNesting }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeAllocatorEntryError { Unregistered, Closed, NestingOverflow }

struct NativeAllocatorEpoch { state: AtomicUsize }
impl NativeAllocatorEpoch {
    const fn new() -> Self { Self { state: AtomicUsize::new(OPEN) } }
}

/// Private RAII admission; no source borrow may escape this current-thread scope.
pub(super) struct NativeAllocatorOperationGuard {
    descriptor: NonNull<NativeAllocatorThreadDescriptor>,
    _not_send_sync: PhantomData<*mut ()>,
}

impl NativeAllocatorOperationGuard {
    pub(super) fn enter() -> Result<Self, NativeAllocatorEntryError> {
        Self::enter_at(&EPOCH, current_native_allocator_thread_descriptor())
    }

    fn enter_at(epoch: &NativeAllocatorEpoch, descriptor: NonNull<NativeAllocatorThreadDescriptor>) -> Result<Self, NativeAllocatorEntryError> {
        // SAFETY: this private entry accepts only the current TLS descriptor;
        // isolated tests use an exclusively owned live fixture on this thread.
        let record = unsafe { descriptor.as_ref() };
        if record.registration.load(Ordering::Acquire) != REGISTERED {
            return Err(NativeAllocatorEntryError::Unregistered);
        }
        let depth = unsafe { *record.nesting.get() };
        if depth != 0 {
            // A pre-commit writer must drain this already admitted entry.
            // Its nested source work may be necessary to finish that drain.
            // Permanent Terminal is never compatible with live entry.
            if epoch.state.load(Ordering::SeqCst) & MODE_MASK == TERMINAL {
                return Err(NativeAllocatorEntryError::Closed);
            }
            let next = depth.checked_add(1).ok_or(NativeAllocatorEntryError::NestingOverflow)?;
            unsafe { *record.nesting.get() = next; }
            return Ok(Self { descriptor, _not_send_sync: PhantomData });
        }
        loop {
            let observed = epoch.state.load(Ordering::SeqCst);
            match observed & MODE_MASK {
                TERMINAL_CLOSING | TERMINAL => return Err(NativeAllocatorEntryError::Closed),
                FORK_CLOSED => { core::hint::spin_loop(); continue; },
                _ => {},
            }
            record.entered.store(true, Ordering::SeqCst);
            if epoch.state.load(Ordering::SeqCst) == observed {
                unsafe { *record.nesting.get() = 1; }
                return Ok(Self { descriptor, _not_send_sync: PhantomData });
            }
            record.entered.store(false, Ordering::SeqCst);
        }
    }
}

impl Drop for NativeAllocatorOperationGuard {
    fn drop(&mut self) {
        let record = unsafe { self.descriptor.as_ref() };
        let depth = unsafe { *record.nesting.get() };
        debug_assert!(depth != 0);
        unsafe { *record.nesting.get() = depth - 1; }
        if depth == 1 { record.entered.store(false, Ordering::SeqCst); }
    }
}

/// A diagnostic callback may acquire libc locks while its allocator source
/// borrows are still live. It therefore publishes callback presence without
/// withdrawing ordinary entry. A closing writer must refuse and unwind its
/// outer locks; it may never infer quiescence from this callback.
struct DiagnosticCallbackPresence {
    descriptor: NonNull<NativeAllocatorThreadDescriptor>,
    previous_callbacks: usize,
    _not_send_sync: PhantomData<*mut ()>,
}

impl Drop for DiagnosticCallbackPresence {
    fn drop(&mut self) {
        let record = unsafe { self.descriptor.as_ref() };
        unsafe { *record.callback_nesting.get() = self.previous_callbacks; }
        record.callback.store(self.previous_callbacks != 0, Ordering::SeqCst);
    }
}

/// Marks a source diagnostic's foreign output call, preserving ordinary entry
/// and all source borrows. Unlike deferred callbacks this does not suspend the
/// allocator operation. Publication precedes every foreign lock acquisition;
/// writers recheck this marker on every drain pass, including after observing
/// an ordinary entry on an earlier pass.
///
/// # Safety
/// The caller is the current thread inside a guarded native allocator source
/// operation. The closure is exactly its synchronous diagnostic output call,
/// and must not transfer source ownership or outlive the ordinary entry. Any
/// foreign lock acquisition belongs inside this closure, after publication.
/// A writer refusing this marker must release its outer locks before invoking
/// parent/error hooks. The closure may keep existing source borrows; those are
/// protected by ordinary entry until the enclosing operation returns.
pub unsafe fn with_native_allocator_diagnostic_callback<R>(
    callback: impl FnOnce() -> R,
) -> Result<R, NativeAllocatorCallbackBoundaryError> {
    unsafe { with_diagnostic_callback_at(current_native_allocator_thread_descriptor(), callback) }
}

unsafe fn with_diagnostic_callback_at<R>(
    pointer: NonNull<NativeAllocatorThreadDescriptor>,
    callback: impl FnOnce() -> R,
) -> Result<R, NativeAllocatorCallbackBoundaryError> {
    let record = unsafe { pointer.as_ref() };
    if unsafe { *record.nesting.get() } == 0 || !record.entered.load(Ordering::SeqCst) {
        return Err(NativeAllocatorCallbackBoundaryError::NoOperation);
    }
    let previous_callbacks = unsafe { *record.callback_nesting.get() };
    let next = previous_callbacks.checked_add(1)
        .ok_or(NativeAllocatorCallbackBoundaryError::InvalidNesting)?;
    unsafe { *record.callback_nesting.get() = next; }
    record.callback.store(true, Ordering::SeqCst);
    let presence = DiagnosticCallbackPresence { descriptor: pointer, previous_callbacks,
        _not_send_sync: PhantomData };
    let result = callback();
    drop(presence);
    Ok(result)
}

/// Temporary terminal-safety coverage of the existing raw-fork copy interval.
/// This is an ordinary epoch entry, not allocator-wide fork quiescence. It
/// prevents permanent terminal transfer from racing the copy but does not
/// repair vanished child owners. The shared fork writer and its child-repair
/// continuation replace this guard when full generic repair is implemented.
#[must_use = "hold through the raw copy and complete before user hooks"]
pub struct NativeAllocatorRawForkCopyGuard {
    operation: NativeAllocatorOperationGuard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAllocatorRawForkCopyError { Unavailable, Closed }

impl NativeAllocatorRawForkCopyGuard {
    /// Ends the parent or syscall-error copy interval before parent user hooks.
    pub fn complete_parent(self) { drop(self); }

    /// Ends only the copied ordinary admission on the surviving child TLS.
    /// This makes no claim about inherited page/source-owner repair.
    ///
    /// # Safety
    /// The raw fork has returned in its sole child; TLS still names the exact
    /// copied current descriptor, whose mapping remains valid. No registry
    /// reset may have reclaimed that mapping. This guard is the copied value,
    /// not a foreign or reconstructed parent descriptor capability.
    pub unsafe fn complete_child(self) { drop(self); }
}

/// Protects the existing raw-fork copy from terminal source-owner transfer.
/// Future entry after Terminal is rejected; pre-commit closing also refuses
/// fresh entry so libc can take its ordinary parent/error unlock path.
///
/// # Safety
/// Cover every raw fork route, including fork and _Fork, from before the raw
/// syscall through the corresponding parent/child completion. Acquire after
/// public prepare hooks and before any source copying, and release before
/// user hooks. On refusal libc performs its paired lock/signal completion;
/// it must not invoke the syscall. This does not authorize inherited source
/// repair or claim generic allocator fork correctness.
pub unsafe fn begin_native_allocator_raw_fork_copy(
) -> Result<NativeAllocatorRawForkCopyGuard, NativeAllocatorRawForkCopyError> {
    raw_fork_copy_at(&EPOCH, current_native_allocator_thread_descriptor())
}

fn raw_fork_copy_at(epoch: &NativeAllocatorEpoch, descriptor: NonNull<NativeAllocatorThreadDescriptor>)
    -> Result<NativeAllocatorRawForkCopyGuard, NativeAllocatorRawForkCopyError> {
    let operation = NativeAllocatorOperationGuard::enter_at(epoch, descriptor).map_err(|error| match error {
        NativeAllocatorEntryError::Closed => NativeAllocatorRawForkCopyError::Closed,
        _ => NativeAllocatorRawForkCopyError::Unavailable,
    })?;
    Ok(NativeAllocatorRawForkCopyGuard { operation })
}

struct CallbackSuspension {
    descriptor: NonNull<NativeAllocatorThreadDescriptor>,
    saved_depth: usize,
    armed: bool,
}

impl Drop for CallbackSuspension {
    fn drop(&mut self) {
        if !self.armed { return; }
        let record = unsafe { self.descriptor.as_ref() };
        // Unwind or failed resume retains this owner. Restore only lexical
        // guard depth so outer Drop remains valid; no source entry reopens.
        unsafe { *record.nesting.get() = self.saved_depth; }
        record.registration.store(RETAINED, Ordering::Release);
        record.entered.store(false, Ordering::SeqCst);
    }
}

/// Invokes foreign code after source borrows end, with a callback marker that
/// bridges the interval outside ordinary entry. Nested allocation enters afresh.
///
/// # Safety
/// Every source/session/owner borrow from all suspended native frames has ended.
/// The caller holds no allocator/libc lock needed by a closing writer. The
/// approved outer lock ordering must establish this even for nested callers.
/// The closure accesses source only through fresh guarded native operations.
/// On error the caller retains the owner and must not enter phase C or otherwise
/// touch source state. The A-to-C caller-stack owner lease remains alive.
pub unsafe fn with_native_allocator_callback_boundary<R>(callback: impl FnOnce() -> R) -> Result<R, NativeAllocatorCallbackBoundaryError> {
    // SAFETY: the public caller supplies the suspended-borrow and lock-order
    // contract; this pointer names only its current pinned TLS record.
    unsafe { with_callback_boundary_at(&EPOCH, current_native_allocator_thread_descriptor(), callback) }
}

/// Samples only the current descriptor's callback handoff atomics for the
/// dispatcher integration regression. It exposes no owner, TLS, source, or
/// admission capability.
#[cfg(test)]
#[inline]
pub(super) fn current_native_allocator_callback_boundary_state() -> (bool, bool) {
    (
        DESCRIPTOR.entered.load(Ordering::SeqCst),
        DESCRIPTOR.callback.load(Ordering::SeqCst),
    )
}

unsafe fn with_callback_boundary_at<R>(
    epoch: &NativeAllocatorEpoch,
    pointer: NonNull<NativeAllocatorThreadDescriptor>,
    callback: impl FnOnce() -> R,
) -> Result<R, NativeAllocatorCallbackBoundaryError> {
    let record = unsafe { pointer.as_ref() };
    let saved = unsafe { *record.nesting.get() };
    if saved == 0 { return Err(NativeAllocatorCallbackBoundaryError::NoOperation); }
    let callbacks = unsafe { *record.callback_nesting.get() };
    let next = callbacks.checked_add(1).ok_or(NativeAllocatorCallbackBoundaryError::InvalidNesting)?;
    unsafe { *record.callback_nesting.get() = next; }
    record.callback.store(true, Ordering::SeqCst);
    let mut suspension = CallbackSuspension { descriptor: pointer, saved_depth: saved, armed: true };
    unsafe { *record.nesting.get() = 0; }
    record.entered.store(false, Ordering::SeqCst);
    // Recheck after marker publication and entry withdrawal. A writer which
    // raced A-to-B must now refuse this callback marker and reopen. Keep the
    // same caller-stack token/heartbeat while waiting outside source borrows;
    // never duplicate phase A or call foreign code under a closed epoch.
    loop {
        match epoch.state.load(Ordering::SeqCst) & MODE_MASK {
            OPEN => break,
            TERMINAL => return Err(NativeAllocatorCallbackBoundaryError::Closed),
            _ => core::hint::spin_loop(),
        }
    }
    let result = callback();
    if unsafe { *record.nesting.get() } != 0 {
        return Err(NativeAllocatorCallbackBoundaryError::InvalidNesting);
    }
    match NativeAllocatorOperationGuard::enter_at(epoch, pointer) {
        Ok(guard) => {
            core::mem::forget(guard);
            unsafe { *record.nesting.get() = saved; *record.callback_nesting.get() = callbacks; }
            record.callback.store(callbacks != 0, Ordering::SeqCst);
            suspension.armed = false;
            Ok(result)
        }
        Err(_) => {
            // Restore lexical guard depth only; entered remains false and the
            // terminal epoch denies every later source projection. Keep the
            // callback marker set so failed resume cannot mint quiescence.
            unsafe { *record.nesting.get() = saved; }
            Err(NativeAllocatorCallbackBoundaryError::Closed)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAllocatorQuiescenceError {
    WriterBusy,
    CurrentOperationActive,
    CallbackActive,
    RetainedDescriptor,
    InvalidDescriptor,
    EpochExhausted,
}

/// Exclusive native-owner authority after permanent epoch closure. It pins the
/// registry borrow through every TLS transfer. It does not revoke references
/// previously obtained through a separate unsafe lower-level allocator API.
#[must_use = "terminal quiescence must retain or consume every exact source owner"]
pub struct NativeAllocatorTerminalQuiescence<'registry> {
    registry: &'registry dyn NativeAllocatorPinnedThreadRegistry,
    _not_send_sync: PhantomData<*mut ()>,
}

/// All reachable native TLS source owners have been consumed or transferred
/// into the source graph. This authority carries no TLS reference; the pinned
/// registry borrow may end before Heap/meta locks and OS release begin.
pub(super) struct NativeAllocatorTransferredProcessOwners {
    _not_send_sync: PhantomData<*mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAllocatorTerminalTransferError { InvalidDescriptor, RetainedSourceOwner }

impl NativeAllocatorTerminalQuiescence<'_> {
    /// Preflights all owners before the first transfer. A later unexpected
    /// failure leaves completed descriptors acknowledged and each remaining
    /// exact payload pinned/retained, with the native epoch permanently shut.
    pub(super) fn transfer_source_owners(self) -> Result<NativeAllocatorTransferredProcessOwners, NativeAllocatorTerminalTransferError> {
        let mut failure = None;
        self.registry.visit_descriptors(&mut |pointer| {
            let record = unsafe { pointer.as_ref() };
            match record.registration.load(Ordering::Acquire) {
                UNPUBLISHED | RETIRED | TRANSFERRED => {}
                REGISTERED => match NonNull::new(record.owner_slot.load(Ordering::Acquire)) {
                    Some(slot) if unsafe { super::terminal_slot_can_transfer(slot) } => {}
                    _ => failure = Some(NativeAllocatorTerminalTransferError::RetainedSourceOwner),
                },
                _ => failure = Some(NativeAllocatorTerminalTransferError::InvalidDescriptor),
            }
        });
        if let Some(error) = failure { return Err(error); }
        self.registry.visit_descriptors(&mut |pointer| {
            if failure.is_some() { return; }
            let record = unsafe { pointer.as_ref() };
            match record.registration.load(Ordering::Acquire) {
                UNPUBLISHED | RETIRED => {
                    // Registration still racing its initial OPEN observation
                    // cannot enter source: the permanent epoch and post-CAS
                    // check deny it. The acknowledgement also prevents its
                    // UNPUBLISHED->REGISTERED CAS from succeeding afterward.
                    record.registration.store(TRANSFERRED, Ordering::Release);
                }
                TRANSFERRED => {}
                REGISTERED => {
                    let transferred = NonNull::new(record.owner_slot.load(Ordering::Acquire))
                        .is_some_and(|slot| unsafe { super::terminal_slot_transfer(slot) });
                    if transferred {
                        record.registration.store(TRANSFERRED, Ordering::Release);
                    } else {
                        record.registration.store(RETAINED, Ordering::Release);
                        failure = Some(NativeAllocatorTerminalTransferError::RetainedSourceOwner);
                    }
                }
                _ => failure = Some(NativeAllocatorTerminalTransferError::InvalidDescriptor),
            }
        });
        if let Some(error) = failure { return Err(error); }
        Ok(NativeAllocatorTransferredProcessOwners { _not_send_sync: PhantomData })
    }
}

impl NativeAllocatorEpoch {
    fn reopen(&self, closed: usize) -> Result<(), NativeAllocatorQuiescenceError> {
        let Some(next) = (closed & !MODE_MASK).checked_add(MODE_MASK + 1) else {
            self.state.store(TERMINAL, Ordering::SeqCst);
            return Err(NativeAllocatorQuiescenceError::EpochExhausted);
        };
        // A parent completion may never overwrite a permanent terminal seal.
        self.state.compare_exchange(closed, next, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ()).map_err(|_| NativeAllocatorQuiescenceError::WriterBusy)
    }

    fn close_terminal(&self, registry: &dyn NativeAllocatorPinnedThreadRegistry) -> Result<(), NativeAllocatorQuiescenceError> {
        self.close_for(registry, TERMINAL_CLOSING).map(|_| ())
    }

    fn close_for(&self, registry: &dyn NativeAllocatorPinnedThreadRegistry, mode: usize) -> Result<usize, NativeAllocatorQuiescenceError> {
        debug_assert!(mode == FORK_CLOSED || mode == TERMINAL_CLOSING);
        let observed = self.state.load(Ordering::SeqCst);
        if observed & MODE_MASK != OPEN { return Err(NativeAllocatorQuiescenceError::WriterBusy); }
        let closed = observed | mode;
        self.state.compare_exchange(observed, closed, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| NativeAllocatorQuiescenceError::WriterBusy)?;
        loop {
            let mut active = false;
            let mut failure = None;
            registry.visit_descriptors(&mut |pointer| {
                // SAFETY: the unsafe registry contract pins the exact record
                // through this scope. No source-owner field is projected.
                let record = unsafe { pointer.as_ref() };
                // Read entry BEFORE callback: callback publication precedes
                // entry clear, so the writer cannot miss the A-to-B handoff.
                active |= record.entered.load(Ordering::SeqCst);
                if record.callback.load(Ordering::SeqCst) {
                    failure = Some(NativeAllocatorQuiescenceError::CallbackActive);
                }
                if record.registration.load(Ordering::Acquire) == RETAINED {
                    failure = Some(NativeAllocatorQuiescenceError::RetainedDescriptor);
                }
                if record.owner_slot.load(Ordering::Acquire).is_null() {
                    failure = Some(NativeAllocatorQuiescenceError::InvalidDescriptor);
                }
            });
            if let Some(error) = failure {
                self.reopen(closed)?;
                return Err(error);
            }
            if !active {
                if mode == TERMINAL_CLOSING {
                    self.state.store(observed | TERMINAL, Ordering::SeqCst);
                }
                return Ok(closed);
            }
            // Only ordinary source entries can remain here. Their callback
            // transition is rechecked each pass; foreign code is never waited
            // upon while the caller retains outer libc registry locks.
            core::hint::spin_loop();
        }
    }
}

/// Prepared raw-fork interval over the already-held libc registry pin. This
/// capability is not child source repair: copied source owners must still be
/// reconciled before the child may reopen entry. Dropping an unfinished interval
/// seals access permanently rather than leaving ordinary entries spinning.
#[must_use = "complete the parent interval or preserve the child repair continuation"]
pub struct NativeAllocatorForkQuiescence<'registry> {
    registry: &'registry dyn NativeAllocatorPinnedThreadRegistry,
    closed: usize,
    armed: bool,
    _not_send_sync: PhantomData<*mut ()>,
}

impl Drop for NativeAllocatorForkQuiescence<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Never overwrite another writer's state or a permanent seal.
            let _ = EPOCH.state.compare_exchange(self.closed,
                (self.closed & !MODE_MASK) | TERMINAL, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
}

impl<'registry> NativeAllocatorForkQuiescence<'registry> {
    /// Reopens the exact parent generation before libc releases its prepared
    /// locks. Source owner identities and payloads remain unchanged.
    ///
    /// # Safety
    /// This is the parent process (including raw syscall failure), never the
    /// copied child. The original registry pin still covers every descriptor.
    /// Paired libc lock completion and signal/parent hooks follow this call;
    /// hooks must run only after those locks have been released.
    pub unsafe fn resume_parent(mut self) -> Result<(), NativeAllocatorQuiescenceError> {
        EPOCH.reopen(self.closed)?;
        self.armed = false;
        Ok(())
    }

    /// Moves the copied interval into the allocator's child-repair boundary.
    /// This intentionally provides no public reopen operation: a successful
    /// raw syscall is not proof that vanished source owners have been repaired.
    ///
    /// # Safety
    /// This is the sole surviving child thread immediately after the raw fork,
    /// before libc forgets any sibling descriptor or resets the registry. All
    /// copied TLS/control mappings and the prepared registry pin remain valid.
    pub unsafe fn into_child_repair(mut self) -> NativeAllocatorForkChildRepair<'registry> {
        self.armed = false;
        NativeAllocatorForkChildRepair { interval: Self { registry: self.registry,
            closed: self.closed, armed: true, _not_send_sync: PhantomData } }
    }
}

/// Exact copied registry/epoch ownership awaiting source-level child repair.
/// The allocator must consume vanished owner capabilities and re-root the
/// surviving source identity before this continuation can release its pin or
/// reopen entry. No current public method claims that work is already done.
#[must_use = "copied native source owners still require allocator child repair"]
pub struct NativeAllocatorForkChildRepair<'registry> {
    interval: NativeAllocatorForkQuiescence<'registry>,
}

/// Drains native source entry under libc's already-prepared raw-fork registry
/// pin. Both fork and _Fork must use the same registry, not a second list/lock.
/// Any callback refusal reopens the epoch; libc must unwind all prepared locks
/// before parent hooks. Diagnostic callbacks keep source entry published, so
/// every drain iteration rechecks their markers rather than waiting on them.
///
/// # Safety
/// Every native source operation and foreign callback participates in this
/// protocol. The registry is the exact prepared, continuously pinned libc
/// registry (borrow its existing lock for fork; acquire that same lock for
/// _Fork). Existing outer libc locks precede this close; no allocation or user
/// callback runs while the pin is held. Call outside any current source entry.
/// Keep the pin across raw fork and parent completion or child source repair;
/// never relock it through the general scoped registry accessor. The raw fork
/// syscall is the sole syscall allowed within this prepared interval. Child
/// repair must be implemented and preflighted before enabling a product caller.
pub unsafe fn begin_native_allocator_fork_quiescence(
    registry: &dyn NativeAllocatorPinnedThreadRegistry,
) -> Result<NativeAllocatorForkQuiescence<'_>, NativeAllocatorQuiescenceError> {
    if unsafe { *DESCRIPTOR.nesting.get() != 0 || *DESCRIPTOR.callback_nesting.get() != 0 } {
        return Err(NativeAllocatorQuiescenceError::CurrentOperationActive);
    }
    let closed = EPOCH.close_for(registry, FORK_CLOSED)?;
    Ok(NativeAllocatorForkQuiescence { registry, closed, armed: true, _not_send_sync: PhantomData })
}

/// Closes future entry, excludes ordinary operations and refuses callback
/// leases before granting any remote TLS-owner access. A failed preflight
/// reopens a fresh epoch; success is permanent even if destruction later fails.
///
/// # Safety
/// The supplied pinned registry covers every native entry, including the
/// initial record. The caller holds the approved terminal lock ordering and
/// invokes this outside every source borrow and native operation. All source
/// and callback entries must participate in this descriptor protocol.
pub unsafe fn begin_native_allocator_terminal_quiescence(
    registry: &dyn NativeAllocatorPinnedThreadRegistry,
) -> Result<NativeAllocatorTerminalQuiescence<'_>, NativeAllocatorQuiescenceError> {
    if unsafe { *DESCRIPTOR.nesting.get() != 0 || *DESCRIPTOR.callback_nesting.get() != 0 } {
        return Err(NativeAllocatorQuiescenceError::CurrentOperationActive);
    }
    EPOCH.close_terminal(registry)?;
    Ok(NativeAllocatorTerminalQuiescence { registry, _not_send_sync: PhantomData })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    struct Registry<'a>(&'a NativeAllocatorThreadDescriptor);
    // SAFETY: fixtures are exclusive on this test thread and outlive every
    // synchronous visit; exactly one complete local descriptor is included.
    unsafe impl NativeAllocatorPinnedThreadRegistry for Registry<'_> {
        fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
            visitor(NonNull::from(self.0));
        }
    }

    fn registered_record() -> NativeAllocatorThreadDescriptor {
        let record = NativeAllocatorThreadDescriptor::new();
        record.registration.store(REGISTERED, Ordering::Relaxed);
        let owner = std::boxed::Box::leak(std::boxed::Box::new(ThreadLifecycleSlot::new()));
        record.owner_slot.store(core::ptr::from_mut(owner), Ordering::Relaxed);
        record
    }

    #[test]
    fn raw_fork_copy_completion_releases_only_its_own_descriptor_and_terminal_refuses() {
        let parent_epoch = NativeAllocatorEpoch::new();
        let parent_record = registered_record();
        let child_epoch = NativeAllocatorEpoch::new();
        let child_record = registered_record();
        // Separate fixture mappings represent the parent and copied child;
        // neither completion may clear the other mapping's admission record.
        let parent = raw_fork_copy_at(&parent_epoch, NonNull::from(&parent_record)).unwrap();
        let child = raw_fork_copy_at(&child_epoch, NonNull::from(&child_record)).unwrap();
        parent.complete_parent();
        assert!(!parent_record.entered.load(Ordering::SeqCst));
        assert!(child_record.entered.load(Ordering::SeqCst));
        unsafe { child.complete_child(); }
        assert!(!child_record.entered.load(Ordering::SeqCst));
        assert_eq!(unsafe { *parent_record.nesting.get() }, 0);
        assert_eq!(unsafe { *child_record.nesting.get() }, 0);
        parent_epoch.close_terminal(&Registry(&parent_record)).unwrap();
        assert!(matches!(raw_fork_copy_at(&parent_epoch, NonNull::from(&parent_record)),
            Err(NativeAllocatorRawForkCopyError::Closed)));
        assert!(!parent_record.entered.load(Ordering::SeqCst));
    }

    #[test]
    fn fork_epoch_parent_resume_preserves_terminal_and_rejects_callbacks() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        record.callback.store(true, Ordering::SeqCst);
        assert_eq!(epoch.close_for(&Registry(&record), FORK_CLOSED),
            Err(NativeAllocatorQuiescenceError::CallbackActive));
        record.callback.store(false, Ordering::SeqCst);
        let closed = epoch.close_for(&Registry(&record), FORK_CLOSED).unwrap();
        assert_eq!(closed, 4 | FORK_CLOSED);
        epoch.reopen(closed).unwrap();
        let operation = NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)).unwrap();
        drop(operation);
        epoch.close_terminal(&Registry(&record)).unwrap();
        assert!(epoch.reopen(closed).is_err());
        assert_eq!(epoch.state.load(Ordering::SeqCst) & MODE_MASK, TERMINAL);
        assert!(matches!(epoch.close_for(&Registry(&record), FORK_CLOSED),
            Err(NativeAllocatorQuiescenceError::WriterBusy)));
    }

    #[test]
    fn terminal_epoch_refuses_callback_then_permanently_denies_source_entry() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        record.callback.store(true, Ordering::SeqCst);
        assert_eq!(epoch.close_terminal(&Registry(&record)), Err(NativeAllocatorQuiescenceError::CallbackActive));
        assert_eq!(epoch.state.load(Ordering::SeqCst), 4);
        record.callback.store(false, Ordering::SeqCst);
        let guard = NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)).unwrap();
        assert!(record.entered.load(Ordering::SeqCst));
        drop(guard);
        epoch.close_terminal(&Registry(&record)).unwrap();
        assert!(matches!(NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)), Err(NativeAllocatorEntryError::Closed)));
        assert!(epoch.reopen(FORK_CLOSED).is_err());
        assert_eq!(epoch.state.load(Ordering::SeqCst) & MODE_MASK, TERMINAL);
    }

    #[test]
    fn registration_racing_terminal_scan_retires_only_the_unattached_worker() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        record.registration.store(UNPUBLISHED, Ordering::Relaxed);
        assert!(!register_worker_at(&epoch, &record, || {
            // The published descriptor is visible, but its registration CAS
            // has not run. Force the exact losing registration interleaving.
            epoch.close_terminal(&Registry(&record)).unwrap();
        }));
        assert_eq!(record.registration.load(Ordering::Acquire), RETIRED);
        assert!(matches!(NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)), Err(NativeAllocatorEntryError::Unregistered)));
        assert!(!record.entered.load(Ordering::SeqCst));

        let epoch = NativeAllocatorEpoch::new();
        let live = registered_record();
        assert!(!register_worker_at(&epoch, &live, || {
            epoch.close_terminal(&Registry(&live)).unwrap();
        }));
        assert_eq!(live.registration.load(Ordering::Acquire), REGISTERED,
            "idempotent registration cannot revoke an existing source owner");
    }

    #[test]
    fn callback_boundary_keeps_one_marker_through_nested_allocation_and_resume() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        let pointer = NonNull::from(&record);
        let operation = NativeAllocatorOperationGuard::enter_at(&epoch, pointer).unwrap();
        // SAFETY: no source borrow or lock exists in this isolated fixture;
        // both nested operations use the same thread-local record and epoch.
        let result = unsafe { with_callback_boundary_at(&epoch, pointer, || {
            assert!(!record.entered.load(Ordering::SeqCst));
            assert!(record.callback.load(Ordering::SeqCst));
            assert_eq!(epoch.close_terminal(&Registry(&record)), Err(NativeAllocatorQuiescenceError::CallbackActive));
            let nested = NativeAllocatorOperationGuard::enter_at(&epoch, pointer).unwrap();
            assert!(record.entered.load(Ordering::SeqCst));
            with_callback_boundary_at(&epoch, pointer, || {
                assert!(record.callback.load(Ordering::SeqCst));
                assert!(!record.entered.load(Ordering::SeqCst));
            }).unwrap();
            assert!(record.callback.load(Ordering::SeqCst));
            drop(nested);
            assert!(!record.entered.load(Ordering::SeqCst));
            17
        }) };
        assert_eq!(result, Ok(17));
        assert!(record.entered.load(Ordering::SeqCst));
        assert!(!record.callback.load(Ordering::SeqCst));
        drop(operation);
        epoch.close_terminal(&Registry(&record)).unwrap();
    }

    #[test]
    fn closing_writer_observes_callback_handoff_before_entry_withdrawal() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        let operation = NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)).unwrap();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| epoch.close_terminal(&Registry(&record)));
            while epoch.state.load(Ordering::SeqCst) & MODE_MASK != TERMINAL_CLOSING {
                core::hint::spin_loop();
            }
            // The real A-to-B ordering: publishing callback before clearing
            // entry makes this writer refuse rather than mint quiescence.
            record.callback.store(true, Ordering::SeqCst);
            drop(operation);
            assert_eq!(writer.join().unwrap(), Err(NativeAllocatorQuiescenceError::CallbackActive));
        });
        record.callback.store(false, Ordering::SeqCst);
        epoch.close_terminal(&Registry(&record)).unwrap();
    }

    #[test]
    fn diagnostic_without_source_entry_never_invokes_foreign_output() {
        let record = registered_record();
        let invoked = core::cell::Cell::new(false);
        let result = unsafe { with_diagnostic_callback_at(NonNull::from(&record), || invoked.set(true)) };
        assert_eq!(result, Err(NativeAllocatorCallbackBoundaryError::NoOperation));
        assert!(!invoked.get());
        assert!(!record.entered.load(Ordering::SeqCst));
        assert!(!record.callback.load(Ordering::SeqCst));
        assert_eq!(unsafe { *record.callback_nesting.get() }, 0);
    }

    #[test]
    fn diagnostic_after_writer_scan_preserves_entry_and_unwinds_before_parent_hook() {
        struct ScannedRegistry<'a> {
            record: &'a NativeAllocatorThreadDescriptor,
            scanned: &'a AtomicBool,
        }
        // SAFETY: the scoped thread joins before either pinned fixture dies;
        // only its owner thread touches nesting, and visiting is atomic-only.
        unsafe impl NativeAllocatorPinnedThreadRegistry for ScannedRegistry<'_> {
            fn visit_descriptors(&self, visitor: &mut dyn FnMut(NonNull<NativeAllocatorThreadDescriptor>)) {
                visitor(NonNull::from(self.record));
                self.scanned.store(true, Ordering::SeqCst);
            }
        }
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        let scanned = AtomicBool::new(false);
        let stdio = std::sync::Mutex::new(());
        let parent_hook_ran = AtomicBool::new(false);
        let outer = NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)).unwrap();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                // Model the actual fork lock order: stdio precedes the registry
                // pin/epoch close. The first scan sees entry, but no callback.
                let stdio_lock = stdio.lock().unwrap();
                let result = epoch.close_terminal(&ScannedRegistry { record: &record, scanned: &scanned });
                assert_eq!(result, Err(NativeAllocatorQuiescenceError::CallbackActive));
                assert!(record.entered.load(Ordering::SeqCst));
                assert!(record.callback.load(Ordering::SeqCst));
                assert_eq!(epoch.state.load(Ordering::SeqCst) & MODE_MASK, OPEN);
                // Parent/error completion releases every outer lock before
                // invoking user hooks. A hook acquiring stdio must not recurse
                // into this thread's still-held lock.
                drop(stdio_lock);
                let hook_stdio = stdio.lock().unwrap();
                parent_hook_ran.store(true, Ordering::SeqCst);
                drop(hook_stdio);
            });
            while !scanned.load(Ordering::SeqCst) { core::hint::spin_loop(); }
            assert!(!record.callback.load(Ordering::SeqCst));
            unsafe { with_diagnostic_callback_at(NonNull::from(&record), || {
                assert!(record.entered.load(Ordering::SeqCst));
                assert!(record.callback.load(Ordering::SeqCst));
                let diagnostic_stdio = stdio.lock().unwrap();
                assert!(record.entered.load(Ordering::SeqCst));
                // Nested diagnostics preserve the outer callback marker.
                with_diagnostic_callback_at(NonNull::from(&record), || {}).unwrap();
                assert!(record.callback.load(Ordering::SeqCst));
                drop(diagnostic_stdio);
            }).unwrap(); }
            writer.join().unwrap();
        });
        assert!(parent_hook_ran.load(Ordering::SeqCst));
        assert!(record.entered.load(Ordering::SeqCst));
        assert!(!record.callback.load(Ordering::SeqCst));
        drop(outer);
        epoch.close_terminal(&Registry(&record)).unwrap();
        assert_eq!(epoch.state.load(Ordering::SeqCst) & MODE_MASK, TERMINAL);
    }

    #[test]
    fn nested_source_work_can_finish_while_terminal_writer_drains_outer_entry() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        let pointer = NonNull::from(&record);
        let outer = NativeAllocatorOperationGuard::enter_at(&epoch, pointer).unwrap();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| epoch.close_terminal(&Registry(&record)));
            while epoch.state.load(Ordering::SeqCst) & MODE_MASK != TERMINAL_CLOSING {
                core::hint::spin_loop();
            }
            let inner = NativeAllocatorOperationGuard::enter_at(&epoch, pointer).unwrap();
            drop(inner);
            assert!(record.entered.load(Ordering::SeqCst));
            drop(outer);
            writer.join().unwrap().unwrap();
        });
        assert!(matches!(NativeAllocatorOperationGuard::enter_at(&epoch, pointer), Err(NativeAllocatorEntryError::Closed)));
    }

    #[test]
    fn nested_entry_keeps_outer_record_published_until_last_guard_returns() {
        let epoch = NativeAllocatorEpoch::new();
        let record = registered_record();
        let outer = NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)).unwrap();
        let inner = NativeAllocatorOperationGuard::enter_at(&epoch, NonNull::from(&record)).unwrap();
        drop(inner);
        assert!(record.entered.load(Ordering::SeqCst));
        drop(outer);
        assert!(!record.entered.load(Ordering::SeqCst));
        assert_eq!(unsafe { *record.nesting.get() }, 0);
    }
}

/// Decision at libc's kernel-retired, registry-withdrawn mapping boundary.
/// Pending/Retained keep the exact TLS/control mapping owned by libc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAllocatorDescriptorRetirement { Ready, PendingTerminal, Retained }

/// Reads only descriptor acknowledgement atomics, never foreign source fields.
///
/// # Safety
/// `descriptor` came from this allocator image and its TLS mapping remains
/// pinned. The worker has reached kernel clear-child-TID retirement and libc
/// has withdrawn it under the same registry lifetime protocol used by writers.
/// An outstanding writer pin must be honored; neither PendingTerminal nor
/// Retained permits TLS/control unmap. The initial descriptor is never a
/// reclaimable worker and must not be passed here.
pub unsafe fn native_allocator_descriptor_retirement(
    descriptor: NonNull<NativeAllocatorThreadDescriptor>,
) -> NativeAllocatorDescriptorRetirement {
    if INITIAL_DESCRIPTOR.load(Ordering::Acquire) == descriptor.as_ptr() {
        return NativeAllocatorDescriptorRetirement::Retained;
    }
    let record = unsafe { descriptor.as_ref() };
    if record.entered.load(Ordering::SeqCst) || record.callback.load(Ordering::SeqCst) {
        return NativeAllocatorDescriptorRetirement::Retained;
    }
    match record.registration.load(Ordering::Acquire) {
        UNPUBLISHED | RETIRED | TRANSFERRED => NativeAllocatorDescriptorRetirement::Ready,
        REGISTERED if EPOCH.state.load(Ordering::SeqCst) & MODE_MASK >= TERMINAL_CLOSING => {
            NativeAllocatorDescriptorRetirement::PendingTerminal
        }
        _ => NativeAllocatorDescriptorRetirement::Retained,
    }
}

pub(super) fn mark_current_source_retired() {
    let pointer = current_native_allocator_thread_descriptor();
    if INITIAL_DESCRIPTOR.load(Ordering::Acquire) != pointer.as_ptr() {
        let _ = DESCRIPTOR.registration.compare_exchange(REGISTERED, RETIRED, Ordering::Release, Ordering::Acquire);
    }
}

pub(super) fn rearm_current_source_descriptor() -> bool {
    if EPOCH.state.load(Ordering::SeqCst) & MODE_MASK >= TERMINAL_CLOSING { return false; }
    match DESCRIPTOR.registration.compare_exchange(RETIRED, REGISTERED, Ordering::Release, Ordering::Acquire) {
        Ok(_) | Err(REGISTERED) | Err(UNPUBLISHED) => true,
        Err(_) => false,
    }
}

/// Descriptor-only idempotent finish observation; it never projects a source
/// slot which a terminal writer may already have consumed.
pub(super) fn current_source_is_retired() -> bool {
    matches!(DESCRIPTOR.registration.load(Ordering::Acquire), RETIRED | TRANSFERRED)
}

pub(super) fn native_source_entry_is_terminal() -> bool {
    EPOCH.state.load(Ordering::SeqCst) & MODE_MASK >= TERMINAL_CLOSING
}
