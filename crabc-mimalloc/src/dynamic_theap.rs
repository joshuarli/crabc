// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/threadlocal.c:23-214`,
// `src/init.c:236-360,377-421,448-481`, `src/theap.c:236-449`,
// `src/heap.c:37-100`, and `src/prim/prim-tls.c:211-250`.

//! Private current-thread dynamic Theap attachment.
//!
//! This is a deliberately narrow first-class-heap binding: a caller provides
//! one address-stable `Heap::bootstrap_empty()` image, this owner claims one
//! regular TLS key, and it attaches one direct-zeroed metadata Theap to one
//! later-ticket metadata TLD. It does not implement `mi_heap_new/delete`,
//! subprocess heap lists/counters, cached-root switching, page routing,
//! pthread hooks, or public allocation APIs.

#[cfg(test)]
extern crate std;

use core::marker::PhantomData;
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::NonNull;

use crate::compiler_tls::{
    cached_theap, current_thread_identity, default_theap, fast_slot_peek,
};
use crate::meta::{MetaAllocation, MetaAllocator, MetaError};
use crate::owned_tls_key_registry::{
    OwnedThreadLocalKeyError, OwnedThreadLocalKeyLease, OwnedThreadLocalKeyRegistry,
};
use crate::os::MemoryConfig;
use crate::subproc::MainSubprocess;
use crate::thread_local::{ThreadLocalBackingError, ThreadLocalBackingOwner, ThreadLocalKey};
use crate::tld::{DynamicAttachedThreadLocalData, ThreadLocalDataError, ThreadLocalDataOwner};
use crate::types::{
    Heap, Theap, TheapDynamicInitError, ThreadLocalTheapListError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicAttachmentState {
    Preparing,
    Attached,
    AwaitingKeyRelease,
    TornDown,
    Poisoned,
}

/// One current-thread dynamic attachment failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicTheapError {
    InvalidCurrentThread,
    HeapBinding,
    FirstTicketReserved,
    ThreadLocalData(ThreadLocalDataError),
    Key(OwnedThreadLocalKeyError),
    Backing(ThreadLocalBackingError),
    TheapMetadata(MetaError),
    TheapProjection,
    TheapInit(TheapDynamicInitError),
    RootOwnership,
    SlotOwnership,
    ListOwnership,
    PageCountNonZero,
    TheapList(ThreadLocalTheapListError),
    TheapClear,
    HeapRetire,
    TornDown,
    Poisoned,
}

/// A dynamic begin either rejects after complete pre-publication cleanup or
/// returns the concrete retained owner for a terminal/awaiting-release state.
///
/// A post-registration allocation/list/backing failure must not silently drop
/// a TLD registration, typed metadata capability, or regular-key lease. The
/// caller receives that owner to account for an invalid-owner state or retry
/// the one pre-mutation key-release lock failure; this slice intentionally
/// invents no rollback after Theap/list publication.
#[must_use = "a retained dynamic attachment error carries live ownership that must be handled explicitly"]
pub(crate) enum DynamicTheapBeginError<'heap> {
    Rejected(DynamicTheapError),
    Retained {
        error: DynamicTheapError,
        attachment: DynamicTheapAttachment<'heap>,
    },
}

/// The regular-key portion of one caller-owned dynamic Heap binding.
///
/// `slot_bound` is separate from the lease itself: it makes releasing a key
/// while any dynamic backing slot can still name it structurally impossible
/// through this owner.
struct DynamicHeapBinding {
    lease: OwnedThreadLocalKeyLease,
    slot_bound: bool,
}

impl DynamicHeapBinding {
    #[inline]
    const fn key(&self) -> ThreadLocalKey {
        self.lease.key()
    }

    #[inline]
    fn mark_slot_bound_after_publication(&mut self) {
        debug_assert!(!self.slot_bound);
        self.slot_bound = true;
    }

    #[inline]
    fn clear_slot_bound(&mut self) -> bool {
        if !self.slot_bound {
            return false;
        }
        self.slot_bound = false;
        true
    }

    #[inline]
    fn release_after_slot_clear(&mut self) -> Result<(), DynamicTheapError> {
        if self.slot_bound {
            return Err(DynamicTheapError::SlotOwnership);
        }
        self.lease.release().map_err(DynamicTheapError::Key)
    }
}

#[derive(Clone, Copy)]
struct UnrelatedRoots {
    default: NonNull<Theap>,
    fast: Option<NonNull<()>>,
    cached: NonNull<Theap>,
}

impl UnrelatedRoots {
    #[inline]
    fn capture() -> Self {
        Self {
            default: default_theap(),
            fast: fast_slot_peek(),
            cached: cached_theap(),
        }
    }

    #[inline]
    fn still_matches(self) -> bool {
        core::ptr::eq(default_theap().as_ptr(), self.default.as_ptr())
            && fast_slot_peek() == self.fast
            && core::ptr::eq(cached_theap().as_ptr(), self.cached.as_ptr())
    }
}

/// The exact private owner of one current-thread regular-key Theap.
///
/// The caller's `Pin<&mut Heap>` proves the heap address stays stable while
/// the intrusive Theap lists contain it. The key lease, backing, TLD
/// registration/allocation, and Theap allocation are all retained as fields.
/// The raw marker makes this owner `!Send` and `!Sync`; every live operation
/// also rechecks the captured AArch64 `TPIDR_EL0` identity.
#[must_use = "a dynamic Theap attachment must explicitly tear down or remain terminally retained"]
pub(crate) struct DynamicTheapAttachment<'heap> {
    heap: Pin<&'heap mut Heap>,
    binding: Option<DynamicHeapBinding>,
    backing: Option<ThreadLocalBackingOwner>,
    tld: Option<DynamicAttachedThreadLocalData>,
    theap: Option<MetaAllocation<'static>>,
    roots: UnrelatedRoots,
    thread: crate::types::LiveThreadId,
    state: DynamicAttachmentState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl<'heap> DynamicTheapAttachment<'heap> {
    /// Begins one later-ticket dynamic Theap binding using the process-global
    /// regular-key registry and metadata owner.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own this exact current thread's allocator
    /// lifecycle and process-selection decision. `heap` must be the unique,
    /// address-stable `Heap::bootstrap_empty()` caller image with no aliases,
    /// private-lock guards/waiters, pages, or prior binding. The caller must
    /// not create a second TLD/backing owner, mutate compiler-TLS roots, move
    /// this `!Send` owner to another thread, or release the regular key outside
    /// this capability. It must drive a returned attachment through successful
    /// teardown before allowing it to drop or reusing `heap`. A retained
    /// terminal owner that cannot finish teardown must stay alive (or be
    /// deliberately leaked) for as long as its thread/TLS/process state and
    /// heap storage can be observed; dropping it must not manufacture cleanup.
    /// Ticket zero is explicitly reserved for `MainStaticTheapAttachment`;
    /// this method returns `FirstTicketReserved` without consuming it.
    pub(crate) unsafe fn begin(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        // SAFETY: the process-global identity/capabilities have process
        // lifetime, and the caller upholds the documented current-thread
        // ownership condition.
        unsafe {
            Self::begin_with_components(
                config,
                heap,
                MainSubprocess::global(),
                MetaAllocator::global(),
                OwnedThreadLocalKeyRegistry::global(),
            )
        }
    }

    /// Builds the same private owner over explicit process-lived components.
    /// This supports isolated lifecycle tests without creating a second public
    /// attachment API.
    ///
    /// # Safety
    ///
    /// The obligations are identical to [`Self::begin`], and all components
    /// must name the same selected main-subprocess identity.
    unsafe fn begin_with_components(
        config: MemoryConfig,
        heap: Pin<&'heap mut Heap>,
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        registry: &'static OwnedThreadLocalKeyRegistry,
    ) -> Result<Self, DynamicTheapBeginError<'heap>> {
        let thread = current_thread_identity()
            .ok_or(DynamicTheapBeginError::Rejected(DynamicTheapError::InvalidCurrentThread))?;
        let roots = UnrelatedRoots::capture();
        let tld = match unsafe {
            ThreadLocalDataOwner::begin_later_dynamic_attachment_with_metadata(
                subprocess, metadata, config,
            )
        } {
            Ok(tld) => tld,
            Err(ThreadLocalDataError::FirstTicketReserved) => {
                return Err(DynamicTheapBeginError::Rejected(
                    DynamicTheapError::FirstTicketReserved,
                ));
            }
            Err(error) => {
                return Err(DynamicTheapBeginError::Rejected(
                    DynamicTheapError::ThreadLocalData(error),
                ));
            }
        };
        let mut attachment = Self {
            heap,
            binding: None,
            backing: None,
            tld: Some(tld),
            theap: None,
            roots,
            thread,
            state: DynamicAttachmentState::Preparing,
            _not_send_or_sync: PhantomData,
        };

        let backing = match unsafe {
            ThreadLocalBackingOwner::begin_with_metadata(metadata, subprocess, config)
        } {
            Ok(backing) => backing,
            Err(error) => {
                return match attachment.cancel_before_heap_binding() {
                    Ok(()) => Err(DynamicTheapBeginError::Rejected(
                        DynamicTheapError::Backing(error),
                    )),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        attachment.backing = Some(backing);

        let lease = match registry.claim_for_main_subprocess(config, subprocess, metadata) {
            Ok(lease) => lease,
            Err(error) => {
                return match attachment.cancel_before_heap_binding() {
                    Ok(()) => Err(DynamicTheapBeginError::Rejected(DynamicTheapError::Key(error))),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        let key = lease.key();
        attachment.binding = Some(DynamicHeapBinding {
            lease,
            slot_bound: false,
        });
        let heap_initialized = {
            let heap = attachment.heap_mut();
            // SAFETY: the outer unsafe constructor carries the unique pristine
            // caller-heap image proof required by this narrow initializer.
            unsafe { heap.initialize_dynamic_binding(subprocess, key.raw() as usize) }
        };
        if !heap_initialized {
            return Err(attachment.into_retained_begin_failure(DynamicTheapError::HeapBinding));
        }

        let allocation = match metadata.zalloc_for_main_subprocess(config, subprocess, size_of::<Theap>()) {
            Ok(allocation) => allocation,
            Err(error) => {
                return match attachment.cancel_before_theap_publication() {
                    Ok(()) => Err(DynamicTheapBeginError::Rejected(
                        DynamicTheapError::TheapMetadata(error),
                    )),
                    Err(cleanup) => Err(attachment.into_retained_begin_failure(cleanup)),
                };
            }
        };
        attachment.theap = Some(allocation);
        let initialized = attachment.initialize_and_publish_theap();
        match initialized {
            Ok(()) => {
                attachment.state = DynamicAttachmentState::Attached;
                Ok(attachment)
            }
            Err(error) => Err(attachment.into_retained_begin_failure(error)),
        }
    }

    /// Returns the bound regular key while the attachment retains its lease.
    #[inline]
    pub(crate) fn key(&self) -> Result<ThreadLocalKey, DynamicTheapError> {
        self.ensure_attached_current()?;
        self.binding
            .as_ref()
            .map(DynamicHeapBinding::key)
            .ok_or(DynamicTheapError::Poisoned)
    }

    /// Performs the bounded no-page teardown sequence.
    pub(crate) fn teardown(&mut self) -> Result<(), DynamicTheapError> {
        if self.state == DynamicAttachmentState::AwaitingKeyRelease {
            return self.finish_key_release();
        }
        self.prevalidate_teardown()?;

        let key = self.binding()?.key();
        let theap_pointer = self.theap_pointer()?;
        let clear_slot = {
            let backing = self.backing.as_mut().ok_or(DynamicTheapError::Poisoned)?;
            backing.set(key, core::ptr::null_mut())
        };
        if let Err(error) = clear_slot {
            return Err(self.poison(DynamicTheapError::Backing(error)));
        }
        let slot_cleared = match self.binding.as_mut() {
            Some(binding) => binding.clear_slot_bound(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if !slot_cleared {
            return Err(self.poison(DynamicTheapError::SlotOwnership));
        }
        let backing_teardown = match self.backing.as_mut() {
            Some(backing) => backing.teardown(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = backing_teardown {
            return Err(self.poison(DynamicTheapError::Backing(error)));
        }
        self.backing = None;

        let detach_heap = match self.heap_and_tld_mut() {
            Ok((heap, tld)) => tld.detach_one_theap_from_heap(heap, theap_pointer),
            Err(error) => return Err(self.poison(error)),
        };
        if let Err(error) = detach_heap {
            return Err(self.poison(DynamicTheapError::TheapList(error)));
        }
        let detach_tld = match self.tld.as_mut() {
            Some(tld) => match tld.current_mut() {
                Ok(tld) => tld.detach_one_theap_from_tld(theap_pointer),
                Err(error) => return Err(self.poison(DynamicTheapError::ThreadLocalData(error))),
            },
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = detach_tld {
            return Err(self.poison(DynamicTheapError::TheapList(error)));
        }
        let clear_theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .map(Theap::clear_dynamic_metadata_after_detach);
        match clear_theap {
            Some(true) => {}
            Some(false) => return Err(self.poison(DynamicTheapError::TheapClear)),
            None => return Err(self.poison(DynamicTheapError::TheapProjection)),
        }
        let mut theap = match self.theap.take() {
            Some(theap) => theap,
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        let metadata = match self.tld.as_ref() {
            Some(tld) => tld.metadata(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = metadata.free(&mut theap) {
            return Err(self.poison(DynamicTheapError::TheapMetadata(error)));
        }

        let tld_teardown = match self.tld.as_mut() {
            Some(tld) => tld.teardown_after_theap_detached(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        if let Err(error) = tld_teardown {
            return Err(self.poison(DynamicTheapError::ThreadLocalData(error)));
        }
        self.tld = None;
        let heap_retired = {
            let heap = self.heap_mut();
            // SAFETY: both lists are detached and the owner has exclusive
            // caller-storage authority through the held Pin.
            unsafe { heap.retire_dynamic_binding_after_detach() }
        };
        if !heap_retired {
            return Err(self.poison(DynamicTheapError::HeapRetire));
        }
        self.state = DynamicAttachmentState::AwaitingKeyRelease;
        self.finish_key_release()
    }

    fn initialize_and_publish_theap(&mut self) -> Result<(), DynamicTheapError> {
        let key = self.binding()?.key();
        let theap_pointer = {
            let (heap, tld, allocation) = self.heap_tld_theap_mut()?;
            let theap = allocation
                .initialize_dynamic_theap_metadata()
                .ok_or(DynamicTheapError::TheapProjection)?;
            // SAFETY: this attachment retains the caller's pinned Heap, the
            // exact metadata TLD capability, and the Theap allocation through
            // both list lifetimes; its `!Send`/TPIDR proof excludes a second
            // thread or list mutator until source-ordered detachment.
            unsafe { theap.initialize_dynamic_metadata(heap, tld) }
                .map_err(DynamicTheapError::TheapInit)?;
            core::ptr::from_mut(theap).cast::<()>()
        };
        let published = match self.backing.as_mut() {
            Some(backing) => backing.set(key, theap_pointer),
            None => return Err(DynamicTheapError::Poisoned),
        };
        if let Err(error) = published {
            return Err(DynamicTheapError::Backing(error));
        }
        // This is infallible by construction: it records only the successful
        // source publication immediately above, so no retained owner can
        // carry a live regular slot while claiming it is unbound.
        self.binding
            .as_mut()
            .expect("a successful regular-slot publication retains its key binding")
            .mark_slot_bound_after_publication();
        Ok(())
    }

    fn prevalidate_teardown(&mut self) -> Result<(), DynamicTheapError> {
        self.ensure_attached_current()?;
        if !self.roots.still_matches() {
            return Err(DynamicTheapError::RootOwnership);
        }
        let key = self.binding()?.key();
        if !self.binding()?.slot_bound {
            return Err(DynamicTheapError::SlotOwnership);
        }
        let theap_pointer = self.theap_pointer()?;
        let subprocess = self
            .tld
            .as_ref()
            .ok_or(DynamicTheapError::Poisoned)?
            .subprocess();
        let (page_count, matches_thread, bound_to_subprocess) = {
            let theap = self
                .theap
                .as_mut()
                .and_then(MetaAllocation::dynamic_theap_mut)
                .ok_or(DynamicTheapError::TheapProjection)?;
            (
                theap.page_count(),
                theap.matches_thread(self.thread),
                theap.is_bound_to_main_subprocess(subprocess),
            )
        };
        if page_count != 0 {
            return Err(DynamicTheapError::PageCountNonZero);
        }
        let tld_member = match self.tld.as_mut() {
            Some(tld) => tld
                .current_mut()
                .map_err(DynamicTheapError::ThreadLocalData)?
                .has_exact_theap_member(theap_pointer),
            None => return Err(DynamicTheapError::Poisoned),
        };
        let heap = self.heap.as_ref().get_ref();
        if !matches_thread
            || !bound_to_subprocess
            || !tld_member
            || !heap.has_exact_theap_member(theap_pointer)
            || !heap.matches_dynamic_binding(
                subprocess,
                key.raw() as usize,
            )
        {
            return Err(DynamicTheapError::ListOwnership);
        }
        let value = self
            .backing
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .get(key)
            .map_err(DynamicTheapError::Backing)?;
        if value != theap_pointer.cast() {
            return Err(DynamicTheapError::SlotOwnership);
        }
        Ok(())
    }

    fn cancel_before_theap_publication(&mut self) -> Result<(), DynamicTheapError> {
        if let Some(backing) = self.backing.as_mut() {
            backing.teardown().map_err(DynamicTheapError::Backing)?;
        }
        self.backing = None;
        let retired = {
            let heap = self.heap_mut();
            // SAFETY: no Theap/list entry has been published on this path.
            unsafe { heap.retire_dynamic_binding_after_detach() }
        };
        if !retired {
            return Err(DynamicTheapError::HeapRetire);
        }
        self.tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .teardown_after_theap_detached()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        self.tld = None;
        self.state = DynamicAttachmentState::AwaitingKeyRelease;
        self.finish_key_release()
    }

    /// Cleans up the empty TLD/backing pair before any heap/key/Theap state
    /// exists. This is the recoverable path for a backing or regular-registry
    /// allocation failure after a later TLD ticket has activated its live
    /// registration: successful cleanup must not manufacture a retained live
    /// owner merely because its source sequence was consumed.
    fn cancel_before_heap_binding(&mut self) -> Result<(), DynamicTheapError> {
        if let Some(backing) = self.backing.as_mut() {
            backing.teardown().map_err(DynamicTheapError::Backing)?;
        }
        self.backing = None;
        self.tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .teardown_after_theap_detached()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        self.tld = None;
        Ok(())
    }

    fn into_retained_begin_failure(
        mut self,
        error: DynamicTheapError,
    ) -> DynamicTheapBeginError<'heap> {
        if self.state != DynamicAttachmentState::AwaitingKeyRelease {
            self.state = DynamicAttachmentState::Poisoned;
        }
        DynamicTheapBeginError::Retained {
            error,
            attachment: self,
        }
    }

    #[inline]
    fn poison(&mut self, error: DynamicTheapError) -> DynamicTheapError {
        self.state = DynamicAttachmentState::Poisoned;
        error
    }

    #[inline]
    fn ensure_attached_current(&self) -> Result<(), DynamicTheapError> {
        match self.state {
            DynamicAttachmentState::Attached => match current_thread_identity() {
                Some(thread) if thread == self.thread => Ok(()),
                Some(_) => Err(DynamicTheapError::InvalidCurrentThread),
                None => Err(DynamicTheapError::InvalidCurrentThread),
            },
            DynamicAttachmentState::TornDown => Err(DynamicTheapError::TornDown),
            DynamicAttachmentState::Preparing
            | DynamicAttachmentState::AwaitingKeyRelease
            | DynamicAttachmentState::Poisoned => {
                Err(DynamicTheapError::Poisoned)
            }
        }
    }

    /// Completes only the retained linear regular-key release after every
    /// backing/TLD/Theap/Heap capability has already been retired. A key-lock
    /// error is guaranteed by the lease API to be pre-mutation, so it keeps
    /// this exact owner in `AwaitingKeyRelease` for a later retry. Any other
    /// release failure terminalizes the owner rather than claiming a retry
    /// over ambiguous registry state.
    fn finish_key_release(&mut self) -> Result<(), DynamicTheapError> {
        match current_thread_identity() {
            Some(thread) if thread == self.thread => {}
            Some(_) | None => return Err(DynamicTheapError::InvalidCurrentThread),
        }
        let release = match self.binding.as_mut() {
            Some(binding) => binding.release_after_slot_clear(),
            None => return Err(self.poison(DynamicTheapError::Poisoned)),
        };
        match release {
            Ok(()) => {
                self.binding = None;
                self.state = DynamicAttachmentState::TornDown;
                Ok(())
            }
            Err(error @ DynamicTheapError::Key(OwnedThreadLocalKeyError::Lock(_))) => Err(error),
            Err(error) => Err(self.poison(error)),
        }
    }

    #[inline]
    fn binding(&self) -> Result<&DynamicHeapBinding, DynamicTheapError> {
        self.binding.as_ref().ok_or(DynamicTheapError::Poisoned)
    }

    #[inline]
    fn heap_mut(&mut self) -> &mut Heap {
        // SAFETY: the attachment exclusively owns the caller's pinned mutable
        // heap borrow for its whole lifetime.
        unsafe { Pin::get_unchecked_mut(self.heap.as_mut()) }
    }

    fn heap_and_tld_mut(&mut self) -> Result<(&mut Heap, &mut crate::types::ThreadLocalData), DynamicTheapError> {
        let DynamicTheapAttachment { heap, tld, .. } = self;
        // SAFETY: this owner retains the sole pinned mutable heap borrow.
        let heap = unsafe { Pin::get_unchecked_mut(heap.as_mut()) };
        let tld = tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .current_mut()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        Ok((heap, tld))
    }

    fn heap_tld_theap_mut(
        &mut self,
    ) -> Result<
        (
            &mut Heap,
            &mut crate::types::ThreadLocalData,
            &mut MetaAllocation<'static>,
        ),
        DynamicTheapError,
    > {
        let DynamicTheapAttachment {
            heap, tld, theap, ..
        } = self;
        // SAFETY: this owner retains the sole pinned mutable heap borrow.
        let heap = unsafe { Pin::get_unchecked_mut(heap.as_mut()) };
        let tld = tld
            .as_mut()
            .ok_or(DynamicTheapError::Poisoned)?
            .current_mut()
            .map_err(DynamicTheapError::ThreadLocalData)?;
        let theap = theap.as_mut().ok_or(DynamicTheapError::Poisoned)?;
        Ok((heap, tld, theap))
    }

    fn theap_pointer(&mut self) -> Result<*mut Theap, DynamicTheapError> {
        // The address is derived only from the retained typed dynamic-Theap
        // metadata capability. It is used as an intrusive-list witness while
        // that capability remains exclusively owned by this attachment; no
        // externally supplied pointer is dereferenced through this path.
        let theap = self
            .theap
            .as_mut()
            .and_then(MetaAllocation::dynamic_theap_mut)
            .ok_or(DynamicTheapError::TheapProjection)?;
        Ok(core::ptr::from_mut(theap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler_tls::{
        dynamic_backing_peek, is_empty_dynamic_backing, set_cached_theap,
    };
    use crate::os::{PageSize, fault};
    use crate::tld::ThreadLocalDataOwner;
    use crate::types::MemoryKind;
    use std::boxed::Box;
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the pinned native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn fixture() -> (
        &'static MainSubprocess,
        Pin<&'static MetaAllocator>,
        &'static OwnedThreadLocalKeyRegistry,
    ) {
        (
            MainSubprocess::test_static_owner(),
            MetaAllocator::test_static_owner(),
            OwnedThreadLocalKeyRegistry::test_static_owner(),
        )
    }

    fn pinned_empty_heap() -> Pin<&'static mut Heap> {
        let heap: &'static mut Heap = Box::leak(Box::new(Heap::bootstrap_empty()));
        // SAFETY: the deliberately leaked test heap has one stable address;
        // each test creates only one attachment over its unique mutable ref.
        unsafe { Pin::new_unchecked(heap) }
    }

    fn consume_static_ticket(
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
    ) {
        let mut generic = unsafe {
            ThreadLocalDataOwner::begin_with_test_metadata(subprocess, metadata, memory_config())
        }
        .expect("the isolated fixture begins with its ticket-zero generic TLD");
        generic
            .teardown()
            .expect("the generic ticket-zero owner retires before dynamic selection");
    }

    fn attach(
        subprocess: &'static MainSubprocess,
        metadata: Pin<&'static MetaAllocator>,
        registry: &'static OwnedThreadLocalKeyRegistry,
        heap: Pin<&'static mut Heap>,
    ) -> DynamicTheapAttachment<'static> {
        match unsafe {
            DynamicTheapAttachment::begin_with_components(
                memory_config(),
                heap,
                subprocess,
                metadata,
                registry,
            )
        } {
            Ok(owner) => owner,
            Err(DynamicTheapBeginError::Rejected(error)) => {
                panic!("the prepared later-ticket dynamic attachment succeeds: {error:?}")
            }
            Err(DynamicTheapBeginError::Retained { error, .. }) => {
                panic!("the prepared later-ticket dynamic attachment did not enter terminal state: {error:?}")
            }
        }
    }

    #[test]
    fn regular_slot_publication_keeps_default_fast_cached_roots_and_witnesses_theap_init_order() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let dynamic_before = dynamic_backing_peek();
            let roots_before = UnrelatedRoots::capture();
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let key = owner.key().expect("attached owner retains its regular key");
            assert_ne!(key.raw(), 0);
            assert_ne!(key.raw(), crate::thread_local::TLS_FAST_KEY_RAW);
            assert_eq!(key.index().get(), 0);
            assert_eq!(key.version(), 1);
            assert!(roots_before.still_matches());
            assert_ne!(dynamic_backing_peek(), dynamic_before);

            let theap_pointer = owner.theap_pointer().unwrap();
            let slot = owner
                .backing
                .as_mut()
                .unwrap()
                .get(key)
                .expect("the retained backing projects its own regular slot");
            assert_eq!(slot, theap_pointer.cast());
            assert!(owner.binding.as_ref().unwrap().slot_bound);
            assert_eq!(
                owner
                    .binding
                    .as_mut()
                    .unwrap()
                    .release_after_slot_clear(),
                Err(DynamicTheapError::SlotOwnership),
                "a live backing slot keeps the linear key lease unreleasable"
            );
            assert_eq!(
                owner.backing.as_mut().unwrap().get(key).unwrap(),
                theap_pointer.cast(),
                "a rejected key release cannot clear or stale the live slot"
            );
            let heap = owner.heap.as_ref().get_ref();
            assert!(heap.has_exact_theap_member(theap_pointer));
            assert!(heap.matches_dynamic_binding(subprocess, key.raw() as usize));
            let heap_fields = heap.test_main_static_fields();
            assert_eq!(heap_fields.memid.kind(), MemoryKind::None);
            assert_eq!(heap_fields.theap_slot, key.raw() as usize);
            assert_eq!(heap_fields.numa_node, -1);
            let tld = owner.tld.as_mut().unwrap().current_mut().unwrap();
            assert!(tld.has_exact_theap_member(theap_pointer));
            assert!(tld.test_theap_head_is(theap_pointer));
            let fields = owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .test_main_static_fields();
            // The non-null heap is the source initialized predicate, so this
            // observes every preceding TLD/list/random/cookie field before
            // the Release heap publication.
            assert!(fields.initialized);
            assert_eq!(fields.refcount, 1);
            assert!(fields.cookie_is_odd);
            assert!(fields.random_initialized);
            assert!(!fields.random_weak);
            assert_eq!(fields.page_full_retain, 2);
            assert!(fields.allows_page_reclaim);
            assert!(fields.allows_page_abandon);
            assert!(!fields.detached);
            assert_eq!(fields.memid.kind(), MemoryKind::Malloc);
            assert!(fields.memid.is_pinned());
            assert!(fields.memid.initially_committed());

            owner.teardown().expect("the no-page regular attachment tears down");
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(dynamic_backing_peek().is_none());
            assert!(roots_before.still_matches());
            assert!(owner.heap.as_ref().get_ref().test_main_static_fields().theaps_empty);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::TornDown));
        })
        .join()
        .expect("the current-thread attachment test completes");
    }

    #[test]
    fn nonzero_page_rejection_is_wholly_pre_mutation_and_recovery_detaches_after_page_removal() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let key = owner.key().unwrap();
            let theap_pointer = owner.theap_pointer().unwrap();
            owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .note_page_added();
            assert_eq!(owner.teardown(), Err(DynamicTheapError::PageCountNonZero));
            assert_eq!(owner.state, DynamicAttachmentState::Attached);
            assert!(roots.still_matches());
            assert_eq!(
                owner.backing.as_mut().unwrap().get(key).unwrap(),
                theap_pointer.cast(),
                "the regular slot is untouched before the page-count rejection"
            );
            assert!(owner.heap.as_ref().get_ref().has_exact_theap_member(theap_pointer));
            assert!(owner
                .tld
                .as_mut()
                .unwrap()
                .current_mut()
                .unwrap()
                .has_exact_theap_member(theap_pointer));
            assert_eq!(subprocess.live_thread_count(), 1);
            assert!(owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .note_page_removed());
            owner.teardown().unwrap();
            assert_eq!(subprocess.live_thread_count(), 0);
        })
        .join()
        .expect("the pre-mutation page-count test completes");
    }

    #[test]
    fn root_mismatch_preserves_the_foreign_root_and_retains_attachment_authority() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            let roots = UnrelatedRoots::capture();
            let key = owner.key().unwrap();
            let slot = owner.backing.as_mut().unwrap().get(key).unwrap();
            let mut foreign = Theap::empty();
            let foreign_pointer = NonNull::from(&mut foreign);
            set_cached_theap(foreign_pointer);
            assert_eq!(owner.teardown(), Err(DynamicTheapError::RootOwnership));
            assert_eq!(cached_theap(), foreign_pointer);
            assert_eq!(owner.state, DynamicAttachmentState::Attached);
            assert_eq!(owner.backing.as_mut().unwrap().get(key).unwrap(), slot);
            assert_eq!(subprocess.live_thread_count(), 1);
            // Restore precisely the captured unrelated root after proving the
            // owner did not overwrite the foreign pointer.
            set_cached_theap(roots.cached);
            owner.teardown().unwrap();
        })
        .join()
        .expect("foreign-root preflight test completes");
    }

    #[test]
    fn tld_and_theap_allocation_failures_consume_only_total_sequence_and_leave_roots_pristine() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            let dynamic_before = dynamic_backing_peek();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::ThreadLocalData(
                    ThreadLocalDataError::Metadata(MetaError::InitializationFailed)
                )))
            ));
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert_eq!(dynamic_backing_peek(), dynamic_before);
            assert!(roots.still_matches());
            fault.set(fault::Plan::disabled());

            metadata
                .get_ref()
                .test_fail_next_direct_zeroed_size(size_of::<Theap>());
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::TheapMetadata(
                    MetaError::AllocationUnavailable
                )))
            ));
            assert_eq!(subprocess.total_thread_count(), 3);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert!(roots.still_matches());
        })
        .join()
        .expect("allocation failures leave no live dynamic attachment");
    }

    #[test]
    fn registry_claim_failure_after_tld_registration_cleans_up_without_retaining_live_count() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            registry.test_fail_next_bitmap_allocation();
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::Key(_)))
            ));
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert!(roots.still_matches());
        })
        .join()
        .expect("recoverable registry OOM cleans up the activated TLD");
    }

    #[test]
    fn post_list_publication_backing_failure_returns_a_retained_poisoned_owner() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let roots = UnrelatedRoots::capture();
            let backing_size = crate::compiler_tls::DynamicThreadLocalBacking::allocation_size(16)
                .expect("the first source backing request is representable");
            assert_ne!(backing_size, size_of::<Theap>());
            metadata
                .get_ref()
                .test_fail_next_direct_zeroed_size(backing_size);
            let retained = match unsafe {
                DynamicTheapAttachment::begin_with_components(
                    memory_config(),
                    pinned_empty_heap(),
                    subprocess,
                    metadata,
                    registry,
                )
            } {
                Err(DynamicTheapBeginError::Retained { error, attachment }) => {
                    assert_eq!(
                        error,
                        DynamicTheapError::Backing(ThreadLocalBackingError::Metadata(
                            MetaError::AllocationUnavailable
                        ))
                    );
                    attachment
                }
                Ok(_) | Err(DynamicTheapBeginError::Rejected(_)) => {
                    panic!("a post-list backing allocation failure retains its concrete owner")
                }
            };
            let mut owner = retained;
            let theap_pointer = owner.theap_pointer().unwrap();
            assert_eq!(owner.state, DynamicAttachmentState::Poisoned);
            assert!(owner.backing.is_some());
            assert!(owner.tld.is_some());
            assert!(owner.theap.is_some());
            assert!(owner.binding.as_ref().is_some_and(|binding| !binding.slot_bound));
            assert_eq!(
                registry.test_live_lease_count(),
                1,
                "the unbound key lease stays live"
            );
            assert_eq!(subprocess.total_thread_count(), 2);
            assert_eq!(subprocess.live_thread_count(), 1);
            assert!(roots.still_matches());
            assert!(is_empty_dynamic_backing(dynamic_backing_peek().unwrap()));
            assert!(owner.heap.as_ref().get_ref().has_exact_theap_member(theap_pointer));
            assert!(owner
                .tld
                .as_mut()
                .unwrap()
                .current_mut()
                .unwrap()
                .has_exact_theap_member(theap_pointer));
            assert!(owner
                .theap
                .as_mut()
                .unwrap()
                .dynamic_theap_mut()
                .unwrap()
                .is_initialized());
            assert_eq!(owner.teardown(), Err(DynamicTheapError::Poisoned));
            assert_eq!(
                registry.test_live_lease_count(),
                1,
                "poisoning cannot release the key"
            );
            assert_eq!(subprocess.live_thread_count(), 1);
            // This isolated invalid-owner fixture deliberately retains every
            // terminal capability. Dropping the token would falsely model a
            // completed cleanup without a source-ordered release path.
            core::mem::forget(owner);
        })
        .join()
        .expect("retained post-publication owner test completes");
    }

    #[test]
    fn stale_regular_generation_is_null_after_teardown_and_slot_reclaim() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut first = attach(subprocess, metadata, registry, pinned_empty_heap());
            let stale = first.key().unwrap();
            first.teardown().unwrap();
            // `_mi_thread_locals_thread_done` leaves the old thread's backing
            // null. A later attachment therefore belongs to a fresh native
            // thread, while the process registry still reclaims the key.
            thread::spawn(move || {
                let mut second = attach(subprocess, metadata, registry, pinned_empty_heap());
                let current = second.key().unwrap();
                assert_eq!(current.index(), stale.index());
                assert_ne!(current.version(), stale.version());
                assert!(second.backing.as_mut().unwrap().get(stale).unwrap().is_null());
                assert!(!second.backing.as_mut().unwrap().get(current).unwrap().is_null());
                second.teardown().unwrap();
            })
            .join()
            .expect("a fresh native thread receives the reclaimed regular key");
        })
        .join()
        .expect("generation reuse remains source-stale-safe");
    }

    #[test]
    fn key_release_lock_failure_keeps_only_the_linear_lease_for_retry() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            registry.test_fail_next_release_lock();
            assert_eq!(
                owner.teardown(),
                Err(DynamicTheapError::Key(OwnedThreadLocalKeyError::Lock(
                    crabc_core::Errno::INTR
                )))
            );
            assert_eq!(owner.state, DynamicAttachmentState::AwaitingKeyRelease);
            assert!(owner.backing.is_none());
            assert!(owner.tld.is_none());
            assert!(owner.theap.is_none());
            assert!(owner.binding.as_ref().is_some_and(|binding| !binding.slot_bound));
            assert!(owner.heap.as_ref().get_ref().test_main_static_fields().theaps_empty);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(dynamic_backing_peek().is_none());
            owner
                .teardown()
                .expect("the exact retained lease retries its pre-mutation release");
            assert_eq!(owner.state, DynamicAttachmentState::TornDown);
        })
        .join()
        .expect("the key-release retry test completes");
    }

    #[test]
    fn dynamic_selection_never_seizes_ticket_zero_and_generic_zero_can_precede_a_later_attachment() {
        thread::spawn(|| {
            let (subprocess, metadata, registry) = fixture();
            let roots = UnrelatedRoots::capture();
            assert!(matches!(
                unsafe {
                    DynamicTheapAttachment::begin_with_components(
                        memory_config(),
                        pinned_empty_heap(),
                        subprocess,
                        metadata,
                        registry,
                    )
                },
                Err(DynamicTheapBeginError::Rejected(DynamicTheapError::FirstTicketReserved))
            ));
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(roots.still_matches());
            consume_static_ticket(subprocess, metadata);
            let mut owner = attach(subprocess, metadata, registry, pinned_empty_heap());
            assert_eq!(owner.tld.as_ref().unwrap().sequence().get(), 1);
            owner.teardown().unwrap();
        })
        .join()
        .expect("dynamic selection observes generic ticket-zero ownership exactly");
    }
}
