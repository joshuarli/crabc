// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:184-214,305-360,536-592`
// (`mi_heap_main_init_once`, `_mi_thread_init_with_heap`, and
// `mi_process_init_once`) and `src/subproc.c:29-46,95-101`.

//! Source-ordered main-process initialization.
//!
//! The current port has one deliberately bounded process-startup transition:
//! select the ticket-zero static branch, initialize the source static main
//! Heap, ready the detached metadata route, publish the process PageMap, and
//! only then attach the ticket-zero TLD/Theap and compiler-TLS roots. This is
//! an ordering and ownership coordinator, not a general allocator startup:
//! it does not choose options, reserve or manage the process-shared arena,
//! initialize pthread keys, route allocations/frees, run process shutdown,
//! or expose the metadata allocator's private map/arena as process-global
//! state. Its one page-bearing factory only creates a private first-fresh-page
//! owner; that owner remains arena-free until a valid allocation miss.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crate::main_theap::{
    MainStaticAttachmentStorage, MainStaticHeapFoundation,
    MainStaticHeapFoundationError, MainStaticHeapLease, MainStaticTheapAttachment,
    MainStaticPageSessionError, MainStaticProcessPageSession,
    MainStaticProcessPageSessionError, MainStaticTheapError,
};
use crate::main_static_page::{
    MainStaticFirstArenaPageAllocator, MainStaticFirstArenaPageAllocatorBeginError,
};
use crate::meta::{MetaAllocator, MetaError};
use crate::os::MemoryConfig;
use crate::page_map::PageMapHeader;
use crate::process_arena::{
    ProcessPageArenaLease, ProcessPageArenaLeaseError, ProcessSharedArenaError,
    ProcessSharedArenaStorage,
};
use crate::process_page_map::{
    ProcessPageMapError, ProcessPageMapLease, ProcessPageMapStorage,
};
use crate::subproc::{
    MainStaticBootstrapSelectionError, MainSubprocess,
};

const COLD: u8 = 0;
const INITIALIZING: u8 = 1;
const READY: u8 = 2;
const RETAINED: u8 = 3;

/// Final process-lifetime state for the bounded source main-process startup.
///
/// `READY` is published only after every predecessor in the source order has
/// completed. `RETAINED` is terminal: a failure after the coordinator wins
/// the static ticket-zero selection may leave a static Heap, detached metadata
/// image, PageMap, TLD, or TLS root live, so retrying as if the process were
/// cold would invent an unsafe second startup branch.
pub(crate) struct ProcessMainInitializationStorage {
    state: AtomicU8,
    config: UnsafeCell<MaybeUninit<MemoryConfig>>,
    subprocess: AtomicPtr<MainSubprocess>,
    page_map_storage: AtomicPtr<ProcessPageMapStorage>,
}

// SAFETY: COLD -> INITIALIZING is an exclusive CAS. The final configuration,
// subprocess, and PageMap-storage pointer are written before READY's Release
// publication and never replaced. A live `ProcessMainThread` remains
// current-thread-only through its contained main attachment; READY leases are
// immutable process-root witnesses only.
unsafe impl Sync for ProcessMainInitializationStorage {}

impl ProcessMainInitializationStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            config: UnsafeCell::new(MaybeUninit::uninit()),
            subprocess: AtomicPtr::new(core::ptr::null_mut()),
            page_map_storage: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Returns the one production process coordinator. It remains cold until
    /// a future runtime startup path supplies the frozen memory configuration.
    #[inline]
    pub(crate) fn global() -> &'static Self {
        &PROCESS_MAIN_INITIALIZATION
    }

    /// Builds an isolated leaked process-lifetime startup fixture.
    #[cfg(test)]
    pub(crate) fn test_static_owner() -> &'static Self {
        std::boxed::Box::leak(std::boxed::Box::new(Self::new()))
    }

    /// Runs the bounded source startup path over the process-static owners.
    ///
    /// # Safety
    ///
    /// The caller must own this thread's allocator startup/teardown lifecycle
    /// and must retain the returned `ProcessMainThread` until its explicit
    /// teardown or terminal retention. It must not concurrently construct a
    /// generic ticket-zero TLD, mutate compiler-TLS roots, or independently
    /// initialize the same source-main storage. The coordinator itself rejects
    /// any unsafe reentry after it wins the initial CAS.
    pub(crate) unsafe fn initialize(
        &'static self,
        config: MemoryConfig,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: the process statics all have process lifetime and the
        // caller upholds the current-thread lifecycle contract above.
        unsafe {
            self.initialize_with_components(
                config,
                MainStaticAttachmentStorage::global(),
                MainSubprocess::global(),
                MetaAllocator::global(),
                ProcessPageMapStorage::global(),
            )
        }
    }

    /// Runs the same transition against isolated process-lifetime owners.
    ///
    /// # Safety
    ///
    /// Test callers retain every supplied final static owner, own the current
    /// thread's roots/TLD lifecycle, and do not introduce a competing source
    /// ticket-zero constructor.
    #[cfg(test)]
    pub(crate) unsafe fn initialize_with_test_components(
        &'static self,
        config: MemoryConfig,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        // SAFETY: forwarded unchanged to the common source-order transition.
        unsafe {
            self.initialize_with_components(
                config,
                main_static,
                subprocess,
                metadata,
                page_map_storage,
            )
        }
    }

    unsafe fn initialize_with_components(
        &'static self,
        config: MemoryConfig,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
        metadata: core::pin::Pin<&'static MetaAllocator>,
        page_map_storage: &'static ProcessPageMapStorage,
    ) -> Result<ProcessMainThread, ProcessMainInitError> {
        match self.state.load(Ordering::Acquire) {
            COLD => {}
            INITIALIZING => return Err(ProcessMainInitError::Initializing),
            READY => return Err(ProcessMainInitError::AlreadyInitialized),
            RETAINED | _ => return Err(ProcessMainInitError::Retained),
        }

        // This preflight is intentionally before both the process-once claim
        // and static selection. A foreign root/current-thread observation is
        // pure: it leaves the process storage, ticket sequence, static Heap,
        // metadata owner, and PageMap untouched.
        MainStaticTheapAttachment::preflight_current_roots()
            .map_err(ProcessMainInitError::Preflight)?;
        if self
            .state
            .compare_exchange(COLD, INITIALIZING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return match self.state.load(Ordering::Acquire) {
                INITIALIZING => Err(ProcessMainInitError::Initializing),
                READY => Err(ProcessMainInitError::AlreadyInitialized),
                RETAINED | _ => Err(ProcessMainInitError::Retained),
            };
        }

        let mut selection = match subprocess.reserve_static_bootstrap() {
            Ok(selection) => selection,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::BootstrapSelection(error));
            }
        };
        let foundation = match MainStaticHeapFoundation::initialize(
            main_static,
            subprocess,
            &mut selection,
        ) {
            Ok(foundation) => foundation,
            Err(error) => {
                selection.retain();
                self.mark_retained();
                return Err(ProcessMainInitError::HeapFoundation(error));
            }
        };
        let metadata_ready = match metadata.prepare_for_main_subprocess(config, subprocess) {
            Ok(ready) => ready,
            Err(error) => {
                selection.retain();
                self.mark_retained();
                return Err(ProcessMainInitError::Metadata(error));
            }
        };
        debug_assert!(metadata_ready.matches(metadata));
        debug_assert!(core::ptr::eq(metadata_ready.subprocess().as_ptr(), subprocess.as_ptr()));
        debug_assert_eq!(metadata_ready.memory_config(), config);

        let page_map = match page_map_storage.initialize(config, subprocess) {
            Ok(page_map) => page_map,
            Err(error) => {
                selection.retain();
                self.mark_retained();
                return Err(ProcessMainInitError::PageMap(error));
            }
        };

        // SAFETY: preflight established current-thread/root ownership; the
        // COLD -> INITIALIZING CAS and selected linear token exclude another
        // ticket-zero route; `foundation` exists in its final static slot;
        // detached metadata is ready; and the exact selected PageMap has been
        // initialized before compiler-TLS root publication.
        let attachment = match unsafe {
            MainStaticTheapAttachment::begin_after_heap_foundation(foundation, selection)
        } {
            Ok(attachment) => attachment,
            Err(error) => {
                self.mark_retained();
                return Err(ProcessMainInitError::InitialThread(error));
            }
        };

        // SAFETY: this CAS winner owns every final startup slot; no READY
        // reader can observe any field before the Release store below.
        unsafe { (*self.config.get()).write(config) };
        self.subprocess.store(subprocess.as_ptr(), Ordering::Release);
        self.page_map_storage
            .store(core::ptr::from_ref(page_map_storage).cast_mut(), Ordering::Release);
        self.state.store(READY, Ordering::Release);

        let ready = ProcessMainReadyLease {
            storage: self,
            page_map,
            config,
            subprocess,
        };
        Ok(ProcessMainThread {
            storage: self,
            attachment: Some(attachment),
            ready,
            state: ProcessMainThreadState::Attached,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Reobtains the immutable process-ready witness for the same frozen
    /// process inputs. It never creates a second ticket-zero attachment.
    pub(crate) fn ready_lease(
        &'static self,
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> Result<ProcessMainReadyLease, ProcessMainInitError> {
        if self.state.load(Ordering::Acquire) != READY {
            return Err(ProcessMainInitError::Retained);
        }
        let stored_config = self.config();
        if stored_config != config {
            return Err(ProcessMainInitError::ConfigurationMismatch);
        }
        if !core::ptr::eq(self.subprocess.load(Ordering::Acquire), subprocess.as_ptr()) {
            return Err(ProcessMainInitError::SubprocessMismatch);
        }
        let page_map_storage = NonNull::new(self.page_map_storage.load(Ordering::Acquire))
            .ok_or(ProcessMainInitError::Retained)?;
        // SAFETY: READY Release-publishes the exact process-lifetime storage
        // pointer. It is never replaced or destroyed in this bounded owner.
        let page_map = unsafe { page_map_storage.as_ref() }
            .initialize(config, subprocess)
            .map_err(ProcessMainInitError::PageMap)?;
        Ok(ProcessMainReadyLease {
            storage: self,
            page_map,
            config,
            subprocess,
        })
    }

    #[inline]
    fn config(&self) -> MemoryConfig {
        // SAFETY: callers first observed READY with Acquire, whose Release
        // publication follows this final-slot write.
        unsafe { *(*self.config.get()).assume_init_ref() }
    }

    #[inline]
    fn mark_retained(&self) {
        self.state.store(RETAINED, Ordering::Release);
    }
}

static PROCESS_MAIN_INITIALIZATION: ProcessMainInitializationStorage =
    ProcessMainInitializationStorage::new();

/// A process-main startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainInitError {
    /// The current thread or compiler-TLS roots were not eligible before any
    /// process source state was selected.
    Preflight(MainStaticTheapError),
    Initializing,
    AlreadyInitialized,
    Retained,
    ConfigurationMismatch,
    SubprocessMismatch,
    BootstrapSelection(MainStaticBootstrapSelectionError),
    HeapFoundation(MainStaticHeapFoundationError),
    Metadata(MetaError),
    PageMap(ProcessPageMapError),
    InitialThread(MainStaticTheapError),
}

/// A copyable immutable witness that the bounded source process startup
/// reached `READY` for one frozen main-subprocess/configuration/PageMap tuple.
///
/// It does not expose a PageMap mutation lease, an arena, the detached
/// metadata map/arena, a thread attachment, or process shutdown authority.
#[derive(Clone, Copy)]
pub(crate) struct ProcessMainReadyLease {
    storage: &'static ProcessMainInitializationStorage,
    page_map: ProcessPageMapLease,
    config: MemoryConfig,
    subprocess: &'static MainSubprocess,
}

// SAFETY: this lease only carries process-lifetime immutable witnesses. Page
// mutations remain gated by `ProcessPageMapMutationLease`, and thread state is
// deliberately absent.
unsafe impl Send for ProcessMainReadyLease {}
// SAFETY: see the Send justification above.
unsafe impl Sync for ProcessMainReadyLease {}

impl ProcessMainReadyLease {
    #[inline]
    pub(crate) fn root(self) -> Result<NonNull<PageMapHeader>, ProcessMainInitError> {
        self.ensure_ready()?;
        self.page_map.root().map_err(ProcessMainInitError::PageMap)
    }

    #[inline]
    pub(crate) fn page_map(self) -> Result<ProcessPageMapLease, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(self.page_map)
    }

    #[inline]
    pub(crate) fn memory_config(self) -> Result<MemoryConfig, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(self.config)
    }

    #[inline]
    pub(crate) fn subprocess(self) -> Result<&'static MainSubprocess, ProcessMainInitError> {
        self.ensure_ready()?;
        Ok(self.subprocess)
    }

    #[inline]
    fn ensure_ready(self) -> Result<(), ProcessMainInitError> {
        if self.storage.state.load(Ordering::Acquire) != READY {
            return Err(ProcessMainInitError::Retained);
        }
        if self.storage.config() != self.config
            || !core::ptr::eq(
                self.storage.subprocess.load(Ordering::Acquire),
                self.subprocess.as_ptr(),
            )
        {
            return Err(ProcessMainInitError::Retained);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessMainThreadState {
    Attached,
    TornDown,
    Retained,
}

/// Current-thread owner of the source ticket-zero TLD/Theap after a successful
/// process-main startup transition.
#[must_use = "a process-main thread owner must explicitly tear down or retain its ticket-zero attachment"]
pub(crate) struct ProcessMainThread {
    storage: &'static ProcessMainInitializationStorage,
    attachment: Option<MainStaticTheapAttachment>,
    ready: ProcessMainReadyLease,
    state: ProcessMainThreadState,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// A refusal while turning the retained source-order process-main owner into
/// its one bounded first-arena page owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainFirstArenaPageAllocatorError {
    Process(ProcessMainInitError),
    PageOwner(MainStaticFirstArenaPageAllocatorBeginError),
}

/// A refusal while converting the retained ticket-zero attachment into its
/// one permanent page-session owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainProcessPageSessionError {
    Process(ProcessMainInitError),
    PageSession(MainStaticProcessPageSessionError),
}

/// A refusal while deriving the already-published process arena from the
/// immutable source-order process-ready witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessMainReadySharedArenaError {
    Process(ProcessMainInitError),
    Arena(ProcessSharedArenaError),
    Pair(ProcessPageArenaLeaseError),
}

impl ProcessMainThread {
    /// Returns the immutable process-ready witness only while the ticket-zero
    /// attachment is still live and current.
    pub(crate) fn ready(&self) -> Result<ProcessMainReadyLease, ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        self.ready.ensure_ready()?;
        Ok(self.ready)
    }

    /// Borrows the ticket-zero attachment for an existing bounded page owner
    /// or later-main attachment. The process coordinator remains the only
    /// constructor for this owner in production.
    pub(crate) fn attachment_mut(
        &mut self,
    ) -> Result<&mut MainStaticTheapAttachment, ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        self.attachment.as_mut().ok_or(ProcessMainInitError::Retained)
    }

    /// Converts the ticket-zero page authority into its one permanent static
    /// page session.
    ///
    /// The returned owner has no Rust borrow of this coordinator. Instead it
    /// permanently closes `teardown`, so its explicitly derived shared-main
    /// Heap lease can drive later no-page thread lifecycle work while ticket
    /// zero retains the static page state. This is an ownership transition,
    /// not a general allocator start or a C ABI/backend selection.
    pub(crate) fn begin_process_lifetime_page_session(
        &self,
    ) -> Result<MainStaticProcessPageSession, ProcessMainProcessPageSessionError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainProcessPageSessionError::Process(
                ProcessMainInitError::Retained,
            ));
        }
        let attachment = self.attachment.as_ref().ok_or(
            ProcessMainProcessPageSessionError::Process(ProcessMainInitError::Retained),
        )?;
        attachment
            .begin_process_lifetime_page_session()
            .map_err(ProcessMainProcessPageSessionError::PageSession)
    }

    /// Reconstructs the one immutable process map/arena pair after a bounded
    /// source reservation has already published it.
    ///
    /// This is not an arena search or a reservation policy. The pair is
    /// available only while this ticket-zero owner remains live and the
    /// process-shared sidecar is already READY; joining its two immutable
    /// witnesses rejects a root, configuration, or subprocess mismatch before
    /// any page lifecycle can begin.
    pub(crate) fn ready_shared_arena_pair(
        &self,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        self.ready_shared_arena_pair_with_storage(ProcessSharedArenaStorage::global())
    }

    fn ready_shared_arena_pair_with_storage(
        &self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        let page_map = self
            .ready()
            .and_then(ProcessMainReadyLease::page_map)
            .map_err(ProcessMainReadySharedArenaError::Process)?;
        let arena = arena_storage
            .ready_lease()
            .map_err(ProcessMainReadySharedArenaError::Arena)?;
        ProcessPageArenaLease::join(page_map, arena).map_err(ProcessMainReadySharedArenaError::Pair)
    }

    /// Test-only injection of an isolated process-lifetime arena sidecar.
    #[cfg(test)]
    fn ready_shared_arena_pair_with_test_storage(
        &self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<ProcessPageArenaLease, ProcessMainReadySharedArenaError> {
        self.ready_shared_arena_pair_with_storage(arena_storage)
    }

    /// Borrows this retained ticket-zero owner as the one private lazy
    /// first-arena page engine.
    ///
    /// The source-order coordinator provides the only valid process-ready map
    /// witness and ticket-zero attachment. This factory exposes neither raw
    /// static storage nor arena ownership; the returned owner remains bounded
    /// to its first ordinary fresh-page miss and the global one-arena policy.
    pub(crate) fn begin_first_arena_page_allocator(
        &mut self,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        self.begin_first_arena_page_allocator_with_storage(ProcessSharedArenaStorage::global())
    }

    fn begin_first_arena_page_allocator_with_storage(
        &mut self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        let page_map = self
            .ready()
            .and_then(ProcessMainReadyLease::page_map)
            .map_err(ProcessMainFirstArenaPageAllocatorError::Process)?;
        let attachment = self
            .attachment_mut()
            .map_err(ProcessMainFirstArenaPageAllocatorError::Process)?;
        MainStaticFirstArenaPageAllocator::begin(attachment, page_map, arena_storage)
            .map_err(ProcessMainFirstArenaPageAllocatorError::PageOwner)
    }

    /// Test-only injection of an isolated process-lifetime arena sidecar.
    #[cfg(test)]
    fn begin_first_arena_page_allocator_with_test_storage(
        &mut self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<MainStaticFirstArenaPageAllocator<'_>, ProcessMainFirstArenaPageAllocatorError> {
        self.begin_first_arena_page_allocator_with_storage(arena_storage)
    }

    /// Mints the live static main-Heap lease on the ticket-zero thread.
    ///
    /// The private libc bridge calls this during process initialization and
    /// retains the Copy process-lifetime witness for later pthread workers.
    /// A worker must never mint the lease itself: this method verifies the
    /// initial attachment's current-thread identity. The caller must keep the
    /// ticket-zero owner alive and must not begin its teardown while the
    /// returned lease or any attachment made from it exists.
    #[inline]
    pub(crate) fn shared_main_heap_lease(
        &self,
    ) -> Result<MainStaticHeapLease<'_>, ProcessMainInitError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(ProcessMainInitError::Retained);
        }
        self.attachment
            .as_ref()
            .ok_or(ProcessMainInitError::Retained)?
            .shared_main_heap_lease()
            .map_err(ProcessMainInitError::InitialThread)
    }

    /// Performs the existing bounded main-thread TLD/Theap teardown. Process
    /// startup itself remains terminal afterward: the static source TLD slot
    /// is never reused and this coordinator deliberately has no process
    /// destruction/restart protocol.
    pub(crate) fn teardown(&mut self) -> Result<(), MainStaticTheapError> {
        if self.state != ProcessMainThreadState::Attached {
            return Err(MainStaticTheapError::TornDown);
        }
        let result = self
            .attachment
            .as_mut()
            .ok_or(MainStaticTheapError::Poisoned)?
            .teardown();
        self.storage.mark_retained();
        self.state = if result.is_ok() {
            ProcessMainThreadState::TornDown
        } else {
            ProcessMainThreadState::Retained
        };
        result
    }
}

impl Drop for ProcessMainThread {
    fn drop(&mut self) {
        if self.state == ProcessMainThreadState::Attached {
            // A dropped ticket-zero owner can leave roots, TLD registration,
            // or page state live. Retain the process rather than letting a
            // later caller receive a fresh-looking startup capability.
            self.storage.mark_retained();
            self.state = ProcessMainThreadState::Retained;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::ArenaId;
    use crate::bootstrap::empty_default_theap_ptr;
    use crate::compiler_tls::{
        default_theap, fast_slot_peek, roots_are_pristine_for_main_static_attachment,
        set_default_theap,
    };
    use crate::main_heap_page::MainHeapThreadProcessPageAllocator;
    use crate::main_heap_thread::MainHeapThreadAttachment;
    use crate::meta::MetaAllocator;
    use crate::os::{fault, MapAccess, PageSize};
    use crate::process_arena::{ProcessPageArenaLease, ProcessSharedArenaStorage};
    use crate::single_thread::PageAllocatorEngine;
    use crate::subproc::GenericThreadTicketError;
    use crate::tld::{ThreadLocalDataError, ThreadLocalDataOwner};
    use crate::types::Theap;
    use std::ptr::NonNull;
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn fixture() -> (
        &'static ProcessMainInitializationStorage,
        &'static MainStaticAttachmentStorage,
        &'static MainSubprocess,
        core::pin::Pin<&'static MetaAllocator>,
        &'static ProcessPageMapStorage,
    ) {
        (
            ProcessMainInitializationStorage::test_static_owner(),
            MainStaticAttachmentStorage::test_static_owner(),
            MainSubprocess::test_static_owner(),
            MetaAllocator::test_static_owner(),
            ProcessPageMapStorage::test_static_owner(),
        )
    }

    #[test]
    fn process_main_initialization_orders_heap_metadata_map_then_ticket_zero_roots() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the selected process-main source sequence initializes");
            let ready = owner.ready().expect("only the completed startup publishes ready");

            assert_eq!(subprocess.total_thread_count(), 1);
            assert_eq!(subprocess.live_thread_count(), 1);
            assert_eq!(ready.memory_config().unwrap(), config);
            assert_eq!(ready.subprocess().unwrap().as_ptr(), subprocess.as_ptr());
            assert_eq!(
                ready.root().unwrap(),
                ready.page_map().unwrap().root().unwrap(),
                "the coordinator publishes the exact process PageMap root"
            );
            assert!(metadata.test_is_ready_for(config, subprocess));
            assert_ne!(
                metadata.test_private_page_map_address().unwrap(),
                ready.page_map().unwrap().page_map().unwrap() as *const _ as usize,
                "the detached metadata map is never reused as the global PageMap"
            );
            assert!(
                ProcessSharedArenaStorage::global().test_is_cold(),
                "process startup does not reserve or manage an arena"
            );

            let attachment = owner.attachment_mut().unwrap();
            let theap = attachment.test_theap_pointer();
            assert_eq!(default_theap().as_ptr(), theap);
            assert_eq!(fast_slot_peek().unwrap().as_ptr().cast::<Theap>(), theap);

            owner.teardown().expect("the bounded ticket-zero owner tears down");
            assert!(matches!(ready.root(), Err(ProcessMainInitError::Retained)));
        })
        .join()
        .expect("process-main initialization test thread completes");
    }

    #[test]
    fn preflight_rejection_leaves_process_startup_cold_and_ticket_zero_unselected() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut foreign = Theap::empty();
            set_default_theap(NonNull::from(&mut foreign));
            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::Preflight(MainStaticTheapError::RootsNotPristine))
            ));
            assert_eq!(storage.state.load(Ordering::Acquire), COLD);
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(!page_map_storage.test_has_published_root());
            set_default_theap(NonNull::new(empty_default_theap_ptr()).unwrap());
        })
        .join()
        .expect("preflight-rejection test thread completes");
    }

    #[test]
    fn metadata_prepare_failure_after_heap_foundation_never_publishes_a_global_map_or_tls_root() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::Metadata(MetaError::InitializationFailed))
            ));
            fault.set(fault::Plan::disabled());

            assert_eq!(storage.state.load(Ordering::Acquire), RETAINED);
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(!page_map_storage.test_has_published_root());
            assert!(roots_are_pristine_for_main_static_attachment());
            assert!(matches!(
                subprocess.issue_generic_thread_ticket(),
                Err(GenericThreadTicketError::BootstrapRetained)
            ));
        })
        .join()
        .expect("metadata-failure test thread completes");
    }

    #[test]
    fn rejected_page_map_after_heap_and_metadata_retains_ticket_zero_without_tls_publication() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            // First consume this isolated global-map owner without publishing
            // a root. The coordinator must encounter that retained source
            // boundary only after its Heap and detached-metadata predecessors;
            // it must not publish ticket-zero TLS roots as a fallback.
            let fault = fault::install(fault::Plan::at(
                fault::Point::Map,
                1,
                crabc_core::Errno::NOMEM,
            ));
            assert!(matches!(
                page_map_storage.initialize(config, subprocess),
                Err(ProcessPageMapError::Initialization(crabc_core::Errno::NOMEM))
            ));
            fault.set(fault::Plan::disabled());

            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::PageMap(ProcessPageMapError::Poisoned))
            ));
            assert_eq!(storage.state.load(Ordering::Acquire), RETAINED);
            assert_eq!(subprocess.total_thread_count(), 0);
            assert_eq!(subprocess.live_thread_count(), 0);
            assert!(roots_are_pristine_for_main_static_attachment());
            assert!(matches!(
                subprocess.issue_generic_thread_ticket(),
                Err(GenericThreadTicketError::BootstrapRetained)
            ));
            assert!(matches!(
                unsafe {
                    ThreadLocalDataOwner::begin_with_test_metadata(subprocess, metadata, config)
                },
                Err(ThreadLocalDataError::BootstrapRetained)
            ));
        })
        .join()
        .expect("page-map-failure test thread completes");
    }

    #[test]
    fn ready_process_rejects_a_second_thread_owner_but_reissues_its_immutable_matching_lease() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the first source startup succeeds");
            let first = owner.ready().unwrap();
            let second = storage.ready_lease(config, subprocess).unwrap();
            assert_eq!(first.root().unwrap(), second.root().unwrap());
            assert!(matches!(
                unsafe {
                    storage.initialize_with_test_components(
                        config,
                        main_static,
                        subprocess,
                        metadata,
                        page_map_storage,
                    )
                },
                Err(ProcessMainInitError::AlreadyInitialized)
            ));
            let different_config = MemoryConfig::from_observations(
                PageSize::new(16_384).expect("Linux/AArch64 supports this page size"),
                1024 * 1024,
                false,
                false,
            );
            assert!(matches!(
                storage.ready_lease(different_config, subprocess),
                Err(ProcessMainInitError::ConfigurationMismatch)
            ));
            assert_eq!(subprocess.total_thread_count(), 1);
            owner.teardown().expect("the first owner still owns teardown");
        })
        .join()
        .expect("ready-process reuse test thread completes");
    }

    #[test]
    fn process_main_owner_opens_the_ticket_zero_first_arena_page_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("source-order startup creates the retained ticket-zero owner");

            let mut page_owner = owner
                .begin_first_arena_page_allocator_with_test_storage(arena_storage)
                .expect("the process owner supplies its exact ready map and ticket-zero attachment");
            assert!(arena_storage.test_is_cold(), "the factory itself makes no startup reservation");
            let block = page_owner
                .allocate(37, false)
                .expect("the first ticket-zero request reaches the bounded default arena");
            assert!(
                !arena_storage.test_is_cold(),
                "the process-owned page route reserves only after its first fresh page miss"
            );
            // SAFETY: `block` is the exact active allocation returned above
            // and has not escaped the process-main page owner.
            unsafe { page_owner.free(block) }
                .expect("the process-owned first-arena block frees normally");
            assert!(matches!(page_owner.finish(), Ok(())));
            owner
                .teardown()
                .expect("the released page owner returns ticket-zero teardown authority");
        })
        .join()
        .expect("process-main first-arena page-owner fixture completes");
    }

    #[test]
    fn process_ready_first_arena_pair_reuses_the_published_default_arena_for_one_later_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("source-order startup creates the ticket-zero owner");

            assert!(matches!(
                owner.ready_shared_arena_pair_with_test_storage(arena_storage),
                Err(ProcessMainReadySharedArenaError::Arena(ProcessSharedArenaError::Retained))
            ), "a cold arena sidecar cannot become a process-ready page pair");

            let mut first = owner
                .begin_first_arena_page_allocator_with_test_storage(arena_storage)
                .expect("the ticket-zero owner opens its first default arena route");
            let block = first
                .allocate(37, false)
                .expect("the first fresh page publishes the default arena");
            // SAFETY: `block` is the exact still-live allocation returned by
            // this first owner and has not escaped it.
            unsafe { first.free(block) }.expect("the first owner releases its only block");
            assert!(matches!(
                first.finish(),
                Ok(())
            ), "the empty first owner releases its map lifecycle");

            let pair = owner
                .ready_shared_arena_pair_with_test_storage(arena_storage)
                .expect("the ready process derives the exact published first-arena pair");
            assert_eq!(
                pair.page_map_root().unwrap(),
                owner.ready().unwrap().root().unwrap(),
                "the reuse pair retains the coordinator's release-published map root"
            );
            let main_heap = owner
                .shared_main_heap_lease()
                .expect("ticket zero mints the later-owner heap witness");

            thread::scope(|scope| {
                scope
                    .spawn(move || {
                        let mut later = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap, metadata, config,
                            )
                        } {
                            Ok(attachment) => attachment,
                            Err(_) => panic!("the later source attachment must publish"),
                        };
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut later, pair)
                            .expect("the published first arena is reusable by the selected later owner");
                        let block = allocator
                            .allocate(37, false)
                            .expect("the later owner allocates through the reused arena");
                        for index in 0..37 {
                            // SAFETY: `block` is uniquely live and has its
                            // complete requested 37-byte extent.
                            unsafe { block.as_ptr().add(index).write((index as u8).wrapping_add(19)) };
                        }
                        // SAFETY: `block` is the exact current allocation of
                        // this live later-thread engine and remains exclusive.
                        let replacement = unsafe {
                            allocator.reallocate(Some(block), crate::config::SMALL_MAX_OBJ_SIZE + 1)
                        }
                        .expect("the later owner exposes ordinary realloc through the reused arena");
                        for index in 0..37 {
                            // SAFETY: the successful replacement is uniquely
                            // live and preserves the initialized old prefix.
                            assert_eq!(
                                unsafe { replacement.as_ptr().add(index).read() },
                                (index as u8).wrapping_add(19)
                            );
                        }
                        // SAFETY: `replacement` is the sole current allocation
                        // returned by the successful reallocation.
                        unsafe { allocator.free(replacement) }
                            .expect("the later owner releases its only allocation");
                        assert!(matches!(
                            allocator.finish(),
                            Ok(())
                        ), "the later page engine drains cleanly");
                        later
                            .finish_after_user_destructors()
                            .expect("the later attachment completes after its empty page engine");
                    })
                    .join()
                    .expect("the later source owner remains current-thread-local");
            });

            owner
                .teardown()
                .expect("the reused first arena leaves ticket-zero teardown authority intact");
        })
        .join()
        .expect("process-ready first-arena reuse fixture completes");
    }

    #[test]
    fn process_lifetime_static_page_session_keeps_ticket_zero_pages_sound_with_a_later_main_lease() {
        thread::spawn(|| {
            let config = memory_config();
            let (storage, main_static, subprocess, metadata, page_map_storage) = fixture();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                storage.initialize_with_test_components(
                    config,
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("source-order startup creates ticket zero before the permanent session");

            let session = owner
                .begin_process_lifetime_page_session()
                .expect("the empty ticket-zero image converts to one permanent page owner");
            let main_heap = session.shared_main_heap_lease();
            assert!(matches!(
                owner
                    .attachment_mut()
                    .expect("the permanent session retains the ticket-zero attachment")
                    .page_session(),
                Err(MainStaticPageSessionError::ProcessPageSessionLive)
            ), "the permanent session excludes a second borrowed static page owner");

            thread::scope(|scope| {
                scope
                    .spawn(move || {
                        let mut later = match unsafe {
                            MainHeapThreadAttachment::begin_with_test_metadata(
                                main_heap, metadata, config,
                            )
                        } {
                            Ok(attachment) => attachment,
                            Err(_) => panic!("the persistent static lease admits one later no-page owner"),
                        };
                        later
                            .finish_after_user_destructors()
                            .expect("the later no-page owner detaches before ticket-zero page use");
                    })
                    .join()
                    .expect("the later no-page lifecycle stays current-thread local");
            });

            let page_map = owner
                .ready()
                .and_then(ProcessMainReadyLease::page_map)
                .expect("the permanent session keeps the process map witness ready");
            let arena = match arena_storage.reserve_one_os_arena(
                page_map,
                crate::config::ARENA_MIN_SIZE,
                MapAccess::Committed,
            ) {
                Ok(arena) => arena,
                Err(_) => panic!("one explicit process arena is available for the static page proof"),
            };
            let pair = ProcessPageArenaLease::join(page_map, arena)
                .expect("the static page engine receives its exact map/arena pair");
            let lifecycle = pair
                .begin_page_lifecycle()
                .expect("the static process page lifecycle claims the plain map boundary");
            let arena = pair
                .arena()
                .expect("the paired source arena remains published");
            let page_map = lifecycle
                .page_map()
                .expect("the page lifecycle grants the static engine its map view");
            // SAFETY: `session` is the one permanent ticket-zero page owner,
            // and `lifecycle` remains live beside the exact paired arena for
            // this complete ordinary allocation/free engine.
            let mut engine = unsafe {
                PageAllocatorEngine::activate_main_static(session, arena, ArenaId::none(), page_map)
            };
            let block = engine
                .allocate(37, false)
                .expect("ticket zero allocates after the later no-page owner detached");
            // SAFETY: `block` is the one live allocation from this exact
            // static engine and has not escaped the test.
            unsafe { engine.free(block) }
                .expect("the ticket-zero page lifecycle frees its allocation");
            assert!(matches!(
                engine.finish(),
                Ok(())
            ), "the static page engine releases every page before its session is retained");
            lifecycle
                .finish()
                .expect("the empty static page engine releases the map lifecycle");
            assert!(matches!(
                owner.teardown(),
                Err(MainStaticTheapError::ProcessPageSessionLive)
            ), "the copied permanent shared-main lease cannot be followed by main-image teardown");
        })
        .join()
        .expect("process-lifetime ticket-zero/static-main ownership fixture completes");
    }
}
