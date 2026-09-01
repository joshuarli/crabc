// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// "LICENSE" at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:181-224,305-360`,
// `src/page-map.c:228-365`, `src/alloc.c:29-159,379-451`, `src/free.c:221-255`, and `src/arena.c:341-406,
// 525-569,674-723,781-821,951-1114,1129-1213,1240-1282`.

//! Page-bearing binding of the static main Theap to one process-owned arena.
//!
//! This module holds the first bounded page allocator which pairs the
//! already-published process PageMap with a caller-managed process arena and
//! borrows the ticket-zero static owner. Its separate first-arena owner starts
//! with no arena and invokes the fixed source default reservation only after
//! an empty ticket-zero Theap needs its first ordinary page. It deliberately
//! does not implement later arena selection, general process initialization,
//! later-thread attachment, or pthread/TLS hooks.

use core::ptr::NonNull;

use crate::arena::ArenaId;
use crate::config::{
    ARENA_SLICE_SIZE, BIN_HUGE, SMALL_PAGE_SIZE, SMALL_SIZE_MAX, WORD_SIZE,
};
use crate::main_theap::{
    MainStaticPageSessionError, MainStaticProcessPageSession, MainStaticTheapAttachment,
    MainStaticTheapError,
};
use crate::os::MemoryConfig;
use crate::page;
use crate::process_arena::{
    ProcessPageArenaLease, ProcessPageArenaLeaseError, ProcessSharedArenaReserveFailure,
    ProcessSharedArenaStorage,
};
use crate::process_page_map::{ProcessPageMapError, ProcessPageMapMutationLease};
#[cfg(test)]
use crate::process_page_map::ProcessPageMapSuspendedEngineAccess;
use crate::size_class;
use crate::single_thread::{
    FreeError, PageAllocatorEngine, RemoteFreePreparationError, RemoteFreeProducer,
};
#[cfg(test)]
use crate::single_thread::PageAllocatorEngineState;
use crate::types::PageKind;
#[cfg(test)]
use crate::types::Page;

#[cfg(test)]
extern crate std;

/// The one bounded main-thread allocator over a matched process map/arena.
///
/// Field order is intentional: if this owner is dropped unfinished, the page
/// engine first poisons the borrowed static attachment and then the process
/// map mutation lease poisons its root before releasing the private lock. A
/// successful [`Self::finish`] is the only path that leaves either owner ready
/// for a later bounded session.
#[must_use = "a main-static process page allocator must finish or retain its owner explicitly"]
pub(crate) struct MainStaticProcessPageAllocator<'main> {
    engine: PageAllocatorEngine<'static, 'static, crate::main_theap::MainStaticPageSession<'main>>,
    page_map_lifecycle: ProcessPageMapMutationLease,
}

/// A pre-publication refusal while opening the bounded static page allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticProcessPageAllocatorBeginError {
    Pair(ProcessPageArenaLeaseError),
    /// The static ticket-zero attachment belongs to another process image.
    /// This is checked before it is borrowed as a page session or the PageMap
    /// lifecycle lock is acquired.
    SubprocessMismatch,
    Session(MainStaticPageSessionError),
    PageMap(ProcessPageMapError),
}

/// The only failure outcomes while consuming a bounded static page engine.
#[must_use = "a retained main-static page allocator still owns live page state"]
pub(crate) enum MainStaticProcessPageAllocatorFinishError<'main> {
    /// One page, queue, producer, or OS-release owner remains live. The exact
    /// engine and its PageMap mutation lease remain together for retry or a
    /// terminal owner decision.
    Retained(MainStaticProcessPageAllocator<'main>),
    /// The engine reached an empty source state, but releasing the private
    /// PageMap lifecycle lock reported a post-Release wake failure. The map
    /// owner is terminally poisoned; no engine state remains to retry.
    PageMap(ProcessPageMapError),
}

impl<'main> MainStaticProcessPageAllocator<'main> {
    /// Starts one source-shaped page lifecycle for the ticket-zero attachment.
    ///
    /// The paired lease proves a common root/configuration/subprocess before
    /// this function touches either static image. The map mutation lease then
    /// serializes every ordinary PageMap entry operation for the complete
    /// engine and any joined scoped remote producer lifetime.
    pub(crate) fn begin(
        attachment: &'main mut MainStaticTheapAttachment,
        pair: ProcessPageArenaLease,
    ) -> Result<Self, MainStaticProcessPageAllocatorBeginError> {
        let process = pair
            .subprocess()
            .map_err(MainStaticProcessPageAllocatorBeginError::Pair)?;
        if !attachment
            .subprocess()
            .map_or(false, |attachment_process| core::ptr::eq(attachment_process.as_ptr(), process.as_ptr()))
        {
            return Err(MainStaticProcessPageAllocatorBeginError::SubprocessMismatch);
        }
        let arena = pair
            .arena()
            .map_err(MainStaticProcessPageAllocatorBeginError::Pair)?;
        let session = attachment
            .page_session()
            .map_err(MainStaticProcessPageAllocatorBeginError::Session)?;
        let page_map_lifecycle = pair
            .begin_page_lifecycle()
            .map_err(MainStaticProcessPageAllocatorBeginError::Pair)?;
        let page_map = page_map_lifecycle
            .page_map()
            .map_err(MainStaticProcessPageAllocatorBeginError::PageMap)?;
        // SAFETY: `pair` validated the exact map/arena/process identity and
        // `page_map_lifecycle` remains stored beside the engine until finish
        // or terminal Drop. `session` is the uniquely borrowed ticket-zero
        // static owner for the same complete lifetime.
        let engine = unsafe {
            PageAllocatorEngine::activate_main_static(session, arena, ArenaId::none(), page_map)
        };
        Ok(Self {
            engine,
            page_map_lifecycle,
        })
    }

    /// Allocates one ordinary main-static block through the source page engine.
    #[inline]
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        self.engine.allocate(request, zero)
    }

    /// Reallocates one ordinary main-static allocation through the source page
    /// engine.
    ///
    /// # Safety
    ///
    /// When present, `block` must be one current allocation from this exact
    /// owner, with no aliased access during this operation. A failed
    /// replacement leaves that allocation current and unchanged.
    #[inline]
    pub(crate) unsafe fn reallocate(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        unsafe { self.engine.reallocate(block, new_size) }
    }

    /// Frees one current main-static allocation.
    ///
    /// # Safety
    ///
    /// `block` must be one current allocation returned by this exact owner;
    /// it must not be freed, handed to a scoped remote producer, or accessed
    /// concurrently through another path.
    #[inline]
    pub(crate) unsafe fn free(&mut self, block: NonNull<u8>) -> Result<(), FreeError> {
        unsafe { self.engine.free(block) }
    }

    /// Runs the bounded local retired-page collector after any scoped remote
    /// producer has joined.
    #[inline]
    pub(crate) fn collect_retired(&mut self, force: bool) -> bool {
        self.engine.collect_retired(force)
    }

    /// Prepares one joined scoped remote free for a live regular or full page.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation in this engine. The returned
    /// producer must publish or cancel before this owner resumes allocation,
    /// collection, finish, or drop.
    #[inline]
    pub(crate) unsafe fn begin_remote_free<'owner>(
        &'owner mut self,
        block: NonNull<u8>,
    ) -> Result<RemoteFreeProducer<'owner>, RemoteFreePreparationError> {
        unsafe { self.engine.begin_remote_free(block) }
    }

    /// Finishes only after every source page/queue/map/arena transition is
    /// empty, then releases the process map mutation lifetime.
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainStaticProcessPageAllocatorFinishError<'main>> {
        let Self {
            engine,
            page_map_lifecycle,
        } = self;
        match engine.finish() {
            Ok(()) => page_map_lifecycle
                .finish()
                .map_err(MainStaticProcessPageAllocatorFinishError::PageMap),
            Err(engine) => Err(MainStaticProcessPageAllocatorFinishError::Retained(Self {
                engine,
                page_map_lifecycle,
            })),
        }
    }

    #[cfg(test)]
    #[inline]
    unsafe fn test_page_for_block(&self, block: NonNull<u8>) -> *mut Page {
        unsafe { self.engine.page_for_block(block) }
    }
}

/// One ticket-zero owner which has not yet observed its first ordinary
/// fresh-page miss, or has activated the existing page engine from the source
/// first-arena policy.
///
/// This is intentionally narrower than a general allocator. It carries no
/// arena at construction, validates the zero-page ticket-zero session before
/// mapping, and calls `mi_arena_reserve`'s frozen first-arena branch only for
/// the first ordinary request that needs a page. Once active it delegates to
/// the already-bounded [`MainStaticProcessPageAllocator`]; exhaustion of that
/// one arena does not manufacture later arena-count scaling or a second route.
#[must_use = "a first-arena static page owner must finish or retain its ticket-zero attachment explicitly"]
pub(crate) struct MainStaticFirstArenaPageAllocator<'main> {
    state: MainStaticFirstArenaPageAllocatorState<'main>,
}

enum MainStaticFirstArenaPageAllocatorState<'main> {
    AwaitingFreshPage {
        attachment: &'main mut MainStaticTheapAttachment,
        page_map: crate::process_page_map::ProcessPageMapLease,
        arena_storage: &'static ProcessSharedArenaStorage,
    },
    Active(MainStaticProcessPageAllocator<'main>),
    Retained {
        attachment: &'main mut MainStaticTheapAttachment,
    },
    Transition,
}

/// A pre-reservation refusal for the lazy ticket-zero arena owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticFirstArenaPageAllocatorBeginError {
    PageMap(ProcessPageMapError),
    Attachment(MainStaticTheapError),
    SubprocessMismatch,
}

/// A free attempted before the lazy owner activated its source page engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticFirstArenaPageAllocatorFreeError {
    NotActive,
    Free(FreeError),
}

/// The result of finishing one lazy ticket-zero page owner.
#[must_use = "a retained first-arena page owner still owns its ticket-zero attachment or page engine"]
pub(crate) enum MainStaticFirstArenaPageAllocatorFinishError<'main> {
    Retained(MainStaticFirstArenaPageAllocator<'main>),
    PageMap(ProcessPageMapError),
}

impl<'main> MainStaticFirstArenaPageAllocator<'main> {
    /// Opens a first-arena owner without reserving any virtual memory.
    ///
    /// The map and attachment must already name the same process image. This
    /// only proves that immutable relation; the complete zero-page session is
    /// revalidated immediately before a valid request can reserve its first
    /// arena.
    pub(crate) fn begin(
        attachment: &'main mut MainStaticTheapAttachment,
        page_map: crate::process_page_map::ProcessPageMapLease,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<Self, MainStaticFirstArenaPageAllocatorBeginError> {
        let map_subprocess = page_map
            .subprocess()
            .map_err(MainStaticFirstArenaPageAllocatorBeginError::PageMap)?;
        let attachment_subprocess = attachment
            .subprocess()
            .map_err(MainStaticFirstArenaPageAllocatorBeginError::Attachment)?;
        if !core::ptr::eq(map_subprocess.as_ptr(), attachment_subprocess.as_ptr()) {
            return Err(MainStaticFirstArenaPageAllocatorBeginError::SubprocessMismatch);
        }
        Ok(Self {
            state: MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage {
                attachment,
                page_map,
                arena_storage,
            },
        })
    }

    /// Allocates one ordinary ticket-zero block, reserving the source default
    /// arena only when this empty owner needs its first fresh page.
    #[inline]
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticFirstArenaPageAllocatorState::Active(mut allocator) => {
                let block = allocator.allocate(request, zero);
                self.state = MainStaticFirstArenaPageAllocatorState::Active(allocator);
                block
            }
            MainStaticFirstArenaPageAllocatorState::Retained { attachment } => {
                self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                None
            }
            MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage {
                mut attachment,
                page_map,
                arena_storage,
            } => {
                let config = match page_map.memory_config() {
                    Ok(config) => config,
                    Err(_) => {
                        self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                        return None;
                    }
                };
                let required_size = match first_ordinary_fresh_page_size(config, request) {
                    Some(size) => size,
                    None => {
                        self.state = MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage {
                            attachment,
                            page_map,
                            arena_storage,
                        };
                        return None;
                    }
                };
                // This repeats the exact ticket-zero page-session checks while
                // no arena has been mapped. It prevents an invalid root/image
                // from becoming a process-global reservation side effect.
                if attachment.preflight_fresh_page_session().is_err() {
                    self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                    return None;
                }
                let page_map_lifecycle = match page_map.begin_page_lifecycle() {
                    Ok(lifecycle) => lifecycle,
                    Err(ProcessPageMapError::LifecycleBusy) => {
                        self.state = MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage {
                            attachment,
                            page_map,
                            arena_storage,
                        };
                        return None;
                    }
                    Err(_) => {
                        self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                        return None;
                    }
                };
                let arena = match arena_storage.reserve_default_os_arena(page_map, required_size) {
                    Ok(arena) => arena,
                    Err(ProcessSharedArenaReserveFailure::Rejected { .. }) => {
                        self.state = if page_map_lifecycle.finish().is_ok() {
                            MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage {
                                attachment,
                                page_map,
                                arena_storage,
                            }
                        } else {
                            MainStaticFirstArenaPageAllocatorState::Retained { attachment }
                        };
                        return None;
                    }
                    Err(ProcessSharedArenaReserveFailure::Retained { .. }) => {
                        let _ = page_map_lifecycle.finish();
                        self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                        return None;
                    }
                };
                let pair = match ProcessPageArenaLease::join(page_map, arena) {
                    Ok(pair) => pair,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                        return None;
                    }
                };
                let arena = match pair.arena() {
                    Ok(arena) => arena,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                        return None;
                    }
                };
                let page_map_ref = match page_map_lifecycle.page_map() {
                    Ok(page_map_ref) => page_map_ref,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        self.state = MainStaticFirstArenaPageAllocatorState::Retained { attachment };
                        return None;
                    }
                };
                let session = attachment.page_session().unwrap_or_else(|_| {
                    // `preflight_fresh_page_session` proved this exact
                    // attachment immediately above; no operation between the
                    // preflight and this construction can alter its roots,
                    // page count, or static image. Treat a contrary result as
                    // an internal invariant violation, never an alternate
                    // post-reservation allocation path.
                    unreachable!("the preflighted ticket-zero page session remains valid")
                });
                // SAFETY: the preflight and repeated page-session construction
                // prove the zero-page ticket-zero image; `pair` joins the
                // newly published source arena to this exact root; and the
                // stored lifecycle serializes every plain PageMap access until
                // the activated engine finishes.
                let allocator = MainStaticProcessPageAllocator {
                    engine: unsafe {
                        PageAllocatorEngine::activate_main_static(
                            session,
                            arena,
                            ArenaId::none(),
                            page_map_ref,
                        )
                    },
                    page_map_lifecycle,
                };
                self.state = MainStaticFirstArenaPageAllocatorState::Active(allocator);
                match &mut self.state {
                    MainStaticFirstArenaPageAllocatorState::Active(allocator) => {
                        allocator.allocate(request, zero)
                    }
                    _ => unreachable!("the just-activated first-arena owner remains active"),
                }
            }
            MainStaticFirstArenaPageAllocatorState::Transition => {
                unreachable!("a mutable first-arena owner cannot reenter its state transition")
            }
        }
    }

    /// Reallocates one ordinary ticket-zero allocation.
    ///
    /// The null-pointer case is the source `realloc(NULL, size)` allocation
    /// entry, so it follows this owner's first-fresh-page reservation policy.
    /// A non-null block can exist only after that policy has activated the
    /// bounded page engine; before activation, accepting one would manufacture
    /// a foreign allocation route.
    ///
    /// # Safety
    ///
    /// When present, `block` must be one current allocation from this exact
    /// owner, with no aliased access during the operation. It must not have
    /// been freed or transferred to a remote producer. On failure, that block
    /// remains current and unchanged.
    #[inline]
    pub(crate) unsafe fn reallocate(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        let Some(block) = block else {
            return self.allocate(new_size, false);
        };
        match &mut self.state {
            MainStaticFirstArenaPageAllocatorState::Active(allocator) => {
                // SAFETY: the caller proved this block belongs to the exact
                // active engine and remains exclusively accessible here.
                unsafe { allocator.reallocate(Some(block), new_size) }
            }
            MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticFirstArenaPageAllocatorState::Retained { .. }
            | MainStaticFirstArenaPageAllocatorState::Transition => None,
        }
    }

    /// Frees one allocation returned by this exact active first-arena owner.
    ///
    /// # Safety
    ///
    /// `block` must be a current allocation from this owner and must not have
    /// been freed, handed to a remote producer, or accessed concurrently.
    #[inline]
    pub(crate) unsafe fn free(
        &mut self,
        block: NonNull<u8>,
    ) -> Result<(), MainStaticFirstArenaPageAllocatorFreeError> {
        match &mut self.state {
            MainStaticFirstArenaPageAllocatorState::Active(allocator) => unsafe {
                allocator
                    .free(block)
                    .map_err(MainStaticFirstArenaPageAllocatorFreeError::Free)
            },
            MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticFirstArenaPageAllocatorState::Retained { .. }
            | MainStaticFirstArenaPageAllocatorState::Transition => {
                Err(MainStaticFirstArenaPageAllocatorFreeError::NotActive)
            }
        }
    }

    /// Completes the active page engine, or closes an owner that never mapped
    /// an arena because no ordinary fresh-page request succeeded.
    pub(crate) fn finish(
        self,
    ) -> Result<(), MainStaticFirstArenaPageAllocatorFinishError<'main>> {
        match self.state {
            MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage { .. } => Ok(()),
            MainStaticFirstArenaPageAllocatorState::Active(allocator) => match allocator.finish() {
                Ok(()) => Ok(()),
                Err(MainStaticProcessPageAllocatorFinishError::Retained(allocator)) => {
                    Err(MainStaticFirstArenaPageAllocatorFinishError::Retained(Self {
                        state: MainStaticFirstArenaPageAllocatorState::Active(allocator),
                    }))
                }
                Err(MainStaticProcessPageAllocatorFinishError::PageMap(error)) => {
                    Err(MainStaticFirstArenaPageAllocatorFinishError::PageMap(error))
                }
            },
            MainStaticFirstArenaPageAllocatorState::Retained { attachment } => {
                Err(MainStaticFirstArenaPageAllocatorFinishError::Retained(Self {
                    state: MainStaticFirstArenaPageAllocatorState::Retained { attachment },
                }))
            }
            MainStaticFirstArenaPageAllocatorState::Transition => {
                unreachable!("a consumed first-arena owner cannot remain mid-transition")
            }
        }
    }

    #[cfg(test)]
    #[inline]
    unsafe fn test_page_for_block(&self, block: NonNull<u8>) -> *mut Page {
        match &self.state {
            MainStaticFirstArenaPageAllocatorState::Active(allocator) => {
                unsafe { allocator.test_page_for_block(block) }
            }
            MainStaticFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticFirstArenaPageAllocatorState::Retained { .. }
            | MainStaticFirstArenaPageAllocatorState::Transition => core::ptr::null_mut(),
        }
    }
}

/// The process-lifetime counterpart to [`MainStaticFirstArenaPageAllocator`]
/// used only by the private runtime's ticket-zero allocation seam.
///
/// It starts without a mapping and retains the permanent static page session
/// after its first ordinary miss. Unlike the borrowed test/process owner, it
/// intentionally has no process finish transition: source process exit and
/// complete page-bearing fork ownership are not implemented, so dropping or
/// closing the runtime owner would turn live process state into a false
/// reusable attachment. An all-free active engine retains the same permanent
/// session and published first arena, which may reactivate sequentially on
/// ticket zero. The retired unit-test scheduler separately returns its legacy
/// PageMap mutation lease before that dormant state.
#[must_use = "the permanent ticket-zero runtime page owner must remain retained for process life"]
pub(crate) struct MainStaticRuntimeFirstArenaPageAllocator {
    state: MainStaticRuntimeFirstArenaPageAllocatorState,
}

/// The active ticket-zero engine and its exact owned PageMap ranges.
///
/// Production retains no process-wide PageMap mutation lease beside a live
/// initial client: its engine owns and serializes only the ranges it registers,
/// reads, mutates, and unregisters. The retired unit-test scheduler below
/// still carries its historical long lease so its parked-engine fixtures keep
/// their original capability boundary.
struct MainStaticRuntimeActiveEngine {
    engine: PageAllocatorEngine<'static, 'static, MainStaticProcessPageSession>,
    #[cfg(test)]
    page_map_lifecycle: ProcessPageMapMutationLease,
    page_map: crate::process_page_map::ProcessPageMapLease,
    arena_storage: &'static ProcessSharedArenaStorage,
}

// The old runtime scheduler could suspend a live ticket-zero engine while it
// lent its PageMap exclusion to a later worker. Native-shadow initial-thread
// operations now retain their promoted compiler-TLS owner directly, and
// later-worker preparation accepts only the existing dormant pair. Keep this
// shape only for the older runtime unit fixtures until `runtime_lifecycle.rs`
// removes their scheduler coverage; it is absent from normal allocator builds.
#[cfg(test)]
/// A live initial-thread engine after it has lent only its plain PageMap
/// exclusion to the runtime scheduler.
///
/// The static session, source engine state, and suspended-map access remain
/// private to ticket zero.  A later worker may borrow the already-published
/// process pair for one independently serialized operation, but it receives
/// neither this engine state nor a way to resume or free its client.
#[must_use = "a parked ticket-zero engine must resume on ticket zero or remain terminally retained"]
struct MainStaticRuntimeParkedEngine {
    session: MainStaticProcessPageSession,
    engine_state: PageAllocatorEngineState<'static, 'static>,
    page_map_access: ProcessPageMapSuspendedEngineAccess,
    page_map: crate::process_page_map::ProcessPageMapLease,
    arena_storage: &'static ProcessSharedArenaStorage,
}

#[cfg(test)]
enum MainStaticRuntimeParkedEngineResumeFailure {
    Busy(MainStaticRuntimeParkedEngine),
    Retained {
        session: MainStaticProcessPageSession,
        engine_state: PageAllocatorEngineState<'static, 'static>,
        page_map_access: ProcessPageMapSuspendedEngineAccess,
    },
}

enum MainStaticRuntimeFirstArenaPageAllocatorState {
    AwaitingFreshPage {
        session: MainStaticProcessPageSession,
        page_map: crate::process_page_map::ProcessPageMapLease,
        arena_storage: &'static ProcessSharedArenaStorage,
    },
    Active(MainStaticRuntimeActiveEngine),
    /// Test-only compatibility state for the retired ticket-zero scheduler.
    #[cfg(test)]
    ParkedActive(MainStaticRuntimeParkedEngine),
    /// The source page image was force-collected at an explicit handoff after
    /// an all-free local cycle. The permanent session and first arena remain
    /// process-owned. Production can reactivate its own disjoint ranges
    /// directly; the test-only retired scheduler has returned its historical
    /// long PageMap exclusion before reaching here.
    DormantExistingArena {
        session: MainStaticProcessPageSession,
        page_map: crate::process_page_map::ProcessPageMapLease,
        arena_storage: &'static ProcessSharedArenaStorage,
    },
    Retained,
    Transition,
}

/// A pre-publication refusal while creating the private runtime page owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticRuntimeFirstArenaPageAllocatorBeginError {
    PageMap(ProcessPageMapError),
    SubprocessMismatch,
}

/// A free outside the active ticket-zero runtime engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainStaticRuntimeFirstArenaPageAllocatorFreeError {
    NotActive,
    /// A separately serialized PageMap operation still owns the suspended
    /// initial engine's guard. The ticket-zero client remains live and may
    /// retry after that operation republishes its scheduler state.
    Busy,
    Free(FreeError),
}

#[cfg(test)]
impl MainStaticRuntimeActiveEngine {
    /// Releases only this engine's long PageMap guard while retaining every
    /// ticket-zero source fact required to resume it on the original thread.
    ///
    /// The caller has already excluded ticket-zero reentry through the
    /// runtime scheduler.  A failed wake after guard release is terminal: the
    /// returned separated state must remain retained rather than pretending
    /// that the initial engine is still active or all-free.
    fn suspend(self) -> Result<MainStaticRuntimeParkedEngine, (MainStaticProcessPageSession, PageAllocatorEngineState<'static, 'static>)> {
        let Self {
            engine,
            page_map_lifecycle,
            page_map,
            arena_storage,
        } = self;
        let (session, engine_state) = engine.suspend_runtime_ticket_zero();
        // SAFETY: `session` and `engine_state` remain together in the only
        // returned parked token. No raw PageMap access survives this consuming
        // transition, and only ticket zero may later reassemble the engine.
        match unsafe { page_map_lifecycle.into_suspended_engine_access() } {
            Ok(page_map_access) => Ok(MainStaticRuntimeParkedEngine {
                session,
                engine_state,
                page_map_access,
                page_map,
                arena_storage,
            }),
            Err(_) => Err((session, engine_state)),
        }
    }
}

#[cfg(test)]
impl MainStaticRuntimeParkedEngine {
    /// Reclaims the one long PageMap lease for this exact ticket-zero engine.
    ///
    /// A competing complete operation leaves the parked capability unchanged;
    /// every other failure retains the static session and engine state because
    /// the page-map handoff can no longer be replayed safely.
    fn resume(self) -> Result<MainStaticRuntimeActiveEngine, MainStaticRuntimeParkedEngineResumeFailure> {
        let Self {
            session,
            engine_state,
            page_map_access,
            page_map,
            arena_storage,
        } = self;
        // SAFETY: this is the exact suspended access paired with `session`
        // and `engine_state`; the caller immediately reassembles the only
        // ticket-zero engine on success.
        let page_map_lifecycle = match unsafe { page_map_access.into_mutation_lease() } {
            Ok(page_map_lifecycle) => page_map_lifecycle,
            Err((page_map_access, ProcessPageMapError::LifecycleBusy)) => {
                return Err(MainStaticRuntimeParkedEngineResumeFailure::Busy(Self {
                    session,
                    engine_state,
                    page_map_access,
                    page_map,
                    arena_storage,
                }));
            }
            Err((page_map_access, _)) => {
                return Err(MainStaticRuntimeParkedEngineResumeFailure::Retained {
                    session,
                    engine_state,
                    page_map_access,
                });
            }
        };
        Ok(MainStaticRuntimeActiveEngine {
            engine: PageAllocatorEngine::resume_runtime_ticket_zero(session, engine_state),
            page_map_lifecycle,
            page_map,
            arena_storage,
        })
    }

    /// Preserves exact live source ownership after a terminal handoff error.
    ///
    /// The PageMap access intentionally drops last: its Drop latches the
    /// process root, while the session and engine state remain permanently
    /// retained instead of running a partial shutdown.
    fn retain_terminal(self) {
        let Self {
            session,
            engine_state,
            page_map_access,
            page_map: _,
            arena_storage: _,
        } = self;
        session.retain_terminal();
        core::mem::forget(session);
        core::mem::forget(engine_state);
        drop(page_map_access);
    }
}

#[cfg(test)]
fn retain_runtime_park_failure(
    session: MainStaticProcessPageSession,
    engine_state: PageAllocatorEngineState<'static, 'static>,
) {
    session.retain_terminal();
    core::mem::forget(session);
    core::mem::forget(engine_state);
}

#[cfg(test)]
fn retain_runtime_resume_failure(
    session: MainStaticProcessPageSession,
    engine_state: PageAllocatorEngineState<'static, 'static>,
    page_map_access: ProcessPageMapSuspendedEngineAccess,
) {
    session.retain_terminal();
    core::mem::forget(session);
    core::mem::forget(engine_state);
    drop(page_map_access);
}

impl MainStaticRuntimeFirstArenaPageAllocator {
    /// Forms the lazy process-lifetime owner without reserving an arena.
    ///
    /// The caller already converted the source ticket-zero attachment into
    /// its permanent page session. This constructor checks only the immutable
    /// map/subprocess relation; the full root/image/zero-page preflight runs
    /// again immediately before the first mapping side effect.
    pub(crate) fn begin(
        session: MainStaticProcessPageSession,
        page_map: crate::process_page_map::ProcessPageMapLease,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> Result<Self, MainStaticRuntimeFirstArenaPageAllocatorBeginError> {
        let map_subprocess = page_map
            .subprocess()
            .map_err(MainStaticRuntimeFirstArenaPageAllocatorBeginError::PageMap)?;
        if !core::ptr::eq(map_subprocess.as_ptr(), session.subprocess().as_ptr()) {
            session.retain_terminal();
            return Err(MainStaticRuntimeFirstArenaPageAllocatorBeginError::SubprocessMismatch);
        }
        Ok(Self {
            state: MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage {
                session,
                page_map,
                arena_storage,
            },
        })
    }

    /// Temporarily lends the already-published dormant process pair to one
    /// later worker.
    ///
    /// A live initial engine remains current-thread local and is never
    /// suspended to make this pair available. Its only caller is the private
    /// runtime bridge, which creates one independently serialized later-main
    /// engine. Any pair or callback failure is terminal: after a later engine
    /// may have touched source page ownership, this permanent session cannot
    /// claim a retry.
    pub(crate) fn with_later_thread_page_pair<R>(
        &mut self,
        operation: impl FnOnce(ProcessPageArenaLease) -> Result<R, ()>,
    ) -> Result<R, ()> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                session,
                page_map,
                arena_storage,
            } => {
                let pair = arena_storage
                    .ready_lease()
                    .map_err(|_| ())
                    .and_then(|arena| ProcessPageArenaLease::join(page_map, arena).map_err(|_| ()));
                let Ok(pair) = pair else {
                    session.retain_terminal();
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                    return Err(());
                };
                match operation(pair) {
                    Ok(result) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                            session,
                            page_map,
                            arena_storage,
                        };
                        Ok(result)
                    }
                    Err(()) => {
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        Err(())
                    }
                }
            }
            #[cfg(test)]
            MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked) => {
                let pair = parked
                    .arena_storage
                    .ready_lease()
                    .map_err(|_| ())
                    .and_then(|arena| {
                        ProcessPageArenaLease::join(parked.page_map, arena).map_err(|_| ())
                    });
                let Ok(pair) = pair else {
                    parked.retain_terminal();
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                    return Err(());
                };
                match operation(pair) {
                    Ok(result) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                        Ok(result)
                    }
                    Err(()) => {
                        parked.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        Err(())
                    }
                }
            }
            other => {
                self.state = other;
                Err(())
            }
        }
    }

    /// Parks the live ticket-zero normal engine before a creating initial
    /// thread publishes a later pthread.
    ///
    /// This is a scheduler preparation, not a page-owner transfer. The
    /// engine and its caller-visible clients remain ticket-zero private; the
    /// returned suspended access merely allows a later complete operation to
    /// acquire the process PageMap lease. Dormant or never-mapped owners need
    /// no token and remain immediately lendable through the established path.
    #[cfg(test)]
    pub(crate) fn prepare_live_engine_for_later_thread(&mut self) -> bool {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(active) => {
                match active.suspend() {
                    Ok(parked) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                        true
                    }
                    Err((session, engine_state)) => {
                        retain_runtime_park_failure(session, engine_state);
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        false
                    }
                }
            }
            other @ (MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(_)) => {
                self.state = other;
                true
            }
            MainStaticRuntimeFirstArenaPageAllocatorState::Retained
            | MainStaticRuntimeFirstArenaPageAllocatorState::Transition => {
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                false
            }
        }
    }

    /// Reports the retired scheduler's test-only parked state.
    ///
    /// Production has no parked ticket-zero engine: normal native-shadow
    /// initial-thread operations own their direct compiler-TLS engine, while
    /// a later worker can borrow only the dormant pair. The false production
    /// branch preserves the existing runtime-lifecycle scalar query until its
    /// owning compatibility scheduler is deleted.
    #[inline]
    pub(crate) fn has_parked_live_engine(&self) -> bool {
        #[cfg(test)]
        {
            matches!(
                self.state,
                MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(_)
            )
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Establishes the one first arena needed before the existing later-main
    /// page-engine handoff can borrow a dormant process pair.
    ///
    /// A never-used ticket-zero owner has no arena identity to lend, while an
    /// active owner may already contain caller-visible allocations.  This
    /// helper therefore permits only the empty pre-first-page state: it makes
    /// and releases one private word-sized allocation, which drives the
    /// normal source engine through its all-free finish into
    /// `DormantExistingArena`.  It never touches an active owner, never
    /// allocates a second arena, and never treats a failed release as a
    /// retryable handoff.
    pub(crate) fn prepare_dormant_page_pair(&mut self) -> bool {
        match &self.state {
            MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. } => true,
            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. } => {
                let Some(block) = self.allocate(WORD_SIZE, false) else {
                    return false;
                };
                // SAFETY: `block` is the exact private allocation made above
                // while this owner remains exclusively borrowed. Nothing can
                // publish or alias it before this matching source free.
                if unsafe { self.free(block) }.is_err() {
                    return false;
                }
                matches!(
                    &self.state,
                    MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
                )
            }
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(_)
            | MainStaticRuntimeFirstArenaPageAllocatorState::Retained
            | MainStaticRuntimeFirstArenaPageAllocatorState::Transition => false,
            #[cfg(test)]
            MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(_) => false,
        }
    }

    /// Whether this permanent ticket-zero owner contains no active engine or
    /// caller-visible native allocation.
    ///
    /// The runtime asks this only after its fork-admission gate has excluded
    /// every later owner and after its own `READY` state has excluded a
    /// current ticket-zero operation.  `AwaitingFreshPage` has never mapped
    /// the first arena; `DormantExistingArena` reached the source all-free
    /// finish and retains only the process-lifetime session and arena
    /// identity. Both copied images are safe to continue independently in a
    /// quiescent child. An `Active` engine may hold a caller client and exact
    /// PageMap entries, so it deliberately remains outside this narrow fork
    /// contract.
    #[inline]
    pub(crate) fn is_quiescent_for_fork(&self) -> bool {
        matches!(
            &self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
                | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
        )
    }

    /// Runs one allocation operation while preserving the permanent
    /// ticket-zero owner's source arena/page-map transition.
    ///
    /// Ordinary and aligned allocation share this lifecycle: a first request
    /// may reserve exactly one source default arena, and a dormant owner may
    /// only reactivate that same arena. Production releases its short setup
    /// lease before an active engine can publish a client, then relies on the
    /// engine's exact-owned-range PageMap contract. The operation itself
    /// selects only the source allocation primitive; it cannot change the
    /// owner state machine.
    fn allocate_with(
        &mut self,
        request: usize,
        allocate: impl FnOnce(
            &mut PageAllocatorEngine<'static, 'static, MainStaticProcessPageSession>,
        ) -> Option<NonNull<u8>>,
    ) -> Option<NonNull<u8>> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(mut active) => {
                let block = allocate(&mut active.engine);
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
                block
            }
            #[cfg(test)]
            MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked) => {
                match parked.resume() {
                    Ok(mut active) => {
                        let block = allocate(&mut active.engine);
                        match active.suspend() {
                            Ok(parked) => {
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                                block
                            }
                            Err((session, engine_state)) => {
                                retain_runtime_park_failure(session, engine_state);
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                                None
                            }
                        }
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Busy(parked)) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                        None
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Retained {
                        session,
                        engine_state,
                        page_map_access,
                    }) => {
                        retain_runtime_resume_failure(session, engine_state, page_map_access);
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        None
                    }
                }
            }
            MainStaticRuntimeFirstArenaPageAllocatorState::Retained => {
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                None
            }
            MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                session,
                page_map,
                arena_storage,
            } => {
                // This branch reuses only the already-published first arena.
                // It must not turn a later ordinary request into a second
                // `mi_arena_reserve` policy decision.
                if !size_class::request_size_is_valid(request.max(WORD_SIZE)) {
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                        session,
                        page_map,
                        arena_storage,
                    };
                    return None;
                }
                if !session.preflight_fresh_page_session() {
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                    return None;
                }
                let arena_lease = match arena_storage.ready_lease() {
                    Ok(arena) => arena,
                    Err(_) => {
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let pair = match ProcessPageArenaLease::join(page_map, arena_lease) {
                    Ok(pair) => pair,
                    Err(_) => {
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let page_map_lifecycle = match page_map.begin_page_lifecycle() {
                    Ok(lifecycle) => lifecycle,
                    Err(ProcessPageMapError::LifecycleBusy) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                            session,
                            page_map,
                            arena_storage,
                        };
                        return None;
                    }
                    Err(_) => {
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let arena = match pair.arena() {
                    Ok(arena) => arena,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                #[cfg(test)]
                let page_map_ref = match page_map_lifecycle.page_map() {
                    Ok(page_map_ref) => page_map_ref,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                #[cfg(not(test))]
                let page_map_ref = match unsafe { pair.page_map_for_owned_ranges() } {
                    Ok(page_map_ref) => page_map_ref,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                #[cfg(not(test))]
                if page_map_lifecycle.finish().is_err() {
                    // No page registration or caller-visible client exists
                    // yet. The failed Release has already poisoned the root,
                    // so retain the permanent session instead of exposing a
                    // fresh engine without its completed setup boundary.
                    session.retain_terminal();
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                    return None;
                }
                // SAFETY: the permanent session just revalidated ticket-zero
                // roots and an empty static Theap. Production owns every map
                // range this engine can touch; the test-only scheduler keeps
                // its legacy complete-lifecycle lease.
                #[cfg(test)]
                let mut engine = unsafe {
                    PageAllocatorEngine::activate_main_static(
                        session,
                        arena,
                        ArenaId::none(),
                        page_map_ref,
                    )
                };
                // SAFETY: the paired process facts establish one process
                // image. This engine alone owns each range it registers and
                // keeps its metadata live until it unregisters that range.
                #[cfg(not(test))]
                let mut engine = unsafe {
                    PageAllocatorEngine::activate_main_static_for_owned_ranges(
                        session,
                        arena,
                        ArenaId::none(),
                        page_map_ref,
                    )
                };
                let block = allocate(&mut engine);
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(
                    MainStaticRuntimeActiveEngine {
                        engine,
                        #[cfg(test)]
                        page_map_lifecycle,
                        page_map,
                        arena_storage,
                    },
                );
                block
            }
            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage {
                session,
                page_map,
                arena_storage,
            } => {
                let config = match page_map.memory_config() {
                    Ok(config) => config,
                    Err(_) => {
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let required_size = match first_ordinary_fresh_page_size(config, request) {
                    Some(size) => size,
                    None => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage {
                            session,
                            page_map,
                            arena_storage,
                        };
                        return None;
                    }
                };
                if !session.preflight_fresh_page_session() {
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                    return None;
                }
                let page_map_lifecycle = match page_map.begin_page_lifecycle() {
                    Ok(lifecycle) => lifecycle,
                    Err(ProcessPageMapError::LifecycleBusy) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage {
                            session,
                            page_map,
                            arena_storage,
                        };
                        return None;
                    }
                    Err(_) => {
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let arena = match arena_storage.reserve_default_os_arena(page_map, required_size) {
                    Ok(arena) => arena,
                    Err(ProcessSharedArenaReserveFailure::Rejected { .. }) => {
                        self.state = if page_map_lifecycle.finish().is_ok() {
                            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage {
                                session,
                                page_map,
                                arena_storage,
                            }
                        } else {
                            session.retain_terminal();
                            MainStaticRuntimeFirstArenaPageAllocatorState::Retained
                        };
                        return None;
                    }
                    Err(ProcessSharedArenaReserveFailure::Retained { .. }) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let pair = match ProcessPageArenaLease::join(page_map, arena) {
                    Ok(pair) => pair,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                let arena = match pair.arena() {
                    Ok(arena) => arena,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                #[cfg(test)]
                let page_map_ref = match page_map_lifecycle.page_map() {
                    Ok(page_map_ref) => page_map_ref,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                #[cfg(not(test))]
                let page_map_ref = match unsafe { pair.page_map_for_owned_ranges() } {
                    Ok(page_map_ref) => page_map_ref,
                    Err(_) => {
                        let _ = page_map_lifecycle.finish();
                        session.retain_terminal();
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return None;
                    }
                };
                #[cfg(not(test))]
                if page_map_lifecycle.finish().is_err() {
                    // The default arena is published, but no page has been
                    // registered or client returned. A failed setup release
                    // poisons the root, so keep the permanent session
                    // terminal rather than exposing that arena again.
                    session.retain_terminal();
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                    return None;
                }
                // SAFETY: the permanent session revalidated the exact
                // ticket-zero roots/images immediately before mapping. The
                // test-only scheduler retains its legacy complete-lifecycle
                // lease beside the engine.
                #[cfg(test)]
                let mut engine = unsafe {
                    PageAllocatorEngine::activate_main_static(
                        session,
                        arena,
                        ArenaId::none(),
                        page_map_ref,
                    )
                };
                // SAFETY: the paired process facts establish one process
                // image. This engine alone owns each range it registers and
                // keeps its metadata live until it unregisters that range.
                #[cfg(not(test))]
                let mut engine = unsafe {
                    PageAllocatorEngine::activate_main_static_for_owned_ranges(
                        session,
                        arena,
                        ArenaId::none(),
                        page_map_ref,
                    )
                };
                let block = allocate(&mut engine);
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(
                    MainStaticRuntimeActiveEngine {
                        engine,
                        #[cfg(test)]
                        page_map_lifecycle,
                        page_map,
                        arena_storage,
                    },
                );
                block
            }
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition => {
                unreachable!("a mutable runtime first-arena owner cannot reenter its state transition")
            }
        }
    }

    /// Allocates one ordinary ticket-zero block, lazily reserving the frozen
    /// first default arena only after this session needs a fresh page.
    #[inline]
    pub(crate) fn allocate(&mut self, request: usize, zero: bool) -> Option<NonNull<u8>> {
        self.allocate_with(request, |engine| engine.allocate(request, zero))
    }

    /// Allocates one aligned ticket-zero block through the same permanent
    /// source owner as [`Self::allocate`].
    ///
    /// The page engine retains the pinned in-arena versus OS-aligned
    /// singleton decision. This wrapper validates alignment before it can
    /// reserve the first arena, so an invalid C-ABI alignment remains a
    /// non-mutating allocation refusal.
    #[inline]
    pub(crate) fn allocate_aligned(
        &mut self,
        request: usize,
        alignment: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if !size_class::alignment_is_valid(alignment) {
            return None;
        }
        self.allocate_with(request, |engine| {
            if zero {
                engine.allocate_aligned_zeroed(request, alignment)
            } else {
                engine.allocate_aligned(request, alignment)
            }
        })
    }

    /// Allocates through the continuously owned initial-thread engine.
    ///
    /// This admits only the direct active, dormant, or pre-first-page source
    /// states. A suspended engine is deliberately not a valid input: the
    /// persistent initial owner never parks or resumes around an ordinary
    /// local allocation.
    #[inline]
    pub(crate) fn allocate_current_initial_thread_local(
        &mut self,
        request: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if !matches!(
            &self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
                | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
                | MainStaticRuntimeFirstArenaPageAllocatorState::Active(_)
        ) {
            return None;
        }
        self.allocate(request, zero)
    }

    /// Allocates an aligned block through the continuously owned initial
    /// engine, rejecting a suspended compatibility owner before it can enter
    /// the generic parked path.
    #[inline]
    pub(crate) fn allocate_aligned_current_initial_thread_local(
        &mut self,
        request: usize,
        alignment: usize,
        zero: bool,
    ) -> Option<NonNull<u8>> {
        if !matches!(
            &self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
                | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
                | MainStaticRuntimeFirstArenaPageAllocatorState::Active(_)
        ) {
            return None;
        }
        self.allocate_aligned(request, alignment, zero)
    }

    /// Reallocates one live ticket-zero runtime allocation.
    ///
    /// # Safety
    ///
    /// `block`, when present, must be a current allocation of this exact
    /// owner, with no aliased access, remote producer, or prior free.
    #[inline]
    pub(crate) unsafe fn reallocate(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        let Some(block) = block else {
            return self.allocate(new_size, false);
        };
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(mut active) => {
                // SAFETY: forwarded unchanged from this method's exact-current
                // allocation contract while the runtime owns the live engine.
                let replacement = unsafe { active.engine.reallocate(Some(block), new_size) };
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
                replacement
            }
            #[cfg(test)]
            MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked) => {
                match parked.resume() {
                    Ok(mut active) => {
                        // SAFETY: this exact parked engine was reassembled on
                        // ticket zero before its current client is touched.
                        let replacement = unsafe { active.engine.reallocate(Some(block), new_size) };
                        match active.suspend() {
                            Ok(parked) => {
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                                replacement
                            }
                            Err((session, engine_state)) => {
                                retain_runtime_park_failure(session, engine_state);
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                                None
                            }
                        }
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Busy(parked)) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                        None
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Retained {
                        session,
                        engine_state,
                        page_map_access,
                    }) => {
                        retain_runtime_resume_failure(session, engine_state, page_map_access);
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        None
                    }
                }
            }
            other @ (MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::Retained
            | MainStaticRuntimeFirstArenaPageAllocatorState::Transition) => {
                self.state = other;
                None
            }
        }
    }

    /// Reallocates a current client through the directly owned initial engine.
    ///
    /// A caller that cannot prove the direct active state receives `None`.
    ///
    /// # Safety
    ///
    /// `block`, when present, must be current in this exact active owner with
    /// no aliased access, remote producer, or prior free.
    #[inline]
    pub(crate) unsafe fn reallocate_current_initial_thread_local(
        &mut self,
        block: Option<NonNull<u8>>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        let Some(block) = block else {
            return self.allocate_current_initial_thread_local(new_size, false);
        };
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(mut active) => {
                // SAFETY: the persistent initial owner keeps this exact
                // engine current and exclusively borrowed for the call.
                let replacement = unsafe { active.engine.reallocate(Some(block), new_size) };
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
                replacement
            }
            other => {
                self.state = other;
                None
            }
        }
    }

    /// Reallocates one current native C-ABI client through the initial
    /// persistent engine. The core retains ordinary realloc's source
    /// decision/copy/free order while selecting a naturally aligned
    /// replacement for the public Linux/AArch64 C boundary.
    ///
    /// # Safety
    ///
    /// `block` must be current in this exact active owner with no aliased
    /// access, remote producer, or prior free.
    #[inline]
    pub(crate) unsafe fn reallocate_current_initial_thread_local_c_abi(
        &mut self,
        block: NonNull<u8>,
        new_size: usize,
    ) -> Option<NonNull<u8>> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(mut active) => {
                // SAFETY: the persistent initial owner keeps this exact
                // engine current and exclusively borrowed for the call.
                let replacement = unsafe { active.engine.reallocate_c_abi(Some(block), new_size) };
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
                replacement
            }
            other => {
                self.state = other;
                None
            }
        }
    }

    /// Returns the usable size of one current ticket-zero allocation.
    ///
    /// # Safety
    ///
    /// `block` must remain a current allocation of this exact owner and no
    /// other page operation may concurrently mutate its PageMap entry. The
    /// runtime invokes this only while its ticket-zero operation guard holds
    /// the permanent owner exclusively.
    #[inline]
    pub(crate) unsafe fn usable_size(&mut self, block: NonNull<u8>) -> Option<usize> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(active) => {
                // SAFETY: forwarded unchanged from this method's current
                // allocation and exclusive-runtime-owner contract.
                let usable_size = unsafe { active.engine.usable_size(block) };
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
                usable_size
            }
            #[cfg(test)]
            MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked) => {
                match parked.resume() {
                    Ok(active) => {
                        // SAFETY: the suspended ticket-zero engine is again
                        // the one active owner of this exact client.
                        let usable_size = unsafe { active.engine.usable_size(block) };
                        match active.suspend() {
                            Ok(parked) => {
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                                usable_size
                            }
                            Err((session, engine_state)) => {
                                retain_runtime_park_failure(session, engine_state);
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                                None
                            }
                        }
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Busy(parked)) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                        None
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Retained {
                        session,
                        engine_state,
                        page_map_access,
                    }) => {
                        retain_runtime_resume_failure(session, engine_state, page_map_access);
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        None
                    }
                }
            }
            other @ (MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::Retained
            | MainStaticRuntimeFirstArenaPageAllocatorState::Transition) => {
                self.state = other;
                None
            }
        }
    }

    /// Returns the usable size of a current client in the directly owned
    /// initial engine.
    ///
    /// # Safety
    ///
    /// `block` must remain current in this active owner and no remote
    /// publication or concurrent mutation may overlap this local query.
    #[inline]
    pub(crate) unsafe fn usable_size_current_initial_thread_local(
        &mut self,
        block: NonNull<u8>,
    ) -> Option<usize> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(active) => {
                // SAFETY: the persistent initial owner holds the only direct
                // mutable projection of this exact current engine.
                let usable_size = unsafe { active.engine.usable_size(block) };
                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
                usable_size
            }
            other => {
                self.state = other;
                None
            }
        }
    }

    /// Force-collects an active initial engine only when an explicit boundary
    /// needs to lend its dormant process pair to a later worker.
    ///
    /// Pinned `mi_free` performs its local page free without a Theap teardown;
    /// this is the separate source collection boundary. A live client leaves
    /// the exact active engine intact and rejects the handoff. A completed
    /// all-free engine transitions once to its dormant process pair.
    fn finish_active_engine_for_dormant_pair(
        &mut self,
        active: MainStaticRuntimeActiveEngine,
    ) -> bool {
        // The exact-owned-range contract stays with an active engine until
        // this explicit boundary proves that every page, queue, direct slot,
        // retired record, and pending OS release is gone. Only the retired
        // test scheduler additionally returns its old long PageMap lease.
        #[cfg(test)]
        let MainStaticRuntimeActiveEngine {
            engine,
            page_map_lifecycle,
            page_map,
            arena_storage,
        } = active;
        #[cfg(not(test))]
        let MainStaticRuntimeActiveEngine {
            engine,
            page_map,
            arena_storage,
        } = active;
        match engine.finish_runtime_ticket_zero() {
            Err(engine) => {
                #[cfg(test)]
                {
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(
                        MainStaticRuntimeActiveEngine {
                            engine,
                            page_map_lifecycle,
                            page_map,
                            arena_storage,
                        },
                    );
                }
                #[cfg(not(test))]
                {
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(
                        MainStaticRuntimeActiveEngine {
                            engine,
                            page_map,
                            arena_storage,
                        },
                    );
                }
                false
            }
            Ok(session) => {
                #[cfg(test)]
                {
                    match page_map_lifecycle.finish() {
                        Ok(()) => {
                            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                                session,
                                page_map,
                                arena_storage,
                            };
                            true
                        }
                        Err(_) => {
                            // The source free already completed. A failed private
                            // wake after releasing the guard poisons the root, so
                            // retain the permanent session rather than reconstructing
                            // a false active lifecycle.
                            session.retain_terminal();
                            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                            false
                        }
                    }
                }
                #[cfg(not(test))]
                {
                    self.state = MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                        session,
                        page_map,
                        arena_storage,
                    };
                    true
                }
            }
        }
    }

    /// Completes an exact free through the historical generic runtime path.
    ///
    /// The direct persistent initial-thread path below deliberately bypasses
    /// this helper: pinned `mi_free` leaves its all-free page owned by the
    /// current Theap until an explicit collection or handoff boundary.
    unsafe fn free_active_engine(
        &mut self,
        mut active: MainStaticRuntimeActiveEngine,
        block: NonNull<u8>,
    ) -> Result<(), MainStaticRuntimeFirstArenaPageAllocatorFreeError> {
        // SAFETY: forwarded unchanged from this method's exact-current
        // allocation contract while this state owns the sole engine.
        if let Err(error) = unsafe { active.engine.free(block) } {
            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Active(active);
            return Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::Free(error));
        }
        let _ = self.finish_active_engine_for_dormant_pair(active);
        Ok(())
    }

    /// Frees a current client through the continuously owned initial-thread
    /// engine.
    ///
    /// This path operates only on the direct active owner and leaves that
    /// engine resident when the page becomes all-free. Pinned `mi_free` keeps
    /// that local Theap/page state for a later local allocation; only an
    /// explicit later-worker handoff force-collects it.
    ///
    /// # Safety
    ///
    /// `block` must be current in this exact active owner with no aliased
    /// access, remote producer, or prior free.
    #[inline]
    pub(crate) unsafe fn free_current_initial_thread_local(
        &mut self,
        block: NonNull<u8>,
    ) -> Result<(), MainStaticRuntimeFirstArenaPageAllocatorFreeError> {
        match &mut self.state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(active) => {
                // SAFETY: the persistent initial owner keeps this exact
                // engine current and exclusively borrowed for the local free.
                unsafe { active.engine.free(block) }
                    .map_err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::Free)
            }
            _ => Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::NotActive),
        }
    }

    /// Gives the persistent initial owner a dormant process pair before a
    /// later worker starts. An all-free active engine force-collects exactly
    /// here; a live initial client never parks or transfers merely to make a
    /// later worker admissible.
    #[inline]
    pub(crate) fn prepare_dormant_page_pair_current_initial_thread_local(&mut self) -> bool {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(active) => {
                self.finish_active_engine_for_dormant_pair(active)
            }
            other => {
                let may_prepare = matches!(
                    &other,
                    MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
                        | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
                );
                self.state = other;
                may_prepare && self.prepare_dormant_page_pair()
            }
        }
    }

    /// Frees one exact ticket-zero runtime allocation.
    ///
    /// # Safety
    ///
    /// `block` must be current in this owner and may not be freed, remotely
    /// transferred, or accessed concurrently through another path.
    #[inline]
    pub(crate) unsafe fn free(
        &mut self,
        block: NonNull<u8>,
    ) -> Result<(), MainStaticRuntimeFirstArenaPageAllocatorFreeError> {
        let state = core::mem::replace(
            &mut self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Transition,
        );
        match state {
            MainStaticRuntimeFirstArenaPageAllocatorState::Active(active) => {
                // SAFETY: forwarded unchanged from this method's exact-current
                // allocation contract while this state owns the sole engine.
                unsafe { self.free_active_engine(active, block) }
            }
            #[cfg(test)]
            MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked) => {
                let mut active = match parked.resume() {
                    Ok(active) => active,
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Busy(parked)) => {
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                        return Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::Busy);
                    }
                    Err(MainStaticRuntimeParkedEngineResumeFailure::Retained {
                        session,
                        engine_state,
                        page_map_access,
                    }) => {
                        retain_runtime_resume_failure(session, engine_state, page_map_access);
                        self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        return Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::NotActive);
                    }
                };
                // SAFETY: ticket zero resumed the exact suspended source
                // engine before this client free; no worker receives this
                // engine or its client identity through the pair handoff.
                if let Err(error) = unsafe { active.engine.free(block) } {
                    match active.suspend() {
                        Ok(parked) => {
                            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                            return Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::Free(error));
                        }
                        Err((session, engine_state)) => {
                            retain_runtime_park_failure(session, engine_state);
                            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                            return Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::NotActive);
                        }
                    }
                }

                let MainStaticRuntimeActiveEngine {
                    engine,
                    page_map_lifecycle,
                    page_map,
                    arena_storage,
                } = active;
                match engine.finish_runtime_ticket_zero() {
                    Err(engine) => {
                        let active = MainStaticRuntimeActiveEngine {
                            engine,
                            page_map_lifecycle,
                            page_map,
                            arena_storage,
                        };
                        match active.suspend() {
                            Ok(parked) => {
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::ParkedActive(parked);
                            }
                            Err((session, engine_state)) => {
                                retain_runtime_park_failure(session, engine_state);
                                self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                                return Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::NotActive);
                            }
                        }
                    }
                    Ok(session) => match page_map_lifecycle.finish() {
                        Ok(()) => {
                            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena {
                                session,
                                page_map,
                                arena_storage,
                            };
                        }
                        Err(_) => {
                            // The source free already completed. A failed
                            // private wake after releasing the guard poisons
                            // the root, so retain the permanent session rather
                            // than reconstructing a false parked lifecycle.
                            session.retain_terminal();
                            self.state = MainStaticRuntimeFirstArenaPageAllocatorState::Retained;
                        }
                    },
                }
                Ok(())
            }
            other @ (MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::DormantExistingArena { .. }
            | MainStaticRuntimeFirstArenaPageAllocatorState::Retained
            | MainStaticRuntimeFirstArenaPageAllocatorState::Transition) => {
                self.state = other;
                Err(MainStaticRuntimeFirstArenaPageAllocatorFreeError::NotActive)
            }
        }
    }

    /// Whether a failed page/root transition has made this permanent owner
    /// terminal. An ordinary invalid allocation remains retryable while it
    /// is still awaiting its first fresh page.
    #[inline]
    pub(crate) fn is_retained(&self) -> bool {
        matches!(
            self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::Retained
        )
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn test_is_waiting_for_first_page(&self) -> bool {
        matches!(
            self.state,
            MainStaticRuntimeFirstArenaPageAllocatorState::AwaitingFreshPage { .. }
        )
    }
}

/// Returns the first ordinary page span selected by an empty source Theap.
///
/// This mirrors `PageAllocatorEngine::allocate` through its first
/// `mi_arenas_page_alloc` call: small direct requests always need one small
/// page, while generic requests preserve `mi_good_size`, huge singleton, and
/// normal page-kind selection. It deliberately says nothing about a later
/// queue miss: this owner implements only the first-arena boundary.
fn first_ordinary_fresh_page_size(config: MemoryConfig, request: usize) -> Option<usize> {
    let request = request.max(WORD_SIZE);
    if !size_class::request_size_is_valid(request) {
        return None;
    }
    if request <= SMALL_SIZE_MAX {
        return Some(SMALL_PAGE_SIZE);
    }
    let bin = size_class::bin(request)?;
    let (block_size, kind) = if bin == BIN_HUGE {
        let block_size = config.good_alloc_size(request);
        if block_size == 0 || block_size < request {
            return None;
        }
        (block_size, PageKind::Singleton)
    } else {
        let block_size = size_class::good_size(request, config.page_size().bytes())?;
        if size_class::bin(block_size)? != bin {
            return None;
        }
        let kind = size_class::page_kind_for_block_size(block_size)?;
        if kind == PageKind::Singleton {
            return None;
        }
        (block_size, kind)
    };
    let slice_count = match kind {
        PageKind::Small | PageKind::Medium | PageKind::Large => {
            page::regular_page_slice_count(kind)?
        }
        PageKind::Singleton => page::singleton_page_slice_count(block_size)?,
    };
    slice_count.checked_mul(ARENA_SLICE_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ARENA_ALIGNMENT, ARENA_MIN_SIZE};
    use crate::main_theap::{MainStaticAttachmentStorage, MainStaticTheapAttachment};
    use crate::os::{MapAccess, Mapping, MemoryConfig, PageSize};
    use crate::process_arena::{ProcessSharedArenaLease, ProcessSharedArenaStorage};
    use crate::process_page_map::{ProcessPageMapLease, ProcessPageMapStorage};
    use crate::subproc::MainSubprocess;
    use std::thread;

    fn memory_config() -> MemoryConfig {
        MemoryConfig::from_observations(
            PageSize::new(4096).expect("the native page size is valid"),
            1024 * 1024,
            false,
            false,
        )
    }

    fn paired_process_owner(
        config: MemoryConfig,
        subprocess: &'static MainSubprocess,
    ) -> (ProcessPageMapLease, ProcessSharedArenaLease) {
        let page_map = ProcessPageMapStorage::test_static_owner()
            .initialize(config, subprocess)
            .expect("the isolated process map initializes");
        let mapping = Mapping::map_aligned_for_allocator(
            config,
            ARENA_MIN_SIZE,
            ARENA_ALIGNMENT,
            MapAccess::Committed,
        )
        .expect("the test owns one complete source arena mapping");
        let arena = match ProcessSharedArenaStorage::test_static_owner()
            .install_one_owned_external_arena(page_map, mapping)
        {
            Ok(arena) => arena,
            Err(_) => panic!("the selected mapping becomes the one process arena"),
        };
        (page_map, arena)
    }

    #[test]
    fn reserved_os_arena_reservation_drives_one_static_page_lifecycle() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let page_map = ProcessPageMapStorage::test_static_owner()
                .initialize(config, subprocess)
                .expect("the isolated process map initializes before reservation");
            let process_arena = match ProcessSharedArenaStorage::test_static_owner()
                .reserve_one_os_arena(page_map, ARENA_MIN_SIZE, MapAccess::Reserved)
            {
                Ok(arena) => arena,
                Err(_) => panic!("the explicit reserved OS arena publishes"),
            };
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the reserved OS arena and map form one process image");
            let arena = process_arena.arena().expect("the OS arena remains published");
            assert_eq!(arena.arena().memid.kind(), crate::types::MemoryKind::Os);
            assert!(!arena.arena().memid.initially_committed());

            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the ticket-zero owner attaches before the OS-backed page lifecycle");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched OS arena admits the static page engine");
            let block = allocator
                .allocate(37, false)
                .expect("a static page commits and allocates from the reserved OS arena");
            let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                .expect("the block is PageMap-published");
            let memory = unsafe { page.as_ref().memid() };
            let slice = memory
                .arena_memory()
                .expect("the static page remains in the reserved OS arena")
                .slice_index as usize;
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                page.as_ptr(),
                "the OS-backed static page publishes exactly one map member"
            );
            assert_eq!(unsafe { arena.pages() }.unwrap().is_set_range(slice, 1), Some(true));

            // SAFETY: `block` is the one exact live allocation returned by
            // this static page engine.
            unsafe { allocator.free(block) }.expect("the OS-backed static block frees");
            match allocator.finish() {
                Ok(()) => {}
                Err(_) => panic!("all-free release closes the page lifecycle"),
            }
            assert!(unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) }.is_null());
            assert_eq!(unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1), Some(true));
            owner
                .teardown()
                .expect("the empty OS-backed static owner tears down cleanly");
        })
        .join()
        .expect("reserved OS arena lifecycle remains current-thread local");
    }

    #[test]
    fn main_static_page_allocator_binds_the_in_place_main_arena_bitmap_before_page_map_publication() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let arena = process_arena.arena().expect("the process arena remains published");
            let arena_index = arena.arena().arena_index;
            let expected_pages = NonNull::from(&arena.arena().pages_main);
            let expected_arena = core::ptr::from_ref(arena.arena()).cast_mut();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the ticket-zero static owner attaches before its page session");
            let expected_heap = owner.test_heap_pointer();
            let expected_theap = owner.test_theap_pointer();

            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit one static page engine");
            assert!(matches!(
                page_map.begin_page_lifecycle(),
                Err(ProcessPageMapError::LifecycleBusy)
            ), "the live engine owns the process map's sole plain-entry lifecycle");
            let block = allocator
                .allocate(37, false)
                .expect("a fresh static-main page allocates from the process arena");
            let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                .expect("the fresh block is PageMap-published");
            // SAFETY: the allocator holds the process map mutation lease and
            // the block/page remain live until the matching local free below.
            let memory = unsafe { page.as_ref().memid() };
            let slice = memory
                .arena_memory()
                .expect("the static page uses the paired arena")
                .slice_index as usize;
            assert_eq!(unsafe { page.as_ref().heap() }, expected_heap);
            assert_eq!(unsafe { page.as_ref().theap() }, expected_theap);
            assert_eq!(
                memory.arena_memory().unwrap().arena,
                expected_arena,
                "fresh page provenance stays in the paired process arena"
            );
            assert_eq!(
                unsafe { arena.pages() }.unwrap().is_set_range(slice, 1),
                Some(true),
                "the embedded main bitmap transitions before PageMap publication"
            );
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                page.as_ptr(),
                "the completed fresh page is visible through the release-published process root"
            );

            // SAFETY: `block` is the one current allocation owned by this
            // exact static page engine.
            unsafe { allocator.free(block) }.expect("the local static free succeeds");
            assert!(matches!(
                allocator.finish(),
                Ok(())
            ), "all-free collection unregisters the map and clears the main bitmap");
            let mutation = page_map
                .begin_page_lifecycle()
                .expect("a completed engine releases the map lifecycle boundary");
            mutation
                .finish()
                .expect("an empty follow-on lifecycle releases cleanly");

            let (heap, _) = owner.test_images();
            assert_eq!(heap.arena_pages_at(arena_index), Some(expected_pages));
            assert_eq!(
                unsafe { arena.pages() }.unwrap().is_clear_range(slice, 1),
                Some(true),
                "release clears the exact embedded main bitmap after PageMap unregistration"
            );
            assert!(
                unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) }.is_null(),
                "the release path removes the full PageMap span before teardown"
            );
            assert!(
                arena
                    .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                    .is_some_and(|claim| claim.release()),
                "the all-free static page returns its source arena slice"
            );
            owner
                .teardown()
                .expect("the empty static page owner tears down after page lifecycle completion");
        })
        .join()
        .expect("static page fixture remains current-thread local");
    }

    #[test]
    fn foreign_process_page_pair_rejects_before_static_heap_map_or_arena_mutation() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let static_subprocess = MainSubprocess::test_static_owner();
            let foreign_subprocess = MainSubprocess::test_static_owner();
            let (foreign_map, foreign_process_arena) =
                paired_process_owner(config, foreign_subprocess);
            let pair = ProcessPageArenaLease::join(foreign_map, foreign_process_arena)
                .expect("the foreign map and arena remain internally matched");
            let arena = foreign_process_arena
                .arena()
                .expect("the foreign arena is registry-published");
            let arena_index = arena.arena().arena_index;
            let map_base = arena.slice_start(0).expect("arena has an address-stable first slice");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, static_subprocess)
            }
            .expect("the independent static owner attaches");

            assert!(matches!(
                MainStaticProcessPageAllocator::begin(&mut owner, pair),
                Err(MainStaticProcessPageAllocatorBeginError::SubprocessMismatch)
            ));
            let (heap, theap) = owner.test_images();
            assert!(heap.arena_pages_at(arena_index).is_none());
            assert_eq!(theap.page_count(), 0);
            assert_eq!(
                unsafe { foreign_map.page_map().unwrap().checked_lookup(map_base) },
                core::ptr::null_mut(),
                "the foreign root receives no page publication"
            );
            assert_eq!(
                unsafe { arena.pages() }.unwrap().is_clear_range(0, arena.arena().slice_count),
                Some(true),
                "the foreign arena bitmap remains untouched"
            );
            let mutation = foreign_map
                .begin_page_lifecycle()
                .expect("mismatch never acquires or poisons the foreign map lifecycle");
            mutation.finish().expect("foreign map remains reusable");
            owner
                .teardown()
                .expect("a pre-mutation rejection leaves the static owner intact");
        })
        .join()
        .expect("foreign-pair rejection remains current-thread local");
    }

    #[test]
    fn preexisting_main_arena_bit_rolls_back_the_static_fresh_claim_without_map_publication() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let arena = process_arena.arena().expect("the process arena remains published");
            let probe = arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                .expect("one ordinary arena slice is available for the injected bitmap state");
            let slice = probe.slice_index();
            let slice_start = probe.start();
            assert!(probe.release());
            assert!(unsafe { arena.pages() }
                .and_then(|pages| pages.set_range(slice, 1))
                .is_some_and(|transition| transition.all_transitioned()));

            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the static owner attaches before its failed fresh-page attempt");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit the static page engine");
            assert!(allocator.allocate(37, false).is_none());
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(slice_start) },
                core::ptr::null_mut(),
                "a duplicate main bitmap bit rejects before PageMap registration"
            );
            assert!(matches!(allocator.finish(), Ok(())));
            assert_eq!(
                unsafe { arena.pages() }.unwrap().clear_range(slice, 1),
                Some(true),
                "the test removes only its preexisting invalid bitmap bit"
            );
            let reclaimed = arena
                .try_claim_suitable_slices(ArenaId::none(), 1, true, 0)
                .expect("the failed static fresh claim returned its exact arena slice");
            assert_eq!(reclaimed.slice_index(), slice);
            assert!(reclaimed.release());
            owner
                .teardown()
                .expect("the failed fresh path leaves no static page state");
        })
        .join()
        .expect("main-bitmap rollback fixture remains current-thread local");
    }

    #[test]
    fn joined_remote_producer_is_collected_by_the_static_main_page_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the static owner attaches before its producer lifecycle");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit the static page engine");
            let block = allocator
                .allocate(37, false)
                .expect("the static owner has one regular source page");
            let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                .expect("the regular static block remains PageMap-published");
            let capacity = unsafe { page.as_ref().capacity() as usize };
            let mut local_blocks = std::vec::Vec::with_capacity(capacity);
            local_blocks.push(block);
            while unsafe { page.as_ref().used() } < capacity {
                let next = allocator
                    .allocate(37, false)
                    .expect("the current static direct page supplies its initialized capacity");
                assert_eq!(unsafe { allocator.test_page_for_block(next) }, page.as_ptr());
                local_blocks.push(next);
            }
            assert!(capacity < unsafe { page.as_ref().reserved() as usize });
            let producer = unsafe { allocator.begin_remote_free(block) }
                .expect("the active static regular page admits its bounded producer");
            thread::scope(|scope| {
                let joined = scope.spawn(move || producer.publish());
                match joined.join().expect("the scoped producer remains live") {
                    Ok(()) => {}
                    Err((producer, _)) => {
                        let _ = producer.cancel();
                        panic!("the static remote producer must publish its exact live block");
                    }
                }
            });
            let reused = allocator
                .allocate(37, false)
                .expect("the regular source scan false-collects the joined remote block");
            assert_eq!(reused, block);
            // SAFETY: owner collection returned this exact remote block to
            // local static ownership once.
            unsafe { allocator.free(reused) }.expect("the reused static block frees");
            for local in local_blocks.into_iter().skip(1) {
                // SAFETY: sibling allocations were never transferred and
                // remain exact current blocks from the same static page.
                unsafe { allocator.free(local) }.expect("the static sibling frees");
            }
            assert!(matches!(allocator.finish(), Ok(())));
            owner
                .teardown()
                .expect("the joined producer leaves no static page owner behind");
        })
        .join()
        .expect("static remote-producer fixture remains current-thread local");
    }

    #[test]
    fn unfinished_static_page_engine_poison_retains_the_page_and_process_map_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let (page_map, process_arena) = paired_process_owner(config, subprocess);
            let pair = ProcessPageArenaLease::join(page_map, process_arena)
                .expect("the selected map and arena form one process image");
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(storage, subprocess)
            }
            .expect("the static owner attaches before its retained-page fixture");
            let mut allocator = MainStaticProcessPageAllocator::begin(&mut owner, pair)
                .expect("the matched process owners admit the static page engine");
            let block = allocator
                .allocate(37, false)
                .expect("the retained fixture creates one live static page");
            let page = unsafe { allocator.test_page_for_block(block) };
            drop(allocator);

            assert_eq!(
                owner.teardown(),
                Err(crate::main_theap::MainStaticTheapError::Poisoned),
                "dropping unfinished page state cannot imitate static thread teardown"
            );
            assert!(matches!(
                page_map.begin_page_lifecycle(),
                Err(ProcessPageMapError::Poisoned)
            ), "the PageMap root remains terminal instead of admitting another plain-entry owner");
            assert_eq!(
                unsafe {
                    page_map
                        .test_retained_page_map()
                        .expect("the terminal root still retains its final PageMap slot")
                        .checked_lookup(block.as_ptr())
                },
                page,
                "the retained terminal owner preserves the live PageMap registration"
            );
            // This intentionally leaves the isolated process image retained.
            // No bounded cleanup path can release a page after its engine was
            // discarded, so a test must not forge one merely to reclaim its
            // leaked fixture backing.
            core::mem::forget(owner);
        })
        .join()
        .expect("unfinished static page fixture remains current-thread local");
    }

    #[test]
    fn first_ticket_zero_fresh_page_reserves_the_default_arena_only_after_a_valid_miss() {
        thread::spawn(|| {
            let config = memory_config();
            let attachment_storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let page_map = ProcessPageMapStorage::test_static_owner()
                .initialize(config, subprocess)
                .expect("the page-map root exists before the lazy owner opens");
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(attachment_storage, subprocess)
            }
            .expect("the ticket-zero owner attaches before its first page miss");
            let mut allocator = MainStaticFirstArenaPageAllocator::begin(
                &mut owner,
                page_map,
                arena_storage,
            )
            .expect("the matching root and ticket-zero attachment open lazily");

            assert!(arena_storage.test_is_cold(), "opening the owner is not an arena reservation");
            assert!(
                allocator
                    .allocate(crate::config::MAX_ALLOC_SIZE + 1, false)
                    .is_none(),
                "an invalid request has no source fresh-page miss or arena side effect"
            );
            assert!(arena_storage.test_is_cold(), "the invalid request leaves the first arena cold");

            let block = allocator
                .allocate(37, false)
                .expect("the first ordinary small request reaches the lazy source arena reserve");
            let page = NonNull::new(unsafe { allocator.test_page_for_block(block) })
                .expect("the first page is registered only after its default arena exists");
            assert!(
                !arena_storage.test_is_cold(),
                "the first source fresh-page miss publishes the one default arena"
            );
            assert_eq!(
                unsafe { page_map.page_map().unwrap().checked_lookup(block.as_ptr()) },
                page.as_ptr(),
                "the activated ticket-zero engine owns the new PageMap registration"
            );

            // SAFETY: `block` is the exact live allocation returned by this
            // active lazy owner and has not escaped to a producer.
            unsafe { allocator.free(block) }
                .expect("the first-arena ticket-zero block releases normally");
            assert!(matches!(allocator.finish(), Ok(())));
            owner
                .teardown()
                .expect("the all-free lazy owner restores static teardown eligibility");
        })
        .join()
        .expect("the lazy first-arena fixture remains current-thread local");
    }

    #[test]
    fn process_lifetime_first_arena_stays_lazy_then_retains_ticket_zero_page_owner() {
        thread::spawn(|| {
            let config = memory_config();
            let attachment_storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let page_map = ProcessPageMapStorage::test_static_owner()
                .initialize(config, subprocess)
                .expect("the page-map root exists before the runtime owner opens");
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(attachment_storage, subprocess)
            }
            .expect("ticket zero attaches before becoming the permanent page owner");
            let session = owner
                .begin_process_lifetime_page_session()
                .expect("the empty ticket-zero image can become permanent");
            let mut allocator = MainStaticRuntimeFirstArenaPageAllocator::begin(
                session,
                page_map,
                arena_storage,
            )
            .expect("the matching process lifetime roots open lazily");

            assert!(allocator.test_is_waiting_for_first_page());
            assert!(arena_storage.test_is_cold(), "opening retains no runtime arena yet");
            assert!(
                allocator
                    .allocate(crate::config::MAX_ALLOC_SIZE + 1, false)
                    .is_none(),
                "an invalid request must not turn the permanent owner into a mapping side effect"
            );
            assert!(allocator.test_is_waiting_for_first_page());
            assert!(arena_storage.test_is_cold(), "the invalid request leaves the arena cold");

            let block = allocator
                .allocate(37, false)
                .expect("the first ordinary request reaches the permanent default arena owner");
            assert!(
                !arena_storage.test_is_cold(),
                "the first valid miss alone publishes the source default arena"
            );
            assert!(
                !unsafe {
                    page_map
                        .page_map()
                        .expect("the PageMap remains published")
                        .checked_lookup(block.as_ptr())
                        .is_null()
                },
                "the active permanent engine registers its exact ticket-zero allocation"
            );

            // SAFETY: `block` is the exact live allocation from this sole
            // process-lifetime engine and has not escaped the ticket-zero thread.
            unsafe { allocator.free(block) }
                .expect("the active permanent owner releases its exact block normally");
            let mutation = page_map
                .begin_page_lifecycle()
                .expect("an all-free runtime engine releases only its PageMap lifecycle lease");
            mutation
                .finish()
                .expect("the observed empty follow-on lifecycle returns the shared map guard");

            let reused = allocator
                .allocate(73, false)
                .expect("the permanent ticket-zero session reactivates through its published first arena");
            // SAFETY: `reused` is the one current allocation from the
            // reactivated permanent owner and has not escaped this fixture.
            unsafe { allocator.free(reused) }
                .expect("the reactivated owner releases its exact block normally");
            assert_eq!(
                owner.teardown(),
                Err(crate::main_theap::MainStaticTheapError::ProcessPageSessionLive),
                "a permanent page session cannot reopen the static teardown path after free"
            );

            // The runtime retains the permanent static session and its first
            // arena until process exit. A bounded test must model that
            // terminal ownership rather than manufacture process cleanup.
            core::mem::forget(allocator);
            core::mem::forget(owner);
        })
        .join()
        .expect("the permanent runtime first-arena fixture remains ticket-zero local");
    }

    #[test]
    fn current_initial_thread_local_operations_lend_only_the_dormant_pair() {
        thread::spawn(|| {
            let config = memory_config();
            let attachment_storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let page_map = ProcessPageMapStorage::test_static_owner()
                .initialize(config, subprocess)
                .expect("the page-map root exists before the runtime owner opens");
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(attachment_storage, subprocess)
            }
            .expect("ticket zero attaches before becoming the permanent page owner");
            let session = owner
                .begin_process_lifetime_page_session()
                .expect("the empty ticket-zero image can become permanent");
            let mut allocator = MainStaticRuntimeFirstArenaPageAllocator::begin(
                session,
                page_map,
                arena_storage,
            )
            .expect("the matching process lifetime roots open lazily");

            let block = allocator
                .allocate_current_initial_thread_local(79, false)
                .expect("the initial thread creates one direct live allocation");
            // SAFETY: `block` is uniquely live in the direct initial engine.
            unsafe {
                block.as_ptr().write(0x31);
                block.as_ptr().add(78).write(0x32);
            }

            // SAFETY: `block` remains the exact unique direct initial client.
            assert!(
                unsafe { allocator.usable_size_current_initial_thread_local(block) }.is_some(),
                "the direct initial owner reports its current client's usable size"
            );
            // SAFETY: `block` remains the exact current direct client. The
            // replacement remains in the same initial engine and covers the
            // initialized 79-byte prefix.
            let block = unsafe {
                allocator.reallocate_current_initial_thread_local(Some(block), 97)
            }
            .expect("the direct initial owner reallocates without a scheduler bridge");
            assert_eq!(unsafe { block.as_ptr().read() }, 0x31);
            assert_eq!(unsafe { block.as_ptr().add(78).read() }, 0x32);

            assert!(
                allocator
                    .with_later_thread_page_pair(|_| Ok::<(), ()>(()))
                    .is_err(),
                "a live direct initial engine never lends its pair by parking"
            );
            assert!(
                !allocator.prepare_dormant_page_pair_current_initial_thread_local(),
                "dormant-pair preparation refuses a current live initial engine"
            );

            // SAFETY: `block` remains the exact unique direct initial client.
            unsafe { allocator.free_current_initial_thread_local(block) }
                .expect("the direct initial owner frees its current client");
            assert!(
                allocator.prepare_dormant_page_pair_current_initial_thread_local(),
                "the all-free initial owner preserves the existing dormant preparation"
            );
            allocator
                .with_later_thread_page_pair(|pair| {
                    let lifecycle = pair.begin_page_lifecycle().map_err(|_| ())?;
                    lifecycle.finish().map_err(|_| ())
                })
                .expect("only the dormant pair is available to a later lifecycle");

            let reused = allocator
                .allocate_current_initial_thread_local(53, false)
                .expect("the direct initial owner reactivates through its retained first arena");
            // SAFETY: `reused` is the sole current client after the dormant
            // pair returned its independent lifecycle.
            unsafe { allocator.free_current_initial_thread_local(reused) }
                .expect("the reactivated direct owner frees normally");

            // The process-lifetime ticket-zero session deliberately remains
            // retained until process exit; this isolated fixture must not
            // forge a static attachment teardown after using that boundary.
            core::mem::forget(allocator);
            core::mem::forget(owner);
        })
        .join()
        .expect("the direct initial-owner fixture remains current-thread local");
    }

    #[test]
    fn first_ticket_zero_realloc_null_activates_and_preserves_the_live_block_on_failure() {
        thread::spawn(|| {
            let config = memory_config();
            let attachment_storage = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let page_map = ProcessPageMapStorage::test_static_owner()
                .initialize(config, subprocess)
                .expect("the page-map root exists before the lazy owner opens");
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let mut owner = unsafe {
                MainStaticTheapAttachment::begin_with_test_storage(attachment_storage, subprocess)
            }
            .expect("the ticket-zero owner attaches before its first page miss");
            let mut allocator = MainStaticFirstArenaPageAllocator::begin(
                &mut owner,
                page_map,
                arena_storage,
            )
            .expect("the matching root and ticket-zero attachment open lazily");

            // SAFETY: the null case creates a new allocation through this
            // exact owner, then keeps that allocation uniquely live here.
            let block = unsafe { allocator.reallocate(None, 37) }
                .expect("realloc(NULL, size) reaches the first ordinary arena miss");
            for index in 0..37 {
                // SAFETY: the returned allocation is uniquely live and has
                // at least the requested 37-byte extent.
                unsafe { block.as_ptr().add(index).write((index as u8).wrapping_add(3)) };
            }
            assert!(
                !arena_storage.test_is_cold(),
                "the realloc null case activates the same lazy default-arena policy"
            );

            // SAFETY: `block` remains the unique current allocation. The
            // rejected size must preserve it without a second allocation.
            assert!(unsafe { allocator.reallocate(Some(block), crate::config::MAX_ALLOC_SIZE + 1) }
                .is_none());
            for index in 0..37 {
                // SAFETY: the failed reallocation retained `block` live.
                assert_eq!(unsafe { block.as_ptr().add(index).read() }, (index as u8).wrapping_add(3));
            }

            // SAFETY: the old allocation is still live and exclusively held;
            // the ordinary replacement must copy its source extent first.
            let replacement = unsafe {
                allocator.reallocate(Some(block), crate::config::SMALL_MAX_OBJ_SIZE + 1)
            }
            .expect("the active first-arena engine reallocates into its medium branch");
            for index in 0..37 {
                // SAFETY: `replacement` is uniquely live and its requested
                // extent covers the original initialized prefix.
                assert_eq!(
                    unsafe { replacement.as_ptr().add(index).read() },
                    (index as u8).wrapping_add(3)
                );
            }

            // SAFETY: the successful reallocation consumed `block` and
            // returned this sole current allocation.
            unsafe { allocator.free(replacement) }
                .expect("the reallocated first-arena block releases normally");
            assert!(matches!(allocator.finish(), Ok(())));
            owner
                .teardown()
                .expect("the reallocation fixture restores static teardown eligibility");
        })
        .join()
        .expect("the lazy first-arena realloc fixture remains current-thread local");
    }

    #[test]
    fn first_fresh_page_requirement_preserves_the_empty_theap_source_size_branches() {
        let config = memory_config();
        assert_eq!(
            first_ordinary_fresh_page_size(config, 0),
            Some(crate::config::SMALL_PAGE_SIZE),
            "a normalized zero request starts with one direct small page"
        );
        assert_eq!(
            first_ordinary_fresh_page_size(config, crate::config::SMALL_MAX_OBJ_SIZE + 1),
            Some(crate::config::MEDIUM_PAGE_SIZE),
            "the first generic post-small request keeps the medium source span"
        );
        assert_eq!(
            first_ordinary_fresh_page_size(config, crate::config::MEDIUM_MAX_OBJ_SIZE + 1),
            Some(crate::config::LARGE_PAGE_SIZE),
            "the first post-medium request keeps the large source span"
        );
        let singleton_request = crate::config::LARGE_MAX_OBJ_SIZE + 1;
        let singleton_block = config.good_alloc_size(singleton_request);
        assert_eq!(
            first_ordinary_fresh_page_size(config, singleton_request),
            crate::page::singleton_page_slice_count(singleton_block)
                .and_then(|slices| slices.checked_mul(crate::config::ARENA_SLICE_SIZE)),
            "the huge-bin first miss preserves its page-rounded singleton span"
        );
        assert_eq!(
            first_ordinary_fresh_page_size(config, crate::config::MAX_ALLOC_SIZE + 1),
            None,
            "an invalid request has no source first-page span"
        );
    }
}
