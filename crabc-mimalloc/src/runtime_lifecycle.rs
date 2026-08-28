// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license is included in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/init.c:236-282,305-360,377-421,
// 448-481`, `src/theap.c:228-306,414-449`, `src/threadlocal.c:205-214`, and
// `src/prim/unix/prim.c:943-974`; the direct libc fork placement follows
// pinned musl 1.2.6 `src/process/fork.c`.

//! Private crabc-runtime lifecycle bridge.
//!
//! This module is the one direct Rust boundary used by `crabc-libc` while the
//! C mimalloc backend remains the production allocator. It retains the
//! source-shaped ticket-zero `ProcessMainThread` and the main-thread-minted
//! `MainStaticHeapLease` for the process lifetime, then places one no-page
//! `MainHeapThreadAttachment` in compiler TLS for each pthread worker that
//! successfully enters through the runtime. A dormant ticket-zero native page
//! owner may lend its already-published pair to one such worker for a bounded
//! local or joined remote-free page-engine round trip; the worker finishes
//! only after libc has run user cleanup handlers and pthread TSD destructors.
//!
//! It deliberately does not route any `malloc`/`free` call, expose a C symbol,
//! select a backend, create a public pthread key, or claim general fork
//! recovery. A failed process setup leaves this shadow lifecycle unavailable
//! and preserves the C backend. A failed worker attachment prevents that
//! worker's start routine from running; libc performs the parent/child startup
//! handshake. On libc's prepared `fork` path, only the original ticket-zero
//! TLS image with no live or retained later bridge owner preserves the copied
//! no-page process owner. Every other child disables this incomplete lifecycle
//! without traversing inherited locks, roots, or page state.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::compiler_tls::current_thread_identity;
use crate::config::{
    LARGE_MAX_OBJ_SIZE, MEDIUM_MAX_OBJ_SIZE, SMALL_MAX_OBJ_SIZE, SMALL_PAGE_SIZE,
};
use crate::main_heap_thread::{
    MainHeapThreadAttachment, MainHeapThreadAttachmentBeginError,
};
use crate::main_heap_page::MainHeapThreadProcessPageAllocator;
use crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocator;
use crate::main_theap::MainStaticHeapLease;
use crate::os::{MemoryConfig, PageSize, StartupInput};
use crate::process_init::{ProcessMainInitializationStorage, ProcessMainThread};
use crate::process_arena::{ProcessPageArenaLease, ProcessSharedArenaStorage};
use crate::single_thread::{RemoteFreeProducer, RemoteFreeProducerPair};

const PROCESS_COLD: u8 = 0;
const PROCESS_INITIALIZING: u8 = 1;
const PROCESS_ACTIVE: u8 = 2;
const PROCESS_RETAINED: u8 = 3;

// A separate process-long owner state keeps the original no-page lifecycle
// intact until an internal ticket-zero request needs the first native page.
// `BUSY` closes same-thread recursive entry while one engine operation can
// touch source page metadata; it is never a general allocator lock.
const PAGE_OWNER_COLD: u8 = 0;
const PAGE_OWNER_STARTING: u8 = 1;
const PAGE_OWNER_READY: u8 = 2;
const PAGE_OWNER_BUSY: u8 = 3;
const PAGE_OWNER_RETAINED: u8 = 4;

/// Result of one private ticket-zero native allocation operation.
///
/// This is a Rust-only friend interface for future bounded integration tests;
/// it has no C ABI and does not select the libc allocation backend.
#[doc(hidden)]
pub enum TicketZeroPageAllocationResult {
    Allocated(core::ptr::NonNull<u8>),
    Unavailable,
    AllocationFailed,
    Retained,
}

/// Result of returning one exact private ticket-zero native allocation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketZeroPageFreeResult {
    Freed,
    Unavailable,
    InvalidPointer,
    Retained,
}

/// Result of one private scoped later-worker page-engine round trip.
///
/// The operation is intentionally narrower than allocation routing: it
/// attaches the current worker, uses the ticket-zero owner's already-published
/// pair only while ticket zero is dormant, returns that engine empty, and
/// finishes the worker attachment. No pointer crosses the boundary.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketZeroLaterThreadPageResult {
    Completed,
    Unavailable,
    AllocationFailed,
    Retained,
}

/// One private, linear remote-free publication capability for a live later
/// worker page. It is only a friend-boundary wrapper around the source-shaped
/// engine token: it accepts no client pointer and exposes no allocator state.
///
/// The adapter may move it to exactly one joined pthread and call
/// [`Self::publish`]. If that operation cannot publish, it must return this
/// value to the runtime callback so the owner can cancel the transfer while it
/// still holds the exclusive engine lifecycle.
#[doc(hidden)]
#[must_use = "the remote-free publication must be published or returned to its runtime callback"]
pub struct TicketZeroRemoteFreeProducer<'owner> {
    producer: RemoteFreeProducer<'owner>,
}

impl<'owner> TicketZeroRemoteFreeProducer<'owner> {
    /// Publishes this one logical handoff to the live owner page's source
    /// remote-free head. It never exposes the transferred client pointer.
    #[inline]
    pub fn publish(self) -> Result<(), Self> {
        match self.producer.publish() {
            Ok(()) => Ok(()),
            Err((producer, _)) => Err(Self { producer }),
        }
    }

}

/// Two opaque source remote-free capabilities for the same stopped worker A.
/// The adapter may split and move them to two joined publisher pthreads B/C;
/// neither receiver obtains a client pointer or an owner capability.
#[doc(hidden)]
#[must_use = "both remote-free publications must be published or returned to the runtime callback"]
pub struct TicketZeroRemoteFreeProducerPair<'owner> {
    producers: RemoteFreeProducerPair<'owner>,
}

impl<'owner> TicketZeroRemoteFreeProducerPair<'owner> {
    #[inline]
    pub fn split(
        self,
    ) -> (
        TicketZeroRemoteFreeProducer<'owner>,
        TicketZeroRemoteFreeProducer<'owner>,
    ) {
        let (first, second) = self.producers.split();
        (
            TicketZeroRemoteFreeProducer { producer: first },
            TicketZeroRemoteFreeProducer { producer: second },
        )
    }

    #[inline]
    fn cancel(self) -> (core::ptr::NonNull<u8>, core::ptr::NonNull<u8>) {
        self.producers.cancel()
    }
}

/// The adapter-supplied, joined two-publisher operation for the private Gate
/// 5B witness. A higher-ranked function pointer proves the adapter cannot
/// retain either capability beyond the owner's scoped engine lifetime.
#[doc(hidden)]
pub type TicketZeroRemoteFreePublisher = for<'owner> fn(
    TicketZeroRemoteFreeProducerPair<'owner>,
) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>>;

// The high two bits are an allocation-free fork admission gate. The low bits
// count every current later-thread attachment, including one still between its
// pre-user-code attach and post-destructor finish transitions. A fork may
// preserve the copied no-page process owner only if it first publishes the
// gate and observes this count at zero. The second high bit records that
// exactly that precondition held for the raw-fork child; it is never exposed
// while the parent is allowed to admit a later owner.
const FORK_GATE_HELD: usize = 1usize << (usize::BITS - 1);
const FORK_GATE_PRESERVE: usize = 1usize << (usize::BITS - 2);
const FORK_GATE_COUNT_MASK: usize = FORK_GATE_PRESERVE - 1;

/// Result of attempting the private worker-entry lifecycle transition.
///
/// This is Rust-only control flow for `crabc-libc`; it is not a stable public
/// allocator interface and has no C ABI representation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadAttachResult {
    /// The current pthread worker owns a live no-page metadata TLD/Theap.
    Attached,
    /// The process shadow lifecycle was never activated or was retained.
    Inactive,
    /// The current thread had already published an attachment.
    AlreadyAttached,
    /// A prior terminal transition leaves this thread's retained owner live.
    Retained,
    /// A completed worker lifecycle cannot be reattached on the same thread.
    Finished,
}

/// Result of attempting the private worker-exit lifecycle transition.
///
/// This is Rust-only control flow for `crabc-libc`; it is not a stable public
/// allocator interface and has no C ABI representation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadFinishResult {
    /// The no-page source `_mi_thread_done` sequence completed exactly once.
    Finished,
    /// This thread was never attached by crabc's pthread runtime.
    NotAttached,
    /// A second finish attempt was rejected after the completed first finish.
    AlreadyFinished,
    /// An incomplete owner remains retained; no completed teardown is claimed.
    Retained,
}

/// Process-lifetime slots for the ticket-zero owner and its Heap witness.
///
/// Both values are written once before `PROCESS_ACTIVE` is Release-published
/// and are never moved, mutated, or dropped by this slice. The heap witness
/// must be minted by the ticket-zero thread before workers exist; worker TPIDR
/// identities may use only the already-published copy. Main-thread teardown
/// needs a complete process-exit/fork contract and remains deliberately out
/// of scope while later workers can still carry source list members.
struct RuntimeProcessStorage {
    state: AtomicU8,
    /// The ticket-zero Linux/AArch64 TPIDR_EL0 identity. A copied process
    /// foundation can be preserved only when `fork` runs on this same TLS
    /// image; a foreign caller has no authority to treat the static TLD as
    /// its current-thread owner.
    initial_thread_identity: AtomicUsize,
    owner: UnsafeCell<MaybeUninit<ProcessMainThread>>,
    main_heap: UnsafeCell<MaybeUninit<MainStaticHeapLease<'static>>>,
    /// The permanent ticket-zero page owner is absent until the private
    /// native seam asks it for a valid allocation. It stays in this final
    /// slot afterward: source-shaped process exit is still out of scope.
    page_owner_state: AtomicU8,
    page_owner: UnsafeCell<MaybeUninit<MainStaticRuntimeFirstArenaPageAllocator>>,
}

// SAFETY: the COLD -> INITIALIZING CAS gives one writer exclusive access to
// `owner`; the final owner is written before PROCESS_ACTIVE's Release store
// and is thereafter read immutably. The independent page-owner state admits
// exactly ticket zero, first for one final-slot write and later for one
// READY -> BUSY engine operation. Terminal retention never mutates either
// owner.
unsafe impl Sync for RuntimeProcessStorage {}

impl RuntimeProcessStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PROCESS_COLD),
            initial_thread_identity: AtomicUsize::new(0),
            owner: UnsafeCell::new(MaybeUninit::uninit()),
            main_heap: UnsafeCell::new(MaybeUninit::uninit()),
            page_owner_state: AtomicU8::new(PAGE_OWNER_COLD),
            page_owner: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline]
    fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) == PROCESS_ACTIVE
    }

    /// Whether the process is active on the same TPIDR_EL0 image that minted
    /// ticket zero. Linux preserves that TLS image through `fork`; a newly
    /// created pthread receives a different one and cannot preserve the
    /// process-static attachment as though it owned ticket zero.
    #[inline]
    fn is_on_initial_thread(&self) -> bool {
        if !self.is_active() {
            return false;
        }
        let expected = self.initial_thread_identity.load(Ordering::Acquire);
        expected != 0
            && current_thread_identity().is_some_and(|current| current.get() == expected)
    }

    #[inline]
    fn is_active_on_initial_thread(&self) -> bool {
        self.is_on_initial_thread()
            // A permanent session—even one still waiting for its first
            // mapping—has page-root authority that this no-page fork bridge
            // cannot repair in a child. Preserve the old fork behavior only
            // before ticket zero begins that irreversible transition.
            && self.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_COLD
    }

    /// Returns the durable ticket-zero owner after its Release publication.
    ///
    /// # Safety
    ///
    /// The storage is process-static. This slice never calls `teardown` or
    /// drops its stored owner, so a caller receiving this reference may retain
    /// a borrow-tied main-Heap lease through a worker's complete lifecycle.
    unsafe fn active_owner(&'static self) -> Option<&'static ProcessMainThread> {
        if !self.is_active() {
            return None;
        }
        // SAFETY: PROCESS_ACTIVE is stored only after this exact static slot
        // is initialized. No path overwrites or drops it thereafter.
        Some(unsafe { (&*self.owner.get()).assume_init_ref() })
    }

    /// Returns the main-thread-minted shared-Heap lease after publication.
    ///
    /// # Safety
    ///
    /// The lease is created while the ticket-zero owner is current, then
    /// stored beside that never-dropped owner before PROCESS_ACTIVE is
    /// Release-published. It is Copy and contains only process-static
    /// addresses plus the owner's lifetime witness.
    unsafe fn active_main_heap(&'static self) -> Option<MainStaticHeapLease<'static>> {
        if !self.is_active() {
            return None;
        }
        // SAFETY: PROCESS_ACTIVE follows the one write to this static slot;
        // no path overwrites or drops the stored lease.
        Some(*unsafe { (&*self.main_heap.get()).assume_init_ref() })
    }

    fn retain(&self) {
        self.state.store(PROCESS_RETAINED, Ordering::Release);
    }

    /// Starts the hidden ticket-zero native owner without reserving an arena.
    ///
    /// This uses only the immutable process coordinator: the permanent
    /// session itself is designed to coexist with the copied shared-main Heap
    /// witness already held by pthread lifecycle code. Any startup failure is
    /// terminal, because retrying could reuse a partially claimed ticket-zero
    /// page image under a different process/lifecycle observation.
    fn start_ticket_zero_page_owner(&'static self) -> bool {
        self.start_ticket_zero_page_owner_with_storage(ProcessSharedArenaStorage::global())
    }

    fn start_ticket_zero_page_owner_with_storage(
        &'static self,
        arena_storage: &'static ProcessSharedArenaStorage,
    ) -> bool {
        if !self.is_on_initial_thread() {
            return false;
        }
        match self.page_owner_state.compare_exchange(
            PAGE_OWNER_COLD,
            PAGE_OWNER_STARTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(PAGE_OWNER_READY) => return true,
            Err(PAGE_OWNER_STARTING | PAGE_OWNER_BUSY | PAGE_OWNER_RETAINED | _) => return false,
        }

        // SAFETY: PROCESS_ACTIVE follows the final owner write. This only
        // takes its shared immutable view; `ProcessMainThread` converts the
        // static attachment through its shared permanent-session transition,
        // so it never conflicts with the stored main-Heap lease.
        let Some(owner) = (unsafe { self.active_owner() }) else {
            self.retain();
            self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
            return false;
        };
        let page_map = match owner.ready().and_then(|ready| ready.page_map()) {
            Ok(page_map) => page_map,
            Err(_) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                return false;
            }
        };
        let session = match owner.begin_process_lifetime_page_session() {
            Ok(session) => session,
            Err(_) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                return false;
            }
        };
        let page_owner = match MainStaticRuntimeFirstArenaPageAllocator::begin(
            session,
            page_map,
            arena_storage,
        ) {
            Ok(owner) => owner,
            Err(_) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                return false;
            }
        };
        // SAFETY: this COLD -> STARTING winner remains the sole writer until
        // the READY publication below. The stored owner is process-lifetime
        // and no path drops or replaces it.
        unsafe { (*self.page_owner.get()).write(page_owner) };
        self.page_owner_state.store(PAGE_OWNER_READY, Ordering::Release);
        true
    }

    /// Runs one non-reentrant operation on the ticket-zero native owner.
    ///
    /// Returning `None` means this private route is inactive or recursively
    /// busy; it never asks the C allocator to interpret a native pointer.
    fn with_ticket_zero_page_owner<R>(
        &'static self,
        operation: impl FnOnce(&mut MainStaticRuntimeFirstArenaPageAllocator) -> R,
    ) -> Option<R> {
        self.with_ticket_zero_page_owner_with_storage(ProcessSharedArenaStorage::global(), operation)
    }

    fn with_ticket_zero_page_owner_with_storage<R>(
        &'static self,
        arena_storage: &'static ProcessSharedArenaStorage,
        operation: impl FnOnce(&mut MainStaticRuntimeFirstArenaPageAllocator) -> R,
    ) -> Option<R> {
        if !self.start_ticket_zero_page_owner_with_storage(arena_storage) {
            return None;
        }
        if self
            .page_owner_state
            .compare_exchange(
                PAGE_OWNER_READY,
                PAGE_OWNER_BUSY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        // SAFETY: READY -> BUSY serializes every mutable engine operation;
        // `start_ticket_zero_page_owner` wrote this final slot before its
        // READY Release publication, and the current TPIDR check prevents a
        // pthread worker from borrowing the ticket-zero engine.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        let result = operation(owner);
        if owner.is_retained() {
            self.retain();
            self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
        } else {
            self.page_owner_state.store(PAGE_OWNER_READY, Ordering::Release);
        }
        Some(result)
    }

    /// Gives one attached later worker the permanent owner's already-published
    /// process pair only while ticket zero has no live native pages.
    ///
    /// This is a scoped handoff, not a concurrent page engine or a generic
    /// map scheduler. `READY -> BUSY` excludes ticket-zero reactivation while
    /// the worker holds the source map lifecycle lease. The callback must
    /// finish its own page engine empty; an error retains both permanent
    /// owners instead of manufacturing a second page lifecycle.
    fn with_dormant_page_pair<R>(
        &'static self,
        operation: impl FnOnce(ProcessPageArenaLease) -> Result<R, ()>,
    ) -> Option<R> {
        if !self.is_active()
            || self
                .page_owner_state
                .compare_exchange(
                    PAGE_OWNER_READY,
                    PAGE_OWNER_BUSY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return None;
        }
        // SAFETY: READY -> BUSY serializes this mutable permanent owner with
        // ticket zero. The final slot was written before READY's Release
        // publication and is never moved or replaced.
        let owner = unsafe { (&mut *self.page_owner.get()).assume_init_mut() };
        match owner.with_dormant_page_pair(operation) {
            Ok(result) => {
                self.page_owner_state.store(PAGE_OWNER_READY, Ordering::Release);
                Some(result)
            }
            Err(()) => {
                self.retain();
                self.page_owner_state.store(PAGE_OWNER_RETAINED, Ordering::Release);
                None
            }
        }
    }

    #[inline]
    fn page_owner_has_started(&self) -> bool {
        self.page_owner_state.load(Ordering::Acquire) != PAGE_OWNER_COLD
    }

    #[inline]
    fn page_owner_unavailable_result(&self) -> TicketZeroPageAllocationResult {
        if self.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || self.state.load(Ordering::Acquire) == PROCESS_RETAINED
        {
            TicketZeroPageAllocationResult::Retained
        } else {
            TicketZeroPageAllocationResult::Unavailable
        }
    }

    fn initialize(&'static self, page_size_bytes: usize) -> bool {
        match self.state.compare_exchange(
            PROCESS_COLD,
            PROCESS_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(PROCESS_ACTIVE) => return true,
            Err(_) => return false,
        }

        let Some(page_size) = PageSize::new(page_size_bytes) else {
            self.retain();
            return false;
        };
        let config = MemoryConfig::detect(StartupInput::new(page_size));
        // SAFETY: libc calls this only after initial TLS exists and before
        // application constructors. This static owner retains ticket zero for
        // the process lifetime, and no competing runtime lifecycle call can
        // pass the INITIALIZING state above.
        let owner = unsafe { ProcessMainInitializationStorage::global().initialize(config) };
        let Ok(owner) = owner else {
            self.retain();
            return false;
        };

        // SAFETY: this successful COLD -> INITIALIZING winner is the sole
        // writer, and `owner` is moved into its final static process slot
        // before PROCESS_ACTIVE makes it visible to worker threads.
        unsafe { (*self.owner.get()).write(owner) };
        // A shared main-Heap lease may only be minted by the ticket-zero
        // owner on its own thread. Store that immutable process witness now;
        // later pthread workers may copy it but must never try to mint it
        // while their TPIDR identity differs from the initial attachment.
        let owner = unsafe { (&*self.owner.get()).assume_init_ref() };
        let Ok(main_heap) = owner.shared_main_heap_lease() else {
            self.retain();
            return false;
        };
        let Some(initial_thread) = current_thread_identity() else {
            self.retain();
            return false;
        };
        // SAFETY: the same sole initializer writes this second final slot
        // before the Release publication below.
        unsafe { (*self.main_heap.get()).write(main_heap) };
        // The initial thread identity is written before PROCESS_ACTIVE's
        // Release publication. It is an immutable witness: a quiescent child
        // retains the copied TPIDR_EL0 image, while every fresh pthread gets a
        // distinct image and cannot pass the fork-preservation check.
        self.initial_thread_identity
            .store(initial_thread.get(), Ordering::Release);
        self.state.store(PROCESS_ACTIVE, Ordering::Release);
        true
    }
}

static RUNTIME_PROCESS: RuntimeProcessStorage = RuntimeProcessStorage::new();

/// Allocation-free admission accounting around the incomplete no-page
/// lifecycle.
///
/// This is deliberately not a general allocator lock or source fork repair.
/// It records only whether the bridge itself has a later TLD/Theap transition
/// in flight or retained. Holding `FORK_GATE_HELD` prevents a new attachment
/// from beginning while libc crosses raw `fork`; an already live owner is
/// conservatively carried into the non-preserving child case rather than
/// traversed, unlocked, or repaired there.
struct RuntimeForkAdmission {
    state: AtomicUsize,
}

impl RuntimeForkAdmission {
    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    /// Claims one later-thread lifecycle admission. A concurrent fork waits
    /// only while it crosses the raw kernel boundary; it never observes a
    /// half-published attachment as absent.
    fn claim_later_thread(&self) -> bool {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD != 0 {
                core::hint::spin_loop();
                continue;
            }
            let count = observed & FORK_GATE_COUNT_MASK;
            if count == FORK_GATE_COUNT_MASK {
                return false;
            }
            let next = observed + 1;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Releases one fully finished later-thread owner. The count remains
    /// visible while a fork gate is held, so a finish racing a fork can only
    /// make that fork more conservative; it can never retroactively turn an
    /// unsafe child into a preserving one.
    fn release_later_thread(&self) -> bool {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            let count = observed & FORK_GATE_COUNT_MASK;
            if count == 0 {
                return false;
            }
            let next = observed - 1;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Holds the direct internal fork boundary and records whether the copied
    /// child may preserve this incomplete no-page image. No allocation, lock
    /// traversal, page operation, or public pthread-atfork slot is involved.
    fn before_fork(&self, can_preserve_process_owner: bool) {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD != 0 {
                core::hint::spin_loop();
                continue;
            }
            let count = observed & FORK_GATE_COUNT_MASK;
            let preserve = can_preserve_process_owner && count == 0;
            let next = observed
                | FORK_GATE_HELD
                | if preserve { FORK_GATE_PRESERVE } else { 0 };
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Releases the parent's fork admission boundary while retaining the
    /// exact number of still-live later owners. This is called before public
    /// parent handlers, so a handler can create a pthread only after the
    /// runtime has restored normal admission.
    fn after_fork_parent(&self) {
        loop {
            let observed = self.state.load(Ordering::Acquire);
            if observed & FORK_GATE_HELD == 0 {
                return;
            }
            let next = observed & FORK_GATE_COUNT_MASK;
            if self
                .state
                .compare_exchange_weak(observed, next, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Resets the copied admission word without acquiring an inherited lock.
    /// The return value is true only when this exact fork path presented its
    /// prepared token and the gate recorded ticket zero with no bridge-owned
    /// later attachment. The explicit token prevents an unprepared raw fork
    /// on another thread from mistaking copied gate bits for its own proof.
    fn after_fork_child(&self, fork_was_prepared: bool) -> bool {
        let observed = self.state.swap(0, Ordering::AcqRel);
        fork_was_prepared
            && (observed & (FORK_GATE_HELD | FORK_GATE_PRESERVE))
            == (FORK_GATE_HELD | FORK_GATE_PRESERVE)
            && observed & FORK_GATE_COUNT_MASK == 0
    }
}

static RUNTIME_FORK_ADMISSION: RuntimeForkAdmission = RuntimeForkAdmission::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadLifecycleState {
    Fresh,
    Attached,
    Finished,
    Retained,
}

/// Per-pthread compiler-TLS storage for the explicit later-thread owner.
///
/// It intentionally has no destructor: libc calls the source-ordered finish
/// explicitly. Dropping an attached owner at ELF TLS teardown would hide a
/// failed lifecycle transition and could free state before the main Heap list
/// had been detached.
struct ThreadLifecycleSlot {
    state: ThreadLifecycleState,
    /// A successful admission remains claimed from child attach through the
    /// complete post-destructor finish. Retained states intentionally keep
    /// their claim in the parent, making later fork preservation reject
    /// rather than treating ambiguous source ownership as quiescent.
    admission_held: bool,
    attachment: Option<MainHeapThreadAttachment<'static>>,
}

impl ThreadLifecycleSlot {
    const fn new() -> Self {
        Self {
            state: ThreadLifecycleState::Fresh,
            admission_held: false,
            attachment: None,
        }
    }
}

#[thread_local]
static THREAD_LIFECYCLE: UnsafeCell<ThreadLifecycleSlot> =
    UnsafeCell::new(ThreadLifecycleSlot::new());

#[inline]
fn current_thread_slot() -> &'static mut ThreadLifecycleSlot {
    // SAFETY: this is compiler TLS. Only the running thread can reach its
    // slot, and libc invokes attach/finish serially on that thread.
    unsafe { &mut *THREAD_LIFECYCLE.get() }
}

/// Initializes the retained ticket-zero process owner from libc's validated
/// `AT_PAGESZ` value. A false result means the shadow lifecycle is unavailable
/// for this process; the existing C mimalloc backend remains selected.
#[doc(hidden)]
#[inline]
pub fn initialize_process(page_size_bytes: usize) -> bool {
    RUNTIME_PROCESS.initialize(page_size_bytes)
}

/// Whether the private process lifecycle can admit a new pthread worker.
#[doc(hidden)]
#[inline]
pub fn process_is_active() -> bool {
    RUNTIME_PROCESS.is_active()
}

/// Attempts one ordinary allocation through the private permanent ticket-zero
/// page owner.
///
/// This does not call or replace libc's `malloc`: callers must retain and use
/// only the returned native pointer through the matching APIs below. An
/// invalid size fails before permanent page-session startup, preserving the
/// existing no-page runtime lifecycle.
#[doc(hidden)]
pub fn ticket_zero_allocate(request: usize, zero: bool) -> TicketZeroPageAllocationResult {
    if !crate::size_class::request_size_is_valid(request) {
        return TicketZeroPageAllocationResult::AllocationFailed;
    }
    match RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| owner.allocate(request, zero)) {
        Some(Some(block)) => TicketZeroPageAllocationResult::Allocated(block),
        Some(None) => {
            if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
                || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED
            {
                TicketZeroPageAllocationResult::Retained
            } else {
                TicketZeroPageAllocationResult::AllocationFailed
            }
        }
        None => RUNTIME_PROCESS.page_owner_unavailable_result(),
    }
}

/// Reallocates one current private ticket-zero native allocation.
///
/// # Safety
///
/// `block`, when present, must have been returned by this exact runtime owner,
/// remain live, and have no aliased or cross-thread access. A failed result
/// preserves a non-null old block. This is not valid for a libc/C-backend
/// pointer and does not select a C allocator route.
#[doc(hidden)]
pub unsafe fn ticket_zero_reallocate(
    block: Option<core::ptr::NonNull<u8>>,
    new_size: usize,
) -> TicketZeroPageAllocationResult {
    if !crate::size_class::request_size_is_valid(new_size) {
        return TicketZeroPageAllocationResult::AllocationFailed;
    }
    if block.is_some() && !RUNTIME_PROCESS.page_owner_has_started() {
        return RUNTIME_PROCESS.page_owner_unavailable_result();
    }
    match RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| {
        // SAFETY: forwarded unchanged from this function's exact native-block
        // caller contract.
        unsafe { owner.reallocate(block, new_size) }
    }) {
        Some(Some(replacement)) => TicketZeroPageAllocationResult::Allocated(replacement),
        Some(None) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroPageAllocationResult::Retained
        }
        Some(None) => TicketZeroPageAllocationResult::AllocationFailed,
        None => RUNTIME_PROCESS.page_owner_unavailable_result(),
    }
}

/// Frees one current private ticket-zero native allocation.
///
/// # Safety
///
/// `block` must be a current unique result of [`ticket_zero_allocate`] or
/// [`ticket_zero_reallocate`]. It must not be a libc/C-backend pointer.
#[doc(hidden)]
pub unsafe fn ticket_zero_free(block: core::ptr::NonNull<u8>) -> TicketZeroPageFreeResult {
    if !RUNTIME_PROCESS.page_owner_has_started() {
        return match RUNTIME_PROCESS.page_owner_unavailable_result() {
            TicketZeroPageAllocationResult::Retained => TicketZeroPageFreeResult::Retained,
            TicketZeroPageAllocationResult::Allocated(_) | TicketZeroPageAllocationResult::Unavailable
            | TicketZeroPageAllocationResult::AllocationFailed => TicketZeroPageFreeResult::Unavailable,
        };
    }
    match RUNTIME_PROCESS.with_ticket_zero_page_owner(|owner| {
        // SAFETY: forwarded unchanged from this function's exact native-block
        // caller contract.
        unsafe { owner.free(block) }
    }) {
        Some(Ok(())) => TicketZeroPageFreeResult::Freed,
        Some(Err(crate::main_static_page::MainStaticRuntimeFirstArenaPageAllocatorFreeError::Free(
            crate::single_thread::FreeError::Unmapped
            | crate::single_thread::FreeError::ForeignPage
            | crate::single_thread::FreeError::InvalidBlock(_),
        ))) => TicketZeroPageFreeResult::InvalidPointer,
        Some(Err(_)) => {
            RUNTIME_PROCESS.retain();
            RUNTIME_PROCESS
                .page_owner_state
                .store(PAGE_OWNER_RETAINED, Ordering::Release);
            TicketZeroPageFreeResult::Retained
        }
        None if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroPageFreeResult::Retained
        }
        None => TicketZeroPageFreeResult::Unavailable,
    }
}

// This fixed, pointer-private test workload deliberately crosses the source
// small, medium, large, and singleton allocation branches. Two small and two
// medium blocks remain live while their siblings are freed and reacquired, so
// the reuse check observes local page ownership rather than a freshly released
// page or a ticket-zero handoff. The final singleton is larger than one large
// page to require a multi-page source singleton span.
const PERSISTENT_WORKER_LOCAL_REQUESTS: [(usize, u8); 7] = [
    (37, 0x11),
    (37, 0x22),
    (SMALL_MAX_OBJ_SIZE + 1, 0x33),
    (SMALL_MAX_OBJ_SIZE + 1, 0x44),
    (MEDIUM_MAX_OBJ_SIZE + 1, 0x55),
    (LARGE_MAX_OBJ_SIZE + 1, 0x66),
    (LARGE_MAX_OBJ_SIZE + 64 * 1024 + 1, 0x77),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentLocalWorkerError {
    AllocationFailed,
    PatternMismatch,
    Free,
}

#[inline]
unsafe fn fill_worker_pattern(block: core::ptr::NonNull<u8>, size: usize, seed: u8) {
    for offset in 0..size {
        // SAFETY: the caller proves this exact current allocation has at
        // least `size` writable bytes and no concurrent or aliased access.
        unsafe {
            block
                .as_ptr()
                .add(offset)
                .write(seed.wrapping_add(offset as u8));
        }
    }
}

#[inline]
unsafe fn worker_pattern_matches(block: core::ptr::NonNull<u8>, size: usize, seed: u8) -> bool {
    for offset in 0..size {
        // SAFETY: the caller proves this exact current allocation has at
        // least `size` readable bytes and no concurrent or aliased access.
        let observed = unsafe { block.as_ptr().add(offset).read() };
        if observed != seed.wrapping_add(offset as u8) {
            return false;
        }
    }
    true
}

#[inline]
fn free_persistent_worker_block(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    block: &mut Option<core::ptr::NonNull<u8>>,
) -> Result<(), PersistentLocalWorkerError> {
    let block = block.take().ok_or(PersistentLocalWorkerError::Free)?;
    // SAFETY: this helper consumes exactly one current local allocation and
    // never publishes it outside the persistent worker engine.
    unsafe { allocator.free(block) }.map_err(|_| PersistentLocalWorkerError::Free)
}

fn free_remaining_persistent_worker_blocks(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    blocks: &mut [Option<core::ptr::NonNull<u8>>; PERSISTENT_WORKER_LOCAL_REQUESTS.len()],
) -> Result<(), PersistentLocalWorkerError> {
    for block in blocks {
        if block.is_some() {
            free_persistent_worker_block(allocator, block)?;
        }
    }
    Ok(())
}

/// Exercises one worker-owned page engine for the complete local Gate 5A
/// witness. It has no transfer, remote-free, abandonment, or owner-exit
/// operation: every pointer stays private to this thread and is freed before
/// its enclosing engine can finish.
fn run_persistent_local_worker_workload(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
) -> Result<(), PersistentLocalWorkerError> {
    let mut blocks = [None; PERSISTENT_WORKER_LOCAL_REQUESTS.len()];

    for (slot, (request, seed)) in blocks.iter_mut().zip(PERSISTENT_WORKER_LOCAL_REQUESTS) {
        let Some(block) = allocator.allocate(request, false) else {
            free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
            return Err(PersistentLocalWorkerError::AllocationFailed);
        };
        // SAFETY: `block` is the exact newly allocated, local block and the
        // request is the checked allocation length for this workload.
        unsafe { fill_worker_pattern(block, request, seed) };
        *slot = Some(block);
    }

    for (block, (request, seed)) in blocks.iter().zip(PERSISTENT_WORKER_LOCAL_REQUESTS) {
        let block = block.ok_or(PersistentLocalWorkerError::PatternMismatch)?;
        // SAFETY: each allocation remains current and exclusively local until
        // the mixed free sequence below consumes it.
        if !unsafe { worker_pattern_matches(block, request, seed) } {
            free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
            return Err(PersistentLocalWorkerError::PatternMismatch);
        }
    }

    free_persistent_worker_block(allocator, &mut blocks[0])?;
    let Some(reused_small) = allocator.allocate(PERSISTENT_WORKER_LOCAL_REQUESTS[0].0, false)
    else {
        free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentLocalWorkerError::AllocationFailed);
    };
    blocks[0] = Some(reused_small);
    // SAFETY: this post-free allocation is current and private to this worker.
    unsafe {
        fill_worker_pattern(
            reused_small,
            PERSISTENT_WORKER_LOCAL_REQUESTS[0].0,
            PERSISTENT_WORKER_LOCAL_REQUESTS[0].1,
        )
    };

    free_persistent_worker_block(allocator, &mut blocks[2])?;
    let Some(reused_medium) = allocator.allocate(PERSISTENT_WORKER_LOCAL_REQUESTS[2].0, false)
    else {
        free_remaining_persistent_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentLocalWorkerError::AllocationFailed);
    };
    blocks[2] = Some(reused_medium);
    // SAFETY: this post-free allocation is current and private to this worker.
    unsafe {
        fill_worker_pattern(
            reused_medium,
            PERSISTENT_WORKER_LOCAL_REQUESTS[2].0,
            PERSISTENT_WORKER_LOCAL_REQUESTS[2].1,
        )
    };

    // Deliberately free across page kinds rather than in allocation order.
    for index in [4, 1, 6, 5, 3, 2, 0] {
        free_persistent_worker_block(allocator, &mut blocks[index])?;
    }
    Ok(())
}

// A regular small page has at most this many exact 37-byte requests: source
// block rounding and page metadata can only decrease the capacity. The
// read-only engine observation below supplies the exact current capacity, so
// the owner fills one page without crossing into a successor before B publishes
// the remote free.
const PERSISTENT_REMOTE_REQUEST: usize = 37;
const PERSISTENT_REMOTE_BLOCK_SLOTS: usize = SMALL_PAGE_SIZE / PERSISTENT_REMOTE_REQUEST;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentRemoteWorkerError {
    AllocationFailed,
    PublicationFailed,
    PageCapacityInvalid,
    ReuseFailed,
    Free,
}

#[inline]
fn free_persistent_remote_worker_block(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    block: &mut Option<core::ptr::NonNull<u8>>,
) -> Result<(), PersistentRemoteWorkerError> {
    let block = block.take().ok_or(PersistentRemoteWorkerError::Free)?;
    // SAFETY: the helper consumes one current block that the remote handoff
    // never received, or that owner collection returned to this exact engine.
    unsafe { allocator.free(block) }.map_err(|_| PersistentRemoteWorkerError::Free)
}

fn free_remaining_persistent_remote_worker_blocks(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    blocks: &mut [Option<core::ptr::NonNull<u8>>; PERSISTENT_REMOTE_BLOCK_SLOTS],
) -> Result<(), PersistentRemoteWorkerError> {
    for block in blocks {
        if block.is_some() {
            free_persistent_remote_worker_block(allocator, block)?;
        }
    }
    Ok(())
}

/// Exercises the live-owner half of Gate 5B. The first small page becomes full
/// before two exact blocks transfer as logical remote publications; the
/// joined owner's next ordinary allocations perform the source false
/// collection, receive both exact blocks back, and finish with no client
/// allocation.
///
/// `publish` owns only the two source remote-free capabilities. It cannot
/// access the worker attachment, page engine, PageMap lease, arena, or client
/// pointers. The owner remains stopped until the callback returns both tokens
/// as published or not-published, so this is not an owner-exit or general
/// asynchronous path.
fn run_persistent_remote_worker_workload(
    allocator: &mut MainHeapThreadProcessPageAllocator<'_, '_>,
    publish: TicketZeroRemoteFreePublisher,
) -> Result<(), PersistentRemoteWorkerError> {
    let mut blocks = [None; PERSISTENT_REMOTE_BLOCK_SLOTS];
    let Some(first) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
        return Err(PersistentRemoteWorkerError::AllocationFailed);
    };
    // SAFETY: `first` is the exact current allocation and no remote producer
    // exists while the owner observes its page's fixed source capacity.
    let capacity = unsafe { allocator.current_allocation_page_capacity(first) }
        .filter(|capacity| *capacity >= 2 && *capacity <= PERSISTENT_REMOTE_BLOCK_SLOTS)
        .ok_or(PersistentRemoteWorkerError::PageCapacityInvalid)?;
    blocks[0] = Some(first);
    for slot in blocks.iter_mut().take(capacity).skip(1) {
        let Some(block) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
            free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
            return Err(PersistentRemoteWorkerError::AllocationFailed);
        };
        *slot = Some(block);
    }

    let first_transferred = blocks[0]
        .take()
        .ok_or(PersistentRemoteWorkerError::Free)?;
    let second_transferred = blocks[1]
        .take()
        .ok_or(PersistentRemoteWorkerError::Free)?;
    // SAFETY: the bounded fixed request filled the target's first small page
    // before these transfers. Both blocks are current, distinct, and remain
    // PageMap-published until B/C join and owner A collects them.
    let producers = unsafe {
        allocator.begin_remote_free_pair(first_transferred, second_transferred)
    }
        .map_err(|_| PersistentRemoteWorkerError::PublicationFailed)?;
    let producers = TicketZeroRemoteFreeProducerPair { producers };
    if let Err(producers) = publish(producers) {
        let (first, second) = producers.cancel();
        blocks[0] = Some(first);
        blocks[1] = Some(second);
        free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentRemoteWorkerError::PublicationFailed);
    }

    let Some(reused) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
        free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentRemoteWorkerError::AllocationFailed);
    };
    let Some(second_reused) = allocator.allocate(PERSISTENT_REMOTE_REQUEST, false) else {
        blocks[0] = Some(reused);
        free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
        return Err(PersistentRemoteWorkerError::AllocationFailed);
    };
    blocks[0] = Some(reused);
    blocks[1] = Some(second_reused);
    free_remaining_persistent_remote_worker_blocks(allocator, &mut blocks)?;
    if (reused == first_transferred && second_reused == second_transferred)
        || (reused == second_transferred && second_reused == first_transferred)
    {
        Ok(())
    } else {
        Err(PersistentRemoteWorkerError::ReuseFailed)
    }
}

/// Runs one complete persistent later-worker page-engine lifecycle against
/// the dormant ticket-zero process pair.
///
/// This private evidence/control seam attaches a fresh worker exactly once,
/// retains one page engine through a fixed mixed local workload, returns that
/// engine empty, and only then completes normal worker attachment teardown.
/// It accepts and returns no allocation pointer, does not route libc
/// allocation, and is deliberately not a concurrent or general worker-owner
/// API.
#[doc(hidden)]
pub fn ticket_zero_later_thread_persistent_local_workload() -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    enum PersistentWorkerResult {
        Completed,
        AllocationFailed,
    }

    let page_result = RUNTIME_PROCESS.with_dormant_page_pair(|pair| {
        let slot = current_thread_slot();
        let attachment = slot.attachment.as_mut().ok_or(())?;
        let mut allocator = MainHeapThreadProcessPageAllocator::begin(attachment, pair)
            .map_err(|_| ())?;
        let workload = run_persistent_local_worker_workload(&mut allocator);
        allocator.finish().map_err(|_| ())?;
        match workload {
            Ok(()) => Ok(PersistentWorkerResult::Completed),
            Err(PersistentLocalWorkerError::AllocationFailed) => {
                Ok(PersistentWorkerResult::AllocationFailed)
            }
            Err(
                PersistentLocalWorkerError::PatternMismatch
                | PersistentLocalWorkerError::Free,
            ) => Err(()),
        }
    });
    let finish = finish_current_thread_after_user_destructors();
    match (page_result, finish) {
        (Some(PersistentWorkerResult::Completed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Completed
        }
        (Some(PersistentWorkerResult::AllocationFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::AllocationFailed
        }
        (_, ThreadFinishResult::Retained)
        | (_, _) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroLaterThreadPageResult::Retained
        }
        _ => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Runs one complete live-owner remote-free lifecycle against the dormant
/// ticket-zero process pair.
///
/// The current fresh worker is owner A. It retains one ordinary page engine,
/// gives the supplied joined publisher the one opaque source remote-free
/// capability for B, then collects and reuses the returned block while A is
/// still alive. The capability carries no client pointer and the caller must
/// return it only after B has published or failed without publication. This
/// remains a test-only bounded witness: it does not create concurrent page
/// engines, owner-exit handling, or a libc allocation route.
#[doc(hidden)]
pub fn ticket_zero_later_thread_remote_free_roundtrip(
    publish: TicketZeroRemoteFreePublisher,
) -> TicketZeroLaterThreadPageResult {
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    enum RemoteWorkerResult {
        Completed,
        AllocationFailed,
        PublicationFailed,
        ReuseFailed,
    }

    let page_result = RUNTIME_PROCESS.with_dormant_page_pair(|pair| {
        let slot = current_thread_slot();
        let attachment = slot.attachment.as_mut().ok_or(())?;
        let mut allocator = MainHeapThreadProcessPageAllocator::begin(attachment, pair)
            .map_err(|_| ())?;
        let workload = run_persistent_remote_worker_workload(&mut allocator, publish);
        allocator.finish().map_err(|_| ())?;
        match workload {
            Ok(()) => Ok(RemoteWorkerResult::Completed),
            Err(PersistentRemoteWorkerError::AllocationFailed) => {
                Ok(RemoteWorkerResult::AllocationFailed)
            }
            Err(PersistentRemoteWorkerError::PublicationFailed) => {
                Ok(RemoteWorkerResult::PublicationFailed)
            }
            Err(PersistentRemoteWorkerError::ReuseFailed) => Ok(RemoteWorkerResult::ReuseFailed),
            Err(PersistentRemoteWorkerError::PageCapacityInvalid | PersistentRemoteWorkerError::Free) => {
                Err(())
            }
        }
    });
    let finish = finish_current_thread_after_user_destructors();
    match (page_result, finish) {
        (Some(RemoteWorkerResult::Completed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Completed
        }
        (Some(RemoteWorkerResult::AllocationFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::AllocationFailed
        }
        (Some(RemoteWorkerResult::PublicationFailed | RemoteWorkerResult::ReuseFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Unavailable
        }
        (_, ThreadFinishResult::Retained)
        | (_, _) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroLaterThreadPageResult::Retained
        }
        _ => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Runs one complete later-worker page-engine lifecycle against the dormant
/// ticket-zero process pair.
///
/// This is a private evidence/control seam. It does not route a libc
/// allocation or make a worker a concurrent allocator owner: it accepts no
/// pointer, allocates and frees one local block before returning, and then
/// completes the already-existing worker attachment teardown. The request
/// must be valid for the native engine.
#[doc(hidden)]
pub fn ticket_zero_later_thread_page_roundtrip(
    request: usize,
    zero: bool,
) -> TicketZeroLaterThreadPageResult {
    if !crate::size_class::request_size_is_valid(request) {
        return TicketZeroLaterThreadPageResult::AllocationFailed;
    }
    match attach_current_thread() {
        ThreadAttachResult::Attached => {}
        ThreadAttachResult::Retained => return TicketZeroLaterThreadPageResult::Retained,
        ThreadAttachResult::Inactive
        | ThreadAttachResult::AlreadyAttached
        | ThreadAttachResult::Finished => return TicketZeroLaterThreadPageResult::Unavailable,
    }

    enum ScopedPageResult {
        Completed,
        AllocationFailed,
    }

    let page_result = RUNTIME_PROCESS.with_dormant_page_pair(|pair| {
        let slot = current_thread_slot();
        let attachment = slot.attachment.as_mut().ok_or(())?;
        let mut allocator = MainHeapThreadProcessPageAllocator::begin(attachment, pair)
            .map_err(|_| ())?;
        let Some(block) = allocator.allocate(request, zero) else {
            return allocator
                .finish()
                .map(|()| ScopedPageResult::AllocationFailed)
                .map_err(|_| ());
        };
        // SAFETY: `block` is current in this scoped engine and has not left
        // the current worker before its matching free.
        unsafe { allocator.free(block) }.map_err(|_| ())?;
        allocator
            .finish()
            .map(|()| ScopedPageResult::Completed)
            .map_err(|_| ())
    });
    let finish = finish_current_thread_after_user_destructors();
    match (page_result, finish) {
        (Some(ScopedPageResult::Completed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::Completed
        }
        (Some(ScopedPageResult::AllocationFailed), ThreadFinishResult::Finished) => {
            TicketZeroLaterThreadPageResult::AllocationFailed
        }
        (_, ThreadFinishResult::Retained)
        | (_, _) if RUNTIME_PROCESS.page_owner_state.load(Ordering::Acquire) == PAGE_OWNER_RETAINED
            || RUNTIME_PROCESS.state.load(Ordering::Acquire) == PROCESS_RETAINED =>
        {
            TicketZeroLaterThreadPageResult::Retained
        }
        _ => TicketZeroLaterThreadPageResult::Unavailable,
    }
}

/// Prevents a later attachment from beginning across libc's direct raw-fork
/// boundary and snapshots whether this no-page bridge can survive in the
/// child.
///
/// Libc invokes this after public prepare handlers and before the raw Linux
/// fork-equivalent syscall. It has no C ABI, does not allocate, and does not
/// consume a public `pthread_atfork` registration slot. The child is eligible
/// for preservation only when the caller is the ticket-zero TPIDR_EL0 image
/// and no later bridge attachment is live or retained.
#[doc(hidden)]
#[inline]
pub fn before_fork() {
    RUNTIME_FORK_ADMISSION.before_fork(RUNTIME_PROCESS.is_active_on_initial_thread());
}

/// Releases the parent's direct fork admission boundary before public parent
/// handlers run. It preserves any real later-owner count observed while the
/// raw fork was in progress.
#[doc(hidden)]
#[inline]
pub fn after_fork_parent() {
    RUNTIME_FORK_ADMISSION.after_fork_parent();
}

/// Attaches the current pthread worker before its user start routine.
///
/// Libc must call this only for a child whose parent observed
/// [`process_is_active`] and must use its startup handshake to prevent a user
/// start routine from running when this returns anything other than
/// [`ThreadAttachResult::Attached`].
#[doc(hidden)]
pub fn attach_current_thread() -> ThreadAttachResult {
    let slot = current_thread_slot();
    match slot.state {
        ThreadLifecycleState::Attached => return ThreadAttachResult::AlreadyAttached,
        ThreadLifecycleState::Finished => return ThreadAttachResult::Finished,
        ThreadLifecycleState::Retained => return ThreadAttachResult::Retained,
        ThreadLifecycleState::Fresh => {}
    }

    if !RUNTIME_PROCESS.is_active() {
        return ThreadAttachResult::Inactive;
    }
    if !RUNTIME_FORK_ADMISSION.claim_later_thread() {
        // A count overflow cannot be mistaken for a fresh process state. It
        // is not a practical capacity policy; it is a terminal failure of the
        // bridge's precise fork-admission accounting.
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    }
    slot.admission_held = true;

    // SAFETY: a published process owner and its main-thread-minted immutable
    // Heap lease stay in final static slots for the process lifetime.
    let Some(process_owner) = (unsafe { RUNTIME_PROCESS.active_owner() }) else {
        if RUNTIME_FORK_ADMISSION.release_later_thread() {
            slot.admission_held = false;
            return ThreadAttachResult::Inactive;
        }
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    };
    let ready = match process_owner.ready() {
        Ok(ready) => ready,
        Err(_) => {
            RUNTIME_PROCESS.retain();
            return ThreadAttachResult::Retained;
        }
    };
    let config = match ready.memory_config() {
        Ok(config) => config,
        Err(_) => {
            RUNTIME_PROCESS.retain();
            return ThreadAttachResult::Retained;
        }
    };
    let Some(main_heap) = (unsafe { RUNTIME_PROCESS.active_main_heap() }) else {
        RUNTIME_PROCESS.retain();
        return ThreadAttachResult::Retained;
    };

    // SAFETY: libc installed this child TLS image and calls before user code;
    // `slot` retains the returned current-thread owner until its explicit
    // post-destructor finish. The static process owner is never torn down by
    // this slice, and no other code may mutate the allocator TLS roots.
    match unsafe { MainHeapThreadAttachment::begin(main_heap, config) } {
        Ok(attachment) => {
            slot.attachment = Some(attachment);
            slot.state = ThreadLifecycleState::Attached;
            ThreadAttachResult::Attached
        }
        Err(MainHeapThreadAttachmentBeginError::Rejected(_)) => {
            // A foreign root or pre-publication failure cannot safely become
            // an invisible lifecycle skip. Retain the process boundary so no
            // later worker receives a fresh-looking capability.
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadAttachResult::Retained
        }
        Err(MainHeapThreadAttachmentBeginError::Retained { attachment, .. }) => {
            // Preserve the exact partial owner in this thread's TLS instead
            // of dropping it. The parent handshake will reject this worker.
            slot.attachment = Some(attachment);
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadAttachResult::Retained
        }
    }
}

/// Finishes one attached worker after libc's cleanup-handler and TSD phases.
#[doc(hidden)]
pub fn finish_current_thread_after_user_destructors() -> ThreadFinishResult {
    let slot = current_thread_slot();
    match slot.state {
        ThreadLifecycleState::Fresh => return ThreadFinishResult::NotAttached,
        ThreadLifecycleState::Finished => return ThreadFinishResult::AlreadyFinished,
        ThreadLifecycleState::Retained => return ThreadFinishResult::Retained,
        ThreadLifecycleState::Attached => {}
    }
    if !slot.admission_held {
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadFinishResult::Retained;
    }

    let Some(mut attachment) = slot.attachment.take() else {
        slot.state = ThreadLifecycleState::Retained;
        RUNTIME_PROCESS.retain();
        return ThreadFinishResult::Retained;
    };
    match attachment.finish_after_user_destructors() {
        Ok(()) => {
            if RUNTIME_FORK_ADMISSION.release_later_thread() {
                slot.admission_held = false;
                slot.state = ThreadLifecycleState::Finished;
                ThreadFinishResult::Finished
            } else {
                // The source owner is already torn down, but its fork
                // accounting no longer names this transition. Retain the
                // process rather than claiming a child-preserving boundary
                // from an inconsistent count.
                slot.state = ThreadLifecycleState::Retained;
                RUNTIME_PROCESS.retain();
                ThreadFinishResult::Retained
            }
        }
        Err(_) => {
            // The `must_use` owner still carries concrete roots/list/metadata
            // state. Retain it in TLS and stop admitting new workers rather
            // than claiming that `_mi_thread_done` completed.
            slot.attachment = Some(attachment);
            slot.state = ThreadLifecycleState::Retained;
            RUNTIME_PROCESS.retain();
            ThreadFinishResult::Retained
        }
    }
}

/// Preserves only a quiescent ticket-zero no-page image in the post-fork child,
/// otherwise disables this incomplete lifecycle without acquiring an
/// inherited allocator lock or walking inherited thread/page ownership.
///
/// The caller is libc's raw-fork child path. `fork_was_prepared` is true only
/// for the direct public `fork` path that just called [`before_fork`]. That
/// explicit token, plus the gate, preserves the copied process owner only when
/// no later bridge attachment was live or retained and the raw fork ran on the
/// original ticket-zero TLS image. It prevents another raw-fork caller from
/// borrowing a concurrently copied gate. A preserving child may attach a
/// fresh pthread through the existing no-page path. Every other child remains
/// disabled: this is intentionally not a general fork repair and never
/// traverses inherited locks, roots, lists, or page ownership.
#[doc(hidden)]
pub fn after_fork_child(fork_was_prepared: bool) {
    if RUNTIME_FORK_ADMISSION.after_fork_child(fork_was_prepared) {
        return;
    }
    RUNTIME_PROCESS.retain();
    let slot = current_thread_slot();
    if slot.state == ThreadLifecycleState::Attached {
        slot.state = ThreadLifecycleState::Retained;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::main_theap::MainStaticAttachmentStorage;
    use crate::meta::MetaAllocator;
    use crate::process_page_map::ProcessPageMapStorage;
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

    /// A read-only audit of the process-long objects that a completed Gate 5A
    /// worker must return to their pre-worker state. `total_thread_count` is
    /// intentionally separate: mimalloc's source sequence is monotonic, while
    /// `live_thread_count` and the shared-later-Theap count must be restored.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PersistentWorkerStateAudit {
        page_map_root: usize,
        page_map_committed_count: usize,
        page_map_reserved_count: usize,
        page_map_registered_entry_count: usize,
        page_map_published_submap_count: usize,
        page_map_lazy_submap_allocation_count: usize,
        arena_address: usize,
        arena_registry_count: usize,
        total_thread_count: usize,
        live_thread_count: usize,
        shared_later_theap_count: usize,
    }

    fn persistent_worker_state_audit(
        runtime: &'static RuntimeProcessStorage,
        arena_storage: &'static ProcessSharedArenaStorage,
        main_static: &'static MainStaticAttachmentStorage,
        subprocess: &'static MainSubprocess,
    ) -> PersistentWorkerStateAudit {
        // SAFETY: this fixture leaked the one permanent process owner before
        // starting its workers, and this audit runs only after a worker join.
        let owner = unsafe { runtime.active_owner() }
            .expect("the isolated runtime keeps its process owner published");
        let ready = owner
            .ready()
            .expect("the permanent ticket-zero owner remains process-ready");
        let process_page_map = ready
            .page_map()
            .expect("the process-ready owner retains its PageMap lease");
        let page_map = process_page_map
            .page_map()
            .expect("the initialized PageMap root remains auditably published");
        let arena = arena_storage
            .ready_lease()
            .expect("the first ticket-zero request published one retained arena");
        PersistentWorkerStateAudit {
            page_map_root: process_page_map
                .root()
                .expect("the PageMap root remains stable")
                .as_ptr()
                .addr(),
            page_map_committed_count: page_map
                .committed_count()
                .expect("the PageMap committed extent remains readable"),
            page_map_reserved_count: page_map.reserved_count(),
            page_map_registered_entry_count: page_map
                .test_registered_entry_count()
                .expect("the finished worker leaves only stable PageMap entries"),
            page_map_published_submap_count: page_map
                .test_published_submap_count()
                .expect("the PageMap published-submap audit remains readable"),
            page_map_lazy_submap_allocation_count: page_map.test_lazy_submap_allocation_count(),
            arena_address: core::ptr::from_ref(
                arena
                    .arena()
                    .expect("the process arena remains registry-published")
                    .arena(),
            )
            .addr(),
            arena_registry_count: arena
                .test_registry_count()
                .expect("the process arena registry remains readable"),
            total_thread_count: subprocess.total_thread_count(),
            live_thread_count: subprocess.live_thread_count(),
            shared_later_theap_count: main_static.test_shared_later_theap_count(),
        }
    }

    /// Publishes a fully constructed isolated source ticket-zero owner into
    /// a fresh runtime slot. The test owns this one thread, has no worker
    /// admission, and deliberately leaks the final process lifetime state.
    unsafe fn publish_test_owner(
        runtime: &'static RuntimeProcessStorage,
        owner: ProcessMainThread,
    ) {
        assert_eq!(
            runtime.state.compare_exchange(
                PROCESS_COLD,
                PROCESS_INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(PROCESS_COLD),
            "the isolated runtime slot begins cold"
        );
        // SAFETY: the successful test-only initialization claim above grants
        // the sole final-slot write, exactly as production initialization.
        unsafe { (*runtime.owner.get()).write(owner) };
        // SAFETY: the final owner is present before its Release publication;
        // this is the ticket-zero thread that constructed it.
        let owner = unsafe { (&*runtime.owner.get()).assume_init_ref() };
        let main_heap = owner
            .shared_main_heap_lease()
            .expect("ticket zero mints the immutable later-thread witness");
        let initial_thread = current_thread_identity()
            .expect("the isolated runtime fixture has its current thread identity");
        // SAFETY: the same initialization winner writes the last immutable
        // witness before PROCESS_ACTIVE makes either slot observable.
        unsafe { (*runtime.main_heap.get()).write(main_heap) };
        runtime
            .initial_thread_identity
            .store(initial_thread.get(), Ordering::Release);
        runtime.state.store(PROCESS_ACTIVE, Ordering::Release);
    }

    #[test]
    fn runtime_ticket_zero_page_owner_is_lazy_and_closes_no_page_fork_preservation() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();

            assert!(runtime.is_active_on_initial_thread());
            assert!(
                runtime.start_ticket_zero_page_owner_with_storage(arena_storage),
                "the runtime creates its permanent owner without an arena reservation"
            );
            assert!(
                arena_storage.test_is_cold(),
                "the runtime page owner remains mapping-free until its first valid request"
            );
            assert!(
                !runtime.is_active_on_initial_thread(),
                "the old no-page fork bridge refuses to preserve a permanent page authority"
            );

            let block = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .flatten()
                .expect("the first ordinary runtime request activates the source default arena");
            assert!(
                !arena_storage.test_is_cold(),
                "only the valid first miss publishes the default arena"
            );
            let free = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `block` is the exact live allocation returned
                    // by this runtime's sole ticket-zero page owner.
                    unsafe { owner.free(block) }
            })
            .expect("the permanent owner remains callable after activation");
            assert!(free.is_ok(), "the exact ticket-zero allocation frees normally");
            let reused = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .flatten()
                .expect("the quiescent runtime owner reactivates through its existing first arena");
            let free_reused = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `reused` is the exact current allocation from
                    // the reactivated permanent ticket-zero owner.
                    unsafe { owner.free(reused) }
                })
                .expect("the reactivated permanent owner remains callable");
            assert!(
                free_reused.is_ok(),
                "the reactivated ticket-zero allocation frees normally"
            );
            assert_eq!(
                runtime.page_owner_state.load(Ordering::Acquire),
                PAGE_OWNER_READY,
                "an all-free runtime owner remains process-owned rather than reopening the no-page state"
            );
        })
        .join()
        .expect("the isolated runtime page-owner fixture remains ticket-zero local");
    }

    #[test]
    fn dormant_ticket_zero_page_owner_lends_persistent_mixed_local_worker_engine() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .flatten()
                .expect("the ticket-zero owner activates its first arena");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `first` is the exact current ticket-zero block.
                    unsafe { owner.free(first) }
                })
                .expect("the ticket-zero owner remains callable")
                .expect("the first ticket-zero block frees into the dormant state");

            let baseline = persistent_worker_state_audit(runtime, arena_storage, main_static, subprocess);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(baseline.shared_later_theap_count, 0);

            for worker_number in 1..=3 {
                thread::spawn(move || {
                    // SAFETY: the test's permanent process owner and copied
                    // main Heap lease remain in final runtime storage for this
                    // worker.
                    let process_owner = unsafe { runtime.active_owner() }
                        .expect("the process owner stays published for the worker");
                    let config = process_owner
                        .ready()
                        .and_then(|ready| ready.memory_config())
                        .expect("the worker observes the frozen process config");
                    let main_heap = unsafe { runtime.active_main_heap() }
                        .expect("the worker copies the ticket-zero main Heap witness");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(_) => panic!("the worker begins its normal shared-main attachment"),
                    };

                    let completed = runtime.with_dormant_page_pair(|pair| {
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut attachment, pair)
                            .map_err(|_| ())?;
                        run_persistent_local_worker_workload(&mut allocator)
                            .expect("the persistent local workload completes before engine teardown");
                        allocator.finish().map_err(|_| ())
                    });
                    assert_eq!(
                        completed,
                        Some(()),
                        "the dormant ticket-zero owner lends its published pair to persistent local worker {worker_number}"
                    );
                    attachment
                        .finish_after_user_destructors()
                        .expect("the empty persistent worker engine restores normal worker teardown");
                })
                .join()
                .expect("each later-main page engine stays on its worker thread");

                let after_worker =
                    persistent_worker_state_audit(runtime, arena_storage, main_static, subprocess);
                assert_eq!(
                    after_worker.page_map_root,
                    baseline.page_map_root,
                    "worker {worker_number} retains the one process PageMap root"
                );
                assert_eq!(
                    after_worker.page_map_committed_count,
                    baseline.page_map_committed_count,
                    "worker {worker_number} returns the PageMap commitment boundary"
                );
                assert_eq!(
                    after_worker.page_map_reserved_count,
                    baseline.page_map_reserved_count,
                    "worker {worker_number} does not change PageMap reservation ownership"
                );
                assert_eq!(
                    after_worker.page_map_registered_entry_count,
                    baseline.page_map_registered_entry_count,
                    "worker {worker_number} leaves no PageMap registrations"
                );
                assert_eq!(
                    after_worker.page_map_published_submap_count,
                    baseline.page_map_published_submap_count,
                    "worker {worker_number} leaves no additional published PageMap submap"
                );
                assert_eq!(
                    after_worker.page_map_lazy_submap_allocation_count,
                    baseline.page_map_lazy_submap_allocation_count,
                    "worker {worker_number} leaves no lazy PageMap allocation"
                );
                assert_eq!(
                    after_worker.arena_address,
                    baseline.arena_address,
                    "worker {worker_number} retains the one process arena identity"
                );
                assert_eq!(
                    after_worker.arena_registry_count,
                    baseline.arena_registry_count,
                    "worker {worker_number} leaves no arena registry ownership"
                );
                assert_eq!(
                    after_worker.live_thread_count,
                    baseline.live_thread_count,
                    "worker {worker_number} restores the source live-TLD count"
                );
                assert_eq!(
                    after_worker.shared_later_theap_count,
                    baseline.shared_later_theap_count,
                    "worker {worker_number} restores the shared-later-Theap count"
                );
                assert_eq!(
                    after_worker.total_thread_count,
                    baseline.total_thread_count + worker_number,
                    "worker {worker_number} consumes exactly one monotonic source thread sequence"
                );
            }

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(101, false)
                })
                .flatten()
                .expect("the dormant ticket-zero owner reactivates after the worker returns its map lease");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    // SAFETY: `resumed` is the exact current ticket-zero block.
                    unsafe { owner.free(resumed) }
                })
                .expect("ticket zero remains callable after the worker engine")
                .expect("the resumed ticket-zero block frees normally");
        })
        .join()
        .expect("the runtime alternates the one process pair between ticket zero and one persistent worker");
    }

    fn publish_remote_from_scoped_test_thread<'owner>(
        producers: TicketZeroRemoteFreeProducerPair<'owner>,
    ) -> Result<(), TicketZeroRemoteFreeProducerPair<'owner>> {
        let (first, second) = producers.split();
        thread::scope(|scope| {
            let first = scope.spawn(move || first.publish());
            let second = scope.spawn(move || second.publish());
            match first
                .join()
                .expect("the first remote publisher remains bounded by its owner join")
            {
                Ok(()) => {}
                Err(_) => panic!("the first remote publisher accepts its exact source block"),
            }
            match second
                .join()
                .expect("the second remote publisher remains bounded by its owner join")
            {
                Ok(()) => {}
                Err(_) => panic!("the second remote publisher accepts its exact source block"),
            }
            Ok(())
        })
    }

    #[test]
    fn dormant_ticket_zero_page_owner_collects_repeated_live_worker_remote_frees() {
        thread::spawn(|| {
            let process_storage = ProcessMainInitializationStorage::test_static_owner();
            let main_static = MainStaticAttachmentStorage::test_static_owner();
            let subprocess = MainSubprocess::test_static_owner();
            let metadata = MetaAllocator::test_static_owner();
            let page_map_storage = ProcessPageMapStorage::test_static_owner();
            let arena_storage = ProcessSharedArenaStorage::test_static_owner();
            let runtime: &'static RuntimeProcessStorage =
                std::boxed::Box::leak(std::boxed::Box::new(RuntimeProcessStorage::new()));
            let owner = unsafe {
                process_storage.initialize_with_test_components(
                    memory_config(),
                    main_static,
                    subprocess,
                    metadata,
                    page_map_storage,
                )
            }
            .expect("the isolated runtime fixture constructs ticket zero");
            // SAFETY: this test supplies the one fresh runtime slot and keeps
            // every source/process owner alive through the permanent fixture.
            unsafe { publish_test_owner(runtime, owner) };

            let first = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(37, false)
                })
                .expect("the ticket-zero owner starts its first page engine")
                .expect("the first ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    unsafe { owner.free(first) }
                })
                .expect("the ticket-zero owner remains callable")
                .expect("the first ticket-zero block frees into the dormant state");

            let baseline = persistent_worker_state_audit(runtime, arena_storage, main_static, subprocess);
            assert_eq!(baseline.page_map_registered_entry_count, 0);
            assert_eq!(baseline.live_thread_count, 1);
            assert_eq!(baseline.shared_later_theap_count, 0);

            for worker_number in 1..=3 {
                thread::spawn(move || {
                    // SAFETY: this fixture keeps the permanent process owner
                    // and its shared main Heap lease process-static while A
                    // owns one engine and its scoped B publisher joins.
                    let process_owner = unsafe { runtime.active_owner() }
                        .expect("the process owner stays published for remote owner A");
                    let config = process_owner
                        .ready()
                        .and_then(|ready| ready.memory_config())
                        .expect("remote owner A observes the frozen process config");
                    let main_heap = unsafe { runtime.active_main_heap() }
                        .expect("remote owner A copies the ticket-zero main Heap witness");
                    let mut attachment = match unsafe {
                        MainHeapThreadAttachment::begin_with_test_metadata(main_heap, metadata, config)
                    } {
                        Ok(attachment) => attachment,
                        Err(_) => panic!("remote owner A begins its normal shared-main attachment"),
                    };

                    let completed = runtime.with_dormant_page_pair(|pair| {
                        let mut allocator = MainHeapThreadProcessPageAllocator::begin(&mut attachment, pair)
                            .map_err(|_| ())?;
                        run_persistent_remote_worker_workload(
                            &mut allocator,
                            publish_remote_from_scoped_test_thread,
                        )
                        .expect("A collects and reuses B's live remote publication");
                        allocator.finish().map_err(|_| ())
                    });
                    assert_eq!(
                        completed,
                        Some(()),
                        "the dormant ticket-zero pair admits completed remote owner A {worker_number}"
                    );
                    attachment
                        .finish_after_user_destructors()
                        .expect("remote owner A tears down after B has joined and all pages are empty");
                })
                .join()
                .expect("each live remote-free owner remains on its fresh worker thread");

                let after_worker =
                    persistent_worker_state_audit(runtime, arena_storage, main_static, subprocess);
                let expected = PersistentWorkerStateAudit {
                    total_thread_count: baseline.total_thread_count + worker_number,
                    ..baseline
                };
                assert_eq!(
                    after_worker, expected,
                    "remote owner A {worker_number} leaves no PageMap, arena, TLD, or Theap residue"
                );
            }

            let resumed = runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    owner.allocate(73, false)
                })
                .expect("ticket zero reactivates after every remote owner joins")
                .expect("the reactivated ticket-zero allocation succeeds");
            runtime
                .with_ticket_zero_page_owner_with_storage(arena_storage, |owner| {
                    unsafe { owner.free(resumed) }
                })
                .expect("the resumed ticket-zero owner stays callable")
                .expect("the reactivated ticket-zero block frees normally");
        })
        .join()
        .expect("the isolated runtime restores its retained baseline after repeated live remote frees");
    }
}
