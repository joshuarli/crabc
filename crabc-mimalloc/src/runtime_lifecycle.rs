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
//! successfully enters through the runtime. The worker finishes only after
//! libc has run user cleanup handlers and pthread TSD destructors.
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
use crate::main_heap_thread::{
    MainHeapThreadAttachment, MainHeapThreadAttachmentBeginError,
};
use crate::main_theap::MainStaticHeapLease;
use crate::os::{MemoryConfig, PageSize, StartupInput};
use crate::process_init::{ProcessMainInitializationStorage, ProcessMainThread};

const PROCESS_COLD: u8 = 0;
const PROCESS_INITIALIZING: u8 = 1;
const PROCESS_ACTIVE: u8 = 2;
const PROCESS_RETAINED: u8 = 3;

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
}

// SAFETY: the COLD -> INITIALIZING CAS gives one writer exclusive access to
// `owner`; the final owner is written before PROCESS_ACTIVE's Release store
// and is thereafter read immutably. Terminal retention never mutates it.
unsafe impl Sync for RuntimeProcessStorage {}

impl RuntimeProcessStorage {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PROCESS_COLD),
            initial_thread_identity: AtomicUsize::new(0),
            owner: UnsafeCell::new(MaybeUninit::uninit()),
            main_heap: UnsafeCell::new(MaybeUninit::uninit()),
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
    fn is_active_on_initial_thread(&self) -> bool {
        if !self.is_active() {
            return false;
        }
        let expected = self.initial_thread_identity.load(Ordering::Acquire);
        expected != 0
            && current_thread_identity().is_some_and(|current| current.get() == expected)
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
