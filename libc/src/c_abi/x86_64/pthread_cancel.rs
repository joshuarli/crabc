//! Linux/x86-64 pthread cancellation state and cleanup ownership.
//!
//! This is a deliberately bounded translation of the ownership portions of
//! pinned musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_cancel.c::{pthread_cancel,__testcancel,__cancel}`
//!   supplies the pending-request and enabled-state decision at a cancellation
//!   point, plus the `PTHREAD_CANCELED` exit result.
//! - `src/thread/pthread_setcancelstate.c::__pthread_setcancelstate` supplies
//!   the per-thread enabled/disabled state transition and optional old value.
//! - `src/thread/pthread_setcanceltype.c::pthread_setcanceltype` supplies the
//!   deferred type value and optional old value.
//! - `src/thread/pthread_create.c::{__pthread_exit,__do_cleanup_push,
//!   __do_cleanup_pop}` supplies LIFO cleanup ownership and the cleanup-before-
//!   TSD-destructor exit ordering.
//!
//! The legacy private fixture admits selected pointer-returning workers,
//! explicit deferred checkpoints, and no asynchronous delivery. The owned
//! product additionally composes `owned_syscall_cancel.rs`: source SIGCANCEL,
//! the x86 syscall PC window, main/worker FS+32 state, and target-lifetime
//! exclusion. Public read/readv/write/writev are cancellation points; ordinary
//! FILE descriptor I/O deliberately remains non-canceling, as in musl.
//! Explicit FILE locks are source-tracked for non-final task retirement.
//! Both paths retain explicit `pthread_testcancel` and private
//! `pthread_cond_wait` points. The legacy condition route uses the worker
//! control mapping's durable barrier and registry-serialized wake leases.
//! Owned main tasks and pthread workers instead use automatic waiter storage
//! and the source MASKED syscall boundary in `pthread_cond.rs`: ECANCELED
//! returns to list repair and mutex reacquisition before user cleanup.
//! A consumed condition signal suppresses cancellation for that handoff.
//! C11 cancellation, foreign tasks and stale handles are not admitted by this
//! state contract. Other syscall cancellation points remain separate routing
//! obligations; no full pthread-family claim follows.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread cancellation leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering};

use super::pthread_create_join;

#[cfg(feature = "x86-owned-static-runtime")]
#[path = "owned_syscall_cancel.rs"]
mod owned_syscall_cancel;

/// Source cancellation-point syscall used only by owned public descriptor APIs.
/// # Safety
/// The syscall pointer, lifetime and argument requirements hold. A caller must
/// not own a non-cancel-safe runtime resource without a cleanup/disable scope.
#[cfg(feature = "x86-owned-static-runtime")]
#[inline(always)]
pub(super) unsafe fn syscall_cp(number: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    unsafe { owned_syscall_cancel::syscall_cp(number,a,b,c,d,e,f) }
}

const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;

const PTHREAD_CANCEL_ENABLE: u8 = 0;
const PTHREAD_CANCEL_DISABLE: u8 = 1;
// Musl accepts the public MASKED value as a third non-delivering state.  The
// legacy fixture only retains a request; owned syscall cancellation returns
// ECANCELED and changes MASKED to DISABLE, exactly as musl __cancel does.
const PTHREAD_CANCEL_MASKED: u8 = 2;
const PTHREAD_CANCEL_DEFERRED: c_int = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 1;
const PTHREAD_CANCELED: *mut c_void = usize::MAX as *mut c_void;

const SLOT_PTHREAD: u8 = 1;
const SLOT_C11: u8 = 2;

/// The installed x86 `struct __ptcb` layout used by the cleanup macros.
///
/// This private mirror is intentionally confined to the C ABI boundary. A
/// cleanup node is caller-owned stack storage and remains valid only from its
/// successful push to the matching pop or selected worker termination.
#[repr(C)]
pub(super) struct CleanupNode {
    function: Option<unsafe extern "C" fn(*mut c_void)>,
    argument: *mut c_void,
    next: *mut CleanupNode,
}

/// Cancellation state embedded in one selected worker's control mapping.
///
/// Keeping this with the control record makes the cancellation lifetime match
/// the opaque handle and removes the artifact-only fixed worker table. The
/// create/join list lock still serializes a handle lookup, pending request,
/// withdrawal, and eventual unmap; a current worker is the sole cleanup-chain
/// mutator while its positive child-TID keeps its mapping live.
pub(super) struct SelectedWorkerCancellation {
    kind: AtomicU8,
    // The cancellation-point assembly reads one aligned source-shaped int.
    pending: AtomicI32,
    state: AtomicU8,
    asynchronous: AtomicU8,
    cleanup_head: AtomicUsize,
    // Explicit flockfile ownership, not internal FILE operation guards.
    stdio_locks: AtomicUsize,
    // A legacy selected pthread condition wait uses a waiter in the private control
    // mapping, rather than automatic storage, only while it is an implicit
    // cancellation point. Its barrier stays mapped through join/detach
    // reclamation, so a canceller that validated this control under the
    // registry lock can change the barrier without a stack-lifetime race. The
    // matching withdrawal closes further leases under that same lock and
    // drains all earlier leases before this storage is reused.
    active_condition_barrier: AtomicUsize,
}

impl SelectedWorkerCancellation {
    pub(super) const fn new(is_pthread: bool) -> Self {
        Self {
            kind: AtomicU8::new(if is_pthread { SLOT_PTHREAD } else { SLOT_C11 }),
            pending: AtomicI32::new(0),
            state: AtomicU8::new(PTHREAD_CANCEL_ENABLE),
            asynchronous: AtomicU8::new(0),
            cleanup_head: AtomicUsize::new(0),
            stdio_locks: AtomicUsize::new(0),
            active_condition_barrier: AtomicUsize::new(0),
        }
    }
}

// The initial owned thread has cancellation/cleanup state without a worker
// control mapping or allocation. The lifecycle owner publishes this address
// into reserved FS+32 only after owned TLS is established; signal handlers
// must never discover it through a registry scan or a TLS-GD resolver.
#[cfg(feature = "x86-owned-static-runtime")]
static MAIN_CANCELLATION: SelectedWorkerCancellation = SelectedWorkerCancellation::new(true);

#[cfg(feature = "x86-owned-static-runtime")]
pub(super) fn main_cancellation_state() -> *const SelectedWorkerCancellation {
    core::ptr::addr_of!(MAIN_CANCELLATION)
}

// The current task alone mutates this intrusive explicit-FILE-lock list.
// It includes C11 tasks too: FILE retirement is not a cancellation policy.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) fn current_stdio_lock_head() -> Option<&'static AtomicUsize> {
    let state = super::pthread_identity::current_selected_cancellation_state();
    if state.is_null() { None } else { Some(unsafe { &(*state).stdio_locks }) }
}

/// Mark explicit FILE locks orphaned after committed non-final task exit.
/// # Safety
/// Cleanup/TSD callbacks have finished, cancellation is disabled, and this
/// task is retiring without ordinary process-exit callbacks. Its FS+32 state
/// and all still-listed FILE objects remain live through this call.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) unsafe fn orphan_current_stdio_locks() {
    unsafe { super::stdio_standard::orphan_current_stdio_locks(); }
}

/// Mark one lock-validated selected pthread worker pending and return its
/// currently published condition barrier, when it may be interrupted.
///
/// The caller holds the create/join registry lock for the complete target
/// lookup and this store. It must not issue a syscall while holding that lock;
/// the create/join owner pins the control mapping and performs any barrier
/// wake after it releases the lock.
pub(super) fn mark_selected_worker_pending(
    state: &SelectedWorkerCancellation,
) -> Option<*mut c_int> {
    if state.kind.load(Ordering::Acquire) != SLOT_PTHREAD {
        return None;
    }
    state.pending.store(1, Ordering::Release);
    // `PTHREAD_CANCEL_DISABLE` records the request but does not interrupt a
    // selected condition wait. ENABLE and musl's retained MASKED state must
    // both leave the wait so its list/barrier protocol can complete; delivery
    // remains deferred until the condition leaf restores the prior state.
    if state.state.load(Ordering::Acquire) != PTHREAD_CANCEL_DISABLE {
        return Some(state.active_condition_barrier.load(Ordering::Acquire) as *mut c_int);
    }
    Some(core::ptr::null_mut())
}

#[inline]
fn current_pthread_slot() -> Option<&'static SelectedWorkerCancellation> {
    #[cfg(feature = "x86-owned-static-runtime")]
    let state = {
        let pointer = super::pthread_identity::current_selected_cancellation_state();
        if pointer.is_null() { return None; }
        pointer
    };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    let state = pthread_create_join::current_selected_pthread_worker_cancellation()?;
    // SAFETY: current-worker resolution proves its control mapping remains
    // live until this task exits. This private reference is used only for the
    // immediate C ABI operation; no caller can retain it across that exit.
    let state = unsafe { &*state };
    (state.kind.load(Ordering::Acquire) == SLOT_PTHREAD).then_some(state)
}

/// Deliver one pending request at any selected deferred cancellation point.
///
/// This private form lets a sibling point preserve its own cleanup/relock
/// transaction without routing through the interposable public symbol.
#[inline(always)]
pub(super) fn test_current_selected_pthread_cancellation() {
    let Some(slot) = current_pthread_slot() else {
        return;
    };
    if slot.pending.load(Ordering::Acquire) != 0
        && slot.state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
    {
        // SAFETY: current-pthread-slot admitted this exact selected
        // pointer-returning worker. The sibling runs active cleanup handlers,
        // then selected TSD destructors, publishes PTHREAD_CANCELED, and exits
        // this task through its existing clear-child-tid lifecycle seam.
        unsafe { pthread_create_join::exit_selected_pthread_worker(PTHREAD_CANCELED) }
    }
}

/// Enter the list-repair portion of a selected condition cancellation point.
///
/// The returned state is restored only after the condition leaf has removed
/// or consumed its waiter and relocked the caller mutex. As in musl, a
/// disabled caller remains disabled while it waits; masking an enabled caller
/// prevents delivery until that repair transaction is complete.
pub(super) fn begin_current_selected_pthread_condition_cancellation() -> Option<u8> {
    let slot = current_pthread_slot()?;
    let previous = slot.state.swap(PTHREAD_CANCEL_MASKED, Ordering::AcqRel);
    if previous == PTHREAD_CANCEL_DISABLE {
        slot.state.store(previous, Ordering::Release);
    }
    Some(previous)
}

/// Publish the durable barrier of the current selected condition waiter.
///
/// The waiter must already be linked and its mutex released. Publishing first
/// and then inspecting `pending` closes both request-before-publication and
/// request-between-publication-and-futex-sleep races: the wake helper changes
/// the barrier value, rather than merely issuing a lossy futex wake.
pub(super) fn activate_current_selected_pthread_condition_waiter(barrier: *mut c_int) {
    let Some(slot) = current_pthread_slot() else {
        return;
    };
    slot.active_condition_barrier
        .store(barrier as usize, Ordering::Release);
    if slot.pending.load(Ordering::Acquire) != 0
        && slot.state.load(Ordering::Acquire) != PTHREAD_CANCEL_DISABLE
    {
        // SAFETY: this current worker just published its mapped waiter
        // barrier, which stays live until the condition leaf clears it.
        unsafe { super::pthread_cond::wake_selected_pthread_condition_waiter(barrier) };
    }
}

/// Withdraw one selected condition waiter's barrier under the worker-registry
/// lock.
///
/// The create/join owner serializes this compare-exchange with target lookup,
/// barrier load, and lease increment in `pthread_cancel`. It then drains every
/// pre-withdrawal lease before the worker can reuse this control-mapped waiter
/// for another condition wait.
pub(super) fn withdraw_selected_pthread_condition_waiter(
    state: &SelectedWorkerCancellation,
    barrier: *mut c_int,
) -> bool {
    state
        .active_condition_barrier
        .swap(0, Ordering::AcqRel)
        == barrier as usize
}

/// Restore the cancellation state saved at a selected condition point.
pub(super) fn restore_current_selected_pthread_condition_cancellation(state: u8) {
    if let Some(slot) = current_pthread_slot() {
        slot.state.store(state, Ordering::Release);
    }
}

/// Execute all active cleanup handlers for the current selected pthread worker.
///
/// The worker itself is the only mutator of its cleanup stack. This is called
/// only on its selected pthread-exit path after current-worker validation; it
/// detaches each node before invoking user code, preserving musl's LIFO and
/// reentrant-push shape without retaining a stale caller-stack pointer.
pub(super) fn run_current_selected_pthread_cleanup_handlers() {
    let Some(slot) = current_pthread_slot() else {
        return;
    };

    loop {
        let node = slot.cleanup_head.load(Ordering::Acquire) as *mut CleanupNode;
        if node.is_null() {
            return;
        }
        // SAFETY: a selected worker owns its active cleanup-node chain. The
        // macro keeps the current stack node valid until this function removes
        // it or the worker stops executing; no other task mutates the chain.
        unsafe {
            slot.cleanup_head
                .store((*node).next as usize, Ordering::Release);
            if let Some(function) = (*node).function {
                function((*node).argument);
            }
        }
    }
}

/// Disable selected deferred cancellation before a pthread-mode exit runs C
/// cleanup handlers.
///
/// Musl's `__pthread_exit` disables cancellation before it drains the cleanup
/// chain.  Retaining that transition prevents a cleanup handler which calls
/// `pthread_testcancel` from recursively re-entering this exit path.  The
/// pending bit intentionally remains observable only as private state: this
/// worker is already exiting and cannot return to a cancellation point.
pub(super) fn disable_current_selected_pthread_cancellation_for_exit() {
    if let Some(slot) = current_pthread_slot() {
        slot.state.store(PTHREAD_CANCEL_DISABLE, Ordering::Release);
        slot.asynchronous.store(0, Ordering::Release);
    }
}

/// Request cancellation using the selected runtime's delivery protocol.
/// # Safety
/// `thread` is a live pthread handle from this runtime, not a stale/reaped
/// handle or a C11/foreign task. Cancellation cleanup obligations belong to
/// the target application; asynchronous targets must obey POSIX async safety.
#[no_mangle]
pub unsafe extern "C" fn pthread_cancel(thread: *mut c_void) -> c_int {
    #[cfg(feature = "x86-owned-static-runtime")]
    { return unsafe { owned_syscall_cancel::request(thread) }; }
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    if pthread_create_join::request_selected_pthread_cancellation(thread) {
        0
    } else {
        EINVAL
    }
}

/// Change cancellation enablement for the current selected pthread task.
/// # Safety
/// `old_state`, when non-null, designates aligned writable C `int` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, old_state: *mut c_int) -> c_int {
    let state = match state {
        0 => PTHREAD_CANCEL_ENABLE,
        1 => PTHREAD_CANCEL_DISABLE,
        2 => PTHREAD_CANCEL_MASKED,
        _ => return EINVAL,
    };
    let Some(slot) = current_pthread_slot() else {
        return ENOTSUP;
    };
    let previous = slot.state.load(Ordering::Acquire);
    if !old_state.is_null() {
        // SAFETY: the C ABI requires writable aligned `int` storage when the
        // optional old-state pointer is non-null.
        unsafe { core::ptr::write(old_state, c_int::from(previous)) };
    }
    slot.state.store(state, Ordering::Release);
    0
}

/// Select deferred/asynchronous owned delivery; legacy fixtures admit only
/// deferred delivery and reject asynchronous requests without state changes.
/// # Safety
/// Non-null `old_type` designates aligned writable C `int` storage. A caller
/// enabling asynchronous cancellation must obey POSIX async-cancel safety.
#[no_mangle]
pub unsafe extern "C" fn pthread_setcanceltype(type_: c_int, old_type: *mut c_int) -> c_int {
    #[cfg(feature = "x86-owned-static-runtime")]
    {
        if type_ != PTHREAD_CANCEL_DEFERRED && type_ != PTHREAD_CANCEL_ASYNCHRONOUS { return EINVAL; }
        let Some(slot) = current_pthread_slot() else { return ENOTSUP; };
        let previous = slot.asynchronous.load(Ordering::Acquire);
        if !old_type.is_null() { unsafe { *old_type = previous as c_int; } }
        slot.asynchronous.store(type_ as u8, Ordering::Release);
        if type_ != 0 { test_current_selected_pthread_cancellation(); }
        return 0;
    }
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    match type_ {
        PTHREAD_CANCEL_DEFERRED => {
            if current_pthread_slot().is_none() {
                return ENOTSUP;
            }
            if !old_type.is_null() {
                // SAFETY: the C ABI requires writable aligned `int` storage
                // when the optional old-type pointer is non-null.
                unsafe { core::ptr::write(old_type, PTHREAD_CANCEL_DEFERRED) };
            }
            0
        }
        PTHREAD_CANCEL_ASYNCHRONOUS => ENOTSUP,
        _ => EINVAL,
    }
}

/// Deliver a pending request at the explicit selected deferred cancellation
/// point. This does not return when it observes an enabled pending request.
/// # Safety
/// Any owned resource requiring cancellation cleanup has a registered cleanup
/// handler or is otherwise safe to abandon at this cancellation point.
#[no_mangle]
pub unsafe extern "C" fn pthread_testcancel() {
    test_current_selected_pthread_cancellation();
}

/// Push one caller-owned cleanup node onto the current selected pthread worker.
///
/// A null node or a caller outside the selected worker seam is ignored rather
/// than inventing a foreign-TP cleanup registry. The macro's matching pop may
/// still explicitly execute its callback when requested.
#[no_mangle]
pub unsafe extern "C" fn _pthread_cleanup_push(
    cleanup: *mut CleanupNode,
    function: Option<unsafe extern "C" fn(*mut c_void)>,
    argument: *mut c_void,
) {
    if cleanup.is_null() {
        return;
    }
    let Some(slot) = current_pthread_slot() else {
        return;
    };
    // SAFETY: the cleanup macro owns writable stack storage for this node and
    // keeps it live until its matching pop or selected thread termination.
    unsafe {
        (*cleanup).function = function;
        (*cleanup).argument = argument;
        (*cleanup).next = slot.cleanup_head.load(Ordering::Acquire) as *mut CleanupNode;
        slot.cleanup_head.store(cleanup as usize, Ordering::Release);
    }
}

/// Pop one caller-owned cleanup node and optionally execute it.
///
/// Selected workers detach through their private chain. For an unselected
/// caller, a requested explicit execution still invokes the supplied callback;
/// that preserves the macro's lexical `pthread_cleanup_pop(1)` action without
/// constructing unowned cancellation state.
#[no_mangle]
pub unsafe extern "C" fn _pthread_cleanup_pop(cleanup: *mut CleanupNode, run: c_int) {
    if cleanup.is_null() {
        return;
    }
    if let Some(slot) = current_pthread_slot() {
        // SAFETY: matching push/pop ownership is a C macro contract. Like
        // musl's helper, this trusts the matching node and restores its next
        // link without searching or validating an arbitrary chain.
        unsafe {
            slot.cleanup_head.store((*cleanup).next as usize, Ordering::Release);
        }
    }
    if run != 0 {
        // SAFETY: the macro-supplied node remains valid through this call, and
        // its callback/argument ownership belongs to the C caller.
        unsafe {
            if let Some(function) = (*cleanup).function {
                function((*cleanup).argument);
            }
        }
    }
}

/// musl timer_create.c::cleanup_fromsig resets logical callback cancellation
/// after TSD cleanup and blocking application/SIGTIMER signals. This current
/// task owns its popped cleanup chain; pending cancellation is consumed here.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) fn reset_timer_callback_cancellation() {
    if let Some(slot) = current_pthread_slot() {
        slot.pending.store(0, Ordering::Release);
        slot.cleanup_head.store(0, Ordering::Release);
        slot.state.store(PTHREAD_CANCEL_ENABLE, Ordering::Release);
        slot.asynchronous.store(0, Ordering::Release);
    }
}
