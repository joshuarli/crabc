//! Deferred Linux/x86-64 static pthread-cancellation boundary.
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
//! The x86 static worker seam intentionally has neither musl's full TCB nor
//! its cancellation signal/syscall-cancellation assembly. Accordingly this
//! artifact admits only selected pointer-returning `pthread_create` workers:
//! `pthread_cancel` records a request, and only the target's explicit
//! `pthread_testcancel` observes it. It installs no signal handler, does not
//! interrupt blocking syscalls, and adds no implicit cancellation points. A
//! request for asynchronous cancellation fails with `ENOTSUP` without changing
//! state. C11 workers, foreign threads, stale handles, and unsupported state
//! records fail closed. This is not general pthread cancellation, C11
//! cancellation, signal coordination, or a public x86 pthread-runtime claim.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread cancellation leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::pthread_create_join;

const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;

const PTHREAD_CANCEL_ENABLE: u8 = 0;
const PTHREAD_CANCEL_DISABLE: u8 = 1;
// Musl accepts the public MASKED value as a third non-delivering state.  The
// selected x86 seam has no cancellation-aware syscalls, so its exact retained
// effect is the one `pthread_testcancel` needs: a pending request stays
// pending and is not delivered until the worker later selects ENABLE.
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
    pending: AtomicU8,
    state: AtomicU8,
    cleanup_head: AtomicUsize,
}

impl SelectedWorkerCancellation {
    pub(super) const fn new(is_pthread: bool) -> Self {
        Self {
            kind: AtomicU8::new(if is_pthread { SLOT_PTHREAD } else { SLOT_C11 }),
            pending: AtomicU8::new(0),
            state: AtomicU8::new(PTHREAD_CANCEL_ENABLE),
            cleanup_head: AtomicUsize::new(0),
        }
    }
}

/// Mark one lock-validated selected pthread worker pending.
///
/// The caller holds the create/join registry lock for the complete target
/// lookup and this store. It must not call user code or release a mapping.
pub(super) fn mark_selected_worker_pending(state: &SelectedWorkerCancellation) -> bool {
    if state.kind.load(Ordering::Acquire) != SLOT_PTHREAD {
        return false;
    }
    state.pending.store(1, Ordering::Release);
    true
}

#[inline]
fn current_pthread_slot() -> Option<&'static SelectedWorkerCancellation> {
    let state = pthread_create_join::current_selected_pthread_worker_cancellation()?;
    // SAFETY: current-worker resolution proves its control mapping remains
    // live until this task exits. This private reference is used only for the
    // immediate C ABI operation; no caller can retain it across that exit.
    let state = unsafe { &*state };
    (state.kind.load(Ordering::Acquire) == SLOT_PTHREAD).then_some(state)
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
    }
}

/// Record a deferred cancellation request for one selected pthread handle.
///
/// No signal is sent. A successful request becomes observable only if its
/// target later calls `pthread_testcancel` while cancellation is enabled.
#[no_mangle]
pub unsafe extern "C" fn pthread_cancel(thread: *mut c_void) -> c_int {
    if pthread_create_join::request_selected_pthread_cancellation(thread) {
        0
    } else {
        EINVAL
    }
}

/// Change deferred-cancellation enablement for the current selected pthread
/// worker. `old_state`, when non-null, must designate writable C `int` storage.
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
    let previous = slot.state.swap(state, Ordering::AcqRel);
    if !old_state.is_null() {
        // SAFETY: the C ABI requires writable aligned `int` storage when the
        // optional old-state pointer is non-null.
        unsafe { core::ptr::write(old_state, c_int::from(previous)) };
    }
    0
}

/// Select the only admitted cancellation type, deferred.
///
/// Asynchronous cancellation would require a signal-frame/syscall-cancellation
/// contract that this static worker seam deliberately does not own, so it is
/// rejected without writing `old_type` or changing any state.
#[no_mangle]
pub unsafe extern "C" fn pthread_setcanceltype(type_: c_int, old_type: *mut c_int) -> c_int {
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
#[no_mangle]
pub unsafe extern "C" fn pthread_testcancel() {
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
