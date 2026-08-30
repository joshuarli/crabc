//! Bounded Linux/x86-64 static C11 thread-lifecycle leaf.
//!
//! This is a private static companion to the existing selected pthread worker
//! seam, not a general C11 threads implementation. Its provenance is fixed to
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license recorded in its `COPYRIGHT` file:
//!
//! - `src/thread/thrd_create.c` supplies the C11 status translation: `0` is
//!   `thrd_success`, `EAGAIN` is `thrd_nomem`, and all other creation failures
//!   are `thrd_error`.
//! - `src/thread/pthread_create.c::start_c11` supplies musl's separate C11
//!   callback trampoline. Musl routes its public callback through an internal
//!   pointer-return slot before that trampoline recovers the `int (*)(void *)`
//!   type; this bounded leaf intentionally diverges at that unsafe boundary:
//!   it records `pthread_create_join::SelectedWorkerStart::C11` directly and
//!   invokes it with its native C11 type, never casting it to the pthread
//!   pointer-return callback type.
//! - `src/thread/thrd_join.c` supplies the optional `int *` result write after
//!   a successful pthread-style join. Its `intptr_t` conversion maps here to
//!   the explicitly signed encode/decode helpers.
//! - `src/thread/thrd_exit.c` supplies the C11 `int` result conversion before
//!   the selected worker exits.
//! - `src/thread/thrd_detach.c` supplies the `thrd_success`/`thrd_error`
//!   translation around pthread-style lifetime detachment.
//! - `src/thread/thrd_sleep.c` supplies C11's distinct sleep-status
//!   translation: an interrupted relative realtime sleep is `-1`, while every
//!   other `clock_nanosleep` failure is `-2`. This bounded x86 route delegates
//!   only to the sibling's direct, errno-neutral `clock_nanosleep` seam; it
//!   deliberately does not select musl's cancellation-point machinery.
//!
//! The admitted contract is one valid C11 callback, a TP-as-`thrd_t` handle,
//! one join **or** detach, and either a normal callback return or `thrd_exit`.
//! Normal and explicit exit preserve every signed `int` result, including
//! `INT_MIN` and `INT_MAX`, through the sibling's private pointer-sized result
//! word when joined. A successful detach is prompt and result-neutral; the
//! sibling's later selected create/join boundary reclaims mappings only after
//! `CLONE_CHILD_CLEARTID` clears the child TID. The shared worker seam starts
//! each child from an independent Static Initial TLS v1 image, retains its
//! `%fs:0` identity, and never changes the creator's `errno`: C11's selected
//! errors use only `thrd_*` statuses.
//!
//! This leaf intentionally excludes `thrd_yield`, `call_once`, mutexes,
//! conditions, TSS keys/destructors, cancellation, attributes and
//! detached-at-create lifecycle, dynamic/loader TLS, a full TCB, CRT/sysroot
//! integration, a crabc-rs surface, C11-family completion, and public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 C11 lifecycle leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};

use super::pthread_create_join::{
    self, C11StartRoutine, SelectedWorkerStart,
};

const EAGAIN: c_int = 11;
const EINTR: c_int = 4;
const THRD_SUCCESS: c_int = 0;
const THRD_ERROR: c_int = 2;
const THRD_NOMEM: c_int = 3;
const THRD_SLEEP_INTR: c_int = -1;
const THRD_SLEEP_ERROR: c_int = -2;

/// Create one bounded joinable C11 worker over the selected static TLS seam.
///
/// `thread` must designate writable `thrd_t` storage; `start` must be a valid
/// C11 `int (*)(void *)` callback; and `argument` must remain valid until that
/// callback stops reading it. The returned handle is the child's opaque
/// Variant-II TP, just like `thrd_current` and the selected pthread handle.
///
/// # Safety
///
/// This C ABI cannot validate the output pointer, callback code, or argument
/// lifetime. The callback must return normally or call this leaf's `thrd_exit`;
/// no detached-at-create, cancellation, or general C11 lifecycle behavior is
/// selected.
#[no_mangle]
pub unsafe extern "C" fn thrd_create(
    thread: *mut *mut c_void,
    start: Option<C11StartRoutine>,
    argument: *mut c_void,
) -> c_int {
    let start = match start {
        Some(start) => start,
        None => return THRD_ERROR,
    };
    // SAFETY: the typed C11 callback and output/lifetime obligations are the
    // public boundary contract above. The sibling owns all clone/TLS state.
    match unsafe {
        pthread_create_join::create_selected_worker(
            thread,
            SelectedWorkerStart::C11(start),
            argument,
        )
    } {
        0 => THRD_SUCCESS,
        EAGAIN => THRD_NOMEM,
        _ => THRD_ERROR,
    }
}

/// Join one selected C11 worker and optionally write its exact signed result.
///
/// The result word is decoded only after the sibling has observed
/// clear-child-tid, acquired the callback publication, withdrawn the exact TP
/// registry entry, and released the worker's TLS/control mappings. A null
/// `result` discards the callback value.
///
/// # Safety
///
/// `thread` must be one still-live handle produced by [`thrd_create`]. If
/// non-null, `result` must be writable aligned `int` storage. The caller must
/// not concurrently join the same handle.
#[no_mangle]
pub unsafe extern "C" fn thrd_join(thread: *mut c_void, result: *mut c_int) -> c_int {
    // SAFETY: `thread` and optional result storage meet the C ABI obligations
    // above; the shared join returns only after it owns/reclaims the worker.
    let joined = match unsafe { pthread_create_join::join_selected_worker(thread) } {
        Ok(joined) => joined,
        Err(_) => return THRD_ERROR,
    };
    if joined.kind != pthread_create_join::SelectedWorkerResultKind::C11 {
        // A pthread_exit call from a C11-mode callback is explicitly outside
        // this selected C11 route. The shared worker already reclaimed safely,
        // but this boundary must not decode that raw pointer as an `int`.
        return THRD_ERROR;
    }
    if !result.is_null() {
        // SAFETY: the caller supplied writable C `int` storage. The exact C11
        // decoding does not reinterpret the encoded word as a pointer.
        unsafe {
            core::ptr::write(
                result,
                pthread_create_join::decode_c11_result(joined.encoded_result),
            )
        };
    }
    THRD_SUCCESS
}

/// Detach one selected C11 worker with a prompt ownership transition.
///
/// This shares the sibling's result-neutral selected ownership state: it does
/// not reinterpret a C11 result as a pthread pointer, wait for the worker, or
/// reclaim a still-live stack/TLS mapping. A later selected create/join
/// boundary reaps an exited detached worker after `CLONE_CHILD_CLEARTID`.
///
/// # Safety
///
/// `thread` must be a selected opaque handle. After success, it no longer
/// denotes an admitted joinable C11 lifecycle handle.
#[no_mangle]
pub unsafe extern "C" fn thrd_detach(thread: *mut c_void) -> c_int {
    // SAFETY: this C11 boundary retains the selected opaque-handle ownership
    // contract and maps every selected pthread-style failure to thrd_error.
    match unsafe { pthread_create_join::detach_selected_worker(thread) } {
        0 => THRD_SUCCESS,
        _ => THRD_ERROR,
    }
}

/// Sleep for one C11 relative realtime interval through the selected syscall seam.
///
/// The return is `0` after completion, `-1` only when Linux reports `EINTR`,
/// and `-2` for every other failure. Like C11 and musl, this function reports
/// through its return value rather than modifying C `errno`.
///
/// # Safety
///
/// `duration` must point to a readable, aligned x86-64 `struct timespec` for
/// the syscall. `remaining` must be null or point to writable storage for the
/// same record. The caller owns signal delivery and must keep both records
/// alive until the syscall returns; this bounded route is not a cancellation
/// point and provides no pthread/C11 cancellation cleanup semantics.
#[no_mangle]
pub unsafe extern "C" fn thrd_sleep(
    duration: *const c_void,
    remaining: *mut c_void,
) -> c_int {
    // SAFETY: the C ABI obligations above exactly supply the sibling's raw
    // x86 timespec-pointer contract. Its direct result is zero or positive
    // errno and it intentionally does not publish errno through TLS.
    match unsafe {
        super::clock_nanosleep::clock_nanosleep(
            super::clock_nanosleep::CLOCK_REALTIME,
            0,
            duration,
            remaining,
        )
    } {
        0 => THRD_SUCCESS,
        EINTR => THRD_SLEEP_INTR,
        _ => THRD_SLEEP_ERROR,
    }
}

/// End the current selected C11 worker with its exact signed `int` result.
///
/// # Safety
///
/// This is valid only for a callback created through [`thrd_create`]. The
/// callback must not access any object after this call; it never returns. A
/// detached worker's result is deliberately discarded.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn thrd_exit(result: c_int) -> ! {
    // SAFETY: this converts a C11 `int` at the typed boundary, then takes the
    // exact selected-worker publication/SYS_exit path shared with pthread_exit.
    unsafe { pthread_create_join::exit_selected_c11_worker(result) }
}
