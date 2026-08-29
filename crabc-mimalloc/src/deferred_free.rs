// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:987-1004`
// (`_mi_deferred_free`).

//! Source-shaped deferred-free callback invocation.
//!
//! Pinned mimalloc increments the owning Theap heartbeat for every collector
//! entry, then invokes the process-registered deferred callback only while the
//! matching TLD is not already recursing. The public callback registration
//! surface belongs to the future whole-process allocator ABI, so this module
//! intentionally implements only the invocation boundary. Production has no
//! registered callback yet; the attachment-local test observer proves ordering
//! and recursion behavior without exposing a raw callback registration API.

use core::ptr::NonNull;

#[cfg(test)]
use core::ffi::c_void;

use crate::types::{Theap, ThreadLocalData};

/// A broken Theap/TLD pairing at the deferred-free boundary.
///
/// The source uses raw process-private pointers. The Rust lifecycle makes the
/// pairing explicit so an old Theap cannot invoke a callback after its TLD has
/// crossed the teardown boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeferredFreeInvocationError {
    TldMismatch,
}

/// Runs `_mi_deferred_free` with no registered production callback.
///
/// Even an empty registration advances the source heartbeat. The caller owns
/// the matching live Theap and TLD for this synchronous invocation.
pub(crate) fn collect(
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    force: bool,
) -> Result<u64, DeferredFreeInvocationError> {
    collect_inner(theap, tld, force)
}

fn collect_inner(
    mut theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    _force: bool,
) -> Result<u64, DeferredFreeInvocationError> {
    // SAFETY: the caller retains both metadata allocations exclusively for
    // the complete synchronous source callback boundary.
    if unsafe { !theap.as_ref().matches_tld_pointer(tld.as_ptr()) } {
        return Err(DeferredFreeInvocationError::TldMismatch);
    }
    // SAFETY: the same exclusive lifecycle proof permits the source-local
    // heartbeat update. `wrapping_add` preserves C unsigned overflow.
    Ok(unsafe { theap.as_mut().advance_heartbeat() })
}

/// One attachment-local test observer for the otherwise-unregistered source
/// callback. It never becomes an allocator API or process-global state.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct DeferredFreeTestObserver {
    callback: DeferredFreeTestCallback,
    context: NonNull<c_void>,
}

/// The test observer receives the source callback arguments plus borrowed
/// metadata identities solely so focused regressions can prove its ordering.
/// It has no allocation, free, queue, PageMap, or teardown authority.
#[cfg(test)]
pub(crate) type DeferredFreeTestCallback = unsafe fn(
    force: bool,
    heartbeat: u64,
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    context: *mut c_void,
);

#[cfg(test)]
impl DeferredFreeTestObserver {
    /// Builds one synchronous observer.
    ///
    /// # Safety
    ///
    /// `context` must remain valid and uniquely usable for every callback
    /// until the attached Theap/TLD has completed or terminally retained its
    /// post-exit drain. The callback must not retain either metadata pointer,
    /// mutate allocator state, or unwind across this boundary.
    #[inline]
    pub(crate) unsafe fn new(
        callback: DeferredFreeTestCallback,
        context: NonNull<c_void>,
    ) -> Self {
        Self { callback, context }
    }
}

/// Runs `_mi_deferred_free` with one attachment-local observer.
///
/// This is test-only because the current native engine has not yet established
/// the public, whole-process callback registration and allocator re-entry
/// contract. It preserves the source heartbeat and recursion ordering exactly.
#[cfg(test)]
pub(crate) fn collect_with_test_observer(
    mut theap: NonNull<Theap>,
    mut tld: NonNull<ThreadLocalData>,
    force: bool,
    observer: Option<DeferredFreeTestObserver>,
) -> Result<u64, DeferredFreeInvocationError> {
    // SAFETY: the test owner retains both metadata allocations for the full
    // synchronous callback, as required by `DeferredFreeTestObserver::new`.
    if unsafe { !theap.as_ref().matches_tld_pointer(tld.as_ptr()) } {
        return Err(DeferredFreeInvocationError::TldMismatch);
    }
    // SAFETY: the exact same exclusive source owner advances the heartbeat.
    let heartbeat = unsafe { theap.as_mut().advance_heartbeat() };
    let Some(observer) = observer else {
        return Ok(heartbeat);
    };
    // SAFETY: `tld` is live, exact, and exclusively retained by the caller.
    // `begin_deferred_callback` makes the source recursion check and marker
    // update one boundary, so a nested source entry skips the observer.
    if unsafe { tld.as_mut().begin_deferred_callback() } {
        // The guard clears the marker even if a test assertion unwinds.
        let _recursion = DeferredFreeRecursionGuard { tld };
        // SAFETY: `DeferredFreeTestObserver::new` records the context and
        // callback obligations. The raw identities remain valid for this
        // synchronous call and are observational only.
        unsafe {
            (observer.callback)(force, heartbeat, theap, tld, observer.context.as_ptr());
        }
    }
    Ok(heartbeat)
}

/// Clears one source TLD recursion marker after its callback body returns.
#[cfg(test)]
struct DeferredFreeRecursionGuard {
    tld: NonNull<ThreadLocalData>,
}

#[cfg(test)]
impl Drop for DeferredFreeRecursionGuard {
    fn drop(&mut self) {
        let mut tld = self.tld;
        // SAFETY: this guard is created only after `begin_deferred_callback`
        // on the exact still-live TLD, and it runs before the synchronous
        // owner-exit invocation can advance to teardown.
        unsafe { tld.as_mut().end_deferred_callback() };
    }
}
