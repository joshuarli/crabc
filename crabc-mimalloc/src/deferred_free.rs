// Copyright (c) 2018-2026, Microsoft Research, Daan Leijen
// This is free software; you can redistribute it and/or modify it under the
// terms of the MIT license. A copy of the license can be found in the file
// `LICENSE` at the root of this distribution.
// SPDX-License-Identifier: MIT
//
// Source map: pinned mimalloc v3.5.0 `src/page.c:987-1004`
// (`_mi_deferred_free`).

//! Source-shaped deferred-free callback registration and invocation.
//!
//! Pinned mimalloc v3.5.0 `src/page.c:990-1005` owns one process callback and
//! opaque argument. Registration Release-publishes the argument before the
//! function, and an invocation increments the owning Theap heartbeat before
//! it Acquire-loads either value. The matching TLD's `recurse` bit suppresses
//! recursive callback entry while still advancing every nested heartbeat.
//!
//! [`DeferredFreeInvocation`] is deliberately a non-Send caller-stack token.
//! Its construction performs only the short source scalar mutations. A runtime
//! must release every mutable engine, session, and TLD projection before it
//! invokes selected user code, then revalidate its owner before continuing the
//! source collection or allocation transition.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::types::{LiveThreadId, Theap, ThreadLocalData};

/// A broken Theap/TLD pairing at the deferred-free boundary.
///
/// The source uses raw process-private pointers. The Rust lifecycle makes the
/// pairing explicit so an old Theap cannot invoke a callback after its TLD has
/// crossed the teardown boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeferredFreeInvocationError {
    TldMismatch,
}

/// A value-only identity for one source Theap/TLD lifetime.
///
/// The source owner mints this while it proves both static images are current.
/// It carries raw identity only so phase B can select user code after every
/// owner borrow ends; it grants no allocation, teardown, or TLD ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeferredFreeSource {
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    thread: LiveThreadId,
    thread_sequence: usize,
}

impl DeferredFreeSource {
    /// Captures one current source pair from a bounded owner projection.
    #[inline]
    pub(crate) fn capture(theap: NonNull<Theap>, thread: LiveThreadId) -> Option<Self> {
        // SAFETY: the caller supplies the short current source projection; no
        // reference leaves this function and the returned value is identity,
        // not a borrow or owner capability.
        let theap_ref = unsafe { theap.as_ref() };
        let tld = theap_ref.deferred_free_tld()?;
        let thread_sequence = theap_ref.thread_sequence()?;
        if !theap_ref.matches_thread(thread)
            || unsafe { tld.as_ref() }.thread_sequence().get() != thread_sequence
        {
            return None;
        }
        Some(Self { theap, tld, thread, thread_sequence })
    }

    /// Revalidates the original source image before phase C resumes it.
    #[inline]
    pub(crate) fn matches_current(self, current: Self) -> bool {
        self == current
    }

    /// Selects the process callback from a source identity whose owner is
    /// currently idle. The returned invocation is still caller-stack-only.
    #[inline]
    pub(crate) fn begin(self, force: bool) -> Result<DeferredFreeInvocation, DeferredFreeInvocationError> {
        // Recheck the fields carried as scalars before mutating heartbeat or
        // the recursion marker. This rejects storage replacement/reuse even
        // when the raw address happens to match an earlier source lifetime.
        let Some(current) = Self::capture(self.theap, self.thread) else {
            return Err(DeferredFreeInvocationError::TldMismatch);
        };
        if !self.matches_current(current) {
            return Err(DeferredFreeInvocationError::TldMismatch);
        }
        begin_process(self.theap, self.tld, force)
    }
}

/// Pinned `mi_deferred_free_fun` after the selected C ABI lowering.
pub(crate) type DeferredFreeCallback = unsafe extern "C" fn(bool, u64, *mut c_void);

/// The source process-private callback and opaque context publication pair.
///
/// This is intentionally not a Rust closure registry. Callers own both
/// callback and context lifetimes, as `mi_register_deferred_free` does.
pub(crate) struct DeferredFreeRegistration {
    callback: AtomicPtr<c_void>,
    context: AtomicPtr<c_void>,
}

impl DeferredFreeRegistration {
    pub(crate) const fn new() -> Self {
        Self {
            callback: AtomicPtr::new(core::ptr::null_mut()),
            context: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Mirrors `mi_register_deferred_free`'s argument-then-function Release
    /// publication order.
    ///
    /// # Safety
    ///
    /// `callback`, when present, and every object reachable from `context`
    /// must stay valid for each invocation that can still observe this
    /// publication. The callback must not unwind across the C ABI boundary.
    #[inline]
    pub(crate) unsafe fn register(
        &self,
        callback: Option<DeferredFreeCallback>,
        context: *mut c_void,
    ) {
        self.context.store(context, Ordering::Release);
        let callback = callback.map_or(core::ptr::null_mut(), |callback| {
            callback as *const () as *mut c_void
        });
        self.callback.store(callback, Ordering::Release);
    }

    #[inline]
    fn callback(&self) -> Option<DeferredFreeCallback> {
        let callback = self.callback.load(Ordering::Acquire);
        if callback.is_null() {
            None
        } else {
            // SAFETY: `register` stores only a null pointer or a
            // `DeferredFreeCallback` representation, matching C's `void*`
            // atomic storage for platforms without atomic function pointers.
            Some(unsafe { core::mem::transmute::<*mut c_void, DeferredFreeCallback>(callback) })
        }
    }
}

/// The process registration used by the native allocator engine.
static PROCESS_DEFERRED_FREE: DeferredFreeRegistration = DeferredFreeRegistration::new();

#[inline]
pub(crate) fn process_registration() -> &'static DeferredFreeRegistration {
    &PROCESS_DEFERRED_FREE
}

/// Registers the native engine's process deferred-free callback.
///
/// # Safety
///
/// The caller must satisfy [`DeferredFreeRegistration::register`] and
/// serialize process registration with allocator teardown.
#[inline]
pub(crate) unsafe fn register_process_callback(
    callback: Option<DeferredFreeCallback>,
    context: *mut c_void,
) {
    // SAFETY: forwarded unchanged to the process registration contract.
    unsafe { process_registration().register(callback, context) };
}

/// The result of the source heartbeat and callback-selection prefix.
#[must_use = "a selected deferred callback must be invoked or dropped to clear the TLD recurse marker"]
pub(crate) enum DeferredFreeInvocation {
    Complete(u64),
    Callback(DeferredFreeCallbackInvocation),
}

impl DeferredFreeInvocation {
    #[inline]
    pub(crate) const fn heartbeat(&self) -> u64 {
        match self {
            Self::Complete(heartbeat) => *heartbeat,
            Self::Callback(callback) => callback.heartbeat,
        }
    }

    /// Invokes selected user code after the caller released every mutable
    /// engine, session, and TLD projection.
    ///
    /// # Safety
    ///
    /// The caller must retain the exact source TLD through this synchronous
    /// call and honor the registration callback/context obligations.
    #[inline]
    pub(crate) unsafe fn invoke(self) -> u64 {
        match self {
            Self::Complete(heartbeat) => heartbeat,
            // SAFETY: forwarded to the invocation token contract.
            Self::Callback(callback) => unsafe { callback.invoke() },
        }
    }
}

/// A selected source callback with its heartbeat and published context.
///
/// It owns no allocator, page session, or TLD reference. The raw TLD pointer
/// exists only to clear the source recursion marker after `callback` returns.
pub(crate) struct DeferredFreeCallbackInvocation {
    callback: DeferredFreeCallback,
    context: *mut c_void,
    force: bool,
    heartbeat: u64,
    // `Some` means this caller-stack token still owns the source recurse
    // marker. `invoke` transfers that obligation to its stack guard before
    // selected user code runs, and `Drop` clears it when a continuation fails
    // before dispatch.
    tld: Option<NonNull<ThreadLocalData>>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl DeferredFreeCallbackInvocation {
    /// Calls the selected C callback and clears the matching source recurse
    /// marker on return.
    ///
    /// # Safety
    ///
    /// The callback/context and live TLD pairing must satisfy registration
    /// and invocation-token contracts. No mutable allocator, attachment,
    /// session, or TLD reference may remain live while this call can reenter.
    #[inline]
    unsafe fn invoke(mut self) -> u64 {
        let tld = self
            .tld
            .take()
            .expect("a deferred callback invocation owns one recurse marker");
        let _recursion = DeferredFreeRecursionGuard { tld };
        // SAFETY: the token recorded the exact C callback arguments after the
        // source recursive-entry check succeeded.
        unsafe { (self.callback)(self.force, self.heartbeat, self.context) };
        self.heartbeat
    }
}

impl Drop for DeferredFreeCallbackInvocation {
    fn drop(&mut self) {
        let Some(mut tld) = self.tld else {
            return;
        };
        // SAFETY: retaining a live matching TLD is the invocation token's
        // construction contract. Dropping an undispatched token must restore
        // the source marker so a later collector can select its callback.
        unsafe { tld.as_mut().end_deferred_callback() };
    }
}

/// Starts `_mi_deferred_free` through the process registration without
/// invoking selected user code.
#[inline]
pub(crate) fn begin_process(
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    force: bool,
) -> Result<DeferredFreeInvocation, DeferredFreeInvocationError> {
    begin(process_registration(), theap, tld, force)
}

/// Starts `_mi_deferred_free` through one registration owner.
///
/// Fixture-local owners may exercise the source publication algorithm without
/// mutating the process registration. The native engine uses
/// [`begin_process`].
pub(crate) fn begin(
    registration: &DeferredFreeRegistration,
    mut theap: NonNull<Theap>,
    mut tld: NonNull<ThreadLocalData>,
    force: bool,
) -> Result<DeferredFreeInvocation, DeferredFreeInvocationError> {
    // SAFETY: callers retain both metadata images for this short source
    // prefix. No mutable reference escapes into the returned callback token.
    if unsafe { !theap.as_ref().matches_tld_pointer(tld.as_ptr()) } {
        return Err(DeferredFreeInvocationError::TldMismatch);
    }
    // SAFETY: the exact retained Theap owns the source scalar heartbeat.
    // SAFETY: this source invocation retains the original current Theap
    // capability and exclusively owns its heartbeat scalar. The helper
    // projects that field only; shared Heap list readers may still observe
    // unrelated Theap fields.
    let heartbeat = unsafe { Theap::advance_heartbeat_at(theap) };
    let Some(callback) = registration.callback() else {
        return Ok(DeferredFreeInvocation::Complete(heartbeat));
    };
    // SAFETY: the matching live TLD is retained by the caller. The source
    // marker is set before its argument Acquire load and user callback entry.
    if !unsafe { tld.as_mut().begin_deferred_callback() } {
        return Ok(DeferredFreeInvocation::Complete(heartbeat));
    }
    let context = registration.context.load(Ordering::Acquire);
    Ok(DeferredFreeInvocation::Callback(DeferredFreeCallbackInvocation {
        callback,
        context,
        force,
        heartbeat,
        tld: Some(tld),
        _not_send_or_sync: PhantomData,
    }))
}

/// Runs `_mi_deferred_free` through the process registration.
///
/// New callers that permit allocation from the callback must use
/// [`begin_process`] and invoke its token outside all mutable owner borrows.
/// This compatibility boundary is only for legacy owner-exit callers while
/// the process registration is provably inert. It must not become a public or
/// registered callback route: owner-exit collection still holds source drain
/// state, so a future registration/lifecycle export must instead return an
/// A/B/C caller-stack continuation and invoke its user phase after that drain
/// borrow ends.
pub(crate) fn collect(
    theap: NonNull<Theap>,
    tld: NonNull<ThreadLocalData>,
    force: bool,
) -> Result<u64, DeferredFreeInvocationError> {
    let invocation = begin_process(theap, tld, force)?;
    // SAFETY: this compatibility boundary has the documented no-reentry
    // precondition. Reentrant paths use the caller-stack token directly.
    Ok(unsafe { invocation.invoke() })
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
    // SAFETY: the focused observer retains the same source-local heartbeat
    // field authority as the production invocation above.
    let heartbeat = unsafe { Theap::advance_heartbeat_at(theap) };
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
struct DeferredFreeRecursionGuard {
    tld: NonNull<ThreadLocalData>,
}

impl Drop for DeferredFreeRecursionGuard {
    fn drop(&mut self) {
        let mut tld = self.tld;
        // SAFETY: this guard is created only after `begin_deferred_callback`
        // on the exact still-live TLD, and it runs before the synchronous
        // owner-exit invocation can advance to teardown.
        unsafe { tld.as_mut().end_deferred_callback() };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::types::{Heap, LiveThreadId};
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct CallbackObservation {
        calls: AtomicUsize,
        force: AtomicUsize,
        first_heartbeat: AtomicUsize,
        nested_heartbeat: AtomicUsize,
        registration: *const DeferredFreeRegistration,
        theap: *mut Theap,
        tld: *mut ThreadLocalData,
    }

    unsafe extern "C" fn observe_callback(
        force: bool,
        heartbeat: u64,
        context: *mut c_void,
    ) {
        // SAFETY: the test keeps this exact stack observation and its paired
        // source metadata live through the synchronous invocation.
        let observation = unsafe { &*context.cast::<CallbackObservation>() };
        assert!(force);
        assert_eq!(heartbeat, 1);
        assert_eq!(observation.calls.fetch_add(1, Ordering::SeqCst), 0);
        observation.force.store(usize::from(force), Ordering::SeqCst);
        observation
            .first_heartbeat
            .store(usize::try_from(heartbeat).unwrap(), Ordering::SeqCst);

        let registration = unsafe { &*observation.registration };
        let theap = NonNull::new(observation.theap).expect("the test Theap stays live");
        let tld = NonNull::new(observation.tld).expect("the test TLD stays live");
        let nested = begin(registration, theap, tld, false)
            .expect("nested source entry keeps its exact pairing");
        assert_eq!(nested.heartbeat(), 2);
        // SAFETY: the outer callback still owns the exact TLD recurse marker,
        // so nested invocation contains no user callback and leaves it set.
        assert_eq!(unsafe { nested.invoke() }, 2);
        assert!(unsafe { tld.as_ref().recursing() });
        observation.nested_heartbeat.store(2, Ordering::SeqCst);
    }

    fn paired_source_metadata() -> (Heap, ThreadLocalData, Theap) {
        let thread = LiveThreadId::new(17).expect("the test thread identity is nonzero");
        let mut heap = Heap::bootstrap_empty();
        let mut tld = ThreadLocalData::detached();
        tld.attach_bootstrap_exclusive(thread);
        let mut theap = Theap::empty();
        assert!(theap.bind_exclusive_single_thread(&mut heap, &mut tld));
        (heap, tld, theap)
    }

    #[test]
    fn registered_callback_receives_force_and_nested_entry_only_advances_heartbeat() {
        let (_heap, mut tld, mut theap) = paired_source_metadata();
        let registration = DeferredFreeRegistration::new();
        let observation = CallbackObservation {
            calls: AtomicUsize::new(0),
            force: AtomicUsize::new(0),
            first_heartbeat: AtomicUsize::new(0),
            nested_heartbeat: AtomicUsize::new(0),
            registration: core::ptr::from_ref(&registration),
            theap: core::ptr::from_mut(&mut theap),
            tld: core::ptr::from_mut(&mut tld),
        };
        // SAFETY: the callback/context remain live and this test owns every
        // synchronous invocation through the registration fixture.
        unsafe {
            registration.register(
                Some(observe_callback),
                core::ptr::from_ref(&observation).cast_mut().cast(),
            );
        }

        let invocation = begin(
            &registration,
            NonNull::from(&mut theap),
            NonNull::from(&mut tld),
            true,
        )
        .expect("paired source metadata selects the callback");
        assert_eq!(invocation.heartbeat(), 1);
        // SAFETY: the test deliberately releases no Rust metadata borrow into
        // the callback and keeps all three address-stable values live.
        assert_eq!(unsafe { invocation.invoke() }, 1);
        assert_eq!(observation.calls.load(Ordering::SeqCst), 1);
        assert_eq!(observation.force.load(Ordering::SeqCst), 1);
        assert_eq!(observation.first_heartbeat.load(Ordering::SeqCst), 1);
        assert_eq!(observation.nested_heartbeat.load(Ordering::SeqCst), 2);
        assert!(!tld.recursing());
    }

    #[test]
    fn dropping_undispatched_callback_token_restores_the_tld_marker() {
        unsafe extern "C" fn unused_callback(_: bool, _: u64, _: *mut c_void) {}

        let (_heap, mut tld, mut theap) = paired_source_metadata();
        let registration = DeferredFreeRegistration::new();
        // SAFETY: no invocation escapes this stack-owned fixture.
        unsafe { registration.register(Some(unused_callback), core::ptr::null_mut()) };
        let invocation = begin(
            &registration,
            NonNull::from(&mut theap),
            NonNull::from(&mut tld),
            false,
        )
        .expect("paired source metadata selects the callback");
        assert!(tld.recursing());
        drop(invocation);
        assert!(
            !tld.recursing(),
            "an abandoned caller-stack continuation must not suppress a later callback"
        );
    }
}
