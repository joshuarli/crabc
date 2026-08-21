//! Native thread-runtime access through crabc's private singleton table.
//!
//! `libc.so` owns crabc's pthread registry, thread-local-key slots, and
//! cancellation state. This module reaches that one owner through the private
//! versioned runtime table; it neither links a second pthread implementation
//! nor calls public `pthread_*` symbols or C TLS `errno`.
//!
//! The module is deliberately opt-in with the `runtime-thread` feature. A
//! normal Rust test executable is not necessarily a crabc process, whereas a
//! program running under crabc's loader supplies the required singleton table.

#[cfg(feature = "runtime-thread-alloc")]
use alloc::boxed::Box;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use core::num::NonZeroU64;
use core::ptr::NonNull;

use crabc_core::runtime::{RuntimeV1, ThreadDestructorV1, ThreadHandleV1, ThreadStartV1, V1_ABI_VERSION};

use crate::{Errno, Result};

extern "C" {
    fn __crabc_runtime_v1() -> *const RuntimeV1;
}

fn runtime() -> Result<&'static RuntimeV1> {
    // SAFETY: A crabc process exports this explicit private getter from its
    // loaded libc. The returned table is immutable process-lifetime state.
    let runtime = unsafe { __crabc_runtime_v1() };
    let runtime = NonNull::new(runtime.cast_mut()).ok_or(Errno::INVAL)?;
    // SAFETY: The private getter's non-null result points at a RuntimeV1
    // owned by the loaded libc for the process lifetime.
    let runtime = unsafe { runtime.as_ref() };
    if runtime.abi_version != V1_ABI_VERSION || runtime.abi_size < size_of::<RuntimeV1>() as u32 {
        return Err(Errno::INVAL);
    }
    Ok(runtime)
}

fn status(status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        // The private table transports positive pthread errors directly. A
        // malformed table must not make this facade panic or read TLS errno.
        Err(Errno::from_raw(status).unwrap_or(Errno::INVAL))
    }
}

/// An opaque identity for a thread owned by crabc's singleton pthread runtime.
///
/// It can be compared and used with the explicitly unsafe cancellation API,
/// but its integer representation is not an application ABI and cannot be
/// constructed from a raw value.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ThreadId(NonZeroU64);

impl ThreadId {
    fn from_runtime(handle: ThreadHandleV1) -> Result<Self> {
        NonZeroU64::new(handle).map(Self).ok_or(Errno::INVAL)
    }

    /// Returns the opaque runtime value for logging or equality bridges.
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for ThreadId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ThreadId").field(&self.as_raw()).finish()
    }
}

/// Returns the current crabc runtime thread identity.
pub fn current() -> Result<ThreadId> {
    let mut handle = 0;
    // SAFETY: The private table writes one ThreadHandleV1 to the supplied
    // stack location and does not retain it.
    status(unsafe { (runtime()?.thread_self)(&mut handle) })?;
    ThreadId::from_runtime(handle)
}

/// Raw C-compatible entry point for [`spawn_raw`].
pub type RawThreadStart = ThreadStartV1;

/// A joinable native thread whose callback and result pointers remain raw.
///
/// It is intentionally neither `Send` nor `Sync`. The underlying libc can
/// synchronize its registry, but cross-thread handle transfer has no native
/// lifecycle fixture yet. Dropping a still-joinable handle makes a best-effort
/// detach; use [`NativeJoinHandle::join`] or [`NativeJoinHandle::detach`] when
/// the error outcome matters.
pub struct NativeJoinHandle {
    id: Option<ThreadId>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl NativeJoinHandle {
    fn new(id: ThreadId) -> Self {
        Self {
            id: Some(id),
            _not_send_or_sync: PhantomData,
        }
    }

    /// Returns this native thread's opaque identity while it is joinable.
    #[must_use]
    pub const fn id(&self) -> Option<ThreadId> {
        self.id
    }

    fn join_raw(&mut self) -> Result<*mut c_void> {
        let id = self.id.ok_or(Errno::INVAL)?;
        let mut result = core::ptr::null_mut();
        // SAFETY: `id` came from this private table; `result` points to a
        // writable stack location which is not retained by libc.
        status(unsafe { (runtime()?.thread_join)(id.as_raw(), &mut result) })?;
        self.id = None;
        Ok(result)
    }

    fn detach_raw(&mut self) -> Result<()> {
        let id = self.id.ok_or(Errno::INVAL)?;
        // SAFETY: `id` came from this private table and the call retains no
        // Rust pointer supplied by this facade.
        status(unsafe { (runtime()?.thread_detach)(id.as_raw()) })?;
        self.id = None;
        Ok(())
    }

    /// Joins and returns the raw callback result pointer.
    ///
    /// The pointer must be interpreted only according to the callback passed
    /// to [`spawn_raw`]. A null pointer is an ordinary callback result.
    pub fn join(mut self) -> Result<*mut c_void> {
        self.join_raw()
    }

    /// Detaches this thread and consumes the only join handle.
    pub fn detach(mut self) -> Result<()> {
        self.detach_raw()
    }
}

impl Drop for NativeJoinHandle {
    fn drop(&mut self) {
        if self.id.is_some() {
            // A Drop implementation cannot report a positive pthread error.
            // Keep the lifecycle best-effort and let the caller use detach or
            // join when that failure must be observed.
            let _ = self.detach_raw();
        }
    }
}

impl fmt::Debug for NativeJoinHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeJoinHandle")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Creates a native crabc thread from a raw C-compatible callback.
///
/// # Safety
///
/// `start` and `argument` must remain valid under the callback's C ABI until
/// the callback finishes. The callback must not unwind, and it must arrange
/// ownership of any result pointer returned to [`NativeJoinHandle::join`].
/// The callback must also be compatible with crabc's cancellation and TLS
/// cleanup rules. Use [`spawn`] when an owned Rust closure and result are a
/// suitable model.
pub unsafe fn spawn_raw(start: RawThreadStart, argument: *mut c_void) -> Result<NativeJoinHandle> {
    let mut handle = 0;
    // SAFETY: The caller establishes the callback/argument contract and the
    // output is a writable stack value with the exact private wire layout.
    status(unsafe { (runtime()?.thread_create)(start, argument, &mut handle) })?;
    Ok(NativeJoinHandle::new(ThreadId::from_runtime(handle)?))
}

#[cfg(feature = "runtime-thread-alloc")]
struct StartPacket<F, T> {
    function: Option<F>,
    _result: PhantomData<T>,
}

#[cfg(feature = "runtime-thread-alloc")]
unsafe extern "C" fn typed_start<F, T>(argument: *mut c_void) -> *mut c_void
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // SAFETY: `spawn` transfers exactly one Box<StartPacket<F, T>> into this
    // callback. The pthread callback executes it at most once.
    let mut packet = unsafe { Box::from_raw(argument.cast::<StartPacket<F, T>>()) };
    let function = packet
        .function
        .take()
        .expect("typed thread entry runs exactly once");
    let result = function();
    Box::into_raw(Box::new(result)).cast()
}

/// A joinable thread spawned with an owned Rust closure.
///
/// The handle is intentionally not `Send` or `Sync` until a native
/// cross-thread join/transfer lifecycle fixture establishes that stronger
/// contract. Dropping it makes a best-effort detach, exactly like
/// [`NativeJoinHandle`].
#[cfg(feature = "runtime-thread-alloc")]
pub struct JoinHandle<T> {
    raw: NativeJoinHandle,
    _result: PhantomData<T>,
}

#[cfg(feature = "runtime-thread-alloc")]
impl<T> JoinHandle<T> {
    /// Returns the spawned thread's opaque runtime identity.
    #[must_use]
    pub fn id(&self) -> ThreadId {
        // A typed handle only loses its raw identity during consuming join or
        // detach, so an ordinary borrow always observes an active thread.
        self.raw.id().expect("active JoinHandle must retain its thread id")
    }

    /// Joins the thread and returns the value produced by its closure.
    ///
    /// If joining fails, dropping this consuming handle attempts to detach the
    /// native thread so that the Rust closure packet cannot retain a joinable
    /// libc slot indefinitely.
    pub fn join(mut self) -> Result<T> {
        let result = self.raw.join_raw()?;
        let result = NonNull::new(result).ok_or(Errno::INVAL)?;
        // SAFETY: `spawn`'s typed callback returns exactly one Box<T>. The
        // unsafe cancellation API forbids cancelling a typed spawned thread,
        // which preserves that ownership invariant.
        Ok(*unsafe { Box::from_raw(result.cast::<T>().as_ptr()) })
    }

    /// Detaches this thread and consumes its typed join result.
    pub fn detach(self) -> Result<()> {
        self.raw.detach()
    }
}

#[cfg(feature = "runtime-thread-alloc")]
impl<T> fmt::Debug for JoinHandle<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinHandle")
            .field("id", &self.raw.id())
            .finish_non_exhaustive()
    }
}

/// Spawns a native crabc thread that owns its closure and joins to `T`.
///
/// The closure and result must be transferable to the new thread. Crabc uses
/// aborting panic semantics, so a panic does not unwind through the C thread
/// entry boundary.
#[cfg(feature = "runtime-thread-alloc")]
pub fn spawn<F, T>(function: F) -> Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let packet = Box::new(StartPacket::<F, T> {
        function: Some(function),
        _result: PhantomData,
    });
    let argument = Box::into_raw(packet).cast::<c_void>();
    // SAFETY: The typed callback reconstructs this exact allocation once,
    // owns it through invocation, and returns a separately owned Box<T>.
    let raw = match unsafe { spawn_raw(typed_start::<F, T>, argument) } {
        Ok(raw) => raw,
        Err(error) => {
            // SAFETY: Creation failed, so libc did not receive a running
            // callback and ownership of the packet remains with this call.
            drop(unsafe { Box::from_raw(argument.cast::<StartPacket<F, T>>()) });
            return Err(error);
        }
    };
    Ok(JoinHandle {
        raw,
        _result: PhantomData,
    })
}

/// Whether cancellation is enabled for the current crabc thread.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum CancellationState {
    /// Honor pending cancellation requests.
    Enabled = 0,
    /// Defer all cancellation delivery for the current thread.
    Disabled = 1,
}

impl CancellationState {
    fn from_runtime(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Enabled),
            1 => Ok(Self::Disabled),
            _ => Err(Errno::INVAL),
        }
    }
}

/// When a current thread may act on a cancellation request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u32)]
pub enum CancellationType {
    /// Act only at an explicit cancellation point.
    Deferred = 0,
    /// Permit asynchronous cancellation delivery.
    Asynchronous = 1,
}

impl CancellationType {
    fn from_runtime(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Deferred),
            1 => Ok(Self::Asynchronous),
            _ => Err(Errno::INVAL),
        }
    }
}

/// Requests cancellation of a raw native thread.
///
/// # Safety
///
/// Cancellation can run at a point that bypasses Rust destructors, lock
/// releases, and FFI cleanup. `thread` must identify a callback designed for
/// that behavior. In particular, it must not be a [`JoinHandle`] created by
/// [`spawn`], because that handle relies on receiving an owned `Box<T>` result.
pub unsafe fn cancel(thread: ThreadId) -> Result<()> {
    // SAFETY: The caller establishes the cancellation/lifetime contract for
    // this opaque native-thread identity.
    status(unsafe { (runtime()?.thread_cancel)(thread.as_raw()) })
}

/// Changes the current thread's cancellation state.
///
/// # Safety
///
/// Enabling cancellation can immediately expose the current thread to the
/// cancellation hazards described by [`cancel`]. The caller must ensure all
/// live Rust and FFI invariants tolerate that transition.
pub unsafe fn set_cancellation_state(state: CancellationState) -> Result<CancellationState> {
    let mut previous = 0;
    // SAFETY: `previous` is writable stack storage, and the caller upholds
    // the current-thread cancellation safety contract.
    status(unsafe { (runtime()?.thread_setcancelstate)(state as u32, &mut previous) })?;
    CancellationState::from_runtime(previous)
}

/// Changes the current thread's cancellation delivery mode.
///
/// # Safety
///
/// Selecting asynchronous delivery can interrupt ordinary Rust code. The
/// caller must ensure no active Rust ownership, locking, or FFI invariant
/// depends on destructors or linear control flow.
pub unsafe fn set_cancellation_type(kind: CancellationType) -> Result<CancellationType> {
    let mut previous = 0;
    // SAFETY: `previous` is writable stack storage, and the caller upholds
    // the cancellation mode safety contract.
    status(unsafe { (runtime()?.thread_setcanceltype)(kind as u32, &mut previous) })?;
    CancellationType::from_runtime(previous)
}

/// Delivers a pending cancellation request for the current thread, if any.
///
/// # Safety
///
/// This has the same destructor and invariant hazards as [`cancel`].
pub unsafe fn test_cancellation() -> Result<()> {
    let runtime = runtime()?;
    // SAFETY: The caller upholds the cancellation safety contract.
    unsafe { (runtime.thread_testcancel)() };
    Ok(())
}

/// Destructor callback for a [`Key`].
pub type KeyDestructor = ThreadDestructorV1;

/// A process-global crabc thread-local key.
///
/// Key values are per-thread and remain opaque pointers. The key itself may
/// be shared; its deletion is explicit so applications can observe errors.
pub struct Key {
    raw: Option<u32>,
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

impl Key {
    fn create_inner(destructor: Option<KeyDestructor>) -> Result<Self> {
        let mut key = 0;
        // SAFETY: `key` is writable stack storage and the optional destructor
        // has the exact private table callback ABI.
        status(unsafe { (runtime()?.thread_key_create)(&mut key, destructor) })?;
        if key >= crabc_core::runtime::THREAD_KEY_CAPACITY {
            return Err(Errno::INVAL);
        }
        Ok(Self { raw: Some(key) })
    }

    /// Creates a key whose values have no automatic destructor.
    pub fn new() -> Result<Self> {
        Self::create_inner(None)
    }

    /// Creates a key whose destructor runs during crabc thread cleanup.
    ///
    /// # Safety
    ///
    /// `destructor` may execute on any exiting crabc-managed thread, up to
    /// crabc's documented destructor iterations. It must tolerate that ABI,
    /// must not unwind, and must only consume values whose ownership was
    /// established with [`Key::set`].
    pub unsafe fn with_destructor(destructor: KeyDestructor) -> Result<Self> {
        Self::create_inner(Some(destructor))
    }

    fn raw(&self) -> Result<u32> {
        self.raw.ok_or(Errno::INVAL)
    }

    /// Returns this thread's opaque pointer value, if one was set.
    #[must_use]
    pub fn get(&self) -> Option<NonNull<c_void>> {
        let key = self.raw().ok()?;
        // SAFETY: `key` was allocated by this table and the returned pointer
        // remains opaque to this facade.
        NonNull::new(unsafe { (runtime().ok()?.thread_getspecific)(key) })
    }

    /// Stores an opaque pointer for the current thread.
    ///
    /// # Safety
    ///
    /// The pointed-to value must remain valid for the contract of this key's
    /// destructor, if any, until it is replaced, cleared, or the thread exits.
    pub unsafe fn set(&self, value: Option<NonNull<c_void>>) -> Result<()> {
        let value = value.map_or(core::ptr::null_mut(), NonNull::as_ptr);
        // SAFETY: The caller establishes the pointer lifetime/destructor
        // contract; `self` owns a key created by the private table.
        status(unsafe { (runtime()?.thread_setspecific)(self.raw()?, value.cast_const()) })
    }

    /// Deletes this key from crabc's singleton key registry.
    pub fn delete(mut self) -> Result<()> {
        let key = self.raw()?;
        // SAFETY: `key` was allocated by this private table and has not been
        // deleted through this owning Key value.
        status(unsafe { (runtime()?.thread_key_delete)(key) })?;
        self.raw = None;
        Ok(())
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        if let Some(key) = self.raw {
            // Keep Drop best-effort. Explicit delete is available when the
            // application needs to observe a thread-runtime failure.
            if let Ok(runtime) = runtime() {
                // SAFETY: This Key owns the key number until Drop completes.
                let _ = unsafe { (runtime.thread_key_delete)(key) };
            }
        }
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Key").finish_non_exhaustive()
    }
}
