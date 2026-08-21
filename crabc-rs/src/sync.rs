//! Rust-owned process-private synchronization primitives.
//!
//! These types deliberately do not use the C `pthread_*` ABI or mirror musl's
//! opaque pthread object layouts. Their state is ordinary Rust-owned atomic
//! storage, and blocking/waking crosses only the direct `crabc-core` futex
//! seam. The initial slice is process-private and non-robust: these objects
//! must not be placed in shared memory or used across `fork` without an
//! application-defined reinitialization protocol.

use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::{Errno, Result};

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;
const SEMAPHORE_MAX: i32 = i32::MAX;
// Linux's FUTEX_WAKE count is a signed `int`; `u32::MAX` is not an
// all-waiters request and can leave every waiter asleep. Use the largest
// positive count for process-private broadcasts.
const MAX_WAKE_COUNT: u32 = i32::MAX as u32;
const RW_WRITER: u32 = 1 << 31;
const RW_READER_MAX: u32 = RW_WRITER - 1;

/// A non-poisoning process-private mutex guarding `T`.
///
/// The mutex has no robust-owner recovery and does not remember an owner in
/// the object itself. A guard must be dropped by the thread which acquired it;
/// moving a guard to another thread is intentionally not supported.
pub struct Mutex<T: ?Sized> {
    state: AtomicU32,
    value: UnsafeCell<T>,
}

// `Mutex` provides the synchronization needed to access the value. This is
// the same bound as the standard Rust mutex: sending the mutex requires the
// value to be sendable, and sharing it requires the value to be sendable.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Creates an unlocked mutex containing `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(UNLOCKED),
            value: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Attempts to acquire the mutex without blocking.
    #[must_use]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.state
            .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| self.guard())
    }

    /// Acquires the mutex, returning a guard which unlocks it on drop.
    ///
    /// The only expected futex failures are `EINTR` and `EAGAIN`, both of
    /// which are handled as ordinary wakeup races. Other kernel errors are
    /// returned without changing the ownership of the mutex.
    pub fn lock(&self) -> Result<MutexGuard<'_, T>> {
        if self
            .state
            .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(self.guard());
        }

        loop {
            if self.state.swap(CONTENDED, Ordering::Acquire) == UNLOCKED {
                return Ok(self.guard());
            }

            // SAFETY: `state` is an aligned atomic futex word owned by this
            // mutex, and the null timeout requests an unbounded wait.
            match unsafe {
                crabc_core::thread::futex_wait(
                    (&self.state as *const AtomicU32).cast::<u32>(),
                    CONTENDED,
                    true,
                    core::ptr::null(),
                )
            } {
                Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Returns exclusive access to the value when the mutex is borrowed
    /// exclusively, without performing an atomic operation.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: `&mut self` proves that no guard or other reference can
        // access the value concurrently.
        unsafe { &mut *self.value.get() }
    }

    fn guard(&self) -> MutexGuard<'_, T> {
        MutexGuard {
            mutex: self,
            // A raw-pointer marker keeps the guard tied to its owning thread;
            // the guard must not be sent to a thread which did not lock it.
            _not_send: PhantomData,
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Mutex").finish_non_exhaustive()
    }
}

/// RAII access to a locked [`Mutex`].
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
    _not_send: PhantomData<*mut ()>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Holding the guard is the mutex's exclusive-access proof.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: Holding the guard is the mutex's exclusive-access proof.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("MutexGuard").field(&&**self).finish()
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        let previous = self.mutex.state.swap(UNLOCKED, Ordering::Release);
        if previous == CONTENDED {
            // SAFETY: The mutex remains alive through the guard's drop, and
            // its atomic state is a valid private futex word.
            let _ = unsafe {
                crabc_core::thread::futex_wake(
                    (&self.mutex.state as *const AtomicU32).cast::<u32>(),
                    1,
                    true,
                )
            };
        }
    }
}

/// A non-poisoning process-private reader/writer lock guarding `T`.
///
/// Readers may share the lock with other readers, while a writer has
/// exclusive access. Waiting writers have priority over new readers so a
/// steady stream of readers cannot indefinitely postpone a writer. The lock
/// has no robust-owner recovery; a guard must be dropped by the thread which
/// acquired it.
pub struct RwLock<T: ?Sized> {
    // The low bits contain the active-reader count. RW_WRITER denotes an
    // active writer. Waiting writers are tracked separately so the futex word
    // can remain a compact count/state value.
    state: AtomicU32,
    waiting_writers: AtomicU32,
    value: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Creates an unlocked reader/writer lock containing `value`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            waiting_writers: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Attempts to acquire a shared read lock without blocking.
    #[must_use]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state == RW_WRITER
                || state >= RW_READER_MAX
                || self.waiting_writers.load(Ordering::Acquire) != 0
            {
                return None;
            }
            if self
                .state
                .compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(RwLockReadGuard {
                    lock: self,
                    _not_send: PhantomData,
                });
            }
        }
    }

    /// Acquires a shared read lock, returning a guard which releases it on
    /// drop.
    pub fn read(&self) -> Result<RwLockReadGuard<'_, T>> {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state != RW_WRITER
                && state < RW_READER_MAX
                && self.waiting_writers.load(Ordering::Acquire) == 0
                && self
                    .state
                    .compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return Ok(RwLockReadGuard {
                    lock: self,
                    _not_send: PhantomData,
                });
            }

            // SAFETY: `state` is an aligned atomic futex word owned by this
            // lock, and the null timeout requests an unbounded wait.
            match unsafe {
                crabc_core::thread::futex_wait(
                    (&self.state as *const AtomicU32).cast::<u32>(),
                    state,
                    true,
                    core::ptr::null(),
                )
            } {
                Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Attempts to acquire an exclusive write lock without blocking.
    #[must_use]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        if self.waiting_writers.load(Ordering::Acquire) != 0 {
            return None;
        }
        self.state
            .compare_exchange(0, RW_WRITER, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| RwLockWriteGuard {
                lock: self,
                _not_send: PhantomData,
            })
    }

    /// Acquires an exclusive write lock, returning a guard which releases it
    /// on drop.
    pub fn write(&self) -> Result<RwLockWriteGuard<'_, T>> {
        self.add_waiting_writer()?;
        loop {
            if self
                .state
                .compare_exchange(0, RW_WRITER, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.remove_waiting_writer();
                return Ok(RwLockWriteGuard {
                    lock: self,
                    _not_send: PhantomData,
                });
            }

            let state = self.state.load(Ordering::Acquire);
            if state == 0 {
                continue;
            }

            // SAFETY: `state` is an aligned atomic futex word owned by this
            // lock, and the null timeout requests an unbounded wait.
            match unsafe {
                crabc_core::thread::futex_wait(
                    (&self.state as *const AtomicU32).cast::<u32>(),
                    state,
                    true,
                    core::ptr::null(),
                )
            } {
                Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => {}
                Err(error) => {
                    self.remove_waiting_writer();
                    return Err(error);
                }
            }
        }
    }

    /// Returns exclusive access to the value when the lock is borrowed
    /// exclusively, without performing an atomic operation.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: `&mut self` proves that no guard or other reference can
        // access the value concurrently.
        unsafe { &mut *self.value.get() }
    }

    fn add_waiting_writer(&self) -> Result<()> {
        loop {
            let waiting = self.waiting_writers.load(Ordering::Relaxed);
            if waiting == u32::MAX {
                return Err(Errno::OVERFLOW);
            }
            if self
                .waiting_writers
                .compare_exchange(waiting, waiting + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    fn remove_waiting_writer(&self) {
        let previous = self.waiting_writers.fetch_sub(1, Ordering::Release);
        if previous == 1 && self.state.load(Ordering::Acquire) != RW_WRITER {
            // A reader can be asleep on state == 0 while this writer is the
            // only waiter. Wake it if the writer leaves without acquiring.
            // SAFETY: `state` remains a live aligned private futex word.
            let _ = unsafe {
                crabc_core::thread::futex_wake(
                    (&self.state as *const AtomicU32).cast::<u32>(),
                    MAX_WAKE_COUNT,
                    true,
                )
            };
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RwLock").finish_non_exhaustive()
    }
}

/// Shared access to a locked [`RwLock`].
pub struct RwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
    _not_send: PhantomData<*mut ()>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The read guard is the lock's shared-access proof.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLockReadGuard<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RwLockReadGuard").field(&&**self).finish()
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        let previous = self.lock.state.fetch_sub(1, Ordering::Release);
        if previous == 1 {
            // SAFETY: The lock remains alive through the guard's drop, and
            // its state is a valid private futex word.
            let _ = unsafe {
                crabc_core::thread::futex_wake(
                    (&self.lock.state as *const AtomicU32).cast::<u32>(),
                    MAX_WAKE_COUNT,
                    true,
                )
            };
        }
    }
}

/// Exclusive access to a locked [`RwLock`].
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
    _not_send: PhantomData<*mut ()>,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The write guard is the lock's exclusive-access proof.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The write guard is the lock's exclusive-access proof.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLockWriteGuard<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RwLockWriteGuard").field(&&**self).finish()
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        // SAFETY: The lock remains alive through the guard's drop, and its
        // state is a valid private futex word.
        let _ = unsafe {
            crabc_core::thread::futex_wake(
                (&self.lock.state as *const AtomicU32).cast::<u32>(),
                MAX_WAKE_COUNT,
                true,
            )
        };
    }
}

/// The result of a timed condition-variable wait.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WaitTimeoutResult {
    timed_out: bool,
}

impl WaitTimeoutResult {
    /// Returns whether the supplied timeout elapsed before a wakeup.
    #[must_use]
    pub const fn timed_out(self) -> bool {
        self.timed_out
    }
}

/// A process-private condition variable.
///
/// The associated mutex is unlocked while waiting and reacquired before the
/// returned guard is produced. Spurious wakeups are represented by a normal
/// successful return, so callers should re-check their predicate.
pub struct Condvar {
    sequence: AtomicU32,
}

unsafe impl Send for Condvar {}
unsafe impl Sync for Condvar {}

impl Condvar {
    /// Creates a condition variable with no waiters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU32::new(0),
        }
    }

    /// Wakes at least one current waiter, if any.
    pub fn notify_one(&self) -> Result<()> {
        self.sequence.fetch_add(1, Ordering::Release);
        // SAFETY: `sequence` is a live aligned atomic futex word.
        unsafe {
            crabc_core::thread::futex_wake(
                (&self.sequence as *const AtomicU32).cast::<u32>(),
                1,
                true,
            )
        }
        .map(|_| ())
    }

    /// Wakes all current waiters, if any.
    pub fn notify_all(&self) -> Result<()> {
        self.sequence.fetch_add(1, Ordering::Release);
        // SAFETY: `sequence` is a live aligned atomic futex word.
        unsafe {
            crabc_core::thread::futex_wake(
                (&self.sequence as *const AtomicU32).cast::<u32>(),
                MAX_WAKE_COUNT,
                true,
            )
        }
        .map(|_| ())
    }

    /// Unlocks `guard`, waits, and reacquires its mutex before returning.
    pub fn wait<'a, T: ?Sized>(&self, guard: MutexGuard<'a, T>) -> Result<MutexGuard<'a, T>> {
        let mutex = guard.mutex;
        let sequence = self.sequence.load(Ordering::Acquire);
        drop(guard);

        loop {
            // SAFETY: `sequence` is live for the duration of the call and the
            // null timeout requests an unbounded private wait.
            match unsafe {
                crabc_core::thread::futex_wait(
                    (&self.sequence as *const AtomicU32).cast::<u32>(),
                    sequence,
                    true,
                    core::ptr::null(),
                )
            } {
                Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => break,
                Err(error) => {
                    // Preserve the mutex ownership contract even on a kernel
                    // error while waiting.
                    let _ = mutex.lock()?;
                    return Err(error);
                }
            }
        }

        mutex.lock()
    }

    /// Unlocks `guard`, waits up to `timeout`, and reacquires its mutex.
    ///
    /// `timeout` is a relative Linux/AArch64 timespec. A timeout is reported
    /// through [`WaitTimeoutResult`], not as an `ETIMEDOUT` error.
    pub fn wait_timeout<'a, T: ?Sized>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: &crate::time::Timespec,
    ) -> Result<(MutexGuard<'a, T>, WaitTimeoutResult)> {
        let mutex = guard.mutex;
        let sequence = self.sequence.load(Ordering::Acquire);
        drop(guard);

        let wait_result = {
            // SAFETY: `timeout` is a live Linux/AArch64 timespec and
            // `sequence` is a live aligned atomic futex word.
            unsafe {
                crabc_core::thread::futex_wait(
                    (&self.sequence as *const AtomicU32).cast::<u32>(),
                    sequence,
                    true,
                    (timeout as *const crate::time::Timespec).cast::<u8>(),
                )
            }
        };
        let timed_out = matches!(wait_result, Err(Errno::TIMEDOUT));
        let guard = mutex.lock()?;
        match wait_result {
            Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) | Err(Errno::TIMEDOUT) => {
                Ok((guard, WaitTimeoutResult { timed_out }))
            }
            Err(error) => Err(error),
        }
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Condvar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Condvar").finish_non_exhaustive()
    }
}

/// A non-poisoning one-time initializer.
pub struct Once {
    state: AtomicU32,
}

unsafe impl Send for Once {}
unsafe impl Sync for Once {}

impl Once {
    /// Creates an uninitialized once control.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(UNLOCKED),
        }
    }

    /// Runs `initialize` exactly once, with no poisoning state.
    ///
    /// The workspace uses aborting panic semantics. Callers must not rely on
    /// retrying after a panic or cancellation from inside `initialize`; a
    /// successfully returning initializer is published with release ordering.
    pub fn call_once<F>(&self, initialize: F) -> Result<()>
    where
        F: FnOnce(),
    {
        let mut initialize = Some(initialize);
        loop {
            match self.state.compare_exchange(
                UNLOCKED,
                LOCKED,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    initialize.take().expect("once initializer consumed")();
                    let previous = self.state.swap(CONTENDED, Ordering::Release);
                    if previous == 3 {
                        // SAFETY: `state` is a live private futex word.
                        let _ = unsafe {
                            crabc_core::thread::futex_wake(
                                (&self.state as *const AtomicU32).cast::<u32>(),
                                MAX_WAKE_COUNT,
                                true,
                            )
                        };
                    }
                    return Ok(());
                }
                Err(CONTENDED) => return Ok(()),
                Err(LOCKED) => {
                    let _ = self.state.compare_exchange(
                        LOCKED,
                        3,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                Err(3) => {
                    // SAFETY: `state` is a live private futex word.
                    match unsafe {
                        crabc_core::thread::futex_wait(
                            (&self.state as *const AtomicU32).cast::<u32>(),
                            3,
                            true,
                            core::ptr::null(),
                        )
                    } {
                        Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(_) => {}
            }
        }
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Once {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Once").finish_non_exhaustive()
    }
}

/// A counting process-private semaphore.
pub struct Semaphore {
    permits: AtomicI32,
}

unsafe impl Send for Semaphore {}
unsafe impl Sync for Semaphore {}

impl Semaphore {
    /// Creates a semaphore with `permits` available acquisitions.
    pub const fn new(permits: u32) -> Result<Self> {
        if permits > SEMAPHORE_MAX as u32 {
            return Err(Errno::INVAL);
        }
        Ok(Self {
            permits: AtomicI32::new(permits as i32),
        })
    }

    /// Attempts to acquire one permit without blocking.
    pub fn try_acquire(&self) -> Result<bool> {
        loop {
            let permits = self.permits.load(Ordering::Acquire);
            if permits <= 0 {
                return Ok(false);
            }
            if self
                .permits
                .compare_exchange(permits, permits - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(true);
            }
        }
    }

    /// Acquires one permit, blocking until one becomes available.
    pub fn acquire(&self) -> Result<()> {
        loop {
            if self.try_acquire()? {
                return Ok(());
            }
            // SAFETY: `permits` is a live aligned private futex word. A
            // release races safely with this expected-zero wait via EAGAIN.
            match unsafe {
                crabc_core::thread::futex_wait(
                    (&self.permits as *const AtomicI32).cast::<u32>(),
                    0,
                    true,
                    core::ptr::null(),
                )
            } {
                Ok(()) | Err(Errno::INTR) | Err(Errno::AGAIN) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Returns one permit to the semaphore.
    pub fn release(&self) -> Result<()> {
        loop {
            let permits = self.permits.load(Ordering::Acquire);
            if permits == SEMAPHORE_MAX {
                return Err(Errno::OVERFLOW);
            }
            if self
                .permits
                .compare_exchange(permits, permits + 1, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                if permits <= 0 {
                    // SAFETY: `permits` remains a live private futex word.
                    unsafe {
                        crabc_core::thread::futex_wake(
                            (&self.permits as *const AtomicI32).cast::<u32>(),
                            1,
                            true,
                        )
                    }
                    .map(|_| ())?;
                }
                return Ok(());
            }
        }
    }

    /// Returns the number of currently available permits.
    #[must_use]
    pub fn available(&self) -> u32 {
        self.permits.load(Ordering::Acquire).max(0) as u32
    }
}

impl fmt::Debug for Semaphore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Semaphore")
            .field("available", &self.available())
            .finish()
    }
}

/// The result returned by [`Barrier::wait`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BarrierWaitResult {
    leader: bool,
}

impl BarrierWaitResult {
    /// Returns whether this participant released the other participants.
    #[must_use]
    pub const fn is_leader(self) -> bool {
        self.leader
    }
}

/// A reusable process-private barrier for a fixed number of participants.
///
/// Each round releases when exactly `count` calls to [`Barrier::wait`] have
/// arrived. The last participant is the leader and advances the generation;
/// subsequent rounds reuse the same storage. A zero count is invalid.
pub struct Barrier {
    count: u32,
    state: Mutex<BarrierState>,
    changed: Condvar,
}

struct BarrierState {
    arrived: u32,
    generation: u32,
}

unsafe impl Send for Barrier {}
unsafe impl Sync for Barrier {}

impl Barrier {
    /// Creates a reusable barrier for `count` participants.
    pub const fn new(count: usize) -> Result<Self> {
        if count == 0 || count > u32::MAX as usize {
            return Err(Errno::INVAL);
        }
        Ok(Self {
            count: count as u32,
            state: Mutex::new(BarrierState {
                arrived: 0,
                generation: 0,
            }),
            changed: Condvar::new(),
        })
    }

    /// Waits for the other participants in this generation.
    pub fn wait(&self) -> Result<BarrierWaitResult> {
        let mut state = self.state.lock()?;
        let generation = state.generation;
        state.arrived += 1;
        if state.arrived == self.count {
            state.arrived = 0;
            state.generation = state.generation.wrapping_add(1);
            drop(state);
            self.changed.notify_all()?;
            return Ok(BarrierWaitResult { leader: true });
        }

        while state.generation == generation {
            state = self.changed.wait(state)?;
        }
        Ok(BarrierWaitResult { leader: false })
    }
}

impl fmt::Debug for Barrier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Barrier")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
