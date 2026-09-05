//! Bounded Linux/x86-64 static pthread-key/C11-TSS lifecycle artifact.
//!
//! This leaf preserves the selected static-thread path from pinned musl 1.2.6
//! release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's
//! MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_key_create.c::{__pthread_key_create,
//!   __pthread_key_delete,__pthread_tsd_run_dtors}` supplies the fixed
//!   `PTHREAD_KEYS_MAX=128` table, null-destructor occupied-key distinction,
//!   deletion clearing, and four-pass clear-before-destructor protocol.
//! - `src/thread/pthread_getspecific.c::__pthread_getspecific` and
//!   `src/thread/pthread_setspecific.c::pthread_setspecific` supply the
//!   selected current-thread value access path.
//! - `src/thread/tss_create.c`, `src/thread/tss_delete.c`, and
//!   `src/thread/tss_set.c` supply C11's status and void-adapter boundary.
//! - `src/thread/pthread_create.c::{start,start_c11,__pthread_exit}` supplies
//!   the required ordering: selected TSD destructors finish before a normal or
//!   explicit worker exit publishes its join result and invokes `SYS_exit`.
//!
//! The selected artifact owns exactly 128 application keys, a process-main
//! value table, and value tables for the existing bounded Static Initial TLS
//! v1 workers. A valid caller can create/delete a key, get/set an active
//! selected main or selected-worker value, and observe a normal-return,
//! `pthread_exit`, or `thrd_exit` worker clear every value before invoking its
//! non-null destructor. Destructor rearming is admitted for at most four
//! ascending-key passes. A null destructor still reserves a key, as in musl.
//! The process-main table admits only the bootstrapped `%fs:0` plus Linux
//! `gettid` identity, so copying or inheriting the FS base alone cannot make a
//! raw caller selected.
//!
//! This is deliberately not musl's general thread-list/TSD implementation.
//! Key deletion is selected only through this private main-plus-worker table;
//! foreign threads receive only that fail-closed admission boundary, while
//! their lifecycle, concurrent deletion/destructor interaction, cleanup
//! ownership beyond the selected deferred-pthread exit ordering, main-thread process-exit destructors,
//! fork/atfork,
//! dynamic or loader TLS/DTV, allocator lifecycle ordering, general TCB
//! layout, and musl's weak/same-address TSD ELF aliases remain outside this
//! artifact. Invalid/deleted keys and non-selected callers fail closed instead
//! of relying on musl's unchecked internal fast paths. This does not establish
//! pthread/C11 family completion or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread/C11 TSD leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::{pthread_create_join, pthread_identity, static_tls};

const EAGAIN: c_int = 11;
const EINVAL: c_int = 22;

const THRD_SUCCESS: c_int = 0;
const THRD_ERROR: c_int = 2;

const PTHREAD_KEYS_MAX: usize = 128;
const PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4;

const KEY_FREE: u8 = 0;
const KEY_ALLOCATED: u8 = 1;

const TSD_TEAR_DOWN_IDLE: u8 = 0;
const TSD_TEAR_DOWN_RUNNING: u8 = 1;
const TSD_TEAR_DOWN_COMPLETE: u8 = 2;

type TsdDestructor = unsafe extern "C" fn(*mut c_void);

/// One selected thread's private TSD values.
///
/// The fixed atomics make concurrent key deletion and a selected worker's
/// ordinary get/set access memory-safe without pretending to supply musl's
/// full all-thread-list or fork protocol. Values are still accessed only
/// through the private key lock below, except for the atomic clearing needed
/// when a worker has become a detached-but-not-yet-reaped registry member.
#[repr(C)]
pub(super) struct SelectedTsdValues {
    values: [AtomicUsize; PTHREAD_KEYS_MAX],
    // Mirrors musl's `tsd_used`: it avoids an otherwise pointless 128-slot
    // teardown scan for a worker that never changed any selected value, and
    // lets a destructor's rearm request the next bounded pass.
    used: AtomicU8,
    teardown: AtomicU8,
}

impl SelectedTsdValues {
    pub(super) const fn empty() -> Self {
        Self {
            values: [const { AtomicUsize::new(0) }; PTHREAD_KEYS_MAX],
            used: AtomicU8::new(0),
            teardown: AtomicU8::new(TSD_TEAR_DOWN_IDLE),
        }
    }

    /// Clear one key while the private TSD metadata lock excludes a current
    /// selected set/get operation for that key.
    ///
    /// Detached workers can remain registered after kernel exit; atomics keep
    /// this bounded clearing safe until the external reaper withdraws them.
    pub(super) fn clear_key(&self, key: usize) {
        self.values[key].store(0, Ordering::Release);
    }
}

struct SelectedTsdKey {
    // State distinguishes a vacant key from an allocated null-destructor key.
    state: AtomicU8,
    // A zero function word represents musl's private null-destructor sentinel
    // at this smaller Rust boundary. It never means that the key is free.
    destructor: AtomicUsize,
}

impl SelectedTsdKey {
    const fn empty() -> Self {
        Self {
            state: AtomicU8::new(KEY_FREE),
            destructor: AtomicUsize::new(0),
        }
    }
}

static SELECTED_TSD_KEYS: [SelectedTsdKey; PTHREAD_KEYS_MAX] =
    [const { SelectedTsdKey::empty() }; PTHREAD_KEYS_MAX];
static SELECTED_TSD_NEXT_KEY: AtomicUsize = AtomicUsize::new(0);
static SELECTED_TSD_LOCK: AtomicU8 = AtomicU8::new(0);
static MAIN_SELECTED_TSD_VALUES: SelectedTsdValues = SelectedTsdValues::empty();

/// Acquire the bounded TSD metadata/value lock.
///
/// The lock is never held across a user destructor, clone, join wait, or any
/// syscall. Key deletion takes it before the selected-worker registry lock;
/// current worker lookup drops the registry lock before taking this lock.
fn lock_selected_tsd() {
    while SELECTED_TSD_LOCK
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while SELECTED_TSD_LOCK.load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
    }
}

fn unlock_selected_tsd() {
    SELECTED_TSD_LOCK.store(0, Ordering::Release);
}

/// Begin the selected TSD portion of a static fork transaction.
///
/// This precedes the selected worker-list lock, preserving the established
/// TSD -> worker-registry order used by key deletion. It prevents a raw fork
/// from copying half of `pthread_key_create` or `pthread_key_delete` metadata
/// while the child is about to adopt the calling task's TSD table.
#[cfg(not(feature = "x86-owned-dynamic-runtime"))]
pub(super) fn pthread_fork_prepare() {
    lock_selected_tsd();
}

/// Complete the original-parent (or raw-error) side of the selected TSD fork
/// transaction.
///
/// # Safety
///
/// The caller must hold the matching [`pthread_fork_prepare`] lock and must
/// not have completed this transaction already.
#[cfg(not(feature = "x86-owned-dynamic-runtime"))]
pub(super) unsafe fn pthread_fork_parent() {
    unlock_selected_tsd();
}

#[inline]
fn key_index(key: c_uint) -> Option<usize> {
    let index = key as usize;
    (index < PTHREAD_KEYS_MAX).then_some(index)
}

#[inline]
fn key_is_allocated_locked(index: usize) -> bool {
    SELECTED_TSD_KEYS[index].state.load(Ordering::Acquire) == KEY_ALLOCATED
}

#[inline]
fn destructor_from_word(word: usize) -> Option<TsdDestructor> {
    if word == 0 {
        None
    } else {
        // SAFETY: every nonzero word comes from one live C function pointer
        // stored by pthread_key_create/tss_create while this key was active.
        Some(unsafe { core::mem::transmute::<usize, TsdDestructor>(word) })
    }
}

/// Resolve the current selected main/worker value table.
///
/// A selected worker remains mapped while it calls this helper: join/reaping
/// cannot withdraw it before its `CLONE_CHILD_CLEARTID` word is zero, which
/// happens only after this task stops executing. The worker-registry helper
/// separately verifies `%fs:0`, Linux TID, and the live child-TID word before
/// returning its private table pointer.
fn current_selected_values() -> Option<*const SelectedTsdValues> {
    let thread_pointer = pthread_identity::current_thread_pointer();
    if static_tls::is_initial_thread_pointer(thread_pointer) {
        return Some(core::ptr::addr_of!(MAIN_SELECTED_TSD_VALUES));
    }
    pthread_create_join::current_selected_worker_tsd_values()
}

/// Create one selected POSIX key without changing C `errno`.
///
/// # Safety
///
/// `key` must point to writable, aligned `pthread_key_t` storage. If present,
/// `destructor` must remain valid whenever a selected worker with a non-null
/// value for this key reaches its selected exit path.
#[no_mangle]
pub unsafe extern "C" fn pthread_key_create(
    key: *mut c_uint,
    destructor: Option<TsdDestructor>,
) -> c_int {
    if key.is_null() {
        return EINVAL;
    }
    // The key registry is private to the selected main/worker population.
    // Do not let a raw foreign task allocate capacity that belongs to those
    // value tables merely because key creation itself has no per-thread value.
    if current_selected_values().is_none() {
        return EINVAL;
    }

    lock_selected_tsd();
    let start = SELECTED_TSD_NEXT_KEY.load(Ordering::Relaxed);
    let mut index = start;
    loop {
        if !key_is_allocated_locked(index) {
            SELECTED_TSD_KEYS[index]
                .destructor
                .store(destructor.map_or(0, |function| function as usize), Ordering::Relaxed);
            SELECTED_TSD_KEYS[index]
                .state
                .store(KEY_ALLOCATED, Ordering::Release);
            SELECTED_TSD_NEXT_KEY.store((index + 1) % PTHREAD_KEYS_MAX, Ordering::Relaxed);
            // SAFETY: the public C boundary requires writable key storage.
            unsafe { core::ptr::write(key, index as c_uint) };
            unlock_selected_tsd();
            return 0;
        }
        index = (index + 1) % PTHREAD_KEYS_MAX;
        if index == start {
            unlock_selected_tsd();
            return EAGAIN;
        }
    }
}

/// Delete one selected key and clear its main/selected-worker values.
///
/// No user destructor runs during deletion. This selected clearing is bounded
/// to the process-main table and the live private worker registry; it is not
/// musl's fork-safe all-thread-list deletion protocol.
///
/// # Safety
///
/// `key` must name an active key created through this selected artifact. The
/// caller must not race a worker destructor that observes, deletes, or rearms
/// this key; that broader musl interaction is deliberately outside the slice.
#[no_mangle]
pub unsafe extern "C" fn pthread_key_delete(key: c_uint) -> c_int {
    let Some(index) = key_index(key) else {
        return EINVAL;
    };
    // Deletion changes the global selected key registry and scans selected
    // values, so it has the same selected-caller admission boundary as create.
    if current_selected_values().is_none() {
        return EINVAL;
    }

    lock_selected_tsd();
    if !key_is_allocated_locked(index) {
        unlock_selected_tsd();
        return EINVAL;
    }
    // Clear the active marker first. A concurrent selected set/get that wins
    // the lock afterwards fails closed instead of reviving a deleted key.
    SELECTED_TSD_KEYS[index].state.store(KEY_FREE, Ordering::Release);
    SELECTED_TSD_KEYS[index].destructor.store(0, Ordering::Release);
    MAIN_SELECTED_TSD_VALUES.clear_key(index);
    // This follows the fixed lock order TSD -> selected-worker registry.
    // SAFETY: the sibling scans only registry-published mappings while its
    // registry lock keeps each control record live.
    pthread_create_join::clear_selected_worker_tsd_key(index);
    unlock_selected_tsd();
    0
}

/// Read one selected current-thread value.
///
/// Invalid/deleted keys and non-selected callers return null. This closed
/// behavior avoids musl's unchecked-internal-key precondition becoming an
/// out-of-bounds access in this bounded artifact.
///
/// # Safety
///
/// `key` must be the caller's active selected key. Returned values are opaque
/// borrowed C pointers and may not be dereferenced unless the application
/// still owns the referenced storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_getspecific(key: c_uint) -> *mut c_void {
    let Some(index) = key_index(key) else {
        return core::ptr::null_mut();
    };
    let Some(values) = current_selected_values() else {
        return core::ptr::null_mut();
    };

    lock_selected_tsd();
    let value = if key_is_allocated_locked(index) {
        // SAFETY: current-selected resolution retains this executing worker's
        // mapping, or returned the permanent process-main value table.
        unsafe { (*values).values[index].load(Ordering::Acquire) }
    } else {
        0
    };
    unlock_selected_tsd();
    value as *mut c_void
}

/// Store one selected current-thread value.
///
/// # Safety
///
/// `value` is opaque caller-owned storage. If it is non-null and the selected
/// key has a destructor, it must remain valid until the selected destructor
/// invocation or an explicit replacement/deletion clears it. `key` must be
/// an active selected key for the current selected main or worker thread.
#[no_mangle]
pub unsafe extern "C" fn pthread_setspecific(key: c_uint, value: *const c_void) -> c_int {
    let Some(index) = key_index(key) else {
        return EINVAL;
    };
    let Some(values) = current_selected_values() else {
        return EINVAL;
    };

    lock_selected_tsd();
    let result = if key_is_allocated_locked(index) {
        // SAFETY: current-selected resolution retains this executing worker's
        // mapping, or returned the permanent process-main value table.
        unsafe {
            let previous = (*values).values[index].load(Ordering::Acquire);
            if previous != value as usize {
                (*values).values[index].store(value as usize, Ordering::Release);
                (*values).used.store(1, Ordering::Release);
            }
        }
        0
    } else {
        EINVAL
    };
    unlock_selected_tsd();
    result
}

/// Run the selected worker's private TSD destructor phase once.
///
/// The caller must invoke this only while its worker's control mapping and
/// TSD values remain live, before result publication and `SYS_exit`. Each
/// non-null value is cleared before its current non-null destructor executes.
/// The lock is released for every callback, so a destructor may rearm a key;
/// at most four ascending-key passes are selected.
///
/// # Safety
///
/// `values` must point to the current selected worker's live `ThreadControl`
/// TSD state. The caller must guarantee that no join/reaper can reclaim that
/// control mapping until this function returns.
pub(super) unsafe fn run_selected_worker_tsd_destructors(values: *const SelectedTsdValues) {
    if values.is_null() {
        return;
    }
    // SAFETY: the selected normal/explicit exit seam supplies its own current
    // live worker value table and retains its mapping through this phase.
    let values = unsafe { &*values };
    if values
        .teardown
        .compare_exchange(
            TSD_TEAR_DOWN_IDLE,
            TSD_TEAR_DOWN_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    for _ in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
        lock_selected_tsd();
        let used = values.used.swap(0, Ordering::AcqRel);
        unlock_selected_tsd();
        if used == 0 {
            break;
        }
        for index in 0..PTHREAD_KEYS_MAX {
            lock_selected_tsd();
            // Musl clears every value while scanning, including values whose
            // key has no destructor or was deleted during a prior callback.
            let value = values.values[index].swap(0, Ordering::AcqRel);
            let destructor = if value != 0 && key_is_allocated_locked(index) {
                destructor_from_word(
                    SELECTED_TSD_KEYS[index]
                        .destructor
                        .load(Ordering::Acquire),
                )
            } else {
                None
            };
            unlock_selected_tsd();

            if let Some(destructor) = destructor {
                // SAFETY: the function pointer was installed by a valid C
                // key creator. The opaque non-null value belongs to this key
                // until this selected clear-before-callback handoff.
                unsafe { destructor(value as *mut c_void) };
            }
        }
    }
    values
        .teardown
        .store(TSD_TEAR_DOWN_COMPLETE, Ordering::Release);
}

/// Run the bootstrapped initial thread's selected TSD destructor phase.
///
/// `pthread_exit` uses this before it either performs ordinary last-thread
/// process exit or leaves a remaining selected worker to become that last
/// thread. The static main table is process-lifetime storage, so unlike a
/// worker control mapping it needs no join/reaper lifetime proof.
pub(super) unsafe fn run_selected_main_tsd_destructors() {
    // SAFETY: the process-main table is the one static selected-main value
    // table and this wrapper exposes it only to the selected main exit path.
    unsafe { run_selected_worker_tsd_destructors(core::ptr::addr_of!(MAIN_SELECTED_TSD_VALUES)) }
}

/// Preserve the calling selected thread's TSD values in a post-fork child.
///
/// Before the static TLS owner adopts the child caller as its new main task,
/// the inherited pointer either names the existing main table or one linked
/// worker control. Copy the latter into the child main table, then clear the
/// copied metadata lock: every non-caller thread vanished at fork, so no
/// parent lock owner can exist in the child. Key allocation metadata remains
/// process-copied exactly as it was at the fork boundary.
#[cfg(not(feature = "x86-owned-dynamic-runtime"))]
pub(super) unsafe fn adopt_current_values_after_fork() -> bool {
    let thread_pointer = pthread_identity::current_thread_pointer();
    if static_tls::is_inherited_initial_thread_pointer(thread_pointer) {
        // The child inherited the metadata lock from its sole surviving task.
        // No sibling can finish a concurrent key transition after fork, so
        // clear it only after the stable pointer identity observation.
        SELECTED_TSD_LOCK.store(0, Ordering::Release);
        return true;
    }
    let Some(source) = pthread_create_join::current_selected_worker_tsd_values_after_fork(
        thread_pointer,
    ) else {
        return false;
    };
    // SAFETY: the fork coordinator still holds both the copied TSD metadata
    // lock and worker-list lock. The source control remains mapped and no
    // sibling can be midway through key allocation/deletion, so these atomic
    // snapshots are the complete caller-owned TSD state to retain.
    let source = unsafe { &*source };
    for index in 0..PTHREAD_KEYS_MAX {
        MAIN_SELECTED_TSD_VALUES.values[index].store(
            source.values[index].load(Ordering::Acquire),
            Ordering::Relaxed,
        );
    }
    MAIN_SELECTED_TSD_VALUES
        .used
        .store(source.used.load(Ordering::Acquire), Ordering::Relaxed);
    MAIN_SELECTED_TSD_VALUES
        .teardown
        .store(source.teardown.load(Ordering::Acquire), Ordering::Relaxed);
    SELECTED_TSD_LOCK.store(0, Ordering::Release);
    true
}

/// Create one selected C11 TSS key.
///
/// C11 collapses every pthread-style failure to `thrd_error`.
///
/// # Safety
///
/// `key` and `destructor` have the same writable-storage and lifetime
/// obligations as [`pthread_key_create`].
#[no_mangle]
pub unsafe extern "C" fn tss_create(
    key: *mut c_uint,
    destructor: Option<TsdDestructor>,
) -> c_int {
    if unsafe { pthread_key_create(key, destructor) } == 0 {
        THRD_SUCCESS
    } else {
        THRD_ERROR
    }
}

/// Delete one selected C11 TSS key.
///
/// # Safety
///
/// `key` has the same active-key and no-concurrent-destructor obligation as
/// [`pthread_key_delete`].
#[no_mangle]
pub unsafe extern "C" fn tss_delete(key: c_uint) {
    let _ = unsafe { pthread_key_delete(key) };
}

/// Read one selected C11 TSS value.
///
/// # Safety
///
/// `key` and any returned opaque pointer have the same obligations as
/// [`pthread_getspecific`].
#[no_mangle]
pub unsafe extern "C" fn tss_get(key: c_uint) -> *mut c_void {
    unsafe { pthread_getspecific(key) }
}

/// Store one selected C11 TSS value.
///
/// # Safety
///
/// `key` and `value` have the same selected-current-thread and value-lifetime
/// obligations as [`pthread_setspecific`].
#[no_mangle]
pub unsafe extern "C" fn tss_set(key: c_uint, value: *mut c_void) -> c_int {
    if unsafe { pthread_setspecific(key, value) } == 0 {
        THRD_SUCCESS
    } else {
        THRD_ERROR
    }
}
