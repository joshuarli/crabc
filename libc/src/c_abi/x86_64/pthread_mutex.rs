//! Bounded Linux/x86-64 static normal `pthread_mutex_*` artifact.
//!
//! This module selects one process-private, normal-mutex state machine over
//! the existing static x86 worker/TLS seam. Its provenance is pinned to musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_mutex_init.c` supplies the all-zero normal-mutex
//!   initialization shape.
//! - `src/thread/pthread_mutex_trylock.c::__pthread_mutex_trylock` supplies
//!   the normal fast compare/exchange representation, where `EBUSY` is the
//!   held lock word.
//! - `src/thread/pthread_mutex_lock.c::__pthread_mutex_lock` and
//!   `src/thread/pthread_mutex_timedlock.c::__pthread_mutex_timedlock` supply
//!   the acquire/retry, waiter-mark, futex-wait, and retry ordering.
//! - `src/thread/pthread_mutex_unlock.c::__pthread_mutex_unlock` supplies the
//!   exchange-before-wake release rule that preserves a contended wait mark.
//! - `src/thread/pthread_mutex_destroy.c` supplies the no-resource normal
//!   destroy result.
//!
//! The admitted contract is intentionally narrow: a zero-initialized or
//! `pthread_mutex_init(..., NULL)` process-private `PTHREAD_MUTEX_NORMAL`
//! object may be locked, tried, unlocked, and destroyed. Contention uses
//! Linux `FUTEX_*_PRIVATE` on its exact public lock word. It excludes mutex
//! attributes; recursive, error-checking, robust, PI, and process-shared
//! types; timed locking; C11 `mtx_*`; condition variables; cancellation;
//! signal/fork coordination; dynamic TLS; loader/CRT integration; a general
//! pthread runtime; and public x86 support. Unsupported non-null attributes
//! or nonzero type words return `ENOTSUP` without being interpreted.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 normal pthread-mutex leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{atomic, raw_syscall};

const EBUSY: c_int = 16;
const EINTR: c_int = 4;
const ENOTSUP: c_int = 95;

const MUTEX_TYPE_WORD: usize = 0;
const MUTEX_LOCK_WORD: usize = 1;
const MUTEX_WAITERS_WORD: usize = 2;
const MUTEX_WORD_COUNT: usize = 10;
const MUTEX_WAITER_BIT: c_int = c_int::MIN;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_WAIT_PRIVATE: i64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: i64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

/// Exact public x86 `pthread_mutex_t` storage.
///
/// The installed C header exposes a 40-byte union with ten `int` words and
/// eight-byte alignment. This private record deliberately names only that
/// storage: it is not a Rust pthread handle or public API type.
#[repr(C, align(8))]
struct PublicPthreadMutex {
    words: [c_int; MUTEX_WORD_COUNT],
}

const _: () = {
    assert!(size_of::<PublicPthreadMutex>() == 40);
    assert!(align_of::<PublicPthreadMutex>() == 8);
    assert!(offset_of!(PublicPthreadMutex, words) == 0);
};

/// Return one raw C mutex word without creating a Rust reference to storage
/// that may be concurrently accessed by a different C thread.
///
/// # Safety
///
/// `mutex` must designate a complete aligned public x86 `pthread_mutex_t`.
#[inline(always)]
unsafe fn mutex_word(mutex: *mut PublicPthreadMutex, index: usize) -> *mut c_int {
    debug_assert!(index < MUTEX_WORD_COUNT);
    // SAFETY: `mutex` is a complete public mutex record and `index` is within
    // its ten i32 words. The result stays raw so this helper never creates a
    // Rust reference to concurrently accessed C storage.
    unsafe { core::ptr::addr_of_mut!((*mutex).words).cast::<c_int>().add(index) }
}

/// Whether the C object has the one selected all-zero normal/private type.
///
/// The type word is initialized before publication and is immutable during a
/// valid mutex lifetime. It is therefore deliberately not an atomic state
/// word; callers changing it concurrently are outside POSIX and this slice.
#[inline(always)]
unsafe fn is_selected_normal_mutex(mutex: *mut PublicPthreadMutex) -> bool {
    // SAFETY: the caller supplies a complete mutex whose immutable type word
    // is initialized before the mutex becomes concurrently reachable.
    unsafe { core::ptr::read(mutex_word(mutex, MUTEX_TYPE_WORD)) == 0 }
}

/// Wait once through the private futex path.
///
/// This preserves musl's untimed normal-mutex result filtering: interruption
/// remains observable to the lock loop, while an expected-value race and any
/// other impossible-for-a-valid-mutex raw futex result merely retry the
/// acquisition protocol. The public pthread boundary never writes C `errno`.
#[inline(always)]
unsafe fn futex_wait_private(lock: *mut c_int, expected: c_int) -> c_int {
    // SAFETY: `lock` names the aligned, live lock word of this private mutex;
    // the zero fourth argument is a null timeout, so the kernel observes only
    // the initial three futex words plus that null pointer.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            lock as usize as i64,
            FUTEX_WAIT_PRIVATE,
            i64::from(expected),
            0,
        )
    };
    if result == -i64::from(EINTR) {
        EINTR
    } else {
        0
    }
}

/// Wake at most one private mutex contender.
///
/// Musl treats this as a best-effort post-release handoff. A failure cannot
/// revoke the already-published zero lock state, so this narrow leaf retains
/// that direct no-errno policy.
#[inline(always)]
unsafe fn futex_wake_private(lock: *mut c_int) {
    // SAFETY: `lock` is the live aligned lock word released by the caller;
    // Linux accepts the null timeout fourth word for FUTEX_WAKE.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            lock as usize as i64,
            FUTEX_WAKE_PRIVATE,
            1,
            0,
        )
    };
}

/// Try to acquire a selected normal mutex once.
///
/// The held value is exactly `EBUSY`, as in musl's normal-mutex fast path.
/// A marked waiter has the same low held bits, so it also reports `EBUSY`.
#[inline(always)]
unsafe fn try_lock_selected_normal_mutex(mutex: *mut PublicPthreadMutex) -> c_int {
    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    // SAFETY: every concurrent lock-word operation in this artifact uses the
    // same raw atomic-helper protocol on this aligned public i32 field.
    let observed = unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, 0, EBUSY) };
    if observed == 0 {
        0
    } else {
        EBUSY
    }
}

/// Initialize one selected all-zero normal/private mutex.
///
/// # Safety
///
/// `mutex` must point to writable, aligned storage for one x86
/// `pthread_mutex_t` that is not concurrently accessed. Only a null `attr`
/// is admitted by this bounded artifact; no attribute object is read.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut c_void,
    attr: *const c_void,
) -> c_int {
    if !attr.is_null() {
        return ENOTSUP;
    }
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the C caller supplies a complete, writable, non-concurrent
    // public mutex object; zero is the exact selected normal/private shape.
    unsafe { core::ptr::write_bytes(mutex, 0, 1) };
    0
}

/// Destroy one selected normal/private mutex.
///
/// A valid normal mutex owns no heap or kernel resource. Locked, invalid, or
/// concurrently accessed objects remain outside this C boundary's contract,
/// as they are for POSIX mutex destruction.
///
/// # Safety
///
/// `mutex` must designate a complete aligned selected normal mutex that is no
/// longer used by any thread.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller provides the complete, quiescent public mutex record.
    if !unsafe { is_selected_normal_mutex(mutex) } {
        return ENOTSUP;
    }
    0
}

/// Try once to acquire one selected normal/private mutex.
///
/// # Safety
///
/// `mutex` must designate a live, aligned selected mutex. Its complete
/// lifetime and protected-data synchronization remain with the C caller.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies a complete mutex whose type word is stable.
    if !unsafe { is_selected_normal_mutex(mutex) } {
        return ENOTSUP;
    }
    // SAFETY: the caller supplies the live mutex state machine this helper
    // owns for the selected normal/private representation.
    unsafe { try_lock_selected_normal_mutex(mutex) }
}

/// Acquire one selected normal/private mutex, waiting through private futexes.
///
/// # Safety
///
/// `mutex` must designate a live, aligned selected mutex. The caller owns the
/// object lifetime, protected-data discipline, and all signal/cancellation
/// policy; this direct static leaf is not a cancellation point.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies a complete mutex whose type word is stable.
    if !unsafe { is_selected_normal_mutex(mutex) } {
        return ENOTSUP;
    }

    // SAFETY: this first acquire uses the same aligned lock-word protocol as
    // every contended transition below.
    if unsafe { try_lock_selected_normal_mutex(mutex) } == 0 {
        return 0;
    }

    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    let waiters = unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) };
    // Retain musl's small uncontended-before-wait spin window. It is only a
    // bounded performance hint: the lock word and waiter count are read
    // atomically, and the exact retry/futex state machine below remains the
    // correctness boundary.
    let mut spins = 100;
    while spins > 0
        && unsafe { atomic::x86_64_load_acquire_i32(lock) } != 0
        && unsafe { atomic::x86_64_load_relaxed_i32(waiters) } == 0
    {
        core::hint::spin_loop();
        spins -= 1;
    }
    loop {
        // The retry is required after every handoff, spurious wake, signal,
        // or lost-race notification; it obtains the acquire edge when it
        // changes zero to the held `EBUSY` value.
        if unsafe { try_lock_selected_normal_mutex(mutex) } == 0 {
            return 0;
        }

        // SAFETY: waiters is an aligned advisory i32 that is accessed only by
        // this atomic-helper family while the selected mutex is live.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, 1) };
        // SAFETY: lock is the same aligned atomic i32 used by the fast path.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };

        // Never turn an unlocked mutex into a waiters-marked state. If an
        // unlock raced the setup above, remove the hint and retry acquisition;
        // sleeping on `0x80000000` would strand a waiter because no owner
        // remains to issue a wake.
        if observed == 0 {
            // SAFETY: balances the just-published waiter hint atomically.
            unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
            continue;
        }
        let marked = observed | MUTEX_WAITER_BIT;
        // SAFETY: this is the one atomic state transition that preserves a
        // currently-held lock while making an already-created waiter visible
        // to unlock. A racing unlock makes the compare-exchange fail.
        if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, observed, marked) }
            != observed
        {
            // SAFETY: the mark was not published by this contender, so remove
            // its advisory waiter count before retrying.
            unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
            continue;
        }

        // SAFETY: the marked value was atomically published above on this
        // live private lock word.
        let result = unsafe { futex_wait_private(lock, marked) };
        // SAFETY: balances this loop iteration's advisory waiter count after
        // the futex call has stopped observing the word.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
        // The selected untimed normal route retries both normal wake/race
        // results and EINTR, just as musl's outer mutex loop does. This is not
        // a cancellation point, and timeout/cancellation result handling is
        // deliberately outside this artifact.
        let _ = result;
        continue;
    }
}

/// Release one selected normal/private mutex and wake one contender if needed.
///
/// # Safety
///
/// `mutex` must designate a live, aligned selected mutex held according to
/// the caller's normal-mutex discipline. Unlocking a normal mutex from the
/// wrong thread is outside POSIX and this selected contract.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies a complete mutex whose type word is stable.
    if !unsafe { is_selected_normal_mutex(mutex) } {
        return ENOTSUP;
    }
    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    let waiters = unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) };
    // This is only a conservative wake hint. The lock-word exchange below is
    // the actual release edge and the negative bit is authoritative for a
    // contender that has reached `futex_wait`.
    let waiter_hint = unsafe { atomic::x86_64_load_relaxed_i32(waiters) };
    // SAFETY: an atomic exchange, rather than a plain zero store, preserves a
    // contended negative mark long enough to decide whether a waiter needs a
    // wake. It is the release edge for the caller's protected data.
    let previous = unsafe { atomic::x86_64_swap_acqrel_i32(lock, 0) };
    if previous < 0 || waiter_hint > 0 {
        // SAFETY: the public lock word remains live for the C caller's mutex
        // lifetime; this wake has no C errno result.
        unsafe { futex_wake_private(lock) };
    }
    0
}
