//! Bounded Linux/x86-64 static C11 plain-synchronization leaf.
//!
//! This module presents a narrow C11 API over the already selected private
//! normal-mutex and private condition-variable engines. Its provenance is
//! pinned to musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license
//! recorded in `COPYRIGHT`:
//!
//! - `src/thread/mtx_init.c`, `mtx_destroy.c`, `mtx_lock.c`, `mtx_trylock.c`,
//!   and `mtx_unlock.c` supply the C11 mutex result boundary and its direct
//!   normal-mutex fast path.
//! - `src/thread/cnd_init.c`, `cnd_destroy.c`, `cnd_wait.c`, `cnd_signal.c`,
//!   and `cnd_broadcast.c` supply the C11 condition-object/result boundary.
//! - `src/thread/mtx_timedlock.c` and `cnd_timedwait.c` explain musl's shared
//!   error translations, while their timed operation itself remains outside
//!   this selected x86 artifact.
//!
//! The installed C header deliberately gives `mtx_t` and `cnd_t` their own C
//! record types even though their x86 LP64 storage is layout-compatible with
//! `pthread_mutex_t` and `pthread_cond_t`. This leaf ratchets those distinct
//! 40-byte/48-byte records and crosses only private Rust sibling seams; it
//! never calls an interposable pthread C symbol.
//!
//! The admitted contract is `mtx_init(..., mtx_plain)`, `mtx_destroy`,
//! `mtx_lock`, `mtx_trylock`, `mtx_unlock`, and `cnd_init`, `cnd_destroy`,
//! `cnd_wait`, `cnd_signal`, and `cnd_broadcast` on selected private objects.
//! All valid selected operations preserve C `errno`: C11 status is returned
//! directly. A held plain mutex maps to `thrd_busy`; zero private-engine
//! results map to `thrd_success`; selected boundary failures map to
//! `thrd_error`, except `mtx_unlock`, which retains musl's direct raw
//! pthread-style return because every error route is C11 undefined behavior.
//!
//! Musl accepts recursive and timed initialization kinds, but doing so here
//! would select unimplemented mutex type state machines. This artifact admits
//! only `mtx_plain` and fails every other kind closed with `thrd_error` before
//! it interprets or initializes the record; that candidate-only policy is not
//! a musl-differential claim. Timed mutex/condition calls, static C11 object
//! initialization, recursive mutexes, cancellation, TSS, once, process-shared
//! synchronization, dynamic/loader TLS, CRT/sysroot integration, general C11
//! or pthread parity, promotion, and public x86 support remain excluded.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 C11 plain-synchronization leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{pthread_cond, pthread_mutex};

const EBUSY: c_int = 16;
const MTX_PLAIN: c_int = 0;
const THRD_SUCCESS: c_int = 0;
const THRD_BUSY: c_int = 1;
const THRD_ERROR: c_int = 2;

/// Exact public x86 C11 `mtx_t` storage.
///
/// It is intentionally a distinct Rust record from the sibling
/// `PublicPthreadMutex`, mirroring the installed header's distinct C type.
/// Private helpers consume its raw storage only after this module has made
/// the layout boundary explicit.
#[repr(C, align(8))]
struct PublicC11Mutex {
    words: [c_int; 10],
}

const _: () = {
    assert!(size_of::<PublicC11Mutex>() == 40);
    assert!(align_of::<PublicC11Mutex>() == 8);
    assert!(offset_of!(PublicC11Mutex, words) == 0);
};

/// Exact public x86 C11 `cnd_t` storage.
///
/// It remains intentionally distinct from the sibling pthread condition
/// record even though the selected private engine validates the same storage
/// offsets through a raw C-shaped pointer.
#[repr(C, align(8))]
struct PublicC11Condition {
    words: [c_int; 12],
}

const _: () = {
    assert!(size_of::<PublicC11Condition>() == 48);
    assert!(align_of::<PublicC11Condition>() == 8);
    assert!(offset_of!(PublicC11Condition, words) == 0);
};

/// Map the selected sibling's zero-or-error contract to C11 status.
///
/// This deliberately does not introduce C `errno` publication: all selected
/// failures remain a C11 result only, matching the C11 source wrappers.
#[inline(always)]
const fn c11_status(result: c_int) -> c_int {
    if result == 0 {
        THRD_SUCCESS
    } else {
        THRD_ERROR
    }
}

/// Initialize one selected plain C11 mutex.
///
/// # Safety
///
/// `mutex` must designate writable, aligned `mtx_t` storage that is not
/// concurrently accessed. Only `mtx_plain` is admitted; the caller must not
/// use the object after a non-success result and must later destroy it only
/// after every selected operation has quiesced.
#[no_mangle]
pub unsafe extern "C" fn mtx_init(mutex: *mut c_void, kind: c_int) -> c_int {
    if kind != MTX_PLAIN {
        return THRD_ERROR;
    }
    // SAFETY: the C ABI obligations above establish a complete writable
    // mutex-shaped object with the exact selected all-zero representation.
    c11_status(unsafe { pthread_mutex::init_selected_normal_mutex(mutex) })
}

/// Destroy one selected plain C11 mutex after quiescence.
///
/// # Safety
///
/// `mutex` must designate a selected `mtx_t` initialized by [`mtx_init`],
/// held by no thread, and no longer reachable by concurrent operations. C11
/// destruction is void; an invalid/non-selected record is outside this
/// selected C object-lifetime contract.
#[no_mangle]
pub unsafe extern "C" fn mtx_destroy(mutex: *mut c_void) {
    // SAFETY: the C ABI obligations above establish the selected private
    // record's quiescent destruction boundary. C11 has no error result here.
    let _ = unsafe { pthread_mutex::destroy_selected_normal_mutex(mutex) };
}

/// Lock one selected plain C11 mutex through the private futex engine.
///
/// # Safety
///
/// `mutex` must designate a live aligned selected `mtx_t`. The caller owns
/// the object lifetime, protected-data discipline, and cancellation policy;
/// this static route is not a cancellation point.
#[no_mangle]
pub unsafe extern "C" fn mtx_lock(mutex: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above establish the selected normal mutex
    // state machine for this private sibling call.
    c11_status(unsafe { pthread_mutex::lock_selected_normal_mutex(mutex) })
}

/// Try to lock one selected plain C11 mutex once.
///
/// # Safety
///
/// `mutex` must designate a live aligned selected `mtx_t`. Its type/storage
/// must remain valid while all concurrent accesses use the selected private
/// normal-mutex protocol.
#[no_mangle]
pub unsafe extern "C" fn mtx_trylock(mutex: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above establish a valid selected mutex
    // record for the private one-attempt acquisition seam.
    match unsafe { pthread_mutex::try_lock_selected_normal_mutex(mutex) } {
        0 => THRD_SUCCESS,
        EBUSY => THRD_BUSY,
        _ => THRD_ERROR,
    }
}

/// Unlock one selected plain C11 mutex.
///
/// # Safety
///
/// `mutex` must designate a live aligned selected `mtx_t` held by the current
/// thread. Unlocking a mutex not held by this thread is undefined by C11 and
/// outside this selected boundary.
#[no_mangle]
pub unsafe extern "C" fn mtx_unlock(mutex: *mut c_void) -> c_int {
    // Musl intentionally tail-calls its internal pthread unlock here: errors
    // arise only from C11 undefined behavior. Preserve that direct result
    // instead of broadly translating it through `c11_status`.
    // SAFETY: the C ABI obligations above establish the selected ownership
    // state required by the private normal-mutex release seam.
    unsafe { pthread_mutex::unlock_selected_normal_mutex(mutex) }
}

/// Initialize one selected private C11 condition object.
///
/// # Safety
///
/// `condition` must designate writable, aligned `cnd_t` storage that is not
/// concurrently accessed. The caller must later destroy it only after every
/// enrolled waiter and signaler has returned.
#[no_mangle]
pub unsafe extern "C" fn cnd_init(condition: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above establish a complete writable
    // condition-shaped object with the selected private all-zero layout.
    c11_status(unsafe { pthread_cond::init_selected_private_cond(condition) })
}

/// Destroy one selected private C11 condition object after quiescence.
///
/// # Safety
///
/// `condition` must designate a selected `cnd_t` initialized by [`cnd_init`]
/// with no remaining waiter, signaler, or concurrent user. C11 destruction is
/// void; a non-selected record is outside this selected lifetime contract.
#[no_mangle]
pub unsafe extern "C" fn cnd_destroy(condition: *mut c_void) {
    // SAFETY: the C ABI obligations above establish the selected private
    // condition record's quiescent destruction boundary.
    let _ = unsafe { pthread_cond::destroy_selected_private_cond(condition) };
}

/// Atomically wait on one selected private C11 condition object.
///
/// # Safety
///
/// `condition` and `mutex` must designate live aligned selected `cnd_t` and
/// `mtx_t` records. The caller must hold the mutex on entry, guard and loop on
/// its predicate, retain both records until return, and destroy them only
/// after quiescence. This route is untimed and not a cancellation point.
#[no_mangle]
pub unsafe extern "C" fn cnd_wait(condition: *mut c_void, mutex: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above establish the selected private
    // condition/mutex waiter-list and handoff protocol.
    c11_status(unsafe { pthread_cond::wait_selected_private_cond(condition, mutex) })
}

/// Signal one selected private C11 condition waiter, if any.
///
/// # Safety
///
/// `condition` must designate a live aligned selected `cnd_t`; the caller
/// owns the predicate/mutex discipline and every waiter/list object's
/// lifetime through the complete handoff protocol.
#[no_mangle]
pub unsafe extern "C" fn cnd_signal(condition: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above establish the selected private
    // condition record for its signal/list/barrier protocol.
    c11_status(unsafe { pthread_cond::signal_selected_private_cond(condition) })
}

/// Signal every selected private C11 condition waiter.
///
/// # Safety
///
/// `condition` must designate a live aligned selected `cnd_t`; the caller
/// owns the predicate/mutex discipline and every waiter/list object's
/// lifetime through the complete broadcast handoff protocol.
#[no_mangle]
pub unsafe extern "C" fn cnd_broadcast(condition: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above establish the selected private
    // condition record for its broadcast/list/barrier protocol.
    c11_status(unsafe { pthread_cond::broadcast_selected_private_cond(condition) })
}
