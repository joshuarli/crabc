//! Bounded Linux/x86-64 private `pthread_cond_*` artifact.
//!
//! This module extends the selected static x86 worker/TLS seam with one
//! process-private condition-variable handoff paired only with the sibling
//! all-zero `PTHREAD_MUTEX_NORMAL` state machine. Its provenance is pinned to
//! musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
//! under musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_cond_init.c::pthread_cond_init` supplies the
//!   all-zero private-object initialization shape.
//! - `src/thread/pthread_cond_destroy.c::pthread_cond_destroy` supplies the
//!   quiescent private-object no-resource result.
//! - `src/thread/pthread_cond_wait.c::pthread_cond_wait` and
//!   `src/thread/pthread_cond_timedwait.c::__pthread_cond_timedwait` supply
//!   the stack waiter, list enrollment, barrier, `LEAVING`/`notify` lifetime,
//!   mutex relock, and FIFO requeue protocol used by the untimed route.
//! - `src/thread/pthread_cond_signal.c::pthread_cond_signal`,
//!   `src/thread/pthread_cond_broadcast.c::pthread_cond_broadcast`, and
//!   `src/thread/pthread_cond_timedwait.c::__private_cond_signal` supply the
//!   oldest-first signal/broadcast list split and barrier release.
//! - `src/thread/__wait.c::__wait` and
//!   `src/thread/pthread_cond_timedwait.c::{lock,unlock,unlock_requeue}`
//!   supply the private `0/1/2` futex lock and requeue mechanics.
//!
//! The frozen archive admits NULL-attribute process-private conditions and
//! normal/private mutexes, using its mapped worker cancellation barrier. Its
//! historical boundary and machine-code evidence remain separate from the
//! owned product. Owned static/dynamic operations delegate to
//! `owned_pthread_cond.rs`: initialized clock/sharing attributes, ordinary and
//! timed waits, automatic private waiters or shared sequence/count storage,
//! MASKED cancellation, and mutex-owner validation/relock error precedence.
//! The C11 adapter shares these private Rust seams without interposable calls.
//! The owned mutex owner additionally admits recursive, error-checking, and
//! priority-inheritance records through the same typed relock seam. It follows
//! musl's one-unlock, one-relock condition transaction for recursive depth
//! rather than inventing a full depth-release protocol; PI handoff wakes the
//! waiter barrier rather than requeuing it onto the kernel-owned lock state.
//! The frozen artifact still admits only normal/private mutexes. This component
//! does not change the public profile or claim complete pthread parity or
//! public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 private pthread-condition leaf requires little-endian Linux/x86-64");

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::null_mut;

use super::{atomic, pthread_cancel, pthread_create_join, pthread_mutex, raw_syscall};

#[cfg(feature = "x86-owned-static-runtime")]
#[path = "owned_pthread_cond.rs"]
mod owned;

const ENOTSUP: c_int = 95;
#[cfg(feature = "x86-owned-static-runtime")]
const ECANCELED: c_int = 125;
#[cfg(feature = "x86-owned-static-runtime")]
const PTHREAD_CANCEL_DISABLE: u8 = 1;

const COND_WORD_COUNT: usize = 12;
const COND_LOCK_WORD: usize = 8;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_REQUEUE: i64 = 3;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_WAIT_PRIVATE: i64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: i64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_REQUEUE_PRIVATE: i64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;

const PRIVATE_UNLOCKED: c_int = 0;
const PRIVATE_LOCKED: c_int = 1;
const PRIVATE_CONTENDED: c_int = 2;

const WAITER_WAITING: c_int = 0;
const WAITER_SIGNALED: c_int = 1;
const WAITER_LEAVING: c_int = 2;
const MUTEX_WAITER_BIT: c_int = c_int::MIN;

/// Exact public x86 `pthread_cond_t` storage.
///
/// The installed C header exposes a 48-byte union with twelve `int` words and
/// eight-byte alignment. The private path names its pointer overlays by byte
/// offsets below because `_c_head` overlaps the shared-only sequence/waiter
/// words at byte eight.
#[repr(C, align(8))]
struct PublicPthreadCond {
    words: [c_int; COND_WORD_COUNT],
}

const _: () = {
    assert!(size_of::<PublicPthreadCond>() == 48);
    assert!(align_of::<PublicPthreadCond>() == 8);
    assert!(offset_of!(PublicPthreadCond, words) == 0);
};

/// Stack waiter representation from musl's private condition path.
///
/// A waiter becomes reachable by another C thread only after its initial
/// fields are complete and the condition-list lock publishes it. After that
/// point all concurrently shared integer fields use the raw atomic helpers;
/// pointer-list fields are changed only under the condition-list lock or are
/// immutable after a signaler detaches the group.
#[repr(C)]
struct Waiter {
    prev: *mut Waiter,
    next: *mut Waiter,
    state: c_int,
    barrier: c_int,
    notify: *mut c_int,
}

impl Waiter {
    const fn empty() -> Self {
        Self {
            prev: null_mut(),
            next: null_mut(),
            state: WAITER_WAITING,
            barrier: PRIVATE_CONTENDED,
            notify: null_mut(),
        }
    }
}

const _: () = {
    assert!(size_of::<Waiter>() == 32);
    assert!(align_of::<Waiter>() == 8);
    assert!(offset_of!(Waiter, prev) == 0);
    assert!(offset_of!(Waiter, next) == 8);
    assert!(offset_of!(Waiter, state) == 16);
    assert!(offset_of!(Waiter, barrier) == 20);
    assert!(offset_of!(Waiter, notify) == 24);
};

/// One selected pthread worker's durable condition waiter.
///
/// Musl normally puts a private-condition waiter on the caller stack. That is
/// sufficient when SIGCANCEL interrupts its cancellation-point syscall, but
/// this selected signal-free seam lets another worker change the target's
/// futex barrier directly. Keeping just this selected waiter in the already
/// live worker control mapping gives that request a stable lifetime through
/// the list-removal and join/detach handoff. Its withdrawal is serialized with
/// the cancellation lookup/lease handoff and drains earlier wakes before the
/// same storage can be initialized for another wait. A worker can be blocked
/// in at most one condition wait, and C11 workers deliberately keep the
/// normal stack waiter because they have no pthread cancellation state.
pub(super) struct SelectedPthreadConditionWaiter {
    waiter: UnsafeCell<Waiter>,
}

// All access to the enclosed raw waiter fields follows the surrounding
// condition-list/barrier atomic protocol. `UnsafeCell` avoids claiming a Rust
// shared-reference data-race guarantee for C-owned concurrent storage.
unsafe impl Sync for SelectedPthreadConditionWaiter {}

impl SelectedPthreadConditionWaiter {
    pub(super) const fn new() -> Self {
        Self {
            waiter: UnsafeCell::new(Waiter::empty()),
        }
    }

    #[inline(always)]
    pub(super) fn as_mut_ptr(&self) -> *mut Waiter {
        self.waiter.get()
    }
}

/// Return a raw byte pointer to the condition record without creating a Rust
/// reference to caller-owned storage that may be concurrently accessed.
///
/// # Safety
///
/// `condition` must designate a complete aligned public x86 `pthread_cond_t`.
#[inline(always)]
unsafe fn cond_bytes(condition: *mut PublicPthreadCond) -> *mut u8 {
    // SAFETY: the caller supplies the complete condition record. Keeping the
    // result raw preserves the C-side concurrent-access boundary.
    unsafe { core::ptr::addr_of_mut!((*condition).words).cast::<u8>() }
}

/// Return the immutable process-shared marker at public byte offset zero.
///
/// # Safety
///
/// `condition` must designate a complete aligned public record whose marker
/// was initialized before publication and remains immutable during use.
#[inline(always)]
unsafe fn cond_shared_marker(condition: *mut PublicPthreadCond) -> *mut c_void {
    // SAFETY: byte zero is the pointer-aligned `_c_shared` overlay in the
    // exact 48-byte public record; that marker is immutable after init.
    unsafe { core::ptr::read(cond_bytes(condition).cast::<*mut c_void>()) }
}

/// Whether a condition object admits the selected private representation.
#[inline(always)]
unsafe fn is_selected_private_cond(condition: *mut PublicPthreadCond) -> bool {
    // SAFETY: forwards the caller's complete condition record to the
    // immutable marker accessor.
    unsafe { cond_shared_marker(condition).is_null() }
}

/// Return the private waiter-list head pointer slot at public byte offset 8.
///
/// # Safety
///
/// `condition` must designate a complete aligned public record. Callers may
/// read or write this pointer only while holding the private condition lock.
#[inline(always)]
unsafe fn cond_head_slot(condition: *mut PublicPthreadCond) -> *mut *mut Waiter {
    // SAFETY: byte offset eight is naturally pointer aligned by the public
    // eight-byte record alignment and names musl's `_c_head` overlay.
    unsafe { cond_bytes(condition).add(8).cast::<*mut Waiter>() }
}

/// Return the private list lock at public byte offset 32.
///
/// # Safety
///
/// `condition` must designate a complete aligned public record.
#[inline(always)]
unsafe fn cond_lock_word(condition: *mut PublicPthreadCond) -> *mut c_int {
    // SAFETY: word eight is inside the twelve-word public record and is the
    // aligned `_c_lock` word used only through raw atomic helpers.
    unsafe { core::ptr::addr_of_mut!((*condition).words).cast::<c_int>().add(COND_LOCK_WORD) }
}

/// Return the private waiter-list tail pointer slot at public byte offset 40.
///
/// # Safety
///
/// `condition` must designate a complete aligned public record. Callers may
/// read or write this pointer only while holding the private condition lock.
#[inline(always)]
unsafe fn cond_tail_slot(condition: *mut PublicPthreadCond) -> *mut *mut Waiter {
    // SAFETY: byte offset forty is naturally pointer aligned and names musl's
    // `_c_tail` overlay in the public record.
    unsafe { cond_bytes(condition).add(40).cast::<*mut Waiter>() }
}

/// Return one raw waiter field without manufacturing a Rust reference.
///
/// # Safety
///
/// `waiter` must point to a live stack waiter for the duration of the access.
#[inline(always)]
unsafe fn waiter_state_word(waiter: *mut Waiter) -> *mut c_int {
    // SAFETY: `state` is an aligned field in the live `Waiter` record and is
    // accessed concurrently only through the matching atomic helper family.
    unsafe { core::ptr::addr_of_mut!((*waiter).state) }
}

/// Return one raw waiter barrier word without manufacturing a Rust reference.
///
/// # Safety
///
/// `waiter` must point to a live stack waiter for the duration of the access.
#[inline(always)]
unsafe fn waiter_barrier_word(waiter: *mut Waiter) -> *mut c_int {
    // SAFETY: `barrier` is an aligned field in the live `Waiter` record and
    // all post-publication access uses the raw atomic helper family.
    unsafe { core::ptr::addr_of_mut!((*waiter).barrier) }
}

/// Wait until one private futex word differs from `expected`.
///
/// This is the selected Linux-5.10 private half of musl's `__wait`: retain the
/// bounded spin, then retry `FUTEX_WAIT_PRIVATE` through every signal, wake,
/// and value-race until the barrier or lock word actually changes. Linux
/// futex errors are not C API results here, so this helper never writes errno.
///
/// # Safety
///
/// `word` must name live aligned atomic private storage for the whole wait.
#[inline(always)]
unsafe fn wait_private_while(word: *mut c_int, expected: c_int) {
    let mut spins = 100;
    while spins > 0 {
        // SAFETY: the caller supplies live aligned atomic storage.
        if unsafe { atomic::x86_64_load_acquire_i32(word) } != expected {
            return;
        }
        core::hint::spin_loop();
        spins -= 1;
    }

    // FUTEX_WAIT may wake spuriously, be interrupted, or lose a race before
    // sleeping. The value recheck is the complete selected untimed contract.
    while unsafe { atomic::x86_64_load_acquire_i32(word) } == expected {
        // SAFETY: `word` remains the live aligned futex word, with a null
        // timeout in the fourth x86 syscall register argument (`r10`).
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                word as usize as i64,
                FUTEX_WAIT_PRIVATE,
                i64::from(expected),
                0,
            )
        };
    }
}

/// Acquire musl's self-synchronized-destruction-safe private `0/1/2` lock.
///
/// # Safety
///
/// `word` must name live aligned private atomic storage. Every participant
/// must use this acquire/release protocol for its complete lifetime.
#[inline(always)]
unsafe fn private_lock(word: *mut c_int) {
    // SAFETY: the caller supplies the one aligned private lock word.
    if unsafe {
        atomic::x86_64_compare_exchange_acqrel_i32(
            word,
            PRIVATE_UNLOCKED,
            PRIVATE_LOCKED,
        )
    } != PRIVATE_UNLOCKED
    {
        // SAFETY: mark an observed fast holder contended before sleeping; a
        // racing unlock either preserves the mark for wakeup or leaves zero
        // for the following acquire loop.
        let _ = unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(
                word,
                PRIVATE_LOCKED,
                PRIVATE_CONTENDED,
            )
        };
        loop {
            // SAFETY: same live aligned private lock word.
            unsafe { wait_private_while(word, PRIVATE_CONTENDED) };
            // SAFETY: acquire ownership by installing the contended state;
            // zero observed on success ends the loop exactly as musl's
            // `while (a_cas(l, 0, 2))` form does.
            if unsafe {
                atomic::x86_64_compare_exchange_acqrel_i32(
                    word,
                    PRIVATE_UNLOCKED,
                    PRIVATE_CONTENDED,
                )
            } == PRIVATE_UNLOCKED
            {
                return;
            }
        }
    }
}

/// Release one private `0/1/2` lock and wake one waiter if it was contended.
///
/// # Safety
///
/// `word` must name a live aligned private lock currently held by the caller.
#[inline(always)]
unsafe fn private_unlock(word: *mut c_int) {
    // SAFETY: exchange is the release edge for the private list/barrier state.
    if unsafe { atomic::x86_64_swap_acqrel_i32(word, PRIVATE_UNLOCKED) }
        == PRIVATE_CONTENDED
    {
        // SAFETY: the private lock word remains live; this direct wake does
        // not surface a C errno result.
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                word as usize as i64,
                FUTEX_WAKE_PRIVATE,
                1,
                0,
            )
        };
    }
}

/// Release a detached waiter barrier, requeueing one successor onto the
/// selected normal-mutex futex when musl's normal/private path permits it.
///
/// # Safety
///
/// `barrier` and `mutex_lock` must name live aligned private atomic words.
/// The caller must hold the current waiter barrier and preserve both objects
/// until the kernel has observed the requeue request.
#[inline(always)]
unsafe fn private_unlock_requeue(barrier: *mut c_int, mutex_lock: *mut c_int) {
    // SAFETY: swapping to zero is a release edge and makes a value change
    // visible before the kernel transfers a possible futex waiter.
    let _ = unsafe { atomic::x86_64_swap_acqrel_i32(barrier, PRIVATE_UNLOCKED) };
    // The selected mutex is normal/private, so musl's `w` route is always
    // false and Linux 5.10's private requeue is the only admitted operation.
    // SAFETY: x86 syscall five puts `val2=1` in r10 and `mutex_lock` in r8:
    // futex(barrier, FUTEX_REQUEUE_PRIVATE, 0, 1, mutex_lock).
    let _ = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_FUTEX,
            barrier as usize as i64,
            FUTEX_REQUEUE_PRIVATE,
            0,
            1,
            mutex_lock as usize as i64,
        )
    };
}

/// Change and wake a selected worker's published condition barrier.
///
/// This is deliberately a value change before the wake: an ordinary futex
/// wake could be lost if cancellation lands immediately before the target
/// enters `FUTEX_WAIT_PRIVATE`. A racing signaler performs the same transition
/// through [`private_unlock`]; either winner leaves zero and the waiter
/// resolves the signal-versus-leave race with its `state` CAS.
///
/// # Safety
///
/// `barrier` must be a live selected worker-control waiter barrier published
/// by `pthread_cancel`'s sibling state. It is never a caller-stack address.
pub(super) unsafe fn wake_selected_pthread_condition_waiter(barrier: *mut c_int) {
    if unsafe {
        atomic::x86_64_compare_exchange_acqrel_i32(
            barrier,
            PRIVATE_CONTENDED,
            PRIVATE_UNLOCKED,
        )
    } == PRIVATE_CONTENDED
    {
        // SAFETY: the published barrier remains live through this wake and
        // is an aligned private futex word in the selected waiter record.
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                barrier as usize as i64,
                FUTEX_WAKE_PRIVATE,
                1,
                0,
            )
        };
    }
}

/// Remove an unsignaled stack waiter while holding the condition-list lock.
///
/// # Safety
///
/// `condition` and `waiter` must be live, and the caller must own
/// `condition`'s private list lock. `waiter` must still be linked or be the
/// sole list element.
#[inline(always)]
unsafe fn remove_waiter_locked(condition: *mut PublicPthreadCond, waiter: *mut Waiter) {
    // SAFETY: protected by the caller-held condition lock.
    let head = unsafe { core::ptr::read(cond_head_slot(condition)) };
    // SAFETY: pointer fields are protected by the same list lock.
    let tail = unsafe { core::ptr::read(cond_tail_slot(condition)) };
    // SAFETY: the linked waiter's fields are stable while the list lock is
    // held; this waiter remains live on its waiting thread's stack.
    let previous = unsafe { core::ptr::read(core::ptr::addr_of!((*waiter).prev)) };
    // SAFETY: same list-lock protected linked field.
    let next = unsafe { core::ptr::read(core::ptr::addr_of!((*waiter).next)) };

    if head == waiter {
        // SAFETY: list-head update is protected by the held condition lock.
        unsafe { core::ptr::write(cond_head_slot(condition), next) };
    } else if !previous.is_null() {
        // SAFETY: previous is a live adjacent linked waiter under the held
        // condition lock, so its next field is exclusively list-owned here.
        unsafe { core::ptr::write(core::ptr::addr_of_mut!((*previous).next), next) };
    }
    if tail == waiter {
        // SAFETY: list-tail update is protected by the held condition lock.
        unsafe { core::ptr::write(cond_tail_slot(condition), previous) };
    } else if !next.is_null() {
        // SAFETY: next is a live adjacent linked waiter under the held lock.
        unsafe { core::ptr::write(core::ptr::addr_of_mut!((*next).prev), previous) };
    }
}

/// Signal up to `count` private waiters, or all waiters when `count` is -1.
///
/// # Safety
///
/// `condition` must designate a live selected private condition record. Every
/// enqueued waiter must remain live until this protocol's `notify` reference
/// gate lets its waiting thread leave the stack frame.
#[inline(always)]
unsafe fn private_cond_signal(condition: *mut PublicPthreadCond, mut count: c_int) -> c_int {
    // The reference counter has automatic storage like musl's `volatile int
    // ref`. It is initialized before any pointer to it is published and all
    // post-publication access below uses raw atomic helpers, never a Rust
    // reference.
    let mut reference: c_int = 0;
    let reference_word = core::ptr::addr_of_mut!(reference);
    let lock = unsafe { cond_lock_word(condition) };
    // SAFETY: condition remains live for this selected C call and all list
    // changes below occur while this private lock is held.
    unsafe { private_lock(lock) };

    // SAFETY: the tail slot is list-lock protected.
    let mut waiter = unsafe { core::ptr::read(cond_tail_slot(condition)) };
    let mut first = null_mut::<Waiter>();
    while count != 0 && !waiter.is_null() {
        // Save the newer neighbor while it is protected by the list lock; the
        // current waiter may become independently runnable after unlock.
        let previous = unsafe { core::ptr::read(core::ptr::addr_of!((*waiter).prev)) };
        // SAFETY: waiter state is a live aligned atomic word until the
        // reference protocol below releases any concurrently leaving waiter.
        if unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(
                waiter_state_word(waiter),
                WAITER_WAITING,
                WAITER_SIGNALED,
            )
        } != WAITER_WAITING
        {
            // A waiter that has already entered LEAVING still owns stack
            // storage. Its later locked removal decrements this reference;
            // holding it here prevents a return before that handshake.
            unsafe { atomic::x86_64_fetch_add_acqrel_i32(reference_word, 1) };
            // SAFETY: the list lock orders this pointer publication before a
            // concurrently leaving waiter can examine it after removal.
            unsafe {
                core::ptr::write(
                    core::ptr::addr_of_mut!((*waiter).notify),
                    reference_word,
                )
            };
        } else {
            count -= 1;
            if first.is_null() {
                first = waiter;
            }
        }
        waiter = previous;
    }

    // Split the selected tail group from the remaining condition list. The
    // detached group is never list-mutated again; its barriers serialize FIFO
    // traversal through `prev` links.
    if !waiter.is_null() {
        let selected_head = unsafe { core::ptr::read(core::ptr::addr_of!((*waiter).next)) };
        if !selected_head.is_null() {
            // SAFETY: still under the condition lock; the selected head no
            // longer retains a pointer back into the remaining list.
            unsafe {
                core::ptr::write(
                    core::ptr::addr_of_mut!((*selected_head).prev),
                    null_mut(),
                )
            };
        }
        // SAFETY: sever the remaining list's link into the selected group.
        unsafe { core::ptr::write(core::ptr::addr_of_mut!((*waiter).next), null_mut()) };
    } else {
        // SAFETY: all waiters were detached, so the public head is empty.
        unsafe { core::ptr::write(cond_head_slot(condition), null_mut()) };
    }
    // SAFETY: `waiter` is the newest waiter left on the condition record, or
    // null after detaching all of them.
    unsafe { core::ptr::write(cond_tail_slot(condition), waiter) };
    // SAFETY: publish the completed list split before any waiter can leave.
    unsafe { private_unlock(lock) };

    // A signaler must keep its local reference word live until every waiter
    // observed in LEAVING has removed itself and decremented it.
    loop {
        // SAFETY: every post-publication reference access is atomic.
        let current = unsafe { atomic::x86_64_load_acquire_i32(reference_word) };
        if current == 0 {
            break;
        }
        // SAFETY: wait until a leaving waiter decrements the counter.
        unsafe { wait_private_while(reference_word, current) };
    }

    if !first.is_null() {
        // SAFETY: first remains live on its waiting thread's stack and is
        // protected by its initialized barrier until this release.
        unsafe { private_unlock(waiter_barrier_word(first)) };
    }
    0
}

/// Initialize one selected all-zero private condition record without crossing
/// a public C ABI.
///
/// # Safety
///
/// `condition` must designate writable, aligned storage for one complete
/// public x86 condition-shaped record that is not concurrently accessed. The
/// caller owns any C API-specific attribute/result contract around the exact
/// all-zero private representation.
#[inline(always)]
pub(super) unsafe fn init_selected_private_cond(condition: *mut c_void) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    // SAFETY: the caller supplies a complete writable non-concurrent record;
    // all-zero is musl's selected normal/private representation.
    unsafe { core::ptr::write_bytes(condition, 0, 1) };
    0
}

/// Destroy one selected private condition record without crossing a public C
/// ABI.
///
/// # Safety
///
/// `condition` must designate a complete aligned selected private condition
/// record that is quiescent and has no remaining waiter. Its immutable shared
/// marker must remain valid for the record's complete lifetime.
#[inline(always)]
pub(super) unsafe fn destroy_selected_private_cond(condition: *mut c_void) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    // SAFETY: the caller supplies the complete quiescent record and its
    // process-shared marker is immutable after initialization.
    if !unsafe { is_selected_private_cond(condition) } {
        return ENOTSUP;
    }
    0
}

/// Initialize one selected all-zero private condition object.
///
/// # Safety
///
/// `condition` must point to writable, aligned storage for one x86
/// `pthread_cond_t` that is not concurrently accessed. For owned products, a
/// non-null `attr` designates an initialized readable condition attribute.
/// The frozen archive admits only a null attribute.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_init(
    condition: *mut c_void,
    attr: *const c_void,
) -> c_int {
    #[cfg(feature = "x86-owned-static-runtime")]
    return unsafe { owned::init(condition, attr) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    {
        if !attr.is_null() { return ENOTSUP; }
        unsafe { init_selected_private_cond(condition) }
    }
}

/// Destroy one selected private condition object after quiescence.
///
/// Private conditions own no allocation or kernel resource. The owned shared
/// representation retains musl's waiter-drain transition before storage reuse;
/// the caller still owns the POSIX destruction/no-new-waiter discipline.
///
/// # Safety
///
/// `condition` must designate a complete aligned initialized condition whose
/// lifetime and quiescence satisfy POSIX destruction requirements.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_destroy(condition: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above exactly match the private selected
    // destruction seam.
    #[cfg(feature = "x86-owned-static-runtime")]
    return unsafe { owned::destroy(condition) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    unsafe { destroy_selected_private_cond(condition) }
}

/// Atomically enroll and wait on one selected private condition object.
///
/// The caller must hold the selected normal/private mutex on entry, protect
/// its predicate with that same mutex, test the predicate in a loop, and keep
/// both objects alive until this function returns. The wait always reacquires
/// the mutex before returning and never writes C errno.
///
/// # Safety
///
/// `condition` and `mutex` must designate live aligned selected public x86
/// objects. The caller owns object lifetimes, predicate discipline, signal and
/// cancellation policy, and quiescent destruction. This shared private body
/// does not itself make C11 waits or arbitrary callers cancellable; the public
/// pthread wrapper selects cancellation for owned main/worker pthread tasks
/// and the frozen archive's validated selected pthread worker. It does not
/// accept non-normal mutex state.
#[cfg(not(feature = "x86-owned-static-runtime"))]
#[inline(always)]
pub(super) unsafe fn wait_selected_private_cond(
    condition: *mut c_void,
    mutex: *mut c_void,
) -> c_int {
    // Musl tests for an already-pending request before it enrolls the
    // waiter. This private direct call keeps the same cancellation-point
    // placement without using an interposable public C symbol.
    pthread_cancel::test_current_selected_pthread_cancellation();

    let condition = condition.cast::<PublicPthreadCond>();
    // SAFETY: the caller provides the complete record and its shared marker
    // is immutable through the selected condition lifetime.
    if !unsafe { is_selected_private_cond(condition) } {
        return ENOTSUP;
    }
    // SAFETY: validate the selected normal mutex before publishing the stack
    // waiter so unsupported type words cannot leave a linked node behind.
    let Some(mutex_words) = (unsafe { pthread_mutex::selected_normal_mutex_words(mutex) }) else {
        return ENOTSUP;
    };

    // Only pointer-returning selected pthread workers obtain the durable
    // control-mapped waiter needed by the signal-free cancellation wake path.
    // C11 and foreign callers retain musl's automatic-storage waiter.
    let selected_waiter = pthread_create_join::current_selected_pthread_condition_waiter();
    let mut stack_waiter = Waiter::empty();
    let node = match selected_waiter {
        Some(waiter) => unsafe { (*waiter).as_mut_ptr() },
        None => core::ptr::addr_of_mut!(stack_waiter),
    };
    // SAFETY: `node` is either the current worker's control-mapped private
    // waiter or this invocation's automatic waiter. Neither is reachable by
    // another task until the fully initialized record is linked below.
    unsafe { core::ptr::write(node, Waiter::empty()) };
    let condition_lock = unsafe { cond_lock_word(condition) };
    // SAFETY: condition and the selected control-mapped or stack waiter remain
    // live for this C call; this
    // list lock serializes all head/tail/pointer mutation and publishes the
    // fully initialized node before the mutex release below.
    unsafe { private_lock(condition_lock) };
    let old_head = unsafe { core::ptr::read(cond_head_slot(condition)) };
    // SAFETY: these pointer writes occur under the held list lock.
    unsafe { core::ptr::write(core::ptr::addr_of_mut!((*node).next), old_head) };
    unsafe { core::ptr::write(cond_head_slot(condition), node) };
    // SAFETY: inspect the tail under the same held list lock.
    if unsafe { core::ptr::read(cond_tail_slot(condition)) }.is_null() {
        // SAFETY: this is the first waiter, so it is also the oldest tail.
        unsafe { core::ptr::write(cond_tail_slot(condition), node) };
    } else {
        // SAFETY: old_head is a live linked waiter whenever the tail was not
        // null; its previous link is list-owned under this lock.
        unsafe { core::ptr::write(core::ptr::addr_of_mut!((*old_head).prev), node) };
    }
    // SAFETY: publish the list enrollment before releasing the mutex.
    unsafe { private_unlock(condition_lock) };

    // SAFETY: the prior selected-type admission remains valid because the
    // mutex type word is immutable during a valid C mutex lifetime. This
    // private call deliberately avoids routing through an interposable C ABI.
    let unlock_result = unsafe { pthread_mutex::unlock_selected_normal_mutex(mutex) };
    if unlock_result != 0 {
        // The selected contract makes this unreachable after admission, but
        // preserve a non-stranded stack node if a violating caller mutates the
        // type word between the two private operations.
        // SAFETY: this waiter is still WAITING and is removed under the list
        // lock before its stack frame is allowed to return.
        unsafe { private_lock(condition_lock) };
        unsafe { remove_waiter_locked(condition, node) };
        unsafe { private_unlock(condition_lock) };
        return unlock_result;
    }

    // Mask an enabled selected pthread while its waiter/list state is exposed;
    // a disabled worker stays disabled. The published mapped barrier makes a
    // concurrent request either change this value or be observed by the
    // activation recheck, so a request cannot be lost between enrollment and
    // the futex wait below.
    let saved_cancellation = selected_waiter.and_then(|_| {
        pthread_cancel::begin_current_selected_pthread_condition_cancellation()
    });
    if saved_cancellation.is_some() {
        pthread_cancel::activate_current_selected_pthread_condition_waiter(
            unsafe { waiter_barrier_word(node) },
        );
    }

    // SAFETY: the stack waiter and its barrier remain live through this loop.
    unsafe { wait_private_while(waiter_barrier_word(node), PRIVATE_CONTENDED) };
    if saved_cancellation.is_some() {
        pthread_create_join::withdraw_current_selected_pthread_condition_waiter(
            unsafe { waiter_barrier_word(node) },
        );
    }
    // SAFETY: the CAS arbitrates a concurrent signaler against a locally
    // leaving waiter exactly as musl's private cancellation/timeout path does.
    let old_state = unsafe {
        atomic::x86_64_compare_exchange_acqrel_i32(
            waiter_state_word(node),
            WAITER_WAITING,
            WAITER_LEAVING,
        )
    };

    if old_state == WAITER_WAITING {
        // A selected deferred cancellation wake can reach this still-WAITING
        // branch before a signal consumes the barrier. Retain musl's list
        // removal protocol so that cancellation first withdraws the waiter,
        // then relocks the mutex before its cleanup chain runs.
        // SAFETY: serialize removal with a signaler that might have observed
        // this node entering LEAVING.
        unsafe { private_lock(condition_lock) };
        unsafe { remove_waiter_locked(condition, node) };
        unsafe { private_unlock(condition_lock) };
        // SAFETY: the signaler publishes notify under the same list lock.
        let notify = unsafe { core::ptr::read(core::ptr::addr_of!((*node).notify)) };
        if !notify.is_null()
            // SAFETY: notify points at a signaler's still-live atomic local
            // reference word until the final decrement/wake completes.
            && unsafe { atomic::x86_64_fetch_add_acqrel_i32(notify, -1) } == 1
        {
            // SAFETY: a final decrement wakes the signaler waiting on its
            // local reference word; this has no C errno result.
            let _ = unsafe {
                raw_syscall::syscall4(
                    raw_syscall::SYS_FUTEX,
                    notify as usize as i64,
                    FUTEX_WAKE_PRIVATE,
                    1,
                    0,
                )
            };
        }
    } else {
        // SAFETY: a signaled waiter owns its barrier before it permits the
        // next detached waiter to proceed, preserving FIFO release order.
        unsafe { private_lock(waiter_barrier_word(node)) };
    }

    // SAFETY: this selects the already-admitted same normal mutex and gives
    // the caller the mutex ownership required by pthread_cond_wait's return.
    let relock_result = unsafe { pthread_mutex::lock_selected_normal_mutex(mutex) };
    if relock_result != 0 {
        if let Some(saved) = saved_cancellation {
            pthread_cancel::restore_current_selected_pthread_condition_cancellation(saved);
        }
        return relock_result;
    }
    if old_state == WAITER_WAITING {
        if let Some(saved) = saved_cancellation {
            pthread_cancel::restore_current_selected_pthread_condition_cancellation(saved);
            // A request that won the unsignaled waiter race is delivered only
            // after this relock. Active cleanup therefore observes the mutex
            // held, exactly as musl's condition cancellation path requires.
            pthread_cancel::test_current_selected_pthread_cancellation();
        }
        return 0;
    }

    // Preserve musl's normal-mutex waiter hint and contended-bit setup before
    // requeueing a successor from its barrier futex onto the mutex futex.
    // SAFETY: `node.next` is immutable after the signaler detached its group.
    let next = unsafe { core::ptr::read(core::ptr::addr_of!((*node).next)) };
    if next.is_null() {
        // SAFETY: this is the final detached tail; retain the temporary hint
        // across the potential requeue from an older predecessor.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(mutex_words.waiters_word(), 1) };
    }
    // SAFETY: `prev` is the next FIFO successor in the detached group and is
    // immutable after the list split.
    let previous = unsafe { core::ptr::read(core::ptr::addr_of!((*node).prev)) };
    if !previous.is_null() {
        // A positive selected mutex lock is exactly EBUSY. Mark it before
        // requeue so its exchange-on-unlock performs the required wake.
        let mutex_lock = mutex_words.lock_word();
        let current = unsafe { atomic::x86_64_load_acquire_i32(mutex_lock) };
        if current > 0 {
            let _ = unsafe {
                atomic::x86_64_compare_exchange_acqrel_i32(
                    mutex_lock,
                    current,
                    current | MUTEX_WAITER_BIT,
                )
            };
        }
        // SAFETY: transfer at most one FIFO successor to the selected mutex
        // futex after publishing its barrier's zero release value.
        unsafe { private_unlock_requeue(waiter_barrier_word(previous), mutex_lock) };
    } else if next.is_null() {
        // This was the lone detached waiter, so balance its temporary mutex
        // waiter hint after no successor needs requeueing.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(mutex_words.waiters_word(), 1) };
    }
    if let Some(saved) = saved_cancellation {
        // A signaler that won the waiter-state race consumed a condition
        // signal. Musl suppresses cancellation for that completed handoff;
        // leave any request pending for a later selected point.
        pthread_cancel::restore_current_selected_pthread_condition_cancellation(saved);
    }
    0
}

/// Wait on an owned condition using its initialized clock/sharing fields.
/// # Safety
/// The caller holds a supported live mutex, protects its predicate with it,
/// and retains both objects through wait, relock, and cancellation cleanup.
#[cfg(feature = "x86-owned-static-runtime")]
#[inline(always)]
pub(super) unsafe fn wait_selected_private_cond(condition: *mut c_void, mutex: *mut c_void) -> c_int {
    unsafe { owned::wait(condition, mutex, core::ptr::null()) }
}

/// The C11 timed adapter shares the owned condition transaction directly.
/// # Safety
/// In addition to ordinary wait obligations, `deadline` is a readable aligned
/// x86 timespec that remains immutable during the call.
#[cfg(feature = "x86-owned-static-runtime")]
pub(super) unsafe fn timed_wait_selected_cond(
    condition: *mut c_void, mutex: *mut c_void, deadline: *const c_void,
) -> c_int {
    unsafe { owned::wait(condition, mutex, deadline) }
}

/// Atomically enroll and wait through the selected private condition path.
///
/// # Safety
///
/// `condition` and `mutex` must designate live aligned selected public x86
/// objects. The caller owns their lifetimes, predicate discipline, signal and
/// cancellation policy, and quiescent destruction. Owned main/worker pthread
/// tasks use the initialized private/shared condition and an admitted mutex;
/// cancellation repairs enrollment and reacquires that mutex before cleanup.
/// The frozen archive retains its normal/private worker-only route.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_wait(
    condition: *mut c_void,
    mutex: *mut c_void,
) -> c_int {
    // SAFETY: the C ABI obligations above exactly match the private selected
    // wait seam, including its raw C-shaped records.
    unsafe { wait_selected_private_cond(condition, mutex) }
}

/// Signal the oldest enrolled selected private condition waiter, if any,
/// without crossing a public C ABI.
///
/// # Safety
///
/// `condition` must designate a live aligned selected private condition
/// record. The caller owns predicate/mutex discipline, object lifetime, and
/// quiescent destruction for the complete wait/list/barrier protocol.
#[inline(always)]
pub(super) unsafe fn signal_selected_private_cond(condition: *mut c_void) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    // SAFETY: the caller supplies the complete record with immutable shared
    // marker for the selected condition lifetime.
    if !unsafe { is_selected_private_cond(condition) } {
        return ENOTSUP;
    }
    // SAFETY: the selected condition lifetime keeps the waiter list and stack
    // nodes valid through its private signal/release protocol.
    unsafe { private_cond_signal(condition, 1) }
}

/// Signal the oldest enrolled selected private condition waiter, if any.
///
/// # Safety
///
/// `condition` must designate a live aligned initialized x86
/// `pthread_cond_t`. The caller owns predicate/mutex discipline and object
/// lifetime. Owned products honor its sharing field; the frozen archive
/// retains its private-only admission.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_signal(condition: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above exactly match the private selected
    // signal seam.
    #[cfg(feature = "x86-owned-static-runtime")]
    return unsafe { owned::signal(condition, 1) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    unsafe { signal_selected_private_cond(condition) }
}

/// Signal every enrolled selected private condition waiter without crossing a
/// public C ABI.
///
/// # Safety
///
/// `condition` must designate a live aligned selected private condition
/// record. The caller owns predicate/mutex discipline, object lifetime, and
/// quiescent destruction for the complete wait/list/barrier protocol.
#[inline(always)]
pub(super) unsafe fn broadcast_selected_private_cond(condition: *mut c_void) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    // SAFETY: the caller supplies the complete record with immutable shared
    // marker for the selected condition lifetime.
    if !unsafe { is_selected_private_cond(condition) } {
        return ENOTSUP;
    }
    // SAFETY: -1 is musl's all-waiters sentinel for the private signal path.
    unsafe { private_cond_signal(condition, -1) }
}

/// Signal every enrolled selected private condition waiter.
///
/// # Safety
///
/// `condition` must designate a live aligned initialized x86
/// `pthread_cond_t`. The caller owns predicate/mutex discipline and object
/// lifetime. Owned products honor its sharing field; the frozen archive
/// retains its private-only admission.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_broadcast(condition: *mut c_void) -> c_int {
    // SAFETY: the C ABI obligations above exactly match the private selected
    // broadcast seam.
    #[cfg(feature = "x86-owned-static-runtime")]
    return unsafe { owned::signal(condition, -1) };
    #[cfg(not(feature = "x86-owned-static-runtime"))]
    unsafe { broadcast_selected_private_cond(condition) }
}
