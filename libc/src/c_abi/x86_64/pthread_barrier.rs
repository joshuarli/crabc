//! Linux/x86-64 static `pthread_barrier_*` artifact.
//!
//! This module completes the operational half of the installed x86 pthread
//! barrier surface. It is a source-specific semantic port of pinned musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_barrierattr_init.c::pthread_barrierattr_init` zeros
//!   the four-byte public attribute record.
//! - `src/thread/pthread_barrierattr_destroy.c::pthread_barrierattr_destroy`
//!   returns success without consuming that record.
//! - `src/thread/pthread_barrier_init.c::pthread_barrier_init` validates the
//!   count then writes musl's limit-plus-attribute encoding.
//! - `src/thread/pthread_barrier_destroy.c::pthread_barrier_destroy` retains
//!   musl's process-shared self-synchronized destruction rendezvous.
//! - `src/thread/pthread_barrier_wait.c::pthread_barrier_wait` retains musl's
//!   separate process-private stack-instance and process-shared count paths.
//! - `src/thread/vmlock.c` supplies the one private process-local vmlock
//!   shared with selected robust-mutex pending/list lifetime transitions.
//!
//! The companion `pthread_barrierattr_pshared` module continues to own the
//! existing set/get pair. Together these modules select the complete public
//! barrier API over the installed 32-byte x86 record: reusable private thread
//! barriers and shared-futex barriers in explicitly shared storage. The slice
//! has no allocation, C-errno publication, cancellation point, general TCB,
//! loader/CRT integration, or public-x86 support claim. Its process-shared
//! route is limited to Linux futexes and musl's local vmlock protocol; it does
//! not imply a general process lifecycle or shared-memory ownership runtime.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread barrier leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{atomic, pthread_vmlock, raw_syscall};

const EINVAL: c_int = 22;
const BARRIER_WORD_COUNT: usize = 8;
const BARRIER_LOCK_WORD: usize = 0;
const BARRIER_WAITERS_WORD: usize = 1;
const BARRIER_LIMIT_WORD: usize = 2;
const BARRIER_COUNT_WORD: usize = 3;
const BARRIER_WAITERS2_WORD: usize = 4;
const BARRIER_INSTANCE_POINTER_INDEX: usize = 3;
const MAX_STORED_BARRIER_LIMIT: c_uint = c_int::MAX as c_uint - 1;
const SHARED_BARRIER_BIT: c_int = c_int::MIN;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: i64 = 128;

/// Exact public x86 `pthread_barrierattr_t` storage.
#[repr(C)]
struct PublicPthreadBarrierAttr {
    attr: c_uint,
}

/// The public x86 barrier union has both eight `int` words and four pointers.
/// The pointer overlay's third pointer is musl's `_b_inst` slot at byte 24;
/// it is deliberately not the count/waiter words at byte 12/16.
#[repr(C)]
union PublicPthreadBarrierStorage {
    words: [c_int; BARRIER_WORD_COUNT],
    pointers: [*mut c_void; BARRIER_WORD_COUNT / 2],
}

/// Exact public x86 `pthread_barrier_t` storage.
#[repr(C, align(8))]
struct PublicPthreadBarrier {
    storage: PublicPthreadBarrierStorage,
}

/// Musl's private process-local barrier instance.
///
/// The instance owner keeps this record on its stack until every follower has
/// exited the round and woken it. All post-publication fields are raw atomic
/// words; no Rust reference is created from a caller-owned barrier object.
#[repr(C)]
struct PrivateBarrierInstance {
    count: c_int,
    last: c_int,
    waiters: c_int,
    finished: c_int,
}

const _: () = {
    assert!(size_of::<PublicPthreadBarrierAttr>() == 4);
    assert!(align_of::<PublicPthreadBarrierAttr>() == 4);
    assert!(offset_of!(PublicPthreadBarrierAttr, attr) == 0);
    assert!(size_of::<PublicPthreadBarrierStorage>() == 32);
    assert!(align_of::<PublicPthreadBarrierStorage>() == 8);
    assert!(size_of::<PublicPthreadBarrier>() == 32);
    assert!(align_of::<PublicPthreadBarrier>() == 8);
    assert!(offset_of!(PublicPthreadBarrier, storage) == 0);
    assert!(size_of::<PrivateBarrierInstance>() == 16);
    assert!(align_of::<PrivateBarrierInstance>() == 4);
    assert!(offset_of!(PrivateBarrierInstance, count) == 0);
    assert!(offset_of!(PrivateBarrierInstance, last) == 4);
    assert!(offset_of!(PrivateBarrierInstance, waiters) == 8);
    assert!(offset_of!(PrivateBarrierInstance, finished) == 12);
};

/// Return one public barrier word without manufacturing a Rust reference to
/// concurrent caller-owned storage.
///
/// # Safety
///
/// `barrier` must designate a complete, eight-byte-aligned public x86
/// `pthread_barrier_t`; `index` must be inside its eight-word storage.
#[inline(always)]
unsafe fn barrier_word(barrier: *mut PublicPthreadBarrier, index: usize) -> *mut c_int {
    debug_assert!(index < BARRIER_WORD_COUNT);
    // SAFETY: the caller supplies the complete public barrier and the checked
    // index stays within its public int-array overlay.
    unsafe {
        core::ptr::addr_of_mut!((*barrier).storage)
            .cast::<c_int>()
            .add(index)
    }
}

/// Return musl's `_b_inst` pointer slot at byte 24 of the public union.
///
/// # Safety
///
/// `barrier` must designate a complete, aligned public x86 barrier. The
/// caller must hold the barrier's private lock before reading or writing this
/// non-atomic pointer slot.
#[inline(always)]
unsafe fn barrier_instance_slot(
    barrier: *mut PublicPthreadBarrier,
) -> *mut *mut PrivateBarrierInstance {
    // SAFETY: pointer index three names byte 24 inside the public four-pointer
    // overlay and preserves its required eight-byte alignment.
    unsafe {
        core::ptr::addr_of_mut!((*barrier).storage)
            .cast::<*mut PrivateBarrierInstance>()
            .add(BARRIER_INSTANCE_POINTER_INDEX)
    }
}

/// Return a raw field word from a live private stack instance.
///
/// # Safety
///
/// `instance` must remain live until every participating barrier waiter has
/// completed the source-defined exit handoff.
#[inline(always)]
unsafe fn instance_count_word(instance: *mut PrivateBarrierInstance) -> *mut c_int {
    // SAFETY: `count` is the first aligned raw atomic word of the live record.
    unsafe { core::ptr::addr_of_mut!((*instance).count) }
}

/// See [`instance_count_word`].
#[inline(always)]
unsafe fn instance_last_word(instance: *mut PrivateBarrierInstance) -> *mut c_int {
    // SAFETY: `last` is an aligned raw atomic word in the live record.
    unsafe { core::ptr::addr_of_mut!((*instance).last) }
}

/// See [`instance_count_word`].
#[inline(always)]
unsafe fn instance_waiters_word(instance: *mut PrivateBarrierInstance) -> *mut c_int {
    // SAFETY: `waiters` is an aligned raw atomic word in the live record.
    unsafe { core::ptr::addr_of_mut!((*instance).waiters) }
}

/// See [`instance_count_word`].
#[inline(always)]
unsafe fn instance_finished_word(instance: *mut PrivateBarrierInstance) -> *mut c_int {
    // SAFETY: `finished` is an aligned raw atomic word in the live record.
    unsafe { core::ptr::addr_of_mut!((*instance).finished) }
}

/// Store a raw atomic word with a release edge.
///
/// x86 `xchg` is stronger than musl's release `a_store` but preserves the
/// source state transition and makes no C errno observable.
#[inline(always)]
unsafe fn store_word(word: *mut c_int, value: c_int) {
    // SAFETY: caller supplies live aligned raw atomic storage.
    let _ = unsafe { atomic::x86_64_swap_acqrel_i32(word, value) };
}

/// Atomically OR one raw word, retaining musl `a_or` semantics.
///
/// # Safety
///
/// `word` must be live aligned atomic storage for the full operation.
#[inline(always)]
unsafe fn fetch_or_word(word: *mut c_int, bits: c_int) -> c_int {
    loop {
        // SAFETY: the caller's raw-word contract permits this acquire load.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(word) };
        let replacement = observed | bits;
        // SAFETY: the same raw-word contract permits the atomic replacement.
        if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(word, observed, replacement) }
            == observed
        {
            return observed;
        }
    }
}

/// Convert the source's boolean `priv` argument to Linux's futex flag.
#[inline(always)]
const fn futex_private_mode(is_private: bool) -> i64 {
    if is_private {
        FUTEX_PRIVATE_FLAG
    } else {
        0
    }
}

/// Wait until a raw word differs from `expected`, preserving musl's bounded
/// spin, optional waiter accounting, and private/shared futex selection.
/// Linux 5.10 supports `FUTEX_PRIVATE_FLAG`, so this target deliberately has
/// no musl pre-5.10 `ENOSYS` fallback.
///
/// # Safety
///
/// `word` must name live aligned atomic storage; when non-null, `waiters` must
/// name a second live aligned atomic count for the same wait lifetime.
unsafe fn wait_while(
    word: *mut c_int,
    waiters: *mut c_int,
    expected: c_int,
    is_private: bool,
) {
    let mut spins = 100;
    while spins != 0
        && (waiters.is_null()
            // SAFETY: a non-null waiter word satisfies the caller contract.
            || unsafe { atomic::x86_64_load_relaxed_i32(waiters) } == 0)
    {
        // SAFETY: `word` remains live atomic storage through this wait.
        if unsafe { atomic::x86_64_load_acquire_i32(word) } != expected {
            return;
        }
        core::hint::spin_loop();
        spins -= 1;
    }

    if !waiters.is_null() {
        // SAFETY: the live waiter hint is atomically incremented before sleep.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, 1) };
    }
    while unsafe { atomic::x86_64_load_acquire_i32(word) } == expected {
        // SAFETY: the caller's live aligned word meets Linux's raw futex ABI;
        // the fourth argument is a null timeout through the shared x86 seam.
        let _ = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                word as usize as i64,
                FUTEX_WAIT | futex_private_mode(is_private),
                i64::from(expected),
                0,
            )
        };
    }
    if !waiters.is_null() {
        // SAFETY: balances the accounting increment above.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
    }
}

/// Wake one or all raw futex waiters after a published state transition.
///
/// # Safety
///
/// `word` must name live aligned atomic/futex storage until the kernel has
/// observed the wake request.
#[inline(always)]
unsafe fn wake(word: *mut c_int, count: c_int, is_private: bool) {
    let count = if count < 0 { c_int::MAX } else { count };
    // SAFETY: source-state publication precedes this best-effort raw futex
    // wake, and ignored Linux errors cannot revoke that publication.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            word as usize as i64,
            FUTEX_WAKE | futex_private_mode(is_private),
            i64::from(count),
            0,
        )
    };
}

/// Release the private barrier object lock and wake one private contender.
///
/// # Safety
///
/// `barrier` must be a live private barrier whose lock is held by this caller.
#[inline(always)]
unsafe fn unlock_private_barrier(barrier: *mut PublicPthreadBarrier) {
    // SAFETY: words zero/one belong to the live public barrier record.
    let lock = unsafe { barrier_word(barrier, BARRIER_LOCK_WORD) };
    // SAFETY: words zero/one belong to the live public barrier record.
    let waiters = unsafe { barrier_word(barrier, BARRIER_WAITERS_WORD) };
    // SAFETY: source unlock publishes zero before checking/waking waiters.
    unsafe { store_word(lock, 0) };
    // SAFETY: waiter hint is raw concurrent barrier storage.
    if unsafe { atomic::x86_64_load_relaxed_i32(waiters) } != 0 {
        // SAFETY: private barrier lock remains live through the wake.
        unsafe { wake(lock, 1, true) };
    }
}

/// Retain musl's `pshared_barrier_wait` state path.
///
/// # Safety
///
/// `barrier` must designate a live initialized process-shared public barrier
/// in storage visible to every participating process and thread.
unsafe fn shared_barrier_wait(barrier: *mut PublicPthreadBarrier) -> c_int {
    // SAFETY: every selected index lies in the live public barrier record.
    let lock = unsafe { barrier_word(barrier, BARRIER_LOCK_WORD) };
    // SAFETY: every selected index lies in the live public barrier record.
    let waiters = unsafe { barrier_word(barrier, BARRIER_WAITERS_WORD) };
    // SAFETY: every selected index lies in the live public barrier record.
    let limit_word = unsafe { barrier_word(barrier, BARRIER_LIMIT_WORD) };
    // SAFETY: every selected index lies in the live public barrier record.
    let count = unsafe { barrier_word(barrier, BARRIER_COUNT_WORD) };
    // SAFETY: every selected index lies in the live public barrier record.
    let waiters2 = unsafe { barrier_word(barrier, BARRIER_WAITERS2_WORD) };
    // SAFETY: the initialized immutable limit is read atomically because
    // process-shared destroy may concurrently inspect the same public word.
    let limit = (unsafe { atomic::x86_64_load_acquire_i32(limit_word) } & c_int::MAX)
        .wrapping_add(1);
    let mut result = 0;

    if limit == 1 {
        return -1;
    }

    loop {
        // SAFETY: raw lock word is the shared barrier admission lock.
        let observed = unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, 0, limit) };
        if observed == 0 {
            break;
        }
        // SAFETY: shared wait accounting stays inside the live barrier object.
        unsafe { wait_while(lock, waiters, observed, false) };
    }

    // SAFETY: this atomically admits one participant to the shared round.
    if unsafe { atomic::x86_64_fetch_add_acqrel_i32(count, 1) }.wrapping_add(1) == limit {
        // SAFETY: release the reached-round count before waking every waiter.
        unsafe { store_word(count, 0) };
        result = -1;
        // SAFETY: waiters2 is the live raw count waiter hint.
        if unsafe { atomic::x86_64_load_relaxed_i32(waiters2) } != 0 {
            // SAFETY: count remains live shared futex storage.
            unsafe { wake(count, -1, false) };
        }
    } else {
        // SAFETY: release next entrant, retaining the source lock count.
        unsafe { store_word(lock, 0) };
        // SAFETY: lock waiter accounting is live raw barrier storage.
        if unsafe { atomic::x86_64_load_relaxed_i32(waiters) } != 0 {
            // SAFETY: lock remains live shared futex storage.
            unsafe { wake(lock, 1, false) };
        }
        loop {
            // SAFETY: count is live raw barrier state.
            let observed = unsafe { atomic::x86_64_load_acquire_i32(count) };
            if observed <= 0 {
                break;
            }
            // SAFETY: shared count wait preserves musl's waiter accounting.
            unsafe { wait_while(count, waiters2, observed, false) };
        }
    }

    // SAFETY: source vmlock brackets the exit count so destroy can wait for
    // all shared participants after the object lock becomes quiescent.
    unsafe { pthread_vmlock::lock() };
    // SAFETY: each participant decrements the exit phase exactly once.
    if unsafe { atomic::x86_64_fetch_sub_acqrel_i32(count, 1) }
        == 1i32.wrapping_sub(limit)
    {
        // SAFETY: publish exit completion before waking every count waiter.
        unsafe { store_word(count, 0) };
        // SAFETY: waiters2 is live raw barrier storage.
        if unsafe { atomic::x86_64_load_relaxed_i32(waiters2) } != 0 {
            // SAFETY: count remains live shared futex storage.
            unsafe { wake(count, -1, false) };
        }
    } else {
        loop {
            // SAFETY: count remains live raw shared state.
            let observed = unsafe { atomic::x86_64_load_acquire_i32(count) };
            if observed == 0 {
                break;
            }
            // SAFETY: shared count wait preserves musl's second-phase route.
            unsafe { wait_while(count, waiters2, observed, false) };
        }
    }

    let (prior_lock, prior_waiters) = loop {
        // SAFETY: both public words remain live until source unlock completes.
        let observed_lock = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        // SAFETY: raw waiter hint is sampled with the source CAS retry.
        let observed_waiters = unsafe { atomic::x86_64_load_relaxed_i32(waiters) };
        let replacement = if observed_lock == SHARED_BARRIER_BIT.wrapping_add(1) {
            0
        } else {
            observed_lock.wrapping_sub(1)
        };
        // SAFETY: source's recursive shared unlock is one atomic CAS loop.
        if unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(lock, observed_lock, replacement)
        } == observed_lock
        {
            break (observed_lock, observed_waiters);
        }
    };
    if prior_lock == SHARED_BARRIER_BIT.wrapping_add(1)
        || (prior_lock == 1 && prior_waiters != 0)
    {
        // SAFETY: one shared lock waiter may now reuse or destroy the object.
        unsafe { wake(lock, 1, false) };
    }
    // SAFETY: completes this source-defined vmlock bracket.
    unsafe { pthread_vmlock::unlock() };

    result
}

/// Initialize one public barrier attribute to musl's private zero record.
///
/// # Safety
///
/// `attribute` must designate writable, aligned x86 `pthread_barrierattr_t`
/// storage that is not concurrently accessed.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_init(attribute: *mut c_void) -> c_int {
    // SAFETY: the C caller supplies one writable non-concurrent public record.
    unsafe {
        core::ptr::write(
            attribute.cast::<PublicPthreadBarrierAttr>(),
            PublicPthreadBarrierAttr { attr: 0 },
        )
    };
    0
}

/// Destroy one public barrier attribute.
///
/// Musl owns no resource here, so this deliberately does not inspect or alter
/// the caller record and never publishes through C errno.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_destroy(_attribute: *mut c_void) -> c_int {
    0
}

/// Initialize one public barrier with musl's count-plus-attribute encoding.
///
/// # Safety
///
/// `barrier` must designate writable, aligned x86 `pthread_barrier_t` storage
/// that is not concurrently accessed. A non-null `attribute` must designate a
/// readable initialized public barrier attribute that does not overlap the
/// restricted barrier object.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_init(
    barrier: *mut c_void,
    attribute: *const c_void,
    count: c_uint,
) -> c_int {
    if count.wrapping_sub(1) > MAX_STORED_BARRIER_LIMIT {
        return EINVAL;
    }

    let attribute_bits = if attribute.is_null() {
        0
    } else {
        // SAFETY: the C initializer contract supplies one readable attr record.
        unsafe { core::ptr::read(attribute.cast::<PublicPthreadBarrierAttr>()) }.attr
    };
    let barrier = barrier.cast::<PublicPthreadBarrier>();
    // SAFETY: the caller supplies a complete non-concurrent public barrier;
    // musl's initializer first writes the all-zero record.
    unsafe {
        core::ptr::write_bytes(
            barrier.cast::<u8>(),
            0,
            size_of::<PublicPthreadBarrier>(),
        )
    };
    // SAFETY: limit word two belongs to the freshly initialized public record.
    unsafe {
        core::ptr::write_unaligned(
            barrier_word(barrier, BARRIER_LIMIT_WORD),
            (count.wrapping_sub(1) | attribute_bits) as c_int,
        )
    };
    0
}

/// Destroy a barrier after its source-defined quiescence protocol.
///
/// # Safety
///
/// `barrier` must designate a live initialized public barrier. Private
/// barriers must already be quiescent. For process-shared barriers, callers
/// retain musl's self-synchronized destruction contract: no new wait may race
/// after destruction begins, while already-admitted waiters may drain.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_destroy(barrier: *mut c_void) -> c_int {
    let barrier = barrier.cast::<PublicPthreadBarrier>();
    // SAFETY: the C caller supplies a live initialized public record.
    let limit = unsafe {
        atomic::x86_64_load_acquire_i32(barrier_word(barrier, BARRIER_LIMIT_WORD))
    };
    if limit < 0 {
        // SAFETY: both words belong to the live process-shared barrier record.
        let lock = unsafe { barrier_word(barrier, BARRIER_LOCK_WORD) };
        // SAFETY: concurrent lock observation uses the matching raw atomic.
        if unsafe { atomic::x86_64_load_acquire_i32(lock) } != 0 {
            // SAFETY: destruction marks the source lock before waiting.
            unsafe { fetch_or_word(lock, SHARED_BARRIER_BIT) };
            loop {
                // SAFETY: lock remains live through source destruction wait.
                let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };
                if (observed & c_int::MAX) == 0 {
                    break;
                }
                // SAFETY: shared destroy waits on its live lock with no hint.
                unsafe { wait_while(lock, core::ptr::null_mut(), observed, false) };
            }
        }
        // SAFETY: waits for all source shared-exit vmlock holders in this process.
        unsafe { pthread_vmlock::wait() };
    }
    0
}

/// Wait at one initialized barrier round.
///
/// # Safety
///
/// `barrier` must designate a live initialized public barrier whose complete
/// lifetime, participant count, and concurrent destroy discipline satisfy the
/// pthread contract. All participating threads/processes must use this same
/// selected barrier protocol for the object's lifetime.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_wait(barrier: *mut c_void) -> c_int {
    let barrier = barrier.cast::<PublicPthreadBarrier>();
    // SAFETY: initialized limit word is live raw barrier storage.
    let limit = unsafe {
        atomic::x86_64_load_acquire_i32(barrier_word(barrier, BARRIER_LIMIT_WORD))
    };

    if limit == 0 {
        return -1;
    }
    if limit < 0 {
        // SAFETY: high-bit limit selects the source shared barrier algorithm.
        return unsafe { shared_barrier_wait(barrier) };
    }

    // SAFETY: private path uses these three live public barrier words.
    let lock = unsafe { barrier_word(barrier, BARRIER_LOCK_WORD) };
    // SAFETY: private path uses these three live public barrier words.
    let waiters = unsafe { barrier_word(barrier, BARRIER_WAITERS_WORD) };
    loop {
        // SAFETY: private admission lock is raw concurrent barrier storage.
        if unsafe { atomic::x86_64_swap_acqrel_i32(lock, 1) } == 0 {
            break;
        }
        // SAFETY: musl waits specifically for private lock state one.
        unsafe { wait_while(lock, waiters, 1, true) };
    }

    // SAFETY: the held private lock protects the non-atomic `_b_inst` slot.
    let instance = unsafe { core::ptr::read(barrier_instance_slot(barrier)) };
    if instance.is_null() {
        // A raw pointer escapes to the barrier while this owner blocks. Its
        // stack slot therefore stays live until the followers' exit handoff
        // wakes this function, exactly matching musl's stack instance.
        let mut local_instance = PrivateBarrierInstance {
            count: 0,
            last: 0,
            waiters: 0,
            finished: 0,
        };
        let instance = core::ptr::addr_of_mut!(local_instance);
        // SAFETY: held private lock exclusively owns the pointer slot.
        unsafe { core::ptr::write(barrier_instance_slot(barrier), instance) };
        // SAFETY: source publishes its stack instance before releasing lock.
        unsafe { unlock_private_barrier(barrier) };

        let finished = unsafe { instance_finished_word(instance) };
        let mut spins = 200;
        while spins != 0
            // SAFETY: the live stack instance's finished word is atomic.
            && unsafe { atomic::x86_64_load_acquire_i32(finished) } == 0
        {
            core::hint::spin_loop();
            spins -= 1;
        }
        // SAFETY: owner announces it is waiting for all follower exits.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(finished, 1) };
        while unsafe { atomic::x86_64_load_acquire_i32(finished) } == 1 {
            // SAFETY: live owner stack word is a private raw futex word.
            let _ = unsafe {
                raw_syscall::syscall4(
                    raw_syscall::SYS_FUTEX,
                    finished as usize as i64,
                    FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                    1,
                    0,
                )
            };
        }
        return -1;
    }

    // SAFETY: the held barrier lock protects selecting this published stack
    // instance; all its post-publication fields use raw atomics below.
    let count = unsafe { instance_count_word(instance) };
    // SAFETY: the held barrier lock protects selecting this instance.
    let last = unsafe { instance_last_word(instance) };
    // SAFETY: the held barrier lock protects selecting this instance.
    let instance_waiters = unsafe { instance_waiters_word(instance) };
    // SAFETY: the held barrier lock protects selecting this instance.
    let finished = unsafe { instance_finished_word(instance) };
    // SAFETY: follower admission increments musl's stack instance count.
    if unsafe { atomic::x86_64_fetch_add_acqrel_i32(count, 1) }.wrapping_add(1) == limit {
        // SAFETY: last entrant clears the protected public instance pointer.
        unsafe { core::ptr::write(barrier_instance_slot(barrier), core::ptr::null_mut()) };
        // SAFETY: release new-round admission before waking this round.
        unsafe { unlock_private_barrier(barrier) };
        // SAFETY: publish last entrant state before waking followers.
        unsafe { store_word(last, 1) };
        // SAFETY: instance waiters hint remains live until owner release.
        if unsafe { atomic::x86_64_load_relaxed_i32(instance_waiters) } != 0 {
            // SAFETY: stack instance last word remains live through the wake.
            unsafe { wake(last, -1, true) };
        }
    } else {
        // SAFETY: other entrants may now inspect the protected pointer slot.
        unsafe { unlock_private_barrier(barrier) };
        // SAFETY: live stack instance remains owned by its waiting source owner.
        unsafe { wait_while(last, instance_waiters, 0, true) };
    }

    // SAFETY: each follower exits this source round exactly once.
    if unsafe { atomic::x86_64_fetch_sub_acqrel_i32(count, 1) } == 1
        // SAFETY: source increments finished only for the last follower.
        && unsafe { atomic::x86_64_fetch_add_acqrel_i32(finished, 1) } != 0
    {
        // SAFETY: source wakes the stack instance owner after it announced wait.
        unsafe { wake(finished, 1, true) };
    }

    0
}
