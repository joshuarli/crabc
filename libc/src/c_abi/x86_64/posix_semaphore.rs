//! Selected static Linux/x86-64 unnamed POSIX semaphore boundary.
//!
//! This leaf owns the fixed `sem_init`, `sem_destroy`, `sem_getvalue`,
//! `sem_trywait`, `sem_wait`, and `sem_post` subset, with owned-runtime
//! `sem_timedwait`, over musl's public
//! 32-byte `sem_t` representation.  It keeps the value, waiter hint, and
//! private/shared futex flag in the first three `int` words, uses atomics for
//! every concurrently observed word, and issues only Linux `futex=202` for
//! the contended wait/wake handoff.  A nonzero `pshared` requests the shared
//! futex form, so the selected record works in caller-owned shared storage;
//! it does not introduce a process registry or named semaphore filesystem.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/thread/sem_init.c`, `sem_destroy.c`, `sem_getvalue.c`,
//! `sem_trywait.c`, `sem_post.c`, `sem_timedwait.c`, and `sem_wait.c` map to
//! the corresponding state words, CAS loops, spin-before-wait shape, and
//! futex handoff below. `src/thread/__timedwait.c` maps to the owned
//! realtime-deadline conversion, error filtering, and syscall cancellation
//! point. The owned runtime registers explicit waiter cleanup before that
//! point and checks cancellation before consuming an available token. Its
//! timed-wait EINTR decision uses `signal_control`'s source-defined sticky
//! non-restarting-handler flag. The standalone six-function archive retains
//! its previously qualified un-cancelled, signal-uninterrupted route and no
//! timed entry. The owned runtime adds named semaphore lifetime and shared-memory
//! namespace operations in `owned_named_ipc`; this standalone leaf does not.
//! Semaphore destruction races and general POSIX IPC remain unselected.
//!
//! This is not a Rust synchronization API, a pthread runtime, an allocator,
//! a loader, a CRT, libc.so, or public x86 support.  The public C entries use
//! the selected initial-TLS errno slot only for their named POSIX error
//! results; successful calls deliberately preserve stale errno.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 unnamed POSIX semaphore leaf requires little-endian Linux/x86-64");

use core::{
    ffi::{c_int, c_uint, c_void},
    mem::{align_of, size_of},
};

use super::{atomic, errno, raw_syscall};

const EAGAIN: c_int = 11;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 75;

const SEM_VALUE_MAX: c_int = 0x7fff_ffff;
const SEM_WAITER_BIT: c_int = c_int::MIN;
const SEM_VALUE_WORD: usize = 0;
const SEM_WAITER_COUNT_WORD: usize = 1;
const SEM_PRIVATE_WORD: usize = 2;
const SEM_WORD_COUNT: usize = 8;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: i64 = 128;

/// Exact installed x86 `sem_t` storage.
///
/// This private representation is only the C record consumed by the selected
/// wrappers; it is not a Rust semaphore type or a durable Rust API.
#[repr(C)]
struct PublicSemaphore {
    words: [c_int; SEM_WORD_COUNT],
}

const _: () = {
    assert!(size_of::<PublicSemaphore>() == 32);
    assert!(align_of::<PublicSemaphore>() == 4);
};

/// Obtain one raw word without creating a Rust reference to C storage that
/// can be changed by a concurrent C process or thread.
///
/// # Safety
///
/// `semaphore` must point to a complete aligned public x86 `sem_t`; `index`
/// must name one of its eight `int` words.
#[inline(always)]
unsafe fn semaphore_word(semaphore: *mut PublicSemaphore, index: usize) -> *mut c_int {
    // SAFETY: every caller supplies a complete public record and one fixed
    // in-range word index.  The raw pointer retains the C concurrent-access
    // boundary instead of manufacturing a Rust reference.
    unsafe { core::ptr::addr_of_mut!((*semaphore).words).cast::<c_int>().add(index) }
}

/// Map musl's nonzero sharing field to the only two Linux futex forms this
/// selected record admits.
#[inline(always)]
fn futex_privilege(private_word: c_int) -> i64 {
    if private_word == 0 {
        0
    } else {
        FUTEX_PRIVATE_FLAG
    }
}

/// Try to take one unit without publishing a C `errno` result.
///
/// # Safety
///
/// `semaphore` must be a live, initialized, aligned selected `sem_t`; all
/// concurrent users must use this same atomic value-word protocol.
#[inline(always)]
unsafe fn trywait_raw(semaphore: *mut PublicSemaphore) -> bool {
    let value = unsafe { semaphore_word(semaphore, SEM_VALUE_WORD) };
    loop {
        // SAFETY: `value` names the selected aligned atomic semaphore word.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(value) };
        if observed & SEM_VALUE_MAX == 0 {
            return false;
        }
        // SAFETY: every admitted semaphore operation uses this same atomic
        // CAS protocol on its value word.
        if unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(
                value,
                observed,
                observed.wrapping_sub(1),
            )
        } == observed
        {
            return true;
        }
    }
}

/// Sleep once until a post, race, or interruption changes the selected value
/// word.  Linux 5.10 supplies this direct futex operation, so this target
/// intentionally has no pre-baseline ENOSYS fallback.
///
/// # Safety
///
/// `value` must remain a live aligned semaphore value word through the raw
/// futex call, and `private_word` must come from an initialized selected
/// semaphore record.
#[cfg(not(feature = "x86-owned-static-runtime"))]
#[inline(always)]
unsafe fn futex_wait(value: *mut c_int, private_word: c_int) -> i64 {
    // SAFETY: the public semaphore's value word is caller-owned aligned
    // storage.  The null fourth word selects an unbounded wait.
    unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            value as usize as i64,
            FUTEX_WAIT | futex_privilege(private_word),
            i64::from(SEM_WAITER_BIT),
            0,
        )
    }
}

/// Wake the bounded waiter population after a successful post.
///
/// # Safety
///
/// `value` must remain a live aligned semaphore value word through the raw
/// futex call, and `private_word` must come from an initialized selected
/// semaphore record.
#[inline(always)]
unsafe fn futex_wake(value: *mut c_int, count: c_int, private_word: c_int) {
    let count = if count < 0 { c_int::MAX } else { count };
    // SAFETY: this is the paired futex wake for the selected live value word;
    // Linux ignores the null fourth word for FUTEX_WAKE.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            value as usize as i64,
            FUTEX_WAKE | futex_privilege(private_word),
            i64::from(count),
            0,
        )
    };
}

/// Initialize one unnamed POSIX semaphore in caller-owned storage.
///
/// # Safety
///
/// `semaphore` must point to writable, aligned storage for a complete x86
/// `sem_t` that is not concurrently accessed until initialization completes.
#[no_mangle]
pub unsafe extern "C" fn sem_init(
    semaphore: *mut c_void,
    pshared: c_int,
    value: c_uint,
) -> c_int {
    if value > SEM_VALUE_MAX as c_uint {
        // SAFETY: this C ABI owns publication of its defined EINVAL result.
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }

    let semaphore = semaphore.cast::<PublicSemaphore>();
    // SAFETY: the caller supplies complete, writable, non-concurrent public
    // semaphore storage.  Musl initializes exactly these first three words.
    unsafe {
        semaphore_word(semaphore, SEM_VALUE_WORD).write(value as c_int);
        semaphore_word(semaphore, SEM_WAITER_COUNT_WORD).write(0);
        semaphore_word(semaphore, SEM_PRIVATE_WORD).write(if pshared == 0 {
            FUTEX_PRIVATE_FLAG as c_int
        } else {
            0
        });
    }
    0
}

/// Destroy one quiescent selected semaphore record.
///
/// # Safety
///
/// POSIX requires the caller to ensure that no thread or process is using the
/// object.  The selected representation owns no allocation or kernel resource,
/// so this musl-compatible boundary does not read or mutate its pointer.
#[no_mangle]
pub unsafe extern "C" fn sem_destroy(_semaphore: *mut c_void) -> c_int {
    0
}

/// Attempt to take one semaphore unit without blocking.
///
/// # Safety
///
/// `semaphore` must point to a live, initialized, aligned selected `sem_t`.
/// Every concurrent participant must use compatible atomic semaphore
/// operations for the complete object lifetime.
#[no_mangle]
pub unsafe extern "C" fn sem_trywait(semaphore: *mut c_void) -> c_int {
    let semaphore = semaphore.cast::<PublicSemaphore>();
    // SAFETY: the public C caller owns the initialized record and its
    // concurrent-lifetime contract.
    if unsafe { trywait_raw(semaphore) } {
        0
    } else {
        // SAFETY: this is the defined POSIX empty-semaphore error result.
        unsafe { errno::set_errno(EAGAIN) };
        -1
    }
}

/// Wait for and take one semaphore unit on the selected no-cancellation,
/// signal-uninterrupted route.
///
/// # Safety
///
/// `semaphore` must point to a live, initialized, aligned selected `sem_t`.
/// Every concurrent thread or process must retain the same atomic and futex
/// lifetime discipline until this call returns.
#[cfg(not(feature = "x86-owned-static-runtime"))]
#[no_mangle]
pub unsafe extern "C" fn sem_wait(semaphore: *mut c_void) -> c_int {
    let semaphore = semaphore.cast::<PublicSemaphore>();
    // Keep musl's public trywait call shape: an initially empty semaphore
    // leaves EAGAIN stale if a later post makes this wait succeed.
    if unsafe { sem_trywait(semaphore.cast::<c_void>()) } == 0 {
        return 0;
    }

    let value = unsafe { semaphore_word(semaphore, SEM_VALUE_WORD) };
    let waiter_count = unsafe { semaphore_word(semaphore, SEM_WAITER_COUNT_WORD) };
    let mut spins = 100;
    while spins > 0
        // SAFETY: both words are selected aligned atomics for this live
        // public record; the loop is only a bounded contention hint.
        && unsafe { atomic::x86_64_load_acquire_i32(value) } & SEM_VALUE_MAX == 0
        && unsafe { atomic::x86_64_load_relaxed_i32(waiter_count) } == 0
    {
        core::hint::spin_loop();
        spins -= 1;
    }

    loop {
        if unsafe { sem_trywait(semaphore.cast::<c_void>()) } == 0 {
            return 0;
        }

        // SAFETY: the sharing flag is immutable after selected initialization
        // and can be read plainly before this caller publishes its waiter hint.
        let private_word = unsafe { core::ptr::read(semaphore_word(semaphore, SEM_PRIVATE_WORD)) };
        // SAFETY: this balances exactly after the futex call in every path.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiter_count, 1) };
        // A failed CAS is intentional: if a post won the race, FUTEX_WAIT
        // returns EAGAIN and the outer trywait consumes its new value.
        let _ = unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(value, 0, SEM_WAITER_BIT)
        };
        let result = unsafe { futex_wait(value, private_word) };
        // SAFETY: this caller has stopped observing the value through futex,
        // so its advisory waiter hint can now be withdrawn.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiter_count, 1) };

        // The selected route has no musl signal-action bookkeeping.  Make a
        // direct interrupted futex wait observable rather than inventing a
        // restart policy; ordinary wakeups and expected-value races retry.
        if result == -i64::from(EINTR) {
            // SAFETY: this C ABI owns the direct interrupted-wait error.
            unsafe { errno::set_errno(EINTR) };
            return -1;
        }
    }
}

/// Native LP64 timespec consumed by musl's relative-timeout conversion.
#[cfg(feature = "x86-owned-static-runtime")]
#[repr(C)]
struct SemaphoreDeadline {
    seconds: i64,
    nanoseconds: i64,
}

/// Withdraw one semaphore waiter before the next user cleanup callback runs.
/// The registered C cleanup chain runs on cancellation; Rust Drop does not.
#[cfg(feature = "x86-owned-static-runtime")]
unsafe extern "C" fn cleanup_semaphore_waiter(argument: *mut c_void) {
    // SAFETY: the timed-wait scope publishes this aligned semaphore count
    // after incrementing it and keeps the semaphore live through cleanup.
    unsafe { atomic::x86_64_fetch_sub_acqrel_i32(argument.cast(), 1) };
}

/// Musl `__timedwait_cp` for this realtime semaphore wait. Linux 5.10 native
/// LP64 needs neither time32 conversion nor pre-baseline private-futex fallback.
#[cfg(feature = "x86-owned-static-runtime")]
unsafe fn semaphore_timedwait_result(
    value: *mut c_int,
    private_word: c_int,
    deadline: *const SemaphoreDeadline,
) -> c_int {
    const ETIMEDOUT: c_int = 110;
    const ECANCELED: c_int = 125;
    let mut relative = SemaphoreDeadline { seconds: 0, nanoseconds: 0 };
    let timeout = if deadline.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: the public timed-wait caller retains a readable timespec;
        // validation is deliberately after trywait and waiter registration.
        let absolute_seconds = unsafe { (*deadline).seconds };
        let absolute_nanoseconds = unsafe { (*deadline).nanoseconds };
        if absolute_nanoseconds as u64 >= 1_000_000_000 {
            return EINVAL;
        }
        // Preserve the source's internal realtime clock/error convention.
        if unsafe {
            super::clock_gettime::clock_gettime(
                0,
                core::ptr::addr_of_mut!(relative).cast(),
            )
        } != 0 {
            return EINVAL;
        }
        relative.seconds = absolute_seconds.wrapping_sub(relative.seconds);
        relative.nanoseconds = absolute_nanoseconds - relative.nanoseconds;
        if relative.nanoseconds < 0 {
            relative.seconds = relative.seconds.wrapping_sub(1);
            relative.nanoseconds += 1_000_000_000;
        }
        if relative.seconds < 0 {
            return ETIMEDOUT;
        }
        core::ptr::addr_of!(relative)
    };
    // SAFETY: the waiter scope retains the value word, relative timeout, and
    // registered cleanup through this signal-driven syscall cancellation point.
    let result = -unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_FUTEX,
            value as usize as i64,
            FUTEX_WAIT | futex_privilege(private_word),
            i64::from(SEM_WAITER_BIT),
            timeout as usize as i64,
            0,
            0,
        )
    } as c_int;
    // Musl retries successful wakes, expected-value races, and other raw
    // futex results. Only these source-defined errors escape to the caller.
    match result {
        EINTR if !super::signal_control::interrupting_signal_handler_installed() => 0,
        EINTR | ETIMEDOUT | ECANCELED => result,
        _ => 0,
    }
}

/// Wait for one semaphore unit, observing an enabled pending cancellation
/// request before attempting to consume even an immediately available unit.
///
/// # Safety
/// `semaphore` points to a live initialized and aligned public `sem_t`.
/// Concurrent participants retain its storage and use compatible atomic/futex
/// operations until the call and any cancellation cleanup have finished.
#[cfg(feature = "x86-owned-static-runtime")]
#[no_mangle]
pub unsafe extern "C" fn sem_wait(semaphore: *mut c_void) -> c_int {
    // SAFETY: this is musl's sem_timedwait(sem, NULL) mapping with the same
    // semaphore lifetime and cancellation-cleanup obligations.
    unsafe { sem_timedwait(semaphore, core::ptr::null()) }
}

/// Wait for one semaphore unit until an absolute CLOCK_REALTIME deadline.
/// Cancellation is checked before token consumption. As in musl, a token
/// available to either initial trywait bypasses deadline validation; an empty
/// semaphore validates nanoseconds before checking whether the deadline passed.
///
/// # Safety
/// `semaphore` points to a live initialized and aligned public `sem_t` whose
/// storage remains valid through all concurrent operations and cleanup.
/// `deadline` is null for an unbounded wait, or points to a readable aligned
/// native x86-64 timespec that stays valid until this call finishes.
#[cfg(feature = "x86-owned-static-runtime")]
#[no_mangle]
pub unsafe extern "C" fn sem_timedwait(
    semaphore: *mut c_void,
    deadline: *const c_void,
) -> c_int {
    // No resource has been acquired at this first source cancellation point.
    unsafe { super::pthread_cancel::pthread_testcancel() };
    if unsafe { sem_trywait(semaphore) } == 0 {
        return 0;
    }
    let public = semaphore.cast::<PublicSemaphore>();
    let value = unsafe { semaphore_word(public, SEM_VALUE_WORD) };
    let waiter_count = unsafe { semaphore_word(public, SEM_WAITER_COUNT_WORD) };
    let mut spins = 100;
    while spins > 0
        && unsafe { atomic::x86_64_load_acquire_i32(value) } & SEM_VALUE_MAX == 0
        && unsafe { atomic::x86_64_load_relaxed_i32(waiter_count) } == 0
    {
        core::hint::spin_loop();
        spins -= 1;
    }
    while unsafe { sem_trywait(semaphore) } != 0 {
        let private_word = unsafe { core::ptr::read(semaphore_word(public, SEM_PRIVATE_WORD)) };
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiter_count, 1) };
        let _ = unsafe { atomic::x86_64_compare_exchange_acqrel_i32(value, 0, SEM_WAITER_BIT) };
        let mut cleanup = core::mem::MaybeUninit::<super::pthread_cancel::CleanupNode>::uninit();
        // The selected pthread path initializes every node field and retains
        // this stack address until pop or exit. Outside that path push/pop(0)
        // do not inspect the node; the explicit normal cleanup still runs.
        unsafe {
            super::pthread_cancel::_pthread_cleanup_push(
                cleanup.as_mut_ptr(),
                Some(cleanup_semaphore_waiter),
                waiter_count.cast(),
            );
        }
        let result = unsafe { semaphore_timedwait_result(value, private_word, deadline.cast()) };
        unsafe {
            super::pthread_cancel::_pthread_cleanup_pop(cleanup.as_mut_ptr(), 0);
            cleanup_semaphore_waiter(waiter_count.cast());
        }
        if result != 0 {
            unsafe { errno::set_errno(result) };
            return -1;
        }
    }
    0
}

/// Publish one semaphore unit and wake a waiter when its state requires it.
///
/// # Safety
///
/// `semaphore` must point to a live, initialized, aligned selected `sem_t`.
/// Every concurrent participant must use compatible atomic semaphore
/// operations for the complete object lifetime.
#[no_mangle]
pub unsafe extern "C" fn sem_post(semaphore: *mut c_void) -> c_int {
    let semaphore = semaphore.cast::<PublicSemaphore>();
    let value = unsafe { semaphore_word(semaphore, SEM_VALUE_WORD) };
    let waiter_count = unsafe { semaphore_word(semaphore, SEM_WAITER_COUNT_WORD) };
    // SAFETY: selected initialization makes this immutable before publication.
    let private_word = unsafe { core::ptr::read(semaphore_word(semaphore, SEM_PRIVATE_WORD)) };

    loop {
        // SAFETY: both words are aligned selected atomic fields in the public
        // semaphore record, with the waiter count used only as an advisory hint.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(value) };
        let waiters = unsafe { atomic::x86_64_load_relaxed_i32(waiter_count) };
        if observed & SEM_VALUE_MAX == SEM_VALUE_MAX {
            // SAFETY: this is the defined POSIX overflow result.
            unsafe { errno::set_errno(EOVERFLOW) };
            return -1;
        }
        let mut replacement = observed.wrapping_add(1);
        if waiters <= 1 {
            replacement &= !SEM_WAITER_BIT;
        }
        // SAFETY: the value word uses the same acquire/release CAS protocol
        // as `sem_trywait` and `sem_wait`.
        if unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(value, observed, replacement)
        } != observed
        {
            continue;
        }
        if observed < 0 || waiters != 0 {
            // SAFETY: publication completed above, and this is the paired
            // wake over the still-live selected value word.
            unsafe { futex_wake(value, if waiters > 1 { 1 } else { -1 }, private_word) };
        }
        return 0;
    }
}

/// Read the nonnegative observable counter value.
///
/// # Safety
///
/// `semaphore` must point to a live initialized selected `sem_t`, and `value`
/// must point to writable aligned C `int` storage.  The result is a snapshot;
/// concurrent post/wait activity may change it immediately afterward.
#[no_mangle]
pub unsafe extern "C" fn sem_getvalue(semaphore: *mut c_void, value: *mut c_int) -> c_int {
    let semaphore = semaphore.cast::<PublicSemaphore>();
    let value_word = unsafe { semaphore_word(semaphore, SEM_VALUE_WORD) };
    // SAFETY: the caller supplies the live selected atomic word and writable
    // result pointer; the lower 31 bits are musl's observable count.
    unsafe {
        value.write(atomic::x86_64_load_acquire_i32(value_word) & SEM_VALUE_MAX);
    }
    0
}
