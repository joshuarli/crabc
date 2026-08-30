//! Linux/x86-64 static `pthread_rwlock_*` artifact.
//!
//! This is the complete read/write-lock and read/write-lock-attribute family
//! over the installed 56-byte x86 public record.  Its state transitions and
//! ELF aliases are a source-specific semantic port of musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT
//! license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_rwlock_init.c` and
//!   `src/thread/pthread_rwlock_destroy.c` map the public object lifecycle.
//! - `src/thread/pthread_rwlock_{tryrdlock,timedrdlock,rdlock}.c` map the
//!   reader state machine and its three hidden/public same-address aliases.
//! - `src/thread/pthread_rwlock_{trywrlock,timedwrlock,wrlock}.c` map the
//!   writer state machine and its three hidden/public same-address aliases.
//! - `src/thread/pthread_rwlock_unlock.c` maps the release and wake rule.
//! - `src/thread/pthread_rwlockattr_{init,destroy,setpshared}.c` plus
//!   `src/thread/pthread_attr_get.c::pthread_rwlockattr_getpshared` map the
//!   attribute record.
//! - `src/thread/__timedwait.c` maps the absolute `CLOCK_REALTIME` timeout
//!   conversion, result filtering, and private-versus-shared futex choice.
//!
//! The admitted object protocol is deliberately independent of the earlier
//! process-private normal-mutex and private-condition artifacts.  A rwlock
//! can be initialized private or process-shared, uses the first three public
//! words as musl does, and performs every concurrent access through raw x86
//! atomic operations.  It has no allocation, C `errno` publication, public
//! clock interposition, dynamic TLS, loader/CRT integration, cancellation
//! state, or general pthread-runtime claim.  The raw timed wait mirrors
//! musl's non-cancellation status behavior; broader cancellation ownership
//! remains part of the still-planned pthread/TLS runtime.  It is not public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 pthread-rwlock leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

use super::{atomic, raw_syscall};

const EAGAIN: c_int = 11;
const EBUSY: c_int = 16;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const ETIMEDOUT: c_int = 110;
const ECANCELED: c_int = 125;
const LINUX_ERRNO_MAX: i64 = 4_095;

const RWLOCK_LOCK_WORD: usize = 0;
const RWLOCK_WAITERS_WORD: usize = 1;
const RWLOCK_SHARED_WORD: usize = 2;
const RWLOCK_WORD_COUNT: usize = 14;
const RWLOCK_WRITER: c_int = 0x7fff_ffff;
const RWLOCK_READER_MAX: c_int = 0x7fff_fffe;
const RWLOCK_COUNT_MASK: c_int = 0x7fff_ffff;
const RWLOCK_WAITER_BIT: c_int = c_int::MIN;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: c_int = 128;
const CLOCK_REALTIME: c_int = 0;
const NANOS_PER_SECOND: c_long = 1_000_000_000;

/// Convert musl's stored rwlock sharing route to a Linux futex-private flag.
///
/// Public attribute APIs admit only the private `0` and shared `1` states,
/// stored as `0` and `128` respectively.  Musl still normalizes every other
/// nonzero private argument inside `__timedwait`/`__wake` to
/// `FUTEX_PRIVATE_FLAG`; retaining that normalization preserves its behavior
/// for caller-manufactured opaque attribute bytes without broadening the
/// admitted public attribute contract.
#[inline(always)]
const fn futex_private_flag(shared_route: c_int) -> c_int {
    if (shared_route ^ FUTEX_PRIVATE_FLAG) == 0 {
        0
    } else {
        FUTEX_PRIVATE_FLAG
    }
}

/// Exact public x86 `pthread_rwlock_t` storage.
///
/// The public header gives the seven-pointer union eight-byte alignment while
/// retaining musl's fourteen `int` words.  This record is private because it
/// only establishes ABI offsets for raw C-owned storage; it is not a Rust
/// synchronization type.
#[repr(C, align(8))]
struct PublicPthreadRwlock {
    words: [c_int; RWLOCK_WORD_COUNT],
}

/// Exact public x86 `pthread_rwlockattr_t` storage.
#[repr(C)]
struct PublicPthreadRwlockAttr {
    words: [c_uint; 2],
}

/// Linux x86-64's public `struct timespec` syscall representation.
#[repr(C)]
struct RawTimespec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

const _: () = {
    assert!(size_of::<PublicPthreadRwlock>() == 56);
    assert!(align_of::<PublicPthreadRwlock>() == 8);
    assert!(offset_of!(PublicPthreadRwlock, words) == 0);
    assert!(size_of::<PublicPthreadRwlockAttr>() == 8);
    assert!(align_of::<PublicPthreadRwlockAttr>() == 4);
    assert!(offset_of!(PublicPthreadRwlockAttr, words) == 0);
    assert!(size_of::<RawTimespec>() == 16);
    assert!(align_of::<RawTimespec>() == 8);
};

/// Return one raw word without creating a Rust reference to concurrently
/// accessed C storage.
///
/// # Safety
///
/// `rwlock` must designate a complete, aligned x86 public rwlock record.
#[inline(always)]
unsafe fn rwlock_word(rwlock: *mut PublicPthreadRwlock, index: usize) -> *mut c_int {
    debug_assert!(index < RWLOCK_WORD_COUNT);
    // SAFETY: the caller supplies a complete public rwlock record and the
    // bounded index remains inside its fourteen i32 words.  The raw result
    // avoids manufacturing a Rust reference to concurrent C storage.
    unsafe { core::ptr::addr_of_mut!((*rwlock).words).cast::<c_int>().add(index) }
}

/// Translate a raw Linux `-errno` result to a positive pthread status without
/// touching C `errno`.
#[inline(always)]
const fn pthread_status(result: i64) -> c_int {
    if result < 0 && result >= -LINUX_ERRNO_MAX {
        result.wrapping_neg() as c_int
    } else {
        0
    }
}

/// Issue musl's `__timedwait`-shaped raw futex wait.
///
/// The absolute deadline is converted locally through a raw realtime query so
/// this object protocol neither crosses the public `clock_gettime` C ABI nor
/// writes the caller's errno TLS.  As in musl, all ordinary futex races and
/// errors become a retry; only interruption, timeout, and cancellation are
/// observable by the lock loop.
///
/// # Safety
///
/// `lock` must name the live, aligned rwlock lock word.  When non-null,
/// `absolute_timeout` must name a readable x86 `struct timespec` for the
/// duration of this call.
unsafe fn timed_futex_wait(
    lock: *mut c_int,
    expected: c_int,
    absolute_timeout: *const RawTimespec,
    private: c_int,
) -> c_int {
    let mut relative_timeout = RawTimespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let timeout = if absolute_timeout.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: the public C caller supplies an aligned readable timespec;
        // a raw read avoids creating an aliasing Rust reference to its C
        // storage.  Musl checks the deadline only after an initial trylock.
        let absolute = unsafe { core::ptr::read(absolute_timeout) };
        if absolute.tv_nsec < 0 || absolute.tv_nsec >= NANOS_PER_SECOND {
            return EINVAL;
        }

        let mut now = RawTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `now` is one writable local Linux x86-64 timespec and
        // CLOCK_REALTIME is the exact musl rwlock deadline clock.
        let clock_result = unsafe {
            raw_syscall::syscall2(
                raw_syscall::SYS_CLOCK_GETTIME,
                i64::from(CLOCK_REALTIME),
                core::ptr::addr_of_mut!(now) as usize as i64,
            )
        };
        if pthread_status(clock_result) != 0 {
            // Musl intentionally maps an internal clock-query failure to
            // EINVAL at this pthread-status boundary.
            return EINVAL;
        }

        relative_timeout.tv_sec = absolute.tv_sec.wrapping_sub(now.tv_sec);
        relative_timeout.tv_nsec = absolute.tv_nsec.wrapping_sub(now.tv_nsec);
        if relative_timeout.tv_nsec < 0 {
            relative_timeout.tv_sec = relative_timeout.tv_sec.wrapping_sub(1);
            relative_timeout.tv_nsec += NANOS_PER_SECOND;
        }
        if relative_timeout.tv_sec < 0 {
            return ETIMEDOUT;
        }
        core::ptr::addr_of!(relative_timeout)
    };

    // SAFETY: `lock` and the optional local timeout meet the raw Linux futex
    // ABI.  The fourth x86 syscall argument is routed through r10 by the
    // shared raw-syscall boundary.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            lock as usize as i64,
            FUTEX_WAIT | i64::from(private),
            i64::from(expected),
            timeout as usize as i64,
        )
    };
    match pthread_status(result) {
        EINTR | ETIMEDOUT | ECANCELED => pthread_status(result),
        _ => 0,
    }
}

/// Wake a bounded number of rwlock waiters through the object's selected
/// private-or-shared futex route.
///
/// # Safety
///
/// `lock` must name the live, aligned rwlock lock word.  The caller has
/// already published its release transition, so an ignored wake error cannot
/// revoke that release.
#[inline(always)]
unsafe fn futex_wake(lock: *mut c_int, count: c_int, private: c_int) {
    // SAFETY: the live lock word, futex op, and wake count satisfy the raw
    // Linux ABI.  A futex wake has no timeout pointer.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            lock as usize as i64,
            FUTEX_WAKE | i64::from(private),
            i64::from(count),
            0,
        )
    };
}

/// Acquire one reader slot without waiting.
///
/// # Safety
///
/// `rwlock` must designate a live public x86 rwlock whose lock word is only
/// accessed through compatible atomic operations for its whole lifetime.
unsafe fn try_read_lock(rwlock: *mut PublicPthreadRwlock) -> c_int {
    let lock = unsafe { rwlock_word(rwlock, RWLOCK_LOCK_WORD) };
    loop {
        // SAFETY: `lock` is the admitted aligned concurrent lock word.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        let count = observed & RWLOCK_COUNT_MASK;
        if count == RWLOCK_WRITER {
            return EBUSY;
        }
        if count == RWLOCK_READER_MAX {
            return EAGAIN;
        }
        // SAFETY: this is the exact atomic reader-count increment.  Wrapping
        // arithmetic preserves C's i32 machine operation for malformed
        // caller storage without a debug-mode overflow path.
        if unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(
                lock,
                observed,
                observed.wrapping_add(1),
            )
        } == observed
        {
            return 0;
        }
    }
}

/// Acquire the writer sentinel without waiting.
///
/// # Safety
///
/// `rwlock` must designate a live public x86 rwlock under the same atomic
/// object-lifetime contract as [`try_read_lock`].
#[inline(always)]
unsafe fn try_write_lock(rwlock: *mut PublicPthreadRwlock) -> c_int {
    let lock = unsafe { rwlock_word(rwlock, RWLOCK_LOCK_WORD) };
    // SAFETY: this exact 0-to-writer-sentinel transition is the sole writer
    // acquisition state change on the admitted raw lock word.
    if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, 0, RWLOCK_WRITER) } == 0 {
        0
    } else {
        EBUSY
    }
}

/// Wait until a reader slot is available, following musl's reader condition.
///
/// # Safety
///
/// `rwlock` and `absolute_timeout` must satisfy the raw object contracts of
/// [`try_read_lock`] and [`timed_futex_wait`].
unsafe fn timed_read_lock(
    rwlock: *mut PublicPthreadRwlock,
    absolute_timeout: *const RawTimespec,
) -> c_int {
    let result = unsafe { try_read_lock(rwlock) };
    if result != EBUSY {
        return result;
    }

    let lock = unsafe { rwlock_word(rwlock, RWLOCK_LOCK_WORD) };
    let waiters = unsafe { rwlock_word(rwlock, RWLOCK_WAITERS_WORD) };
    let shared = unsafe { rwlock_word(rwlock, RWLOCK_SHARED_WORD) };
    let mut spins = 100;
    while spins != 0
        // SAFETY: all three raw words belong to the live rwlock record.
        && unsafe { atomic::x86_64_load_acquire_i32(lock) } != 0
        && unsafe { atomic::x86_64_load_relaxed_i32(waiters) } == 0
    {
        core::hint::spin_loop();
        spins -= 1;
    }

    loop {
        let result = unsafe { try_read_lock(rwlock) };
        if result != EBUSY {
            return result;
        }
        // SAFETY: the raw lock word remains live and atomically accessed.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        if observed == 0 || (observed & RWLOCK_COUNT_MASK) != RWLOCK_WRITER {
            continue;
        }
        let marked = observed | RWLOCK_WAITER_BIT;
        // SAFETY: the advisory waiter count and lock word are raw, aligned,
        // concurrent rwlock fields for the full public-object lifetime.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, 1) };
        let _ = unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, observed, marked) };
        // SAFETY: `_rw_shared` is immutable after initialization, just as in
        // musl; the raw route is normalized to its private/shared futex mode.
        let private = futex_private_flag(unsafe { atomic::x86_64_load_relaxed_i32(shared) });
        let result = unsafe { timed_futex_wait(lock, marked, absolute_timeout, private) };
        // SAFETY: balances this iteration's waiter-hint increment.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
        if result != 0 && result != EINTR {
            return result;
        }
    }
}

/// Wait until the writer sentinel can be installed, following musl's writer
/// condition.
///
/// # Safety
///
/// `rwlock` and `absolute_timeout` must satisfy the raw object contracts of
/// [`try_write_lock`] and [`timed_futex_wait`].
unsafe fn timed_write_lock(
    rwlock: *mut PublicPthreadRwlock,
    absolute_timeout: *const RawTimespec,
) -> c_int {
    let result = unsafe { try_write_lock(rwlock) };
    if result != EBUSY {
        return result;
    }

    let lock = unsafe { rwlock_word(rwlock, RWLOCK_LOCK_WORD) };
    let waiters = unsafe { rwlock_word(rwlock, RWLOCK_WAITERS_WORD) };
    let shared = unsafe { rwlock_word(rwlock, RWLOCK_SHARED_WORD) };
    let mut spins = 100;
    while spins != 0
        // SAFETY: all three raw words belong to the live rwlock record.
        && unsafe { atomic::x86_64_load_acquire_i32(lock) } != 0
        && unsafe { atomic::x86_64_load_relaxed_i32(waiters) } == 0
    {
        core::hint::spin_loop();
        spins -= 1;
    }

    loop {
        let result = unsafe { try_write_lock(rwlock) };
        if result != EBUSY {
            return result;
        }
        // SAFETY: the raw lock word remains live and atomically accessed.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        if observed == 0 {
            continue;
        }
        let marked = observed | RWLOCK_WAITER_BIT;
        // SAFETY: the advisory waiter count and lock word are raw, aligned,
        // concurrent rwlock fields for the full public-object lifetime.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, 1) };
        let _ = unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, observed, marked) };
        // SAFETY: `_rw_shared` is immutable after initialization, just as in
        // musl; the raw route is normalized to its private/shared futex mode.
        let private = futex_private_flag(unsafe { atomic::x86_64_load_relaxed_i32(shared) });
        let result = unsafe { timed_futex_wait(lock, marked, absolute_timeout, private) };
        // SAFETY: balances this iteration's waiter-hint increment.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
        if result != 0 && result != EINTR {
            return result;
        }
    }
}

/// Initialize one public rwlock attribute record to musl's private default.
///
/// # Safety
///
/// `attribute` must designate writable, aligned x86 `pthread_rwlockattr_t`
/// storage that is not concurrently accessed.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_init(attribute: *mut c_void) -> c_int {
    let attribute = attribute.cast::<PublicPthreadRwlockAttr>();
    // SAFETY: the C caller provides one writable non-concurrent public attr
    // record; all-zero is musl's exact default representation.
    unsafe { core::ptr::write_bytes(attribute, 0, 1) };
    0
}

/// Destroy one public rwlock attribute record.
///
/// Musl's attribute record owns no resource, so this intentionally neither
/// reads the caller record nor changes C errno.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(_attribute: *mut c_void) -> c_int {
    0
}

/// Set the process-sharing mode of one rwlock attribute record.
///
/// # Safety
///
/// `attribute` must designate writable, aligned x86 rwlock-attribute storage
/// that is not concurrently accessed.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(
    attribute: *mut c_void,
    process_shared: c_int,
) -> c_int {
    if (process_shared as c_uint) > 1 {
        return EINVAL;
    }
    let attribute = attribute.cast::<PublicPthreadRwlockAttr>();
    // SAFETY: the caller supplies the complete non-concurrent public record;
    // word zero is musl's exact pshared storage.
    unsafe { core::ptr::addr_of_mut!((*attribute).words).cast::<c_uint>().write(process_shared as c_uint) };
    0
}

/// Read the process-sharing mode of one rwlock attribute record.
///
/// # Safety
///
/// `attribute` must point to a readable initialized x86 rwlock attribute and
/// `process_shared` to writable `int` storage.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(
    attribute: *const c_void,
    process_shared: *mut c_int,
) -> c_int {
    let attribute = attribute.cast::<PublicPthreadRwlockAttr>();
    // SAFETY: both C pointers meet the public get-attribute contract.  Raw
    // operations avoid creating references to caller storage.
    let value = unsafe { core::ptr::addr_of!((*attribute).words).cast::<c_uint>().read() };
    unsafe { process_shared.write(value as c_int) };
    0
}

/// Initialize one rwlock to its all-zero private or requested shared state.
///
/// # Safety
///
/// `rwlock` must designate writable, aligned x86 `pthread_rwlock_t` storage
/// that is not concurrently accessed.  A non-null `attribute` must designate
/// a readable initialized x86 rwlock-attribute record.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_init(
    rwlock: *mut c_void,
    attribute: *const c_void,
) -> c_int {
    let rwlock = rwlock.cast::<PublicPthreadRwlock>();
    // SAFETY: the caller supplies one complete writable non-concurrent public
    // rwlock record; zero is musl's exact initializer representation.
    unsafe { core::ptr::write_bytes(rwlock, 0, 1) };
    if !attribute.is_null() {
        let attribute = attribute.cast::<PublicPthreadRwlockAttr>();
        // SAFETY: the public init contract admits the initialized attribute
        // record.  `wrapping_mul` preserves musl's unsigned storage operation
        // even for caller-manufactured invalid bytes.
        let shared = unsafe {
            core::ptr::addr_of!((*attribute).words)
                .cast::<c_uint>()
                .read()
                .wrapping_mul(FUTEX_PRIVATE_FLAG as c_uint) as c_int
        };
        // SAFETY: word two belongs to the freshly zeroed non-concurrent
        // rwlock.  It is immutable after successful initialization.
        unsafe { rwlock_word(rwlock, RWLOCK_SHARED_WORD).write(shared) };
    }
    0
}

/// Destroy one rwlock whose caller has made quiescent.
///
/// Musl's rwlock record owns no resource, so this returns zero and does not
/// inspect a potentially concurrent/invalid record.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_destroy(_rwlock: *mut c_void) -> c_int {
    0
}

/// Lock one rwlock for reading, waiting without a deadline as necessary.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock whose lifetime and
/// concurrent access obey the pthread object contract.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_rdlock(rwlock: *mut c_void) -> c_int {
    // SAFETY: the C caller supplies the admitted public rwlock object; a null
    // deadline selects musl's ordinary untimed rwlock path.
    unsafe { timed_read_lock(rwlock.cast::<PublicPthreadRwlock>(), core::ptr::null()) }
}

/// Try one reader acquisition without blocking.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock whose lifetime and
/// concurrent access obey the pthread object contract.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_tryrdlock(rwlock: *mut c_void) -> c_int {
    // SAFETY: the C caller supplies the admitted public rwlock object.
    unsafe { try_read_lock(rwlock.cast::<PublicPthreadRwlock>()) }
}

/// Lock one rwlock for reading until its absolute realtime deadline.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock and `absolute_timeout` a
/// readable x86 `struct timespec` when the initial trylock cannot succeed.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_timedrdlock(
    rwlock: *mut c_void,
    absolute_timeout: *const c_void,
) -> c_int {
    // SAFETY: the C caller supplies the raw rwlock and deadline contracts.
    unsafe {
        timed_read_lock(
            rwlock.cast::<PublicPthreadRwlock>(),
            absolute_timeout.cast::<RawTimespec>(),
        )
    }
}

/// Lock one rwlock for writing, waiting without a deadline as necessary.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock whose lifetime and
/// concurrent access obey the pthread object contract.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_wrlock(rwlock: *mut c_void) -> c_int {
    // SAFETY: the C caller supplies the admitted public rwlock object; a null
    // deadline selects musl's ordinary untimed rwlock path.
    unsafe { timed_write_lock(rwlock.cast::<PublicPthreadRwlock>(), core::ptr::null()) }
}

/// Try one writer acquisition without blocking.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock whose lifetime and
/// concurrent access obey the pthread object contract.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_trywrlock(rwlock: *mut c_void) -> c_int {
    // SAFETY: the C caller supplies the admitted public rwlock object.
    unsafe { try_write_lock(rwlock.cast::<PublicPthreadRwlock>()) }
}

/// Lock one rwlock for writing until its absolute realtime deadline.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock and `absolute_timeout` a
/// readable x86 `struct timespec` when the initial trylock cannot succeed.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_timedwrlock(
    rwlock: *mut c_void,
    absolute_timeout: *const c_void,
) -> c_int {
    // SAFETY: the C caller supplies the raw rwlock and deadline contracts.
    unsafe {
        timed_write_lock(
            rwlock.cast::<PublicPthreadRwlock>(),
            absolute_timeout.cast::<RawTimespec>(),
        )
    }
}

/// Release one reader or writer hold and wake eligible waiters.
///
/// # Safety
///
/// `rwlock` must designate a live x86 public rwlock held according to the
/// caller's pthread ownership discipline.
#[no_mangle]
pub unsafe extern "C" fn __pthread_rwlock_unlock(rwlock: *mut c_void) -> c_int {
    let rwlock = rwlock.cast::<PublicPthreadRwlock>();
    let lock = unsafe { rwlock_word(rwlock, RWLOCK_LOCK_WORD) };
    let waiters = unsafe { rwlock_word(rwlock, RWLOCK_WAITERS_WORD) };
    let shared = unsafe { rwlock_word(rwlock, RWLOCK_SHARED_WORD) };
    loop {
        // SAFETY: all raw words belong to the live public rwlock and use the
        // same atomic protocol for their whole concurrent lifetime.
        let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        let count = observed & RWLOCK_COUNT_MASK;
        let waiter_hint = unsafe { atomic::x86_64_load_relaxed_i32(waiters) };
        let replacement = if count == RWLOCK_WRITER || count == 1 {
            0
        } else {
            observed.wrapping_sub(1)
        };
        // SAFETY: this is the sole release transition; a successful locked
        // compare-exchange publishes the caller's preceding protected writes.
        if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, observed, replacement) }
            != observed
        {
            continue;
        }
        if replacement == 0 && (waiter_hint != 0 || observed < 0) {
            // SAFETY: `_rw_shared` is immutable after init and the lock word
            // remains live through the caller's required rwlock lifetime.
            let private = futex_private_flag(unsafe { atomic::x86_64_load_relaxed_i32(shared) });
            unsafe { futex_wake(lock, count, private) };
        }
        return 0;
    }
}

// Musl's seven public rwlock acquisition/release spellings are weak aliases
// of hidden strong `__pthread_rwlock_*` definitions at the same address.  A
// forwarding Rust wrapper would silently break both the address and archive
// override contracts, so keep the alias graph in assembler.
core::arch::global_asm!(
    ".hidden __pthread_rwlock_rdlock",
    ".weak pthread_rwlock_rdlock",
    ".set pthread_rwlock_rdlock, __pthread_rwlock_rdlock",
    ".hidden __pthread_rwlock_tryrdlock",
    ".weak pthread_rwlock_tryrdlock",
    ".set pthread_rwlock_tryrdlock, __pthread_rwlock_tryrdlock",
    ".hidden __pthread_rwlock_timedrdlock",
    ".weak pthread_rwlock_timedrdlock",
    ".set pthread_rwlock_timedrdlock, __pthread_rwlock_timedrdlock",
    ".hidden __pthread_rwlock_wrlock",
    ".weak pthread_rwlock_wrlock",
    ".set pthread_rwlock_wrlock, __pthread_rwlock_wrlock",
    ".hidden __pthread_rwlock_trywrlock",
    ".weak pthread_rwlock_trywrlock",
    ".set pthread_rwlock_trywrlock, __pthread_rwlock_trywrlock",
    ".hidden __pthread_rwlock_timedwrlock",
    ".weak pthread_rwlock_timedwrlock",
    ".set pthread_rwlock_timedwrlock, __pthread_rwlock_timedwrlock",
    ".hidden __pthread_rwlock_unlock",
    ".weak pthread_rwlock_unlock",
    ".set pthread_rwlock_unlock, __pthread_rwlock_unlock",
);
