//! Owned x86 condition transactions: private waiter lists and shared sequences.
//!
//! Source mapping is pinned musl 1.2.6 commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under the musl MIT license in
//! `COPYRIGHT`. `src/thread/pthread_cond_timedwait.c::__pthread_cond_timedwait`
//! supplies `wait`: owner/deadline validation, enrollment, MASKED cancellation,
//! list withdrawal or shared waiter accounting, relock/error precedence, and
//! consumed-signal suppression. The parent module retains that file's private
//! lock/list/signal helpers. `src/thread/__timedwait.c::__timedwait_cp` supplies
//! `timed_wait`: selected-clock conversion to relative time and result filtering.
//! `pthread_cond_init.c`, `pthread_cond_destroy.c`, `pthread_cond_signal.c`, and
//! `pthread_cond_broadcast.c` supply `init`, `destroy`, and `signal` below.
//!
//! Linux 5.10 provides native 64-bit futex time arguments and private futexes;
//! no time32, pre-private-futex, or historical EINTR-mitigation fallback is
//! selected. Clock observation uses the existing direct-syscall C status
//! translation, including its errno side effect on an invalid clock. Timeout
//! and futex results themselves remain pthread error numbers, not C errno.
//! Mutex admission belongs to `pthread_mutex::condition_mutex`: this module
//! consumes its typed relock interface and does not invent another mutex kind.

use super::*;

const EINVAL: c_int = 22;
const EINTR: c_int = 4;
const ETIMEDOUT: c_int = 110;
const SHARED_SEQUENCE_WORD: usize = 2;
const SHARED_WAITERS_WORD: usize = 3;
const CLOCK_WORD: usize = 4;
const NANOSECONDS_PER_SECOND: i64 = 1_000_000_000;

/// Native Linux/x86-64 timespec storage shared by the C and syscall boundaries.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(offset_of!(Timespec, seconds) == 0);
    assert!(offset_of!(Timespec, nanoseconds) == 8);
};

/// Name an aligned public condition word without creating a shared reference.
/// # Safety
/// `condition` is complete and aligned; `index` names its initialized overlay.
#[inline(always)]
unsafe fn word(condition: *mut PublicPthreadCond, index: usize) -> *mut c_int {
    unsafe { cond_bytes(condition).cast::<c_int>().add(index) }
}

/// Wake a source-selected futex; the release/count transition already occurred.
/// # Safety
/// The aligned atomic word remains live until Linux observes this wake call.
#[inline(always)]
unsafe fn wake(address: *mut c_int, count: c_int, private: bool) {
    let operation = FUTEX_WAKE | if private { FUTEX_PRIVATE_FLAG } else { 0 };
    let _ = unsafe {
        raw_syscall::syscall4(raw_syscall::SYS_FUTEX,
            address as usize as i64, operation, count as i64, 0)
    };
}

/// Initialize the complete condition before publishing its clock/sharing fields.
/// # Safety
/// The output is a writable aligned condition; non-null `attribute` points to
/// an initialized readable four-byte pthread condition attribute word.
pub(super) unsafe fn init(condition: *mut c_void, attribute: *const c_void) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    unsafe { core::ptr::write_bytes(condition, 0, 1) };
    if !attribute.is_null() {
        let attributes = unsafe { core::ptr::read(attribute.cast::<u32>()) };
        unsafe { core::ptr::write(word(condition, CLOCK_WORD), (attributes & 0x7fff_ffff) as c_int) };
        if attributes >> 31 != 0 {
            unsafe { core::ptr::write(cond_bytes(condition).cast::<*mut c_void>(), usize::MAX as *mut c_void) };
        }
    }
    0
}

/// Signal one or all waiters through the initialized condition representation.
/// # Safety
/// The caller owns predicate discipline and the condition's live lifetime.
/// `count` is either one (signal) or minus one (broadcast).
pub(super) unsafe fn signal(condition: *mut c_void, count: c_int) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    if unsafe { is_selected_private_cond(condition) } {
        return unsafe { private_cond_signal(condition, count) };
    }
    if unsafe { atomic::x86_64_load_relaxed_i32(word(condition, SHARED_WAITERS_WORD)) } != 0 {
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(word(condition, SHARED_SEQUENCE_WORD), 1) };
        unsafe { wake(word(condition, SHARED_SEQUENCE_WORD), count, false) };
    }
    0
}

/// Finish musl's shared-condition waiter drain before object storage is reused.
/// # Safety
/// The caller prevents new waiters and owns the POSIX destruction lifetime.
/// Private conditions have no resource to release after their waiters leave.
pub(super) unsafe fn destroy(condition: *mut c_void) -> c_int {
    let condition = condition.cast::<PublicPthreadCond>();
    if unsafe { is_selected_private_cond(condition) } {
        return 0;
    }
    let waiters = unsafe { word(condition, SHARED_WAITERS_WORD) };
    let mut current = unsafe { atomic::x86_64_load_acquire_i32(waiters) };
    if current != 0 {
        // Musl a_or publishes the destruction latch without losing a racing
        // waiter decrement; all accesses remain atomic across processes.
        loop {
            let observed = unsafe {
                atomic::x86_64_compare_exchange_acqrel_i32(waiters, current, current | c_int::MIN)
            };
            if observed == current { break; }
            current = observed;
        }
        let sequence = unsafe { word(condition, SHARED_SEQUENCE_WORD) };
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(sequence, 1) };
        unsafe { wake(sequence, -1, false) };
        loop {
            current = unsafe { atomic::x86_64_load_acquire_i32(waiters) };
            if current & c_int::MAX == 0 { break; }
            let _ = unsafe {
                raw_syscall::syscall4(raw_syscall::SYS_FUTEX,
                    waiters as usize as i64, FUTEX_WAIT, current as i64, 0)
            };
        }
    }
    0
}

/// Wait once using the selected clock and musl's cancellation/result boundary.
/// # Safety
/// The aligned futex and optional deadline remain live; cancellation is MASKED
/// or disabled until the calling condition transaction repairs ownership.
unsafe fn timed_wait(address: *mut c_int, expected: c_int, clock: c_int,
    deadline: Option<Timespec>, private: bool) -> c_int
{
    let mut relative = Timespec { seconds: 0, nanoseconds: 0 };
    let timeout = if let Some(deadline) = deadline {
        let status = unsafe {
            raw_syscall::syscall2(raw_syscall::SYS_CLOCK_GETTIME,
                clock as i64, core::ptr::addr_of_mut!(relative) as usize as i64)
        };
        if super::super::c_status(status) != 0 {
            return EINVAL;
        }
        relative.seconds = deadline.seconds.wrapping_sub(relative.seconds);
        relative.nanoseconds = deadline.nanoseconds - relative.nanoseconds;
        if relative.nanoseconds < 0 {
            relative.seconds = relative.seconds.wrapping_sub(1);
            relative.nanoseconds += NANOSECONDS_PER_SECOND;
        }
        if relative.seconds < 0 { return ETIMEDOUT; }
        core::ptr::addr_of!(relative) as usize as i64
    } else {
        0
    };
    let operation = FUTEX_WAIT | if private { FUTEX_PRIVATE_FLAG } else { 0 };
    let result = unsafe {
        pthread_cancel::syscall_cp(raw_syscall::SYS_FUTEX,
            address as usize as i64, operation, expected as i64, timeout, 0, 0)
    };
    match result {
        value if value == -(EINTR as i64) => EINTR,
        value if value == -(ETIMEDOUT as i64) => ETIMEDOUT,
        value if value == -(ECANCELED as i64) => ECANCELED,
        _ => 0,
    }
}

/// Execute one ordinary or timed owned condition transaction.
/// # Safety
/// Both records are live and aligned; the caller owns the mutex, predicate
/// discipline, and object lifetimes. A non-null deadline names an immutable
/// readable native timespec. As in musl, condition waits are not async-cancel-
/// safe; deferred cancellation owns the repair/cleanup ordering below.
pub(super) unsafe fn wait(condition: *mut c_void, mutex: *mut c_void,
    deadline: *const c_void) -> c_int
{
    let mutex = match unsafe { pthread_mutex::condition_mutex(mutex) } {
        Ok(mutex) => mutex,
        Err(error) => return error,
    };
    let deadline = if deadline.is_null() {
        None
    } else {
        let value = unsafe { core::ptr::read(deadline.cast::<Timespec>()) };
        if value.nanoseconds as u64 >= NANOSECONDS_PER_SECOND as u64 { return EINVAL; }
        Some(value)
    };
    pthread_cancel::test_current_selected_pthread_cancellation();

    let condition = condition.cast::<PublicPthreadCond>();
    let shared = !unsafe { is_selected_private_cond(condition) };
    let clock = unsafe { core::ptr::read(word(condition, CLOCK_WORD)) };
    let mut automatic_waiter = Waiter::empty();
    let node = core::ptr::addr_of_mut!(automatic_waiter);
    let (address, expected) = if shared {
        let sequence = unsafe { word(condition, SHARED_SEQUENCE_WORD) };
        let expected = unsafe { atomic::x86_64_load_acquire_i32(sequence) };
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(word(condition, SHARED_WAITERS_WORD), 1) };
        (sequence, expected)
    } else {
        let condition_lock = unsafe { cond_lock_word(condition) };
        unsafe { private_lock(condition_lock) };
        let old_head = unsafe { core::ptr::read(cond_head_slot(condition)) };
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*node).next), old_head);
            core::ptr::write(cond_head_slot(condition), node);
            if core::ptr::read(cond_tail_slot(condition)).is_null() {
                core::ptr::write(cond_tail_slot(condition), node);
            } else {
                core::ptr::write(core::ptr::addr_of_mut!((*old_head).prev), node);
            }
            private_unlock(condition_lock);
        }
        (unsafe { waiter_barrier_word(node) }, PRIVATE_CONTENDED)
    };
    // Admission already checked robust ownership; public mutex type/lifetime
    // mutation here is outside the caller contract, as in musl's ignored unlock.
    let _ = unsafe { mutex.unlock() };
    let saved_cancellation = pthread_cancel::begin_current_selected_pthread_condition_cancellation();
    let mut error = loop {
        let error = unsafe { timed_wait(address, expected, clock, deadline, !shared) };
        if unsafe { atomic::x86_64_load_acquire_i32(address) } != expected ||
            (error != 0 && error != EINTR)
        {
            break if error == EINTR { 0 } else { error };
        }
    };

    let old_state;
    if shared {
        let sequence = unsafe { word(condition, SHARED_SEQUENCE_WORD) };
        if error == ECANCELED && unsafe { atomic::x86_64_load_acquire_i32(sequence) } != expected {
            error = 0;
        }
        let waiters = unsafe { word(condition, SHARED_WAITERS_WORD) };
        if unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, -1) } == c_int::MIN + 1 {
            unsafe { wake(waiters, 1, false) };
        }
        old_state = WAITER_WAITING;
    } else {
        old_state = unsafe {
            atomic::x86_64_compare_exchange_acqrel_i32(
                waiter_state_word(node), WAITER_WAITING, WAITER_LEAVING)
        };
        if old_state == WAITER_WAITING {
            let condition_lock = unsafe { cond_lock_word(condition) };
            unsafe {
                private_lock(condition_lock);
                remove_waiter_locked(condition, node);
                private_unlock(condition_lock);
            }
            let notify = unsafe { core::ptr::read(core::ptr::addr_of!((*node).notify)) };
            if !notify.is_null() && unsafe { atomic::x86_64_fetch_add_acqrel_i32(notify, -1) } == 1 {
                unsafe { wake(notify, 1, true) };
            }
        } else {
            unsafe { private_lock(waiter_barrier_word(node)) };
        }
    }

    // Relock errors replace timeout or cancellation, but do not bypass the
    // detached waiters' release protocol. The caller must observe mutex state.
    let relock = unsafe { mutex.lock() };
    if relock != 0 { error = relock; }
    if old_state != WAITER_WAITING {
        let next = unsafe { core::ptr::read(core::ptr::addr_of!((*node).next)) };
        // Musl's PI branch omits the ordinary mutex waiter hint: kernel PI
        // owns contention state rather than the non-PI futex-requeue target.
        if next.is_null() && !mutex.pi() {
            unsafe { atomic::x86_64_fetch_add_acqrel_i32(mutex.waiters_word(), 1) };
        }
        let previous = unsafe { core::ptr::read(core::ptr::addr_of!((*node).prev)) };
        if !previous.is_null() {
            let lock = mutex.lock_word();
            let current = unsafe { atomic::x86_64_load_acquire_i32(lock) };
            if current > 0 {
                let _ = unsafe {
                    atomic::x86_64_compare_exchange_acqrel_i32(lock, current, current | MUTEX_WAITER_BIT)
                };
            }
            let barrier = unsafe { waiter_barrier_word(previous) };
            // PI cannot receive a requeued ordinary futex waiter. Just as
            // musl's `unlock_requeue(..., m->_m_type & (8|128))`, wake the
            // predecessor barrier for either PI or process-shared mutexes.
            if mutex.pi() || mutex.shared() {
                unsafe { atomic::x86_64_swap_acqrel_i32(barrier, PRIVATE_UNLOCKED) };
                unsafe { wake(barrier, 1, true) };
            } else {
                unsafe { private_unlock_requeue(barrier, lock) };
            }
        } else if next.is_null() && !mutex.pi() {
            unsafe { atomic::x86_64_fetch_sub_acqrel_i32(mutex.waiters_word(), 1) };
        }
        if error == ECANCELED { error = 0; }
    }
    if let Some(saved) = saved_cancellation {
        pthread_cancel::restore_current_selected_pthread_condition_cancellation(saved);
        if error == ECANCELED {
            pthread_cancel::test_current_selected_pthread_cancellation();
            pthread_cancel::restore_current_selected_pthread_condition_cancellation(PTHREAD_CANCEL_DISABLE);
        }
    }
    error
}

/// Wait until signaled, canceled, or the condition's absolute deadline expires.
/// # Safety
/// `condition` and `mutex` are live aligned initialized objects; the caller
/// holds the mutex and retains predicate/object lifetimes. `deadline` points
/// to a readable aligned native timespec. Deferred cancellation reacquires the
/// mutex before user cleanup; asynchronous cancellation is not safe here.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_timedwait(condition: *mut c_void,
    mutex: *mut c_void, deadline: *const c_void) -> c_int
{
    unsafe { wait(condition, mutex, deadline) }
}
