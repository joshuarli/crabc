//! Owned Linux/x86-64 POSIX AIO request engine.
//!
//! This is a source-specific semantic port of pinned musl 1.2.6 release
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license in
//! `COPYRIGHT`:
//!
//! - `src/aio/aio.c` maps the four-level descriptor map, per-descriptor
//!   queues, detached per-request workers, completion/cancellation/fork
//!   protocol, `aio_{read,write,fsync,error,return,cancel}`, and `__aio_close`.
//! - `src/aio/aio_suspend.c` maps the one/many request futex selection and
//!   `__timedwait_cp`-shaped monotonic relative-timeout conversion.
//! - `src/aio/lio_listio.c` maps wait/list submission, its public allocator
//!   boundary, and list completion notification.
//!
//! The worker queue is POSIX AIO compatibility machinery. It does not expose
//! or select a Rust async runtime. A request owns one detached selected
//! pthread until it has copied the caller control block, completed I/O, made
//! the atomic error publication, and unlinked itself from its descriptor
//! queue. Public `struct aiocb` storage remains C-owned: a caller must retain
//! the control block, buffers, descriptor and notification objects as POSIX
//! requires, and must not make ordinary non-atomic accesses to `__err` while a
//! request is live. This module uses atomic accesses for every concurrently
//! observed `__err` word; `__ret` is written before release completion and may
//! be read after `aio_error` has observed that completion, matching musl's
//! AIO caller synchronization contract.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the owned POSIX AIO engine requires little-endian Linux/x86-64");

use core::{
    cell::UnsafeCell,
    ffi::{c_int, c_long, c_uint, c_ulong, c_void},
    mem::{align_of, offset_of, size_of, MaybeUninit},
    ptr::{self, null, null_mut},
    sync::atomic::{compiler_fence, AtomicI32, AtomicPtr, AtomicUsize, Ordering},
};

use super::{
    atomic, auxv_observation, descriptor_io, errno, posix_semaphore, pthread_attr,
    pthread_cancel, pthread_cond, pthread_create_join, pthread_identity, pthread_mutex,
    pthread_rwlock, raw_syscall, signal_control, signal_set_mutation,
};

const EBADF: c_int = 9;
const EAGAIN: c_int = 11;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const ENOENT: c_int = 2;
const EIO: c_int = 5;
const EINPROGRESS: c_int = 115;
const ECANCELED: c_int = 125;
const ETIMEDOUT: c_int = 110;
const ENOSYS: i64 = 38;

const LIO_READ: c_int = 0;
const LIO_WRITE: c_int = 1;
const LIO_WAIT: c_int = 0;
const O_DSYNC: c_int = 0x1000;
const O_SYNC: c_int = 0x101000;
const O_APPEND: i64 = 0x400;
const F_GETFD: i64 = 1;
const F_GETFL: i64 = 3;
const SEEK_CUR: c_int = 1;

const AIO_CANCELED: c_int = 0;
const AIO_NOTCANCELED: c_int = 1;
const AIO_ALLDONE: c_int = 2;

const SIG_BLOCK: c_int = 0;
const SIG_SETMASK: c_int = 2;
const SIGEV_SIGNAL: c_int = 0;
const SIGEV_NONE: c_int = 1;
const SIGEV_THREAD: c_int = 2;
const SI_ASYNCIO: c_int = -4;

const CLOCK_MONOTONIC: c_int = 1;
const AT_MINSIGSTKSZ: c_ulong = 51;
const MINSIGSTKSZ: usize = 2_048;
const PAGE_SIZE: usize = 4_096;
const NANOS_PER_SECOND: c_long = 1_000_000_000;

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: i64 = 128;

/// Exact x86 public `pthread_mutex_t` storage used only for AIO queue locks.
#[repr(C, align(8))]
struct PublicPthreadMutex {
    words: [c_int; 10],
}

/// Exact x86 public `pthread_cond_t` storage used only for queue sequencing.
#[repr(C, align(8))]
struct PublicPthreadCond {
    words: [c_int; 12],
}

/// Exact x86 public `pthread_rwlock_t` storage used by the descriptor map.
#[repr(C, align(8))]
struct PublicPthreadRwlock {
    words: [c_int; 14],
}

/// Exact x86 public `sem_t` storage used for worker stack-argument handoff.
#[repr(C)]
struct PublicSemaphore {
    words: [c_int; 8],
}

/// Exact public x86 `pthread_attr_t` storage copied by SIGEV_THREAD paths.
#[repr(C)]
#[derive(Clone, Copy)]
struct PublicPthreadAttr {
    words: [usize; 7],
}

/// Linux x86-64 `struct timespec` used by AIO timeout conversion.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

/// Complete public x86 `sigset_t` storage for musl's all-application mask.
#[repr(C, align(8))]
struct SignalSet {
    words: [u64; 16],
}

impl SignalSet {
    const fn empty() -> Self {
        Self { words: [0; 16] }
    }
}

/// Exact C ABI payload for `union sigval`.
#[repr(C)]
#[derive(Clone, Copy)]
union Sigval {
    integer: c_int,
    pointer: *mut c_void,
}

type NotifyFunction = unsafe extern "C" fn(Sigval);

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadNotification {
    function: Option<NotifyFunction>,
    attributes: *const PublicPthreadAttr,
}

#[repr(C)]
union SigeventFields {
    thread: ThreadNotification,
    thread_id: c_int,
    padding: [u8; 48],
}

/// Exact public x86 `struct sigevent` storage embedded in `struct aiocb`.
#[repr(C)]
struct Sigevent {
    value: Sigval,
    signal: c_int,
    notify: c_int,
    fields: SigeventFields,
}

/// Completion data copied from the active arm of a caller-owned `sigevent`.
///
/// The public record has no Rust validity contract as a whole: POSIX permits a
/// `SIGEV_NONE` caller to leave `sigev_signo`, `sigev_value`, and the union
/// tail uninitialized, and `SIGEV_THREAD` does not use `sigev_signo`.  Do not
/// derive or raw-copy `Sigevent`; `notification_snapshot` reads `notify`
/// first and then only the fields selected by that mode. `Sigval` remains a
/// C union copy, so this transfers its initialized active member without
/// interpreting its alternate scalar representation.
#[derive(Clone, Copy)]
enum NotificationSnapshot {
    None,
    Signal { signal: c_int, value: Sigval },
    Thread {
        function: Option<NotifyFunction>,
        value: Sigval,
    },
    Other,
}

/// Exact public x86 `struct aiocb` layout.
///
/// Only `error` is concurrently read/written by this implementation and it
/// is always reached through the raw atomic helpers below. The remaining
/// fields are copied under the POSIX aiocb lifetime discipline.
#[repr(C)]
struct AioCb {
    descriptor: c_int,
    list_operation: c_int,
    request_priority: c_int,
    buffer: *mut c_void,
    byte_count: usize,
    signal_event: Sigevent,
    thread: *mut c_void,
    lock: [c_int; 2],
    error: c_int,
    result: isize,
    offset: c_long,
    next: *mut c_void,
    previous: *mut c_void,
    padding: [u8; 16],
}

/// Linux's initialized `rt_sigqueueinfo` input record.
#[repr(C, align(8))]
struct QueuedSigInfo {
    signal: c_int,
    error: c_int,
    code: c_int,
    alignment_padding: c_int,
    process_id: c_int,
    user_id: c_uint,
    value: Sigval,
    tail: [u8; 96],
}

const _: () = {
    assert!(size_of::<PublicPthreadMutex>() == 40);
    assert!(align_of::<PublicPthreadMutex>() == 8);
    assert!(size_of::<PublicPthreadCond>() == 48);
    assert!(align_of::<PublicPthreadCond>() == 8);
    assert!(size_of::<PublicPthreadRwlock>() == 56);
    assert!(align_of::<PublicPthreadRwlock>() == 8);
    assert!(size_of::<PublicSemaphore>() == 32);
    assert!(align_of::<PublicSemaphore>() == 4);
    assert!(size_of::<PublicPthreadAttr>() == 56);
    assert!(align_of::<PublicPthreadAttr>() == 8);
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(size_of::<Sigval>() == 8);
    assert!(align_of::<Sigval>() == 8);
    assert!(size_of::<Sigevent>() == 64);
    assert!(align_of::<Sigevent>() == 8);
    assert!(offset_of!(Sigevent, signal) == 8);
    assert!(offset_of!(Sigevent, notify) == 12);
    assert!(offset_of!(Sigevent, fields) == 16);
    assert!(offset_of!(ThreadNotification, attributes) == 8);
    assert!(size_of::<AioCb>() == 168);
    assert!(align_of::<AioCb>() == 8);
    assert!(offset_of!(AioCb, descriptor) == 0);
    assert!(offset_of!(AioCb, buffer) == 16);
    assert!(offset_of!(AioCb, signal_event) == 32);
    assert!(offset_of!(AioCb, error) == 112);
    assert!(offset_of!(AioCb, result) == 120);
    assert!(offset_of!(AioCb, offset) == 128);
    assert!(size_of::<QueuedSigInfo>() == 128);
    assert!(align_of::<QueuedSigInfo>() == 8);
    assert!(offset_of!(QueuedSigInfo, process_id) == 16);
};

const AIO_LIST_WORKER: c_int = 1;
const AIO_LIST_CANCEL_CURSOR: c_int = 2;

/// Intrusive queue linkage shared by a real worker and an `aio_cancel` cursor.
///
/// A cursor is a stack-only boundary inserted at the head while `aio_cancel`
/// holds the queue mutex. New submissions prepend before every cursor. Moving
/// a cursor toward the tail therefore walks exactly the request set visible at
/// that call's linearization point, even though it must release the queue
/// mutex while a cancellation is delivered. A real worker embeds this node;
/// a cursor has only this node and must never be converted to `AioThread`.
#[repr(C)]
struct AioListNode {
    next: *mut AioListNode,
    previous: *mut AioListNode,
    kind: c_int,
}

impl AioListNode {
    const fn worker() -> Self {
        Self {
            next: null_mut(),
            previous: null_mut(),
            kind: AIO_LIST_WORKER,
        }
    }

    const fn cancel_cursor() -> Self {
        Self {
            next: null_mut(),
            previous: null_mut(),
            kind: AIO_LIST_CANCEL_CURSOR,
        }
    }
}

/// One stack-resident request record linked under its queue lock.
///
/// `running` is the state observed by cancelers. Its release transition to
/// zero publishes the immutable `error` value to a canceler that acquire-waits
/// for it. `cancel_waiters` is incremented only while the queue mutex keeps
/// this stack object linked; cleanup retains the worker's existing queue
/// reference until every counted waiter has consumed that publication.
/// `queue_lock_held` is worker-local cleanup ownership: condition cancellation
/// reacquires the queue mutex before active cleanup executes.
#[repr(C)]
struct AioThread {
    thread: *mut c_void,
    control: *mut AioCb,
    link: AioListNode,
    queue: *mut AioQueue,
    running: AtomicI32,
    cancel_waiters: AtomicI32,
    queue_lock_held: AtomicI32,
    error: c_int,
    operation: c_int,
    result: isize,
}

/// Stack boundary for one `aio_cancel` traversal. It deliberately carries no
/// worker fields, so the tagged intrusive node prevents accidental worker
/// dereferences while concurrent cancelers temporarily interleave cursors.
#[repr(C)]
struct AioCancelCursor {
    link: AioListNode,
}

/// One descriptor's reference-counted request queue.
///
/// Every non-atomic member is accessed while `lock` is held. The object is
/// allocated through the internal allocator, then retained from submission to
/// worker cleanup. A map read lock prevents destruction while an existing
/// queue's lock is acquired.
#[repr(C)]
struct AioQueue {
    descriptor: c_int,
    seekable: c_int,
    append: c_int,
    references: c_int,
    initialized: c_int,
    lock: PublicPthreadMutex,
    condition: PublicPthreadCond,
    head: *mut AioListNode,
}

/// Submission's stack handoff. The worker copies all non-semaphore fields
/// before it posts `semaphore`; the submitter does not return until that post.
#[repr(C)]
struct AioArgs {
    control: *mut AioCb,
    queue: *mut AioQueue,
    operation: c_int,
    semaphore: PublicSemaphore,
}

type QueueLeaf = [*mut AioQueue; 256];
type QueueLevel2 = [*mut QueueLeaf; 256];
type QueueLevel1 = [*mut QueueLevel2; 256];
type AioMap = [*mut QueueLevel1; 128];

/// A `pthread_rwlock_t` held through raw pointers. `UnsafeCell` prevents Rust
/// from claiming that concurrent C lock operations mutate immutable storage;
/// every access is instead serialized by the selected pthread rwlock protocol.
struct RuntimeMapLock(UnsafeCell<PublicPthreadRwlock>);
unsafe impl Sync for RuntimeMapLock {}

impl RuntimeMapLock {
    const fn new() -> Self {
        Self(UnsafeCell::new(PublicPthreadRwlock { words: [0; 14] }))
    }

    #[inline]
    fn pointer(&self) -> *mut c_void {
        self.0.get().cast()
    }
}

static MAP_LOCK: RuntimeMapLock = RuntimeMapLock::new();
static QUEUE_MAP: AtomicPtr<AioMap> = AtomicPtr::new(null_mut());
static AIO_FD_COUNT: AtomicI32 = AtomicI32::new(0);
static AIO_FUTEX: AtomicI32 = AtomicI32::new(0);
static IO_THREAD_STACK_SIZE: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
unsafe fn map_read_lock() {
    let _ = unsafe { pthread_rwlock::__pthread_rwlock_rdlock(MAP_LOCK.pointer()) };
}

#[inline(always)]
unsafe fn map_try_read_lock() -> c_int {
    unsafe { pthread_rwlock::__pthread_rwlock_tryrdlock(MAP_LOCK.pointer()) }
}

#[inline(always)]
unsafe fn map_write_lock() {
    let _ = unsafe { pthread_rwlock::__pthread_rwlock_wrlock(MAP_LOCK.pointer()) };
}

#[inline(always)]
unsafe fn map_unlock() {
    let _ = unsafe { pthread_rwlock::__pthread_rwlock_unlock(MAP_LOCK.pointer()) };
}

#[inline(always)]
unsafe fn queue_lock(queue: *mut AioQueue) {
    let _ = unsafe { pthread_mutex::pthread_mutex_lock(ptr::addr_of_mut!((*queue).lock).cast()) };
}

#[inline(always)]
unsafe fn queue_unlock(queue: *mut AioQueue) {
    let _ = unsafe { pthread_mutex::pthread_mutex_unlock(ptr::addr_of_mut!((*queue).lock).cast()) };
}

#[inline(always)]
unsafe fn queue_broadcast(queue: *mut AioQueue) {
    let _ = unsafe { pthread_cond::pthread_cond_broadcast(ptr::addr_of_mut!((*queue).condition).cast()) };
}

#[inline(always)]
unsafe fn queue_wait(queue: *mut AioQueue) {
    let _ = unsafe {
        pthread_cond::pthread_cond_wait(
            ptr::addr_of_mut!((*queue).condition).cast(),
            ptr::addr_of_mut!((*queue).lock).cast(),
        )
    };
}

/// Recover the containing worker from its tagged embedded list node.
///
/// # Safety
///
/// `node` must be a live `AIO_LIST_WORKER` node embedded in `AioThread`.
/// Cursor nodes deliberately fail that precondition and are skipped by every
/// generic queue traversal before this conversion.
#[inline(always)]
unsafe fn worker_from_link(node: *mut AioListNode) -> *mut AioThread {
    debug_assert!(unsafe { (*node).kind } == AIO_LIST_WORKER);
    unsafe { node.cast::<u8>().sub(offset_of!(AioThread, link)).cast() }
}

/// Link one node at the queue head while its mutex is held.
#[inline(always)]
unsafe fn queue_link_head(queue: *mut AioQueue, node: *mut AioListNode) {
    let former_head = unsafe { (*queue).head };
    unsafe {
        (*node).previous = null_mut();
        (*node).next = former_head;
        if !former_head.is_null() {
            (*former_head).previous = node;
        }
        (*queue).head = node;
    }
}

/// Unlink one live node while its queue mutex is held.
#[inline(always)]
unsafe fn queue_unlink_node(queue: *mut AioQueue, node: *mut AioListNode) {
    let next = unsafe { (*node).next };
    let previous = unsafe { (*node).previous };
    unsafe {
        if !next.is_null() {
            (*next).previous = previous;
        }
        if !previous.is_null() {
            (*previous).next = next;
        } else {
            (*queue).head = next;
        }
    }
}

/// Advance a cancel cursor across its immediate successor under the queue lock.
///
/// The successor stays linked and preserves real-worker order; only the
/// cursor moves one step toward the tail. New requests are always prepended,
/// so they remain before the cursor and cannot enter this call's finite set.
#[inline(always)]
unsafe fn advance_cancel_cursor(queue: *mut AioQueue, cursor: *mut AioListNode) {
    let node = unsafe { (*cursor).next };
    debug_assert!(!node.is_null());
    let before = unsafe { (*cursor).previous };
    let after = unsafe { (*node).next };
    unsafe {
        if !before.is_null() {
            (*before).next = node;
        } else {
            (*queue).head = node;
        }
        (*node).previous = before;
        (*node).next = cursor;
        (*cursor).previous = node;
        (*cursor).next = after;
        if !after.is_null() {
            (*after).previous = cursor;
        }
    }
}

/// Join cancellation of one linked worker while the queue mutex keeps its
/// stack record alive. Returns whether this caller changed running from one
/// to the source's negative waiter state and therefore must send cancellation.
#[inline(always)]
unsafe fn pin_worker_cancellation(worker: *mut AioThread) -> (bool, bool) {
    let transition = unsafe {
        (*worker)
            .running
            .compare_exchange(1, -1, Ordering::AcqRel, Ordering::Acquire)
    };
    let (live, request) = match transition {
        Ok(_) => (true, true),
        Err(-1) => (true, false),
        Err(_) => (false, false),
    };
    if live {
        // A Linux process cannot have `INT_MAX` concurrently live tasks, so
        // this source-specific counted pin cannot wrap on the selected ABI.
        let prior = unsafe { (*worker).cancel_waiters.fetch_add(1, Ordering::AcqRel) };
        debug_assert!(prior >= 0);
    }
    (live, request)
}

/// Release one canceler's stack pin while the queue mutex excludes unlinking.
#[inline(always)]
unsafe fn unpin_worker_cancellation(worker: *mut AioThread) {
    let prior = unsafe { (*worker).cancel_waiters.fetch_sub(1, Ordering::AcqRel) };
    debug_assert!(prior > 0);
    if prior == 1 {
        // The worker must acquire this same queue mutex before it can observe
        // zero and return its stack frame, so waking under the lock leaves no
        // last-unpin use-after-return window.
        unsafe { futex_wake((*worker).cancel_waiters.as_ptr()) };
    }
}

/// Wait for all stack pins to drain after worker unlinking. The final unpin
/// wakes this futex; intermediate decrements need no wake because the worker
/// cannot leave until the count reaches zero.
#[inline(always)]
unsafe fn wait_for_worker_cancellation_pins(worker: *mut AioThread) {
    loop {
        let pins = unsafe { (*worker).cancel_waiters.load(Ordering::Acquire) };
        if pins == 0 {
            return;
        }
        unsafe { wait_while_equal((*worker).cancel_waiters.as_ptr(), pins) };
    }
}

#[inline(always)]
unsafe fn control_error_word(control: *mut AioCb) -> *mut c_int {
    unsafe { ptr::addr_of_mut!((*control).error) }
}

#[inline(always)]
unsafe fn control_error_load(control: *mut AioCb) -> c_int {
    let word = unsafe { control_error_word(control) };
    // SAFETY: the AIO control-block lifetime contract keeps this aligned word
    // live, and every owned AIO concurrent access is atomic.
    unsafe { AtomicI32::from_ptr(word) }.load(Ordering::Acquire)
}

#[inline(always)]
unsafe fn control_error_store(control: *mut AioCb, value: c_int) {
    let word = unsafe { control_error_word(control) };
    // SAFETY: see `control_error_load`; release publishes request state or the
    // preceding non-atomic result write to a caller's acquire observation.
    unsafe { AtomicI32::from_ptr(word) }.store(value, Ordering::Release);
}

#[inline(always)]
unsafe fn futex_wake(address: *mut c_int) {
    // musl `__wake(addr, -1, 1)` first maps its negative source sentinel to
    // INT_MAX. Linux 5.10's raw FUTEX_WAKE loop compares its signed count, so
    // passing -1 directly wakes only one waiter rather than the source's
    // wake-all contract. Completion can have concurrent cancelers and many
    // aio_suspend waiters, thus preserve that normalization at this raw ABI.
    // SAFETY: `address` is either a worker-owned running/pin word that remains
    // live through the wake, or a completion address cached while the aiocb
    // was live. In the latter case a waiter may already reclaim that storage;
    // this raw syscall only carries the cached numeric address to Linux and
    // performs no Rust dereference or field projection. An invalid reclaimed
    // FUTEX_WAKE address is an ignored kernel failure, as in musl's wake path.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            address as usize as i64,
            FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
            i64::from(c_int::MAX),
            0,
        )
    };
}

/// Musl `__wait(addr, 0, expected, 1)` for a private live AIO word.
///
/// This is intentionally not a cancellation point: the bounded `aio_cancel`
/// correction holds a counted worker pin while it waits for completion, and
/// close reaches that same non-canceling path from its signal-safe hook.
unsafe fn wait_while_equal(address: *mut c_int, expected: c_int) {
    let mut spins = 100;
    while spins != 0 {
        if unsafe { atomic::x86_64_load_acquire_i32(address) } != expected {
            return;
        }
        core::hint::spin_loop();
        spins -= 1;
    }
    while unsafe { atomic::x86_64_load_acquire_i32(address) } == expected {
        // Linux 5.10 supports private futexes. Keep musl's shared retry if a
        // kernel nevertheless reports ENOSYS for this source-shaped call.
        let result = unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FUTEX,
                address as usize as i64,
                FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                i64::from(expected),
                0,
            )
        };
        if result == -ENOSYS {
            let _ = unsafe {
                raw_syscall::syscall4(
                    raw_syscall::SYS_FUTEX,
                    address as usize as i64,
                    FUTEX_WAIT,
                    i64::from(expected),
                    0,
                )
            };
        }
    }
}

/// Musl `__timedwait_cp` for the AIO monotonic wait paths.
///
/// The absolute deadline is already monotonic. Linux consumes a relative
/// duration, so this local conversion avoids public-clock interposition. Only
/// EINTR, ETIMEDOUT, and masked cancellation escape; all normal futex races
/// retry in the caller exactly as source does.
unsafe fn timed_wait_cp(
    address: *mut c_int,
    expected: c_int,
    clock: c_int,
    deadline: *const Timespec,
    private: bool,
) -> c_int {
    let mut relative = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    let timeout = if deadline.is_null() {
        null()
    } else {
        // SAFETY: the public caller retains the readable x86 timespec for
        // this immediate source-defined conversion.
        let absolute = unsafe { ptr::read(deadline) };
        if (absolute.nanoseconds as u64) >= NANOS_PER_SECOND as u64 {
            return EINVAL;
        }
        let mut now = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        let clock_result = unsafe {
            raw_syscall::syscall2(
                raw_syscall::SYS_CLOCK_GETTIME,
                i64::from(clock),
                ptr::addr_of_mut!(now) as usize as i64,
            )
        };
        if clock_result < 0 {
            return EINVAL;
        }
        relative.seconds = absolute.seconds.wrapping_sub(now.seconds);
        relative.nanoseconds = absolute.nanoseconds.wrapping_sub(now.nanoseconds);
        if relative.nanoseconds < 0 {
            relative.seconds = relative.seconds.wrapping_sub(1);
            relative.nanoseconds += NANOS_PER_SECOND;
        }
        if relative.seconds < 0 {
            return ETIMEDOUT;
        }
        ptr::addr_of!(relative)
    };
    let private_operation = FUTEX_WAIT | if private { FUTEX_PRIVATE_FLAG } else { 0 };
    // SAFETY: the aligned completion/futex word and optional stack-local
    // relative timeout remain live across this cancellation-point syscall.
    let mut raw = unsafe {
        pthread_cancel::syscall_cp(
            raw_syscall::SYS_FUTEX,
            address as usize as i64,
            private_operation,
            i64::from(expected),
            timeout as usize as i64,
            0,
            0,
        )
    };
    if raw == -ENOSYS && private {
        raw = unsafe {
            pthread_cancel::syscall_cp(
                raw_syscall::SYS_FUTEX,
                address as usize as i64,
                FUTEX_WAIT,
                i64::from(expected),
                timeout as usize as i64,
                0,
                0,
            )
        };
    }
    let result = raw.wrapping_neg() as c_int;
    match result {
        EINTR if !signal_control::interrupting_signal_handler_installed() => 0,
        EINTR | ETIMEDOUT | ECANCELED => result,
        _ => 0,
    }
}

#[inline(always)]
unsafe fn descriptor_indices(descriptor: c_int) -> (usize, usize, usize, usize) {
    let descriptor = descriptor as u32;
    (
        (descriptor >> 24) as usize,
        ((descriptor >> 16) & 0xff) as usize,
        ((descriptor >> 8) & 0xff) as usize,
        (descriptor & 0xff) as usize,
    )
}

/// Look up one map leaf while the caller holds the map read or write lock.
unsafe fn map_lookup(map: *mut AioMap, descriptor: c_int) -> *mut AioQueue {
    if map.is_null() {
        return null_mut();
    }
    let (a, b, c, d) = unsafe { descriptor_indices(descriptor) };
    let one = unsafe { ptr::read(ptr::addr_of!((*map)[a])) };
    if one.is_null() {
        return null_mut();
    }
    let two = unsafe { ptr::read(ptr::addr_of!((*one)[b])) };
    if two.is_null() {
        return null_mut();
    }
    let leaf = unsafe { ptr::read(ptr::addr_of!((*two)[c])) };
    if leaf.is_null() {
        return null_mut();
    }
    unsafe { ptr::read(ptr::addr_of!((*leaf)[d])) }
}

/// Set one existing map leaf while holding the map write lock.
unsafe fn map_store(map: *mut AioMap, descriptor: c_int, queue: *mut AioQueue) {
    let (a, b, c, d) = unsafe { descriptor_indices(descriptor) };
    let one = unsafe { ptr::read(ptr::addr_of!((*map)[a])) };
    let two = unsafe { ptr::read(ptr::addr_of!((*one)[b])) };
    let leaf = unsafe { ptr::read(ptr::addr_of!((*two)[c])) };
    unsafe { ptr::write(ptr::addr_of_mut!((*leaf)[d]), queue) };
}

/// Allocate one zeroed map level only when its slot is absent.
unsafe fn ensure_level<T>(slot: *mut *mut T) -> *mut T {
    let current = unsafe { ptr::read(slot) };
    if !current.is_null() {
        return current;
    }
    let allocation = unsafe { super::allocator::allocate_zeroed_internal(size_of::<T>()) }.cast::<T>();
    if !allocation.is_null() {
        unsafe { ptr::write(slot, allocation) };
    }
    allocation
}

/// Obtain an existing queue, or create and lock one under musl's four-level
/// map protocol. A non-null return always arrives with its queue mutex held.
unsafe fn get_queue(descriptor: c_int, need: bool) -> *mut AioQueue {
    if descriptor < 0 {
        unsafe { errno::set_errno(EBADF) };
        return null_mut();
    }

    unsafe { map_read_lock() };
    let mut queue = unsafe { map_lookup(QUEUE_MAP.load(Ordering::Acquire), descriptor) };
    let mut masked = false;
    let mut original_mask = SignalSet::empty();
    if queue.is_null() && need {
        unsafe { map_unlock() };
        let descriptor_status = unsafe {
            raw_syscall::syscall2(raw_syscall::SYS_FCNTL, i64::from(descriptor), F_GETFD)
        };
        if descriptor_status < 0 {
            // SAFETY: this is the source fcntl error boundary before any AIO
            // allocation or map mutation.
            unsafe { super::c_status(descriptor_status) };
            return null_mut();
        }

        let mut all_mask = SignalSet::empty();
        unsafe {
            signal_set_mutation::sigfillset(ptr::addr_of_mut!(all_mask).cast());
            let _ = signal_control::pthread_sigmask(
                SIG_BLOCK,
                ptr::addr_of!(all_mask).cast(),
                ptr::addr_of_mut!(original_mask).cast(),
            );
            map_write_lock();
        }
        masked = true;

        if IO_THREAD_STACK_SIZE.load(Ordering::Relaxed) == 0 {
            let auxiliary_minimum = unsafe { auxv_observation::__getauxval(AT_MINSIGSTKSZ) } as usize;
            IO_THREAD_STACK_SIZE.store(
                (MINSIGSTKSZ + 2_048).max(auxiliary_minimum.saturating_add(512)),
                Ordering::Release,
            );
        }

        let mut map = QUEUE_MAP.load(Ordering::Acquire);
        if map.is_null() {
            map = unsafe { super::allocator::allocate_zeroed_internal(size_of::<AioMap>()) }.cast();
            if !map.is_null() {
                QUEUE_MAP.store(map, Ordering::Release);
            }
        }
        if !map.is_null() {
            let (a, b, c, d) = unsafe { descriptor_indices(descriptor) };
            let one = unsafe { ensure_level(ptr::addr_of_mut!((*map)[a])) };
            let two = if one.is_null() {
                null_mut()
            } else {
                unsafe { ensure_level(ptr::addr_of_mut!((*one)[b])) }
            };
            let leaf = if two.is_null() {
                null_mut()
            } else {
                unsafe { ensure_level(ptr::addr_of_mut!((*two)[c])) }
            };
            if !leaf.is_null() {
                queue = unsafe { ptr::read(ptr::addr_of!((*leaf)[d])) };
                if queue.is_null() {
                    queue = unsafe { super::allocator::allocate_zeroed_internal(size_of::<AioQueue>()) }.cast();
                    if !queue.is_null() {
                        unsafe {
                            (*queue).descriptor = descriptor;
                            let _ = pthread_mutex::pthread_mutex_init(
                                ptr::addr_of_mut!((*queue).lock).cast(),
                                null(),
                            );
                            let _ = pthread_cond::pthread_cond_init(
                                ptr::addr_of_mut!((*queue).condition).cast(),
                                null(),
                            );
                            ptr::write(ptr::addr_of_mut!((*leaf)[d]), queue);
                        }
                        AIO_FD_COUNT.fetch_add(1, Ordering::AcqRel);
                    }
                }
            }
        }
    }

    if !queue.is_null() {
        unsafe { queue_lock(queue) };
    }
    unsafe { map_unlock() };
    if masked {
        unsafe {
            let _ = signal_control::pthread_sigmask(
                SIG_SETMASK,
                ptr::addr_of!(original_mask).cast(),
                null_mut(),
            );
        }
    }
    queue
}

/// Drop one queue's worker reference, following musl's unlock/relock-last-ref
/// transition so a new submitter cannot race a free after the queue lock is
/// released to obtain the map write lock.
///
/// A close may already have detached this queue from its descriptor slot so
/// that a recycled descriptor creates a fresh incarnation. The allocation
/// counter still belongs to the final worker free, but that final removal may
/// clear a slot only when it still names this exact queue: a later queue for
/// the same integer descriptor must remain discoverable.
unsafe fn unref_queue(queue: *mut AioQueue) {
    if unsafe { (*queue).references } > 1 {
        unsafe {
            (*queue).references -= 1;
            queue_unlock(queue);
        }
        return;
    }

    unsafe {
        queue_unlock(queue);
        map_write_lock();
        queue_lock(queue);
    }
    if unsafe { (*queue).references } == 1 {
        let descriptor = unsafe { (*queue).descriptor };
        let map = QUEUE_MAP.load(Ordering::Acquire);
        if !map.is_null() && unsafe { map_lookup(map, descriptor) } == queue {
            unsafe { map_store(map, descriptor, null_mut()) };
        }
        AIO_FD_COUNT.fetch_sub(1, Ordering::AcqRel);
        unsafe {
            map_unlock();
            queue_unlock(queue);
            super::allocator::deallocate_internal(queue.cast());
        }
    } else {
        unsafe {
            (*queue).references -= 1;
            map_unlock();
            queue_unlock(queue);
        }
    }
}

/// Read just the selector from a caller-owned notification record.
///
/// This deliberately precedes every other access to `Sigevent`: the selector
/// determines which members POSIX requires the caller to initialize.
#[inline]
unsafe fn notification_selector(event: *const Sigevent) -> c_int {
    unsafe { ptr::read(ptr::addr_of!((*event).notify)) }
}

/// Snapshot the fields needed to deliver one completion notification.
///
/// # Safety
///
/// `event` must name a live aligned public `sigevent`. Its `notify` word must
/// be initialized. For `SIGEV_SIGNAL`, `signal` and the active `Sigval` member
/// must be initialized; for `SIGEV_THREAD`, the callback and active `Sigval`
/// member must be initialized. No other public `sigevent` field is read.
unsafe fn notification_snapshot(event: *const Sigevent) -> NotificationSnapshot {
    match unsafe { notification_selector(event) } {
        SIGEV_NONE => NotificationSnapshot::None,
        SIGEV_SIGNAL => NotificationSnapshot::Signal {
            signal: unsafe { ptr::read(ptr::addr_of!((*event).signal)) },
            // A raw `repr(C)` union copy preserves the initialized C active
            // member without reading either `integer` or `pointer` as a Rust
            // scalar. Its unused union bytes remain opaque.
            value: unsafe { ptr::read(ptr::addr_of!((*event).value)) },
        },
        SIGEV_THREAD => NotificationSnapshot::Thread {
            function: unsafe {
                ptr::read(ptr::addr_of!((*event).fields.thread.function))
            },
            value: unsafe { ptr::read(ptr::addr_of!((*event).value)) },
        },
        _ => NotificationSnapshot::Other,
    }
}

/// Deliver a source-shaped SIGEV_SIGNAL completion notification.
unsafe fn notify_signal(signal: c_int, value: Sigval) {
    let info = QueuedSigInfo {
        signal,
        error: 0,
        code: SI_ASYNCIO,
        alignment_padding: 0,
        process_id: unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETPID) } as c_int,
        user_id: unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETUID) } as c_uint,
        value,
        tail: [0; 96],
    };
    // SAFETY: Linux reads this complete initialized siginfo record. Source
    // intentionally ignores queueing failures at asynchronous completion.
    let _ = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_RT_SIGQUEUEINFO,
            i64::from(info.process_id),
            i64::from(signal),
            ptr::addr_of!(info) as usize as i64,
        )
    };
}

/// Invoke the already-snapshotted completion mode after source queue cleanup.
unsafe fn deliver_notification(notification: NotificationSnapshot) {
    match notification {
        NotificationSnapshot::Signal { signal, value } => unsafe { notify_signal(signal, value) },
        NotificationSnapshot::Thread { function, value } => {
            // SIGEV_THREAD requires a live non-null callback. As in source,
            // violating that C contract is not silently converted to NONE.
            unsafe { function.unwrap_unchecked()(value) };
        }
        NotificationSnapshot::None | NotificationSnapshot::Other => {}
    }
}

/// Common worker cleanup with the bounded canceler pin protocol.
///
/// The musl source publishes completion before unlinking. The owned correction
/// first owns the queue mutex (unless condition cancellation already reacquired
/// it), then retains that source store order while it is impossible for a
/// canceler to observe `running == 0`, reacquire the queue, and return before
/// the aiocb completion word has been published. A pinned worker retains its
/// original queue reference through pin drainage, so cancellation never frees
/// a queue from `aio_cancel` or returns through a stack record too early.
unsafe extern "C" fn cleanup_worker(context: *mut c_void) {
    let worker = context.cast::<AioThread>();
    let queue = unsafe { (*worker).queue };
    let control = unsafe { (*worker).control };
    // Snapshot the active notification arm before terminal publication. The
    // caller may reclaim the aiocb as soon as it observes that publication.
    // `notification_snapshot` deliberately does not load unused C fields.
    let notification = unsafe {
        notification_snapshot(ptr::addr_of!((*control).signal_event))
    };
    // Obtain the completion-word address before its terminal publication.
    // `aio_suspend` may observe that release exchange, return to C, and allow
    // the caller to reclaim the aiocb immediately. Even an addr_of-based
    // projection from `control` after that point would require the old base
    // allocation to remain valid, so the wake below must use only this cached
    // raw address and never dereference/project the aiocb again.
    let completion_word = unsafe { control_error_word(control) };

    // A condition cancellation returns with `queue.lock` reacquired before it
    // enters active cleanup. I/O cancellation arrives outside it. The local
    // flag is set/cleared only by this worker around that exact transition.
    if unsafe { (*worker).queue_lock_held.swap(0, Ordering::AcqRel) } == 0 {
        unsafe { queue_lock(queue) };
    }

    // The caller observes `result` only after acquire-reading the completion
    // error word. This plain write is therefore ordered by the release swap.
    unsafe { ptr::write(ptr::addr_of_mut!((*control).result), (*worker).result) };
    if unsafe { (*worker).running.swap(0, Ordering::AcqRel) } < 0 {
        unsafe { futex_wake((*worker).running.as_ptr()) };
    }
    if unsafe { atomic::x86_64_swap_acqrel_i32(completion_word, (*worker).error) } != EINPROGRESS {
        unsafe { futex_wake(completion_word) };
    }
    if AIO_FUTEX.swap(0, Ordering::AcqRel) != 0 {
        unsafe { futex_wake(AIO_FUTEX.as_ptr()) };
    }

    unsafe {
        queue_unlink_node(queue, ptr::addr_of_mut!((*worker).link));
        queue_broadcast(queue);
    }

    if unsafe { (*worker).cancel_waiters.load(Ordering::Acquire) } == 0 {
        // No canceler escaped the queue lock with this worker pinned, so the
        // worker's original source reference may take the normal last-ref
        // path immediately.
        unsafe { unref_queue(queue) };
    } else {
        // Keep the original worker reference alive. A canceler decrements and
        // wakes only while it holds q; after the wake we reacquire q before
        // testing zero and invoking the only queue-freeing path.
        unsafe { queue_unlock(queue) };
        loop {
            unsafe { wait_for_worker_cancellation_pins(worker) };
            unsafe { queue_lock(queue) };
            if unsafe { (*worker).cancel_waiters.load(Ordering::Acquire) } == 0 {
                unsafe { unref_queue(queue) };
                break;
            }
            unsafe { queue_unlock(queue) };
        }
    }

    if matches!(notification, NotificationSnapshot::Thread { .. }) {
        // `aio.c` clears just the current cancellation pending word before it
        // enters its per-request worker callback. `lio_listio.c` deliberately
        // does not do this in its independent waiter path.
        pthread_cancel::clear_current_aio_callback_pending();
    }
    unsafe { deliver_notification(notification) };
}

/// One detached per-request worker, directly shaped after musl `io_thread_func`.
unsafe extern "C" fn io_thread(context: *mut c_void) -> *mut c_void {
    let arguments = context.cast::<AioArgs>();
    // Copy every handoff field before posting the stack semaphore. The parent
    // may return and reuse `AioArgs` as soon as it receives that post.
    let control = unsafe { (*arguments).control };
    let descriptor = unsafe { (*control).descriptor };
    let operation = unsafe { (*arguments).operation };
    let buffer = unsafe { (*control).buffer };
    let byte_count = unsafe { (*control).byte_count };
    let offset = unsafe { (*control).offset };
    let queue = unsafe { (*arguments).queue };

    let mut worker = AioThread {
        thread: null_mut(),
        control,
        link: AioListNode::worker(),
        queue,
        running: AtomicI32::new(1),
        cancel_waiters: AtomicI32::new(0),
        queue_lock_held: AtomicI32::new(0),
        error: ECANCELED,
        operation,
        result: -1,
    };

    unsafe {
        queue_lock(queue);
        worker.queue_lock_held.store(1, Ordering::Release);
        let _ = posix_semaphore::sem_post(ptr::addr_of_mut!((*arguments).semaphore).cast());
        worker.thread = pthread_identity::current_thread_pointer().cast();
        queue_link_head(queue, ptr::addr_of_mut!(worker.link));

        if (*queue).initialized == 0 {
            let position = descriptor_io::__lseek(descriptor, 0, SEEK_CUR);
            (*queue).seekable = c_int::from(position >= 0);
            let flags = raw_syscall::syscall2(
                raw_syscall::SYS_FCNTL,
                i64::from(descriptor),
                F_GETFL,
            );
            (*queue).append = c_int::from((*queue).seekable == 0 || flags & O_APPEND != 0);
            (*queue).initialized = 1;
        }
    }

    let mut cleanup = MaybeUninit::<pthread_cancel::CleanupNode>::uninit();
    unsafe {
        pthread_cancel::_pthread_cleanup_push(
            cleanup.as_mut_ptr(),
            Some(cleanup_worker),
            ptr::addr_of_mut!(worker).cast(),
        );
    }

    if operation != LIO_READ && (operation != LIO_WRITE || unsafe { (*queue).append } != 0) {
        loop {
            let mut predecessor = worker.link.next;
            while !predecessor.is_null() {
                if unsafe { (*predecessor).kind } == AIO_LIST_WORKER
                    && unsafe { (*worker_from_link(predecessor)).operation } == LIO_WRITE
                {
                    break;
                }
                predecessor = unsafe { (*predecessor).next };
            }
            if predecessor.is_null() {
                break;
            }
            // Cancellation follows the selected cond-wait cleanup/relock
            // protocol before this worker's outer AIO cleanup runs.
            unsafe { queue_wait(queue) };
        }
    }

    let append = unsafe { (*queue).append != 0 };
    let seekable = unsafe { (*queue).seekable != 0 };
    // No cancellation point lies between this store and the unlock. A later
    // I/O cancellation enters cleanup without owning q; a condition wait
    // cancellation left this flag true until its required reacquisition.
    worker.queue_lock_held.store(0, Ordering::Release);
    unsafe { queue_unlock(queue) };

    let result = match operation {
        LIO_WRITE if append => unsafe { descriptor_io::write(descriptor, buffer.cast(), byte_count) },
        LIO_WRITE => unsafe { descriptor_io::pwrite(descriptor, buffer.cast(), byte_count, offset) },
        LIO_READ if !seekable => unsafe { descriptor_io::read(descriptor, buffer, byte_count) },
        LIO_READ => unsafe { descriptor_io::pread(descriptor, buffer, byte_count, offset) },
        O_SYNC => descriptor_io::fsync(descriptor) as isize,
        O_DSYNC => descriptor_io::fdatasync(descriptor) as isize,
        _ => -1,
    };
    worker.result = result;
    worker.error = if result < 0 { unsafe { errno::get_errno() } } else { 0 };

    unsafe { pthread_cancel::_pthread_cleanup_pop(cleanup.as_mut_ptr(), 1) };
    null_mut()
}

/// Make the source's SIGEV_THREAD/non-SIGEV_THREAD detached worker attribute.
///
/// The submitter needs only `notify` and, for SIGEV_THREAD, the optional
/// attribute pointer. It must not read the callback, value, signo, or padding
/// before the worker later snapshots the active notification arm.
unsafe fn worker_attributes(event: *const Sigevent) -> PublicPthreadAttr {
    let mut attributes = PublicPthreadAttr { words: [0; 7] };
    if unsafe { notification_selector(event) } == SIGEV_THREAD {
        let source = unsafe {
            ptr::read(ptr::addr_of!((*event).fields.thread.attributes))
        };
        if !source.is_null() {
            attributes = unsafe { ptr::read(source) };
        } else {
            let _ = unsafe { pthread_attr::pthread_attr_init(ptr::addr_of_mut!(attributes).cast()) };
        }
    } else {
        let _ = unsafe { pthread_attr::pthread_attr_init(ptr::addr_of_mut!(attributes).cast()) };
        let _ = unsafe {
            pthread_attr::pthread_attr_setstacksize(
                ptr::addr_of_mut!(attributes).cast(),
                IO_THREAD_STACK_SIZE.load(Ordering::Acquire),
            )
        };
        let _ = unsafe {
            pthread_attr::pthread_attr_setguardsize(ptr::addr_of_mut!(attributes).cast(), 0)
        };
    }
    let _ = unsafe { pthread_attr::pthread_attr_setdetachstate(ptr::addr_of_mut!(attributes).cast(), 1) };
    attributes
}

/// Submit one read, write, or sync request. The caller supplies a live aiocb
/// and all POSIX buffer/descriptor/notification lifetimes through completion.
unsafe fn submit(control: *mut AioCb, operation: c_int) -> c_int {
    // `__aio_get_queue`'s fresh path briefly blocks application signals while
    // it mutates the map, but musl restores the old mask after acquiring q
    // and before returning q still locked.  An already-pending handler that
    // closes this descriptor can then reenter `aio_cancel` and wait for that
    // very q.  Keep one outer all-application mask from before *any*
    // get-queue path through the source-shaped reference increment and unlock.
    // The inner fresh-path block/restoration remains harmlessly nested: it
    // restores this all-blocked outer mask, not the caller's original mask.
    let mut queue_all_mask = SignalSet::empty();
    let mut queue_original_mask = SignalSet::empty();
    unsafe {
        signal_set_mutation::sigfillset(ptr::addr_of_mut!(queue_all_mask).cast());
        let _ = signal_control::pthread_sigmask(
            SIG_BLOCK,
            ptr::addr_of!(queue_all_mask).cast(),
            ptr::addr_of_mut!(queue_original_mask).cast(),
        );
    }
    let queue = unsafe { get_queue((*control).descriptor, true) };
    let mut arguments = AioArgs {
        control,
        queue,
        operation,
        semaphore: PublicSemaphore { words: [0; 8] },
    };
    let _ = unsafe { posix_semaphore::sem_init(ptr::addr_of_mut!(arguments.semaphore).cast(), 0, 0) };

    if queue.is_null() {
        // This includes invalid descriptors and allocation/fcntl failures.
        // No AIO lock survives a null get_queue result, so restore before
        // translating the source failure into the public control state.
        unsafe {
            let _ = signal_control::pthread_sigmask(
                SIG_SETMASK,
                ptr::addr_of!(queue_original_mask).cast(),
                null_mut(),
            );
        }
        if unsafe { errno::get_errno() } != EBADF {
            unsafe { errno::set_errno(EAGAIN) };
        }
        let error = unsafe { errno::get_errno() };
        unsafe {
            ptr::write(ptr::addr_of_mut!((*control).result), -1);
            control_error_store(control, error);
        }
        return -1;
    }

    unsafe {
        (*queue).references += 1;
        queue_unlock(queue);
        let _ = signal_control::pthread_sigmask(
            SIG_SETMASK,
            ptr::addr_of!(queue_original_mask).cast(),
            null_mut(),
        );
    }

    let attributes = unsafe {
        worker_attributes(ptr::addr_of!((*control).signal_event))
    };
    unsafe {
        control_error_store(control, EINPROGRESS);
    }

    // This is the separate source-shaped worker-creation mask. The earlier
    // queue mask closed the fresh/existing get_queue lock window and has
    // already been restored; do not extend this creation mask across the
    // private stack handoff.
    let mut create_all_mask = SignalSet::empty();
    let mut create_original_mask = SignalSet::empty();
    unsafe {
        signal_set_mutation::sigfillset(ptr::addr_of_mut!(create_all_mask).cast());
        let _ = signal_control::pthread_sigmask(
            SIG_BLOCK,
            ptr::addr_of!(create_all_mask).cast(),
            ptr::addr_of_mut!(create_original_mask).cast(),
        );
    }
    let mut thread = null_mut();
    let create_result = unsafe {
        pthread_create_join::pthread_create(
            ptr::addr_of_mut!(thread),
            ptr::addr_of!(attributes).cast(),
            Some(io_thread),
            ptr::addr_of_mut!(arguments).cast(),
        )
    };
    let mut result = 0;
    if create_result != 0 {
        unsafe {
            queue_lock(queue);
            unref_queue(queue);
            errno::set_errno(EAGAIN);
            ptr::write(ptr::addr_of_mut!((*control).result), -1);
            control_error_store(control, EAGAIN);
        }
        result = -1;
    }
    unsafe {
        let _ = signal_control::pthread_sigmask(
            SIG_SETMASK,
            ptr::addr_of!(create_original_mask).cast(),
            null_mut(),
        );
    }
    if result == 0 {
        // The worker copies every AioArgs field before it posts. This private
        // wait intentionally is not sem_wait: POSIX does not make AIO submit
        // a cancellation point, but source signal-mask restoration precedes
        // the caller's stack handoff.
        unsafe {
            posix_semaphore::wait_aio_handoff_without_cancellation(
                ptr::addr_of_mut!(arguments.semaphore).cast(),
            );
        }
    }
    result
}

/// Queue one positioned/as-appropriate read request.
///
/// # Safety
/// `control` must designate a live aligned public `aiocb`; its descriptor,
/// buffer and notification/storage lifetimes must meet POSIX through request
/// completion/cancellation and `aio_return` observation.
#[no_mangle]
pub unsafe extern "C" fn aio_read(control: *mut AioCb) -> c_int {
    unsafe { submit(control, LIO_READ) }
}

/// Queue one positioned/as-appropriate write request.
///
/// # Safety
/// See [`aio_read`]; the buffer must be readable for the worker I/O duration.
#[no_mangle]
pub unsafe extern "C" fn aio_write(control: *mut AioCb) -> c_int {
    unsafe { submit(control, LIO_WRITE) }
}

/// Queue one fsync/fdatasync request after validating musl's operation word.
///
/// # Safety
/// `control` has the same lifetime requirements as [`aio_read`].
#[no_mangle]
pub unsafe extern "C" fn aio_fsync(operation: c_int, control: *mut AioCb) -> c_int {
    if operation != O_SYNC && operation != O_DSYNC {
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }
    unsafe { submit(control, operation) }
}

/// Return the completed request byte count/result.
///
/// # Safety
/// The caller must first observe a non-`EINPROGRESS` result through
/// [`aio_error`] and keep the aiocb live. That acquire observation pairs with
/// the worker's release completion before this source-shaped plain result read.
#[no_mangle]
pub unsafe extern "C" fn aio_return(control: *mut AioCb) -> isize {
    unsafe { ptr::read(ptr::addr_of!((*control).result)) }
}

/// Observe one request's atomic completion/error state.
///
/// # Safety
/// `control` must name a live aligned aiocb whose error word participates only
/// in this AIO atomic protocol while the request is outstanding.
#[no_mangle]
pub unsafe extern "C" fn aio_error(control: *const AioCb) -> c_int {
    unsafe { control_error_load(control.cast_mut()) & 0x7fff_ffff }
}

/// Cancel one matching live request or all requests for a descriptor.
///
/// # Safety
/// `control`, when non-null, must be a live aiocb for `descriptor`; the
/// descriptor and all queued request objects retain POSIX-required lifetimes.
#[no_mangle]
pub unsafe extern "C" fn aio_cancel(descriptor: c_int, control: *mut AioCb) -> c_int {
    if !control.is_null() && descriptor != unsafe { (*control).descriptor } {
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }

    let mut all_mask = SignalSet::empty();
    let mut original_mask = SignalSet::empty();
    unsafe {
        signal_set_mutation::sigfillset(ptr::addr_of_mut!(all_mask).cast());
        let _ = signal_control::pthread_sigmask(
            SIG_BLOCK,
            ptr::addr_of!(all_mask).cast(),
            ptr::addr_of_mut!(original_mask).cast(),
        );
        errno::set_errno(ENOENT);
    }

    let mut result = AIO_ALLDONE;
    let queue = unsafe { get_queue(descriptor, false) };
    if queue.is_null() {
        if unsafe { errno::get_errno() } == EBADF {
            result = -1;
        }
    } else {
        // The source holds q over its entire traversal. That deadlocks when a
        // sequenced worker is cancelled inside pthread_cond_wait: its cleanup
        // must reacquire q before it can publish running=0. The cursor bounds
        // the exact source-visible request set while we release q per pinned
        // worker. It is stack storage only; all queue mutation remains under
        // q and no new allocation/refcount ownership is introduced here.
        let mut cursor = AioCancelCursor {
            link: AioListNode::cancel_cursor(),
        };
        let cursor_link = ptr::addr_of_mut!(cursor.link);
        unsafe { queue_link_head(queue, cursor_link) };

        loop {
            let node = unsafe { (*cursor_link).next };
            if node.is_null() {
                unsafe {
                    queue_unlink_node(queue, cursor_link);
                    queue_unlock(queue);
                }
                break;
            }

            if unsafe { (*node).kind } == AIO_LIST_CANCEL_CURSOR {
                // Concurrent cancelers publish their own finite boundaries.
                // Advancing across one never crosses a real worker backward.
                unsafe { advance_cancel_cursor(queue, cursor_link) };
                continue;
            }

            debug_assert!(unsafe { (*node).kind } == AIO_LIST_WORKER);
            let worker = unsafe { worker_from_link(node) };
            let matches = control.is_null() || control == unsafe { (*worker).control };
            if !matches {
                unsafe { advance_cancel_cursor(queue, cursor_link) };
                continue;
            }

            // Source treats both old values one and minus one as live: the
            // first caller requests cancellation, later callers join its
            // completion edge. A completed zero is already all-done and is
            // only crossed by the bounded cursor.
            let (pinned, request_cancellation) = unsafe { pin_worker_cancellation(worker) };
            unsafe { advance_cancel_cursor(queue, cursor_link) };
            if !pinned {
                continue;
            }

            if request_cancellation {
                let _ = unsafe { pthread_cancel::pthread_cancel((*worker).thread) };
            }
            // This is the only unlocked interval in a traversal. The counted
            // pin retains both `worker` and its original queue reference.
            unsafe {
                queue_unlock(queue);
                wait_while_equal((*worker).running.as_ptr(), -1);
            }
            // The running release-to-zero publishes this immutable worker
            // error; keeping the pin until after q reacquisition keeps its
            // stack storage live even if cleanup has already unlinked it.
            let error = unsafe { ptr::read(ptr::addr_of!((*worker).error)) };
            unsafe {
                queue_lock(queue);
                unpin_worker_cancellation(worker);
            }
            // Preserve musl's accumulation: successful cancellation changes
            // ALLDONE to CANCELED; an ordinary completion leaves ALLDONE (or
            // an earlier CANCELED) rather than inventing NOTCANCELED.
            if error == ECANCELED {
                result = AIO_CANCELED;
            }
        }
    }

    unsafe {
        let _ = signal_control::pthread_sigmask(
            SIG_SETMASK,
            ptr::addr_of!(original_mask).cast(),
            null_mut(),
        );
    }
    result
}

/// Wait until at least one listed control block has completed.
///
/// # Safety
/// `controls` must name `count` readable aiocb pointers when `count > 0`;
/// every non-null control block must retain the same atomic AIO lifetime until
/// this call returns. `timeout`, when non-null, names one readable x86
/// `timespec` duration record.
#[no_mangle]
pub unsafe extern "C" fn aio_suspend(
    controls: *const *const AioCb,
    count: c_int,
    timeout: *const Timespec,
) -> c_int {
    pthread_cancel::test_current_selected_pthread_cancellation();
    if count < 0 {
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }

    let count = count as usize;
    let mut non_null_count = 0usize;
    let mut last_control = null_mut();
    for index in 0..count {
        let control = unsafe { ptr::read(controls.add(index)) }.cast_mut();
        if !control.is_null() {
            if unsafe { aio_error(control) } != EINPROGRESS {
                return 0;
            }
            non_null_count += 1;
            last_control = control;
        }
    }

    let mut absolute = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    let deadline = if timeout.is_null() {
        null()
    } else {
        // Source ignores a failed clock query and then adds to its local
        // record. A zero initializer keeps this Rust port defined on that
        // otherwise unrepresentable kernel-failure path.
        let _ = unsafe {
            raw_syscall::syscall2(
                raw_syscall::SYS_CLOCK_GETTIME,
                i64::from(CLOCK_MONOTONIC),
                ptr::addr_of_mut!(absolute) as usize as i64,
            )
        };
        let duration = unsafe { ptr::read(timeout) };
        absolute.seconds = absolute.seconds.wrapping_add(duration.seconds);
        absolute.nanoseconds = absolute.nanoseconds.wrapping_add(duration.nanoseconds);
        if absolute.nanoseconds >= NANOS_PER_SECOND {
            absolute.nanoseconds -= NANOS_PER_SECOND;
            absolute.seconds = absolute.seconds.wrapping_add(1);
        }
        ptr::addr_of!(absolute)
    };

    let dummy = AtomicI32::new(0);
    let mut thread_id = 0;
    loop {
        for index in 0..count {
            let control = unsafe { ptr::read(controls.add(index)) }.cast_mut();
            if !control.is_null() && unsafe { aio_error(control) } != EINPROGRESS {
                return 0;
            }
        }

        let (futex, expected) = match non_null_count {
            0 => (dummy.as_ptr(), 0),
            1 => {
                let word = unsafe { control_error_word(last_control) };
                let expected = EINPROGRESS | c_int::MIN;
                let _ = unsafe { atomic::x86_64_compare_exchange_acqrel_i32(word, EINPROGRESS, expected) };
                (word, expected)
            }
            _ => {
                if thread_id == 0 {
                    thread_id = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) } as c_int;
                }
                let observed = unsafe {
                    atomic::x86_64_compare_exchange_acqrel_i32(
                        AIO_FUTEX.as_ptr(),
                        0,
                        thread_id,
                    )
                };
                let expected = if observed == 0 { thread_id } else { observed };
                // Source rechecks after it has joined the shared global futex
                // protocol, closing the completion-before-sleep race.
                for index in 0..count {
                    let control = unsafe { ptr::read(controls.add(index)) }.cast_mut();
                    if !control.is_null() && unsafe { aio_error(control) } != EINPROGRESS {
                        return 0;
                    }
                }
                (AIO_FUTEX.as_ptr(), expected)
            }
        };

        let wait_result = unsafe { timed_wait_cp(futex, expected, CLOCK_MONOTONIC, deadline, true) };
        match wait_result {
            ETIMEDOUT => {
                unsafe { errno::set_errno(EAGAIN) };
                return -1;
            }
            ECANCELED | EINTR => {
                unsafe { errno::set_errno(wait_result) };
                return -1;
            }
            _ => {}
        }
    }
}

/// Internal list state allocated with the public `malloc` spelling, exactly as
/// `lio_listio.c` does. Its flexible aiocb pointer array follows this prefix.
#[repr(C)]
struct LioState {
    event: *mut Sigevent,
    count: c_int,
}

const _: () = {
    assert!(size_of::<LioState>() == 16);
    assert!(align_of::<LioState>() == 8);
};

// `lio_listio.c` intentionally uses public malloc/free rather than aio.c's
// `__libc_*` macros. These thunks retain executable interposition in libc.so:
// a Rust-level call could bind this crate's known weak wrapper before the ELF
// lookup boundary, while the assembly jumps retain an ordinary PLT relocation.
core::arch::global_asm!(r#"
    .text
    .p2align 4
    .globl __crabc_x86_aio_cabi_malloc
    .hidden __crabc_x86_aio_cabi_malloc
    .type __crabc_x86_aio_cabi_malloc,@function
__crabc_x86_aio_cabi_malloc:
    jmp malloc
    .size __crabc_x86_aio_cabi_malloc, .-__crabc_x86_aio_cabi_malloc

    .p2align 4
    .globl __crabc_x86_aio_cabi_free
    .hidden __crabc_x86_aio_cabi_free
    .type __crabc_x86_aio_cabi_free,@function
__crabc_x86_aio_cabi_free:
    jmp free
    .size __crabc_x86_aio_cabi_free, .-__crabc_x86_aio_cabi_free
"#);

unsafe extern "C" {
    #[link_name = "__crabc_x86_aio_cabi_malloc"]
    fn public_malloc(size: usize) -> *mut c_void;
    #[link_name = "__crabc_x86_aio_cabi_free"]
    fn public_free(pointer: *mut c_void);
}

#[inline(always)]
unsafe fn state_controls(state: *mut LioState) -> *mut *mut AioCb {
    unsafe { state.cast::<u8>().add(size_of::<LioState>()).cast() }
}

/// Source `lio_wait`: consume completed slots and use `aio_suspend` until all
/// state-owned controls are done, reporting EIO if any completed with error.
unsafe fn lio_wait(state: *mut LioState) -> c_int {
    let count = unsafe { (*state).count as usize };
    let controls = unsafe { state_controls(state) };
    let mut got_error = false;
    loop {
        let mut index = 0usize;
        while index < count {
            let control = unsafe { ptr::read(controls.add(index)) };
            if control.is_null() {
                index += 1;
                continue;
            }
            let error = unsafe { aio_error(control) };
            if error == EINPROGRESS {
                break;
            }
            if error != 0 {
                got_error = true;
            }
            unsafe { ptr::write(controls.add(index), null_mut()) };
            index += 1;
        }
        if index == count {
            if got_error {
                unsafe { errno::set_errno(EIO) };
                return -1;
            }
            return 0;
        }
        if unsafe { aio_suspend(controls.cast(), count as c_int, null()) } != 0 {
            return -1;
        }
    }
}

/// Detached `LIO_NOWAIT` completion waiter.
unsafe extern "C" fn list_wait_thread(context: *mut c_void) -> *mut c_void {
    let state = context.cast::<LioState>();
    let event = unsafe { (*state).event };
    let _ = unsafe { lio_wait(state) };
    // This is deliberately the public free boundary. The source subsequently
    // uses its separately saved caller event pointer, not state storage.
    unsafe { public_free(state.cast()) };
    let notification = unsafe { notification_snapshot(event) };
    unsafe { deliver_notification(notification) };
    null_mut()
}

/// Construct the source `lio_listio.c` async waiter attribute record.
unsafe fn list_wait_attributes(event: *mut Sigevent) -> PublicPthreadAttr {
    let mut attributes = PublicPthreadAttr { words: [0; 7] };
    if unsafe { notification_selector(event) } == SIGEV_THREAD {
        let source = unsafe {
            ptr::read(ptr::addr_of!((*event).fields.thread.attributes))
        };
        if !source.is_null() {
            attributes = unsafe { ptr::read(source) };
        } else {
            let _ = unsafe { pthread_attr::pthread_attr_init(ptr::addr_of_mut!(attributes).cast()) };
        }
    } else {
        let _ = unsafe { pthread_attr::pthread_attr_init(ptr::addr_of_mut!(attributes).cast()) };
        let _ = unsafe {
            pthread_attr::pthread_attr_setstacksize(ptr::addr_of_mut!(attributes).cast(), PAGE_SIZE)
        };
        let _ = unsafe {
            pthread_attr::pthread_attr_setguardsize(ptr::addr_of_mut!(attributes).cast(), 0)
        };
    }
    let _ = unsafe { pthread_attr::pthread_attr_setdetachstate(ptr::addr_of_mut!(attributes).cast(), 1) };
    attributes
}

/// Submit one list of read/write requests and optionally wait/notify.
///
/// # Safety
/// `controls` names `count` readable aiocb pointers when nonzero. Every
/// non-null aiocb, its I/O storage, descriptor, and optional `event` remain
/// live under POSIX's list-I/O lifetime contract until work/notification ends.
#[no_mangle]
pub unsafe extern "C" fn lio_listio(
    mode: c_int,
    controls: *mut *mut AioCb,
    count: c_int,
    event: *mut Sigevent,
) -> c_int {
    if count < 0 {
        unsafe { errno::set_errno(EINVAL) };
        return -1;
    }
    let count_usize = count as usize;
    let mut state = null_mut::<LioState>();
    if mode == LIO_WAIT
        || (!event.is_null() && unsafe { notification_selector(event) } != SIGEV_NONE)
    {
        let size = size_of::<LioState>() + count_usize * size_of::<*mut AioCb>();
        state = unsafe { public_malloc(size) }.cast();
        if state.is_null() {
            unsafe { errno::set_errno(EAGAIN) };
            return -1;
        }
        unsafe {
            (*state).count = count;
            (*state).event = event;
            let destination = state_controls(state);
            for index in 0..count_usize {
                ptr::write(destination.add(index), ptr::read(controls.add(index)));
            }
        }
    }

    for index in 0..count_usize {
        let control = unsafe { ptr::read(controls.add(index)) };
        if control.is_null() {
            continue;
        }
        let result = match unsafe { (*control).list_operation } {
            LIO_READ => unsafe { aio_read(control) },
            LIO_WRITE => unsafe { aio_write(control) },
            _ => continue,
        };
        if result != 0 {
            unsafe {
                public_free(state.cast());
                errno::set_errno(EAGAIN);
            }
            return -1;
        }
    }

    if mode == LIO_WAIT {
        let result = unsafe { lio_wait(state) };
        unsafe { public_free(state.cast()) };
        return result;
    }

    if !state.is_null() {
        let attributes = unsafe { list_wait_attributes(event) };
        let mut all_mask = SignalSet::empty();
        let mut original_mask = SignalSet::empty();
        unsafe {
            signal_set_mutation::sigfillset(ptr::addr_of_mut!(all_mask).cast());
            let _ = signal_control::pthread_sigmask(
                SIG_BLOCK,
                ptr::addr_of!(all_mask).cast(),
                ptr::addr_of_mut!(original_mask).cast(),
            );
        }
        let mut thread = null_mut();
        let create_result = unsafe {
            pthread_create_join::pthread_create(
                ptr::addr_of_mut!(thread),
                ptr::addr_of!(attributes).cast(),
                Some(list_wait_thread),
                state.cast(),
            )
        };
        if create_result != 0 {
            // Source returns without restoring the all-application mask on
            // this failure branch. Preserve that exact musl ordering/edge.
            unsafe {
                public_free(state.cast());
                errno::set_errno(EAGAIN);
            }
            return -1;
        }
        unsafe {
            let _ = signal_control::pthread_sigmask(
                SIG_SETMASK,
                ptr::addr_of!(original_mask).cast(),
                null_mut(),
            );
        }
    }
    0
}

/// Remove the currently visible queue incarnation after close cancellation.
///
/// The caller owns `MAP_LOCK` in write mode before it looks up the queue, so
/// a final worker unref cannot free that mapped object between lookup and its
/// mutex acquisition. The old queue may remain alive after this function:
/// workers and canceler pins retain its source reference until final cleanup.
/// New submissions after the map slot is clear create a distinct queue for a
/// recycled descriptor number. This function deliberately releases both
/// locks before the C close cancellation point reaches the kernel.
unsafe fn detach_visible_queue_incarnation(descriptor: c_int) {
    if descriptor < 0 {
        return;
    }

    // aio.c requires application signals blocked while it takes AIO locks.
    // `aio_cancel` restored its own temporary mask before this separate
    // map-write/queue-lock section, so preserve that lock boundary here too.
    let mut all_mask = SignalSet::empty();
    let mut original_mask = SignalSet::empty();
    unsafe {
        signal_set_mutation::sigfillset(ptr::addr_of_mut!(all_mask).cast());
        let _ = signal_control::pthread_sigmask(
            SIG_BLOCK,
            ptr::addr_of!(all_mask).cast(),
            ptr::addr_of_mut!(original_mask).cast(),
        );
        map_write_lock();
    }

    let map = QUEUE_MAP.load(Ordering::Acquire);
    if !map.is_null() {
        let queue = unsafe { map_lookup(map, descriptor) };
        if !queue.is_null() {
            unsafe {
                // Map write ownership pins this visible allocation until the
                // queue lock is held. `unref_queue` drops q before it asks for
                // this lock, so this order has no q-to-map deadlock edge.
                queue_lock(queue);
                if map_lookup(map, descriptor) == queue {
                    map_store(map, descriptor, null_mut());
                }
                queue_unlock(queue);
            }
        }
    }

    unsafe {
        map_unlock();
        let _ = signal_control::pthread_sigmask(
            SIG_SETMASK,
            ptr::addr_of!(original_mask).cast(),
            null_mut(),
        );
    }
}

/// Musl's private close hook, invoked by the owned descriptor close boundary.
pub(super) unsafe fn close(descriptor: c_int) -> c_int {
    compiler_fence(Ordering::SeqCst);
    if AIO_FD_COUNT.load(Ordering::Acquire) != 0 {
        let _ = unsafe { aio_cancel(descriptor, null_mut()) };
        // `aio_cancel` only waits for terminal worker publication; it need
        // not wait until final unref removes the map entry. Detach the exact
        // visible queue before Linux can recycle this numeric descriptor.
        // Its worker/canceler references still own old storage; final unref
        // is pointer-identity guarded so it cannot erase a replacement.
        unsafe { detach_visible_queue_incarnation(descriptor) };
    }
    descriptor
}

/// Typed private fork hook used by the owned process/fork transitions.
///
/// `who < 0` holds the map read lock across raw fork, zero releases it in the
/// parent/error process, and one drops inherited queue visibility then resets
/// the rwlock in the sole child exactly as musl does.
pub(super) unsafe fn atfork(who: c_int) {
    if who < 0 {
        unsafe { map_read_lock() };
        return;
    }
    if who == 0 {
        unsafe { map_unlock() };
        return;
    }

    AIO_FD_COUNT.store(0, Ordering::Relaxed);
    if unsafe { map_try_read_lock() } != 0 {
        QUEUE_MAP.store(null_mut(), Ordering::Relaxed);
        return;
    }
    let map = QUEUE_MAP.load(Ordering::Acquire);
    if !map.is_null() {
        for a in 0..128 {
            let one = unsafe { ptr::read(ptr::addr_of!((*map)[a])) };
            if one.is_null() {
                continue;
            }
            for b in 0..256 {
                let two = unsafe { ptr::read(ptr::addr_of!((*one)[b])) };
                if two.is_null() {
                    continue;
                }
                for c in 0..256 {
                    let leaf = unsafe { ptr::read(ptr::addr_of!((*two)[c])) };
                    if leaf.is_null() {
                        continue;
                    }
                    for d in 0..256 {
                        unsafe { ptr::write(ptr::addr_of_mut!((*leaf)[d]), null_mut()) };
                    }
                }
            }
        }
    }
    // Do not unlock: the child may inherit several parent readers and is not
    // their owner. Reinitialization is musl's explicit sole-child repair.
    let _ = unsafe { pthread_rwlock::pthread_rwlock_init(MAP_LOCK.pointer(), null()) };
}

/// Strong musl-private spelling retained for objects that bind `aio_impl.h`.
///
/// # Safety
///
/// This is a fork-transaction hook, never a general application entry point.
/// Callers may pass only `-1`, `0`, or `1`: `-1` acquires the map reader
/// before the raw fork; the matching parent/error path calls `0` exactly once
/// after raw fork; and `1` runs only in the sole surviving child after minimal
/// thread repair and abort-lock release, while the inherited all-signal mask
/// is still held. The child path may discard inherited map visibility and
/// reinitialize its copied rwlock only under that sole-survivor condition;
/// invoking it in a live parent would corrupt the map lock protocol.
#[no_mangle]
pub unsafe extern "C" fn __aio_atfork(who: c_int) {
    unsafe { atfork(who) };
}
