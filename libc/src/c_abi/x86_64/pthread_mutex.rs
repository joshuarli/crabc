//! Selected Linux/x86-64 normal and robust `pthread_mutex_*` artifact.
//!
//! This module selects one process-private, normal-mutex state machine over
//! the existing static x86 worker/TLS seam. Its provenance is pinned to musl
//! 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license recorded in `COPYRIGHT`:
//!
//! - `src/thread/pthread_mutex_init.c` supplies the all-zero normal-mutex
//!   initialization shape.
//! - `src/thread/pthread_mutex_trylock.c::{__pthread_mutex_trylock,
//!   __pthread_mutex_trylock_owner}` supplies the normal fast
//!   compare/exchange representation and the robust owner/list insertion
//!   transition.
//! - `src/thread/pthread_mutex_lock.c::__pthread_mutex_lock` and
//!   `src/thread/pthread_mutex_timedlock.c::__pthread_mutex_timedlock` supply
//!   the acquire/retry, waiter-mark, futex-wait, and retry ordering.
//! - `src/thread/pthread_mutex_unlock.c::__pthread_mutex_unlock` supplies the
//!   exchange-before-wake release rule and robust-list removal/pending-node
//!   transaction.
//! - `src/thread/pthread_mutex_destroy.c` supplies the no-resource normal
//!   destroy result and process-shared vmlock drain.
//! - `src/thread/pthread_mutexattr_setrobust.c`,
//!   `pthread_mutexattr_setpshared.c`, and `pthread_mutex_consistent.c`
//!   supply the admitted attribute capability probe/mutation and owner-death
//!   recovery transitions.
//!
//! The normal route admits a zero-initialized or null-attribute
//! `PTHREAD_MUTEX_NORMAL` object. The robust route additionally admits a
//! normal (`type == 0`) robust attribute, with either process-private or
//! process-shared storage. A selected worker or selected initial task that
//! exits while holding such a mutex publishes `EOWNERDEAD`; a recovery owner
//! must call `pthread_mutex_consistent` before unlock or the next owner sees
//! `ENOTRECOVERABLE`. Process-shared robust transitions register the current
//! task's kernel robust list and use the one shared musl `vmlock` owner while
//! their pending node is visible. Contention uses the matching Linux private
//! or shared futex word. Recursive, error-checking, PI, timed, protocol, and
//! priority-ceiling mutexes remain excluded. The separate private
//! condition-variable sibling remains normal-only; it does not admit robust
//! mutexes. This artifact remains outside general pthread synchronization,
//! dynamic main-thread exit/fork repair, loader/CRT integration, and public
//! x86 support. The
//! separately admitted private condition-variable sibling may use this exact
//! state machine internally, and the separate C11 plain-synchronization
//! sibling translates this exact state machine through distinct `mtx_t`
//! storage. Unsupported non-normal, non-robust, or otherwise non-selected
//! type words return `ENOTSUP` without being interpreted.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 normal pthread-mutex leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use super::{atomic, pthread_create_join, pthread_identity, pthread_vmlock, raw_syscall, static_tls};

const EPERM: c_int = 1;
const EBUSY: c_int = 16;
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
const EOWNERDEAD: c_int = 130;
const ENOTRECOVERABLE: c_int = 131;
const ENOTSUP: c_int = 95;

const MUTEX_TYPE_WORD: usize = 0;
const MUTEX_LOCK_WORD: usize = 1;
const MUTEX_WAITERS_WORD: usize = 2;
const MUTEX_WORD_COUNT: usize = 10;
const MUTEX_WAITER_BIT: c_int = c_int::MIN;
const MUTEX_PREVIOUS_OFFSET: usize = 24;
const MUTEX_NEXT_OFFSET: usize = 32;
const MUTEX_COUNT_WORD: usize = 5;

const MUTEX_ROBUST_BIT: c_int = 4;
const MUTEX_PROCESS_SHARED_BIT: c_int = 128;
const MUTEX_SELECTED_ROBUST_BITS: c_int = MUTEX_ROBUST_BIT | MUTEX_PROCESS_SHARED_BIT;
const MUTEX_OWNER_MASK: c_int = 0x3fff_ffff;
const MUTEX_OWNER_DIED_BIT: c_int = 0x4000_0000;
const MUTEX_NOT_RECOVERABLE: c_int = 0x7fff_ffff;
const MUTEXATTR_ROBUST_BIT: u32 = MUTEX_ROBUST_BIT as u32;
const MUTEXATTR_PROCESS_SHARED_BIT: u32 = MUTEX_PROCESS_SHARED_BIT as u32;
const LINUX_ERRNO_MAX: i64 = 4_095;
const LINUX_X86_64_SYS_GET_ROBUST_LIST: i64 = 274;
const LINUX_ROBUST_LIST_SIZE: usize = 3 * size_of::<usize>();

const FUTEX_WAIT: i64 = 0;
const FUTEX_WAKE: i64 = 1;
const FUTEX_PRIVATE_FLAG: i64 = 128;

/// Exact public x86 `pthread_mutex_t` storage.
///
/// The installed C header exposes a 40-byte union with ten `int` words and
/// eight-byte alignment. This private record deliberately names only that
/// storage: it is not a Rust pthread handle or public API type.
#[repr(C, align(8))]
struct PublicPthreadMutex {
    words: [c_int; MUTEX_WORD_COUNT],
}

/// Exact public x86 `pthread_mutexattr_t` storage.
#[repr(C)]
struct PublicPthreadMutexAttr {
    attr: u32,
}

/// Linux's task-local robust-list head ABI.
///
/// The kernel sees this exact three-word record only after a selected
/// process-shared robust mutex asks it to. `head` names either this record's
/// own head slot or a public mutex's `_m_next` slot; `offset` is the signed
/// byte distance from that node to the mutex futex word; `pending` covers the
/// short acquire/unlink transition where the node is not yet linked.
#[repr(C)]
pub(super) struct SelectedRobustList {
    head: *mut c_void,
    offset: isize,
    pending: *mut c_void,
}

impl SelectedRobustList {
    pub(super) const fn empty() -> Self {
        Self {
            head: core::ptr::null_mut(),
            offset: 0,
            pending: core::ptr::null_mut(),
        }
    }
}

const _: () = {
    assert!(size_of::<PublicPthreadMutex>() == 40);
    assert!(align_of::<PublicPthreadMutex>() == 8);
    assert!(offset_of!(PublicPthreadMutex, words) == 0);
    assert!(size_of::<PublicPthreadMutexAttr>() == 4);
    assert!(align_of::<PublicPthreadMutexAttr>() == 4);
    assert!(offset_of!(PublicPthreadMutexAttr, attr) == 0);
    assert!(size_of::<SelectedRobustList>() == LINUX_ROBUST_LIST_SIZE);
    assert!(align_of::<SelectedRobustList>() == align_of::<usize>());
    assert!(offset_of!(SelectedRobustList, head) == 0);
    assert!(offset_of!(SelectedRobustList, offset) == size_of::<usize>());
    assert!(offset_of!(SelectedRobustList, pending) == 2 * size_of::<usize>());
};

// Match musl's static `check_robust_result = -1`: a successful first probe
// permits later setters without another syscall, while a Linux error remains
// the positive pthread-style result. A racing first probe can duplicate the
// source syscall but cannot manufacture support.
static ROBUST_LIST_SUPPORT: AtomicI32 = AtomicI32::new(-1);

// The selected initial task is not represented by a worker control mapping.
// Its robust-list record is static for the process lifetime. A fork from an
// existing selected worker adopts that worker's still-mapped list instead,
// mirroring musl's current-thread state rather than copying its linked nodes.
static mut SELECTED_INITIAL_ROBUST_LIST: SelectedRobustList = SelectedRobustList::empty();
static SELECTED_ADOPTED_INITIAL_ROBUST_LIST: AtomicUsize = AtomicUsize::new(0);

/// Raw words in one admitted normal/private mutex record.
///
/// This is deliberately a private sibling-module seam rather than another C
/// ABI. The private condition-variable leaf needs the exact lock and waiter
/// words to retain musl's futex-requeue handoff; it must not duplicate the
/// mutex state machine or call an interposable public mutex entry point.
#[derive(Clone, Copy)]
pub(super) struct SelectedNormalMutexWords {
    lock: *mut c_int,
    waiters: *mut c_int,
}

impl SelectedNormalMutexWords {
    /// Return the selected public lock word at byte offset four.
    #[inline(always)]
    pub(super) const fn lock_word(self) -> *mut c_int {
        self.lock
    }

    /// Return the selected public waiter-hint word at byte offset eight.
    #[inline(always)]
    pub(super) const fn waiters_word(self) -> *mut c_int {
        self.waiters
    }
}

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

/// Return either intrusive robust-list pointer slot in a public mutex.
///
/// # Safety
///
/// `mutex` must be a complete aligned public mutex and `offset` must name the
/// exact musl `_m_prev` or `_m_next` pointer field. The caller owns the
/// current task's robust-list transition and must not create a Rust reference
/// to this concurrently kernel-visible storage.
#[inline(always)]
unsafe fn robust_pointer_slot(
    mutex: *mut PublicPthreadMutex,
    offset: usize,
) -> *mut *mut c_void {
    debug_assert!(matches!(offset, MUTEX_PREVIOUS_OFFSET | MUTEX_NEXT_OFFSET));
    // SAFETY: the two selected offsets are eight-byte aligned pointer fields
    // inside the 40-byte public mutex record.
    unsafe { mutex.cast::<u8>().add(offset).cast::<*mut c_void>() }
}

/// Return the public `_m_next` slot itself, which is the Linux robust-list
/// node address for this mutex.
#[inline(always)]
unsafe fn robust_node(mutex: *mut PublicPthreadMutex) -> *mut c_void {
    // SAFETY: `_m_next` is the exact selected robust node slot.
    unsafe { robust_pointer_slot(mutex, MUTEX_NEXT_OFFSET).cast() }
}

/// Recover the enclosing public mutex from a Linux robust-list node address.
///
/// # Safety
///
/// `node` must be either a valid public mutex `_m_next` slot linked by this
/// module or null. Caller-owned mutex lifetime remains the C contract.
#[inline(always)]
unsafe fn mutex_from_robust_node(node: *mut c_void) -> *mut PublicPthreadMutex {
    // SAFETY: a selected node is exactly byte offset 32 within a complete
    // public record, so subtracting that checked offset recovers its base.
    unsafe { node.cast::<u8>().sub(MUTEX_NEXT_OFFSET).cast() }
}

/// Return the sentinel node address for one task-local robust-list head.
#[inline(always)]
unsafe fn robust_head_node(list: *mut SelectedRobustList) -> *mut c_void {
    // SAFETY: `head` is the first pointer-sized slot in the repr(C) Linux
    // record, and taking its raw address never borrows it as Rust data.
    unsafe { core::ptr::addr_of_mut!((*list).head).cast() }
}

/// Publish Linux's kernel-visible robust pending-node pointer.
///
/// The kernel may inspect this word asynchronously after `set_robust_list`.
/// Match musl's volatile pointer stores so compiler optimization cannot merge,
/// elide, or move this transition across the adjacent list/CAS operations.
#[inline(always)]
unsafe fn publish_robust_pending_node(list: *mut SelectedRobustList, node: *mut c_void) {
    // SAFETY: `pending` is the exact third pointer-sized word in the current
    // task's live repr(C) Linux robust-list record.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*list).pending), node) };
}

/// Observe one Linux robust-list head pointer without creating a Rust borrow.
#[inline(always)]
unsafe fn load_robust_head_node(list: *mut SelectedRobustList) -> *mut c_void {
    // SAFETY: `head` is kernel-visible and this task owns its list mutation.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*list).head)) }
}

/// Initialize one fresh task-local Linux robust-list record.
///
/// # Safety
///
/// `list` must name writable, non-concurrently-reachable storage for the
/// complete record. It is initialized before a selected worker is published
/// or while a fork child still owns the copied runtime transaction.
pub(super) unsafe fn initialize_selected_robust_list(list: *mut SelectedRobustList) {
    // SAFETY: the caller owns this fresh/non-concurrent record. The source
    // head begins as a self-referential sentinel and has no pending node or
    // kernel registration offset.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*list).head), robust_head_node(list));
        (*list).offset = 0;
        publish_robust_pending_node(list, core::ptr::null_mut());
    }
}

/// Make one inherited selected worker list the fork child's initial-task
/// robust list.
///
/// # Safety
///
/// The caller must hold the copied selected-worker registry transaction and
/// retain `list`'s mapping for the child process lifetime. It must run before
/// user child callbacks can acquire or release an inherited robust mutex.
pub(super) unsafe fn adopt_selected_initial_robust_list_after_fork(
    list: *mut SelectedRobustList,
) {
    if list.is_null() {
        return;
    }
    // SAFETY: musl `_Fork` clears only the copied kernel-registration offset
    // and pending transition. The linked head stays intact so a mutex held by
    // the fork caller can still be unlocked in the child.
    unsafe {
        (*list).offset = 0;
        publish_robust_pending_node(list, core::ptr::null_mut());
    }
    SELECTED_ADOPTED_INITIAL_ROBUST_LIST.store(list as usize, Ordering::Release);
}

/// Reset the bootstrapped initial task's robust-list kernel state in a fork
/// child that did not originate from a selected worker.
///
/// # Safety
///
/// The caller must be inside the copied static fork transaction before child
/// callbacks. No sibling can concurrently access the child copy.
pub(super) unsafe fn reset_selected_initial_robust_list_after_fork() {
    SELECTED_ADOPTED_INITIAL_ROBUST_LIST.store(0, Ordering::Release);
    // SAFETY: this static record belongs only to the selected initial task.
    let list = core::ptr::addr_of_mut!(SELECTED_INITIAL_ROBUST_LIST);
    // SAFETY: a freshly bootstrapped main can lazily have a null sentinel;
    // preserve existing linked nodes if it already owns robust mutexes.
    if unsafe { load_robust_head_node(list).is_null() } {
        unsafe { initialize_selected_robust_list(list) };
    } else {
        unsafe {
            (*list).offset = 0;
            publish_robust_pending_node(list, core::ptr::null_mut());
        }
    }
}

/// Resolve the current selected task's private robust-list record.
///
/// The bootstrapped initial task (including a dynamic initial task) has the
/// process-lifetime static record unless a static fork child adopted its
/// inherited worker record. A worker path independently validates `%fs:0`,
/// Linux TID, and its live child-TID before exposing its control-mapped list.
fn current_selected_robust_list() -> Option<*mut SelectedRobustList> {
    let thread_pointer = pthread_identity::current_thread_pointer();
    if static_tls::is_initial_thread_pointer(thread_pointer) {
        let adopted = SELECTED_ADOPTED_INITIAL_ROBUST_LIST.load(Ordering::Acquire);
        let list = if adopted == 0 {
            core::ptr::addr_of_mut!(SELECTED_INITIAL_ROBUST_LIST)
        } else {
            adopted as *mut SelectedRobustList
        };
        // SAFETY: the static main record is task-owned, while an adopted
        // worker record remains mapped for the fork child's lifetime.
        if unsafe { load_robust_head_node(list).is_null() } {
            unsafe { initialize_selected_robust_list(list) };
        }
        return Some(list);
    }
    pthread_create_join::current_selected_worker_robust_list()
}

/// Resolve the task ID and robust-list record for a selected mutex owner.
///
/// A raw foreign task receives no private list, even if it copied an owned
/// FS base. That fail-closed admission keeps caller-owned robust mutex list
/// links from escaping this selected worker/initial-task lifecycle.
fn current_selected_robust_owner() -> Option<(c_int, *mut SelectedRobustList)> {
    let list = current_selected_robust_list()?;
    let thread_id = pthread_create_join::current_selected_runtime_thread_id()?;
    Some((thread_id, list))
}

#[inline(always)]
unsafe fn selected_mutex_type(mutex: *mut PublicPthreadMutex) -> c_int {
    // SAFETY: a valid mutex's type is immutable during its public lifetime.
    unsafe { core::ptr::read(mutex_word(mutex, MUTEX_TYPE_WORD)) }
}

#[inline(always)]
unsafe fn is_selected_robust_mutex(mutex: *mut PublicPthreadMutex) -> bool {
    // SAFETY: caller supplies a complete public record with stable type.
    let mutex_type = unsafe { selected_mutex_type(mutex) };
    mutex_type & MUTEX_ROBUST_BIT != 0 && mutex_type & !MUTEX_SELECTED_ROBUST_BITS == 0
}

#[inline(always)]
const fn mutex_is_private(mutex_type: c_int) -> bool {
    mutex_type & MUTEX_PROCESS_SHARED_BIT == 0
}

#[inline(always)]
fn is_linux_error(result: i64) -> bool {
    result < 0 && result >= -LINUX_ERRNO_MAX
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

/// Initialize one selected all-zero normal/private mutex without crossing a
/// public C ABI.
///
/// # Safety
///
/// `mutex` must designate writable, aligned storage for one complete public
/// x86 mutex-shaped record that is not concurrently accessed. The caller owns
/// any C API-specific attribute and result contract around this exact zeroed
/// representation.
#[inline(always)]
pub(super) unsafe fn init_selected_normal_mutex(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies the complete writable non-concurrent public
    // record; zero is the exact selected normal/private representation.
    unsafe { core::ptr::write_bytes(mutex, 0, 1) };
    0
}

/// Destroy one selected normal/private mutex without crossing a public C ABI.
///
/// The representation owns no allocation or kernel resource. A locked,
/// invalid, or concurrently accessed record remains outside the caller's
/// C-level object-lifetime contract.
///
/// # Safety
///
/// `mutex` must designate a complete aligned selected normal/private record
/// that is quiescent and no longer used by any thread.
#[inline(always)]
pub(super) unsafe fn destroy_selected_normal_mutex(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies the complete quiescent record and its type
    // word is initialized before use.
    if !unsafe { is_selected_normal_mutex(mutex) } {
        return ENOTSUP;
    }
    0
}

/// Resolve the raw words of one selected normal/private mutex.
///
/// The condition-variable sibling uses this only after it has admitted the
/// same all-zero type contract. Returning `None` rather than decoding a
/// nonzero type word keeps recursive, error-checking, robust, PI, and shared
/// records outside both private state machines.
///
/// # Safety
///
/// `mutex` must designate a complete aligned public x86 `pthread_mutex_t`.
/// Its type word must remain immutable while the returned words are used, and
/// every concurrent operation on its lock and waiter words must use the
/// selected atomic protocol.
#[inline(always)]
pub(super) unsafe fn selected_normal_mutex_words(
    mutex: *mut c_void,
) -> Option<SelectedNormalMutexWords> {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies the complete public mutex record and this
    // checked type word is immutable during its valid lifetime.
    if !unsafe { is_selected_normal_mutex(mutex) } {
        return None;
    }
    // SAFETY: the indices are the selected lock/waiter slots within the
    // complete public record, and the result remains raw concurrent storage.
    Some(SelectedNormalMutexWords {
        lock: unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) },
        waiters: unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) },
    })
}

/// Wait once through the selected private or shared futex path.
///
/// This preserves musl's untimed mutex result filtering: interruption remains
/// observable to the lock loop, while an expected-value race and any other
/// impossible-for-a-valid-mutex raw futex result merely retry the acquisition
/// protocol. The public pthread boundary never writes C `errno`.
#[inline(always)]
unsafe fn futex_wait(lock: *mut c_int, expected: c_int, is_private: bool) -> c_int {
    let operation = FUTEX_WAIT | if is_private { FUTEX_PRIVATE_FLAG } else { 0 };
    // SAFETY: `lock` names the aligned, live lock word of this private mutex;
    // the zero fourth argument is a null timeout, so the kernel observes only
    // the initial three futex words plus that null pointer.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            lock as usize as i64,
            operation,
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

/// Wake at most one selected private or shared mutex contender.
///
/// Musl treats this as a best-effort post-release handoff. A failure cannot
/// revoke the already-published zero lock state, so this narrow leaf retains
/// that direct no-errno policy.
#[inline(always)]
unsafe fn futex_wake(lock: *mut c_int, is_private: bool) {
    let operation = FUTEX_WAKE | if is_private { FUTEX_PRIVATE_FLAG } else { 0 };
    // SAFETY: `lock` is the live aligned lock word released by the caller;
    // Linux accepts the null timeout fourth word for FUTEX_WAKE.
    let _ = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            lock as usize as i64,
            operation,
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
unsafe fn try_lock_selected_normal_mutex_record(mutex: *mut PublicPthreadMutex) -> c_int {
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

/// Try to acquire one selected normal/private mutex without crossing a public
/// C ABI.
///
/// # Safety
///
/// `mutex` must designate a live, aligned public x86 mutex-shaped record. Its
/// type word must remain immutable, and every concurrent lock-word operation
/// must use the selected normal/private protocol.
#[inline(always)]
pub(super) unsafe fn try_lock_selected_normal_mutex(mutex: *mut c_void) -> c_int {
    let mutex_record = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies the complete record and the selected type
    // word is immutable during a valid mutex lifetime.
    if !unsafe { is_selected_normal_mutex(mutex_record) } {
        return ENOTSUP;
    }
    // SAFETY: the selected record has been admitted above.
    unsafe { try_lock_selected_normal_mutex_record(mutex_record) }
}

/// Acquire an already-admitted selected normal/private mutex.
///
/// This is the shared private state-machine body used by the direct C entry
/// and the condition-variable leaf after it has atomically enrolled a waiter.
/// It intentionally accepts the concrete record instead of a C pointer so
/// the public boundary remains the one place that decodes the object type.
unsafe fn lock_selected_normal_mutex_record(mutex: *mut PublicPthreadMutex) -> c_int {
    // SAFETY: the caller admits the selected record and all lock-word access
    // below uses the same aligned atomic protocol.
    if unsafe { try_lock_selected_normal_mutex_record(mutex) } == 0 {
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
        if unsafe { try_lock_selected_normal_mutex_record(mutex) } == 0 {
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
        let result = unsafe { futex_wait(lock, marked, true) };
        // SAFETY: balances this loop iteration's advisory waiter count after
        // the futex call has stopped observing the word.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
        // The selected untimed normal route retries both normal wake/race
        // results and EINTR, just as musl's outer mutex loop does. This is not
        // a cancellation point, and timeout/cancellation result handling is
        // deliberately outside this artifact.
        let _ = result;
    }
}

/// Acquire one selected normal/private mutex without crossing a public C ABI.
///
/// # Safety
///
/// `mutex` must designate a live, aligned public x86 `pthread_mutex_t` whose
/// lifetime and concurrent access satisfy the selected normal/private mutex
/// contract. A nonzero type word is rejected with `ENOTSUP`.
#[inline(always)]
pub(super) unsafe fn lock_selected_normal_mutex(mutex: *mut c_void) -> c_int {
    let mutex_record = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies the complete record and its type remains
    // immutable for the valid mutex lifetime.
    if !unsafe { is_selected_normal_mutex(mutex_record) } {
        return ENOTSUP;
    }
    // SAFETY: the same caller contract admits the private lock state machine.
    unsafe { lock_selected_normal_mutex_record(mutex_record) }
}

/// Release an already-admitted selected normal/private mutex.
unsafe fn unlock_selected_normal_mutex_record(mutex: *mut PublicPthreadMutex) -> c_int {
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
        unsafe { futex_wake(lock, true) };
    }
    0
}

/// Release one selected normal/private mutex without crossing a public C ABI.
///
/// # Safety
///
/// `mutex` must designate a live, aligned selected normal mutex held by the
/// current C thread under the caller's ownership discipline. A nonzero type
/// word is rejected with `ENOTSUP`.
#[inline(always)]
pub(super) unsafe fn unlock_selected_normal_mutex(mutex: *mut c_void) -> c_int {
    let mutex_record = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: the caller supplies the complete record and its type remains
    // immutable for the valid mutex lifetime.
    if !unsafe { is_selected_normal_mutex(mutex_record) } {
        return ENOTSUP;
    }
    // SAFETY: caller-held ownership admits the selected release transition.
    unsafe { unlock_selected_normal_mutex_record(mutex_record) }
}

/// Probe and cache Linux robust-list availability as musl's attribute setter
/// does before it admits `PTHREAD_MUTEX_ROBUST`.
unsafe fn selected_robust_list_support() -> c_int {
    let cached = ROBUST_LIST_SUPPORT.load(Ordering::Acquire);
    if cached >= 0 {
        return cached;
    }

    let mut head = core::ptr::null_mut::<c_void>();
    let mut length = 0_usize;
    // SAFETY: Linux `get_robust_list(0, &head, &length)` writes only the two
    // local output slots. It is a capability probe, not registration of the
    // current task or exposure of a runtime pointer.
    let result = unsafe {
        raw_syscall::syscall3(
            LINUX_X86_64_SYS_GET_ROBUST_LIST,
            0,
            core::ptr::addr_of_mut!(head) as usize as i64,
            core::ptr::addr_of_mut!(length) as usize as i64,
        )
    };
    let status = if is_linux_error(result) {
        result.wrapping_neg() as c_int
    } else {
        0
    };
    ROBUST_LIST_SUPPORT.store(status, Ordering::Release);
    status
}

/// Enter the kernel-visible pshared robust-list acquire transition.
///
/// # Safety
///
/// `list` belongs to the current selected task and `mutex` is a complete
/// process-shared robust public record that remains live through the matching
/// CAS/link or failure clear. The caller must clear `pending` on every path.
unsafe fn begin_shared_robust_transition(
    list: *mut SelectedRobustList,
    mutex: *mut PublicPthreadMutex,
) {
    // SAFETY: list and mutex are current-transition records as documented.
    if unsafe { (*list).offset } == 0 {
        // SAFETY: both raw addresses are fields in their complete repr(C)
        // records. Linux expects this signed offset from `_m_next` to
        // `_m_lock`, exactly as musl computes it.
        let offset = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) as isize - robust_node(mutex) as isize };
        unsafe {
            (*list).offset = offset;
            let _ = raw_syscall::syscall2(
                raw_syscall::SYS_SET_ROBUST_LIST,
                list as usize as i64,
                LINUX_ROBUST_LIST_SIZE as i64,
            );
        }
    }
    // SAFETY: the pending node protects exactly the unlinked acquire window
    // if Linux tears down this process-shared task before its CAS completes.
    unsafe { publish_robust_pending_node(list, robust_node(mutex)) };
}

/// Link a successfully acquired robust mutex at the current task list head.
///
/// # Safety
///
/// `list` and `mutex` must satisfy the active selected robust-owner contract;
/// no second task may modify this task's list. Kernel observation is paired
/// with `pending` for process-shared operations.
unsafe fn link_robust_mutex(list: *mut SelectedRobustList, mutex: *mut PublicPthreadMutex) {
    // SAFETY: current task owns its list links while it owns the mutex.
    let sentinel = unsafe { robust_head_node(list) };
    // SAFETY: `head` is a kernel-visible pointer slot, accessed raw to avoid
    // manufacturing a shared Rust reference.
    let next = unsafe { load_robust_head_node(list) };
    let node = unsafe { robust_node(mutex) };
    // SAFETY: the selected pointer slots are private list links inside the
    // caller-owned live mutex record.
    unsafe {
        core::ptr::write_volatile(robust_pointer_slot(mutex, MUTEX_NEXT_OFFSET), next);
        core::ptr::write_volatile(robust_pointer_slot(mutex, MUTEX_PREVIOUS_OFFSET), sentinel);
        if next != sentinel {
            core::ptr::write_volatile(next.cast::<u8>().sub(size_of::<*mut c_void>()).cast(), node);
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*list).head), node);
    }
}

/// Unlink one robust mutex from the current task list.
///
/// # Safety
///
/// The caller must still own `mutex` and it must be linked exactly once in
/// `list`. For a process-shared mutex, hold `pthread_vmlock` and publish the
/// node in `pending` until this transition has finished.
unsafe fn unlink_robust_mutex(list: *mut SelectedRobustList, mutex: *mut PublicPthreadMutex) {
    // SAFETY: the owner inserted these two raw links before it made the mutex
    // observable as held, and no other task writes its task-local list.
    let previous = unsafe {
        core::ptr::read_volatile(robust_pointer_slot(mutex, MUTEX_PREVIOUS_OFFSET))
    };
    let next = unsafe {
        core::ptr::read_volatile(robust_pointer_slot(mutex, MUTEX_NEXT_OFFSET))
    };
    let sentinel = unsafe { robust_head_node(list) };
    // SAFETY: predecessor names either the head slot or another `_m_next`
    // slot; successor's preceding pointer-sized word is its `_m_prev` slot.
    unsafe {
        core::ptr::write_volatile(previous.cast::<*mut c_void>(), next);
        if next != sentinel {
            core::ptr::write_volatile(next.cast::<u8>().sub(size_of::<*mut c_void>()).cast(), previous);
        }
    }
}

/// Attempt one selected robust mutex acquisition.
unsafe fn try_lock_selected_robust_mutex_record(mutex: *mut PublicPthreadMutex) -> c_int {
    // SAFETY: caller already supplies a complete public record with stable
    // selected robust type.
    let mutex_type = unsafe { selected_mutex_type(mutex) };
    let Some((thread_id, list)) = current_selected_robust_owner() else {
        return ENOTSUP;
    };
    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    let waiters = unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) };
    // SAFETY: the public lock word is the selected atomic state machine.
    let old = unsafe { atomic::x86_64_load_acquire_i32(lock) };
    let owner = old & MUTEX_OWNER_MASK;
    if owner == thread_id {
        return EBUSY;
    }
    // musl tests the owner field after masking off both state bits.  The raw
    // unrecoverable lock word is `0x7fffffff`, whose owner field is therefore
    // `0x3fffffff`, not the raw word itself.
    if owner == MUTEX_OWNER_MASK {
        return ENOTRECOVERABLE;
    }
    if owner != 0 || (old != 0 && old & MUTEX_OWNER_DIED_BIT == 0) {
        return EBUSY;
    }

    let is_private = mutex_is_private(mutex_type);
    if !is_private {
        // SAFETY: this pshared transition publishes `pending` until all link
        // writes become kernel-visible or the failed-CAS path clears it.
        unsafe { begin_shared_robust_transition(list, mutex) };
    }
    // A process-shared robust owner must retain an already-published waiter
    // hint in the kernel-visible lock word. If it dies abruptly after this
    // acquisition, Linux uses that sign bit to wake the waiting process.
    let desired = thread_id
        | (old & MUTEX_OWNER_DIED_BIT)
        | if !is_private && unsafe { atomic::x86_64_load_relaxed_i32(waiters) } != 0 {
            MUTEX_WAITER_BIT
        } else {
            0
        };
    // SAFETY: all selected contenders use this raw atomic owner transition.
    if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, old, desired) } != old {
        if !is_private {
            // SAFETY: the failed transition never linked the node.
            unsafe { publish_robust_pending_node(list, core::ptr::null_mut()) };
        }
        return EBUSY;
    }

    // SAFETY: successful ownership makes this task the only list mutator for
    // the mutex until unlock or selected task exit.
    unsafe { link_robust_mutex(list, mutex) };
    if !is_private {
        // SAFETY: the mutex node is now reachable from the registered head.
        unsafe { publish_robust_pending_node(list, core::ptr::null_mut()) };
    }
    if old != 0 {
        // SAFETY: this count field is musl's owner-recovery bookkeeping. The
        // admitted normal robust type has no recursive depth but source clears
        // it before returning EOWNERDEAD.
        unsafe { core::ptr::write(mutex_word(mutex, MUTEX_COUNT_WORD), 0) };
        EOWNERDEAD
    } else {
        0
    }
}

/// Acquire one selected robust mutex with musl's lock/wait/retry shape.
unsafe fn lock_selected_robust_mutex_record(mutex: *mut PublicPthreadMutex) -> c_int {
    // SAFETY: type is stable across this public mutex operation.
    let mutex_type = unsafe { selected_mutex_type(mutex) };
    let is_private = mutex_is_private(mutex_type);
    let first = unsafe { try_lock_selected_robust_mutex_record(mutex) };
    if first != EBUSY {
        return first;
    }

    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    let waiters = unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) };
    let mut spins = 100;
    while spins != 0
        && unsafe { atomic::x86_64_load_acquire_i32(lock) } != 0
        && unsafe { atomic::x86_64_load_relaxed_i32(waiters) } == 0
    {
        core::hint::spin_loop();
        spins -= 1;
    }
    loop {
        let result = unsafe { try_lock_selected_robust_mutex_record(mutex) };
        if result != EBUSY {
            return result;
        }
        // SAFETY: this is the source advisory waiter count paired with every
        // marked futex wait below.
        unsafe { atomic::x86_64_fetch_add_acqrel_i32(waiters, 1) };
        let observed = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        let owner = observed & MUTEX_OWNER_MASK;
        if owner == 0 && (observed == 0 || observed & MUTEX_OWNER_DIED_BIT != 0) {
            // SAFETY: no marked sleep was published for this retry.
            unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
            continue;
        }
        let marked = observed | MUTEX_WAITER_BIT;
        if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, observed, marked) }
            != observed
        {
            // SAFETY: only this failed iteration owns its waiter hint.
            unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
            continue;
        }
        // SAFETY: the marked public lock word remains live for the C mutex
        // lifetime; any raw interruption/race requests another retry.
        let _ = unsafe { futex_wait(lock, marked, is_private) };
        // SAFETY: balances this iteration's advisory waiter count.
        unsafe { atomic::x86_64_fetch_sub_acqrel_i32(waiters, 1) };
    }
}

/// Release one selected robust mutex after exact owner validation.
unsafe fn unlock_selected_robust_mutex_record(mutex: *mut PublicPthreadMutex) -> c_int {
    let mutex_type = unsafe { selected_mutex_type(mutex) };
    let Some((thread_id, list)) = current_selected_robust_owner() else {
        return ENOTSUP;
    };
    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    let waiters = unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) };
    // Snapshot before the owner release. A successful release permits another
    // owner to acquire and destroy this caller-owned public object, so no
    // later load may dereference its waiter field.
    let waiter_hint = unsafe { atomic::x86_64_load_relaxed_i32(waiters) };
    let old = unsafe { atomic::x86_64_load_acquire_i32(lock) };
    if old & MUTEX_OWNER_MASK != thread_id {
        return EPERM;
    }
    let new = if old & MUTEX_OWNER_DIED_BIT != 0 {
        MUTEX_NOT_RECOVERABLE
    } else {
        0
    };
    let is_private = mutex_is_private(mutex_type);
    if !is_private {
        // SAFETY: source holds vmlock while a kernel-visible pending node is
        // detached, so destroy waits for this exact transition to finish.
        unsafe { pthread_vmlock::lock() };
        unsafe { publish_robust_pending_node(list, robust_node(mutex)) };
    }
    // SAFETY: the verified owner inserted this node exactly once.
    unsafe { unlink_robust_mutex(list, mutex) };
    let previous = unsafe { atomic::x86_64_swap_acqrel_i32(lock, new) };
    if !is_private {
        // SAFETY: unlink and lock release are complete before pending clears.
        unsafe { publish_robust_pending_node(list, core::ptr::null_mut()) };
        unsafe { pthread_vmlock::unlock() };
    }
    if previous < 0 || waiter_hint != 0 {
        // SAFETY: the caller retains the public mutex through the wake.
        unsafe { futex_wake(lock, is_private) };
    }
    0
}

/// Process the current selected task's remaining robust mutexes before exit.
///
/// This is the musl userspace route for private mutexes and for selected
/// worker mappings that must remain valid until join/detached reclamation. It
/// runs after cleanup/TSD destructors but before the task's clear-child-tid
/// handoff, while the current list and every held caller mutex remain live.
pub(super) unsafe fn mark_current_selected_robust_mutexes_owner_dead() {
    let Some(list) = current_selected_robust_list() else {
        return;
    };
    // SAFETY: source holds the one process-local vmlock through the complete
    // exit-list walk so process-shared destroy cannot overtake a pending node.
    unsafe { pthread_vmlock::lock() };
    let sentinel = unsafe { robust_head_node(list) };
    loop {
        let node = unsafe { load_robust_head_node(list) };
        if node.is_null() || node == sentinel {
            break;
        }
        let mutex = unsafe { mutex_from_robust_node(node) };
        let waiters = unsafe { mutex_word(mutex, MUTEX_WAITERS_WORD) };
        let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
        // Snapshot before the owner-death exchange. A new owner may acquire
        // and destroy its caller-owned mutex immediately after that exchange.
        let waiter_hint = unsafe { atomic::x86_64_load_relaxed_i32(waiters) };
        let mutex_type = unsafe { selected_mutex_type(mutex) };
        let is_private = mutex_is_private(mutex_type);
        // SAFETY: pending protects the current detached node until the list
        // head and owner word publish a complete owner-death transition.
        unsafe { publish_robust_pending_node(list, node) };
        let next = unsafe { core::ptr::read_volatile(node.cast::<*mut c_void>()) };
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*list).head), next) };
        let previous = unsafe { atomic::x86_64_swap_acqrel_i32(lock, MUTEX_OWNER_DIED_BIT) };
        unsafe { publish_robust_pending_node(list, core::ptr::null_mut()) };
        if previous < 0 || waiter_hint != 0 {
            // SAFETY: a valid robust-mutex caller retains its public object
            // until it is no longer locked/contended; this mirrors musl's
            // caller-owned object-lifetime contract at task exit.
            unsafe { futex_wake(lock, is_private) };
        }
    }
    // SAFETY: completes the source vmlock exit-list bracket.
    unsafe { pthread_vmlock::unlock() };
}

/// Set or clear musl's robust attribute bit after its kernel capability probe.
///
/// # Safety
///
/// For a valid `robust` value, `attribute` must point to writable aligned
/// public `pthread_mutexattr_t` storage. Invalid values return `EINVAL`
/// before dereferencing it, matching musl.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setrobust(
    attribute: *mut c_void,
    robust: c_int,
) -> c_int {
    if (robust as u32) > 1 {
        return EINVAL;
    }
    if robust != 0 {
        let status = unsafe { selected_robust_list_support() };
        if status != 0 {
            return status;
        }
        // SAFETY: a valid robust value admits the caller-owned record.
        let mut record = unsafe { core::ptr::read(attribute.cast::<PublicPthreadMutexAttr>()) };
        record.attr |= MUTEXATTR_ROBUST_BIT;
        unsafe { core::ptr::write(attribute.cast::<PublicPthreadMutexAttr>(), record) };
    } else {
        // SAFETY: source clears this one bit without a support probe.
        let mut record = unsafe { core::ptr::read(attribute.cast::<PublicPthreadMutexAttr>()) };
        record.attr &= !MUTEXATTR_ROBUST_BIT;
        unsafe { core::ptr::write(attribute.cast::<PublicPthreadMutexAttr>(), record) };
    }
    0
}

/// Set musl's raw process-sharing attribute bit.
///
/// # Safety
///
/// For a valid `pshared` value, `attribute` must point to writable aligned
/// public `pthread_mutexattr_t` storage. Invalid values return `EINVAL`
/// before dereferencing it, matching musl.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setpshared(
    attribute: *mut c_void,
    pshared: c_int,
) -> c_int {
    if (pshared as u32) > 1 {
        return EINVAL;
    }
    // SAFETY: a valid value admits the caller-owned raw record.
    let mut record = unsafe { core::ptr::read(attribute.cast::<PublicPthreadMutexAttr>()) };
    record.attr &= !MUTEXATTR_PROCESS_SHARED_BIT;
    record.attr |= (pshared as u32) << 7;
    unsafe { core::ptr::write(attribute.cast::<PublicPthreadMutexAttr>(), record) };
    0
}

/// Mark one recovery owner as having made a selected robust mutex consistent.
///
/// # Safety
///
/// `mutex` must designate a live selected robust public mutex. Its caller
/// retains the public object lifetime and must not call this after unlock.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_consistent(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    if !unsafe { is_selected_robust_mutex(mutex) } {
        return EINVAL;
    }
    let Some((thread_id, _)) = current_selected_robust_owner() else {
        return ENOTSUP;
    };
    let lock = unsafe { mutex_word(mutex, MUTEX_LOCK_WORD) };
    loop {
        let old = unsafe { atomic::x86_64_load_acquire_i32(lock) };
        let owner = old & MUTEX_OWNER_MASK;
        if owner == 0 || old & MUTEX_OWNER_DIED_BIT == 0 {
            return EINVAL;
        }
        if owner != thread_id {
            return EPERM;
        }
        let desired = old & !MUTEX_OWNER_DIED_BIT;
        if unsafe { atomic::x86_64_compare_exchange_acqrel_i32(lock, old, desired) } == old {
            return 0;
        }
    }
}

/// Initialize one selected normal or normal-robust mutex.
///
/// # Safety
///
/// `mutex` must point to writable, aligned storage for one x86
/// `pthread_mutex_t` that is not concurrently accessed. A non-null `attr`
/// must designate an initialized public x86 attribute record whose type is
/// either normal or the selected robust/private-or-shared combination.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut c_void,
    attr: *const c_void,
) -> c_int {
    let mutex_type = if attr.is_null() {
        0
    } else {
        // SAFETY: pthread_mutex_init requires a readable initialized record
        // whenever `attr` is non-null; this selected slice consumes only its
        // musl public attribute word.
        unsafe { core::ptr::read(attr.cast::<PublicPthreadMutexAttr>()) }.attr as c_int
    };
    if mutex_type != 0
        && (mutex_type & MUTEX_ROBUST_BIT == 0
            || mutex_type & !MUTEX_SELECTED_ROBUST_BITS != 0)
    {
        return ENOTSUP;
    }
    let mutex = mutex.cast::<PublicPthreadMutex>();
    // SAFETY: musl first writes the complete zero representation, then stores
    // the selected immutable type word before caller publication.
    unsafe {
        core::ptr::write_bytes(mutex, 0, 1);
        core::ptr::write(mutex_word(mutex, MUTEX_TYPE_WORD), mutex_type);
    }
    0
}

/// Destroy one selected normal or robust mutex.
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
    if unsafe { is_selected_normal_mutex(mutex) } {
        return 0;
    }
    if !unsafe { is_selected_robust_mutex(mutex) } {
        return ENOTSUP;
    }
    // Musl waits only for a process-shared nontrivial owner transition. The
    // public caller still owns the POSIX quiescence/no-new-lock admission.
    if !mutex_is_private(unsafe { selected_mutex_type(mutex) }) {
        unsafe { pthread_vmlock::wait() };
    }
    0
}

/// Try once to acquire one selected normal or robust mutex.
///
/// # Safety
///
/// `mutex` must designate a live, aligned selected mutex. Its complete
/// lifetime and protected-data synchronization remain with the C caller.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut c_void) -> c_int {
    let mutex = mutex.cast::<PublicPthreadMutex>();
    if unsafe { is_selected_normal_mutex(mutex) } {
        // SAFETY: the record was admitted as the existing normal route.
        return unsafe { try_lock_selected_normal_mutex_record(mutex) };
    }
    if unsafe { is_selected_robust_mutex(mutex) } {
        // SAFETY: the record was admitted as the selected robust route.
        return unsafe { try_lock_selected_robust_mutex_record(mutex) };
    }
    ENOTSUP
}

/// Acquire one selected normal or robust mutex through matching futexes.
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
    if unsafe { is_selected_normal_mutex(mutex) } {
        // SAFETY: this record passed the existing normal selected-type check.
        return unsafe { lock_selected_normal_mutex_record(mutex) };
    }
    if unsafe { is_selected_robust_mutex(mutex) } {
        // SAFETY: this record passed the selected robust type check.
        return unsafe { lock_selected_robust_mutex_record(mutex) };
    }
    ENOTSUP
}

/// Release one selected normal or robust mutex and wake one contender if needed.
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
    if unsafe { is_selected_normal_mutex(mutex) } {
        // SAFETY: this record passed the existing normal selected-type check.
        return unsafe { unlock_selected_normal_mutex_record(mutex) };
    }
    if unsafe { is_selected_robust_mutex(mutex) } {
        // SAFETY: this record passed the selected robust type check.
        return unsafe { unlock_selected_robust_mutex_record(mutex) };
    }
    ENOTSUP
}
