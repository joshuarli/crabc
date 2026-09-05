//! Private Linux/x86-64 owned `pthread_atfork` and `fork` composition.
//!
//! This leaf admits one owned process transition: the bootstrapped task or
//! one selected static/dynamic TLS worker may register ordinary
//! `pthread_atfork` triples, then call `fork`. Owned products allocate one
//! process-lifetime record per registration; the frozen private archive keeps
//! its no-allocation 32-record table. Prepare hooks run in
//! reverse registration order before the internal signal/list transaction;
//! parent and child hooks run forward after that transaction has restored a
//! callable state. A failed fork follows musl's parent path, so it still runs
//! parent hooks before publishing the raw Linux error through selected TLS.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/thread/pthread_atfork.c` supplies the registration and
//!   reverse-prepare/forward-parent-or-child hook ordering.
//! - `src/process/fork.c` supplies the prepare -> raw fork -> parent/child
//!   handler transition, including the parent-handler route on raw failure.
//! - `src/process/_Fork.c::__post_Fork` supplies child TID/robust repair;
//!   `ldso/dynlink.c::__ldso_atfork` supplies outer loader lock ordering.
//!
//! Musl grows an allocated handler list and coordinates all of its complete
//! pthread runtime around fork. The owned callback registry follows its
//! newest-first list insertion and prepare traversal, then follows reverse
//! links for parent/child completion. Allocation uses the existing internal
//! owned allocator before the registry lock, matching `__libc_malloc` rather
//! than application malloc interposition. Nodes have process lifetime and
//! allocation failure returns `ENOMEM` without changing the list. The private
//! table still reports `ENOMEM` at 32 records. Both forms retain the selected
//! application-signal block/restore pair and TSD/worker-list/TLS child reset;
//! owned products add the stdio/syslog/timezone and inner process-creation locks.
//! The owned dynamic adapter adds the loader's graph/callback transaction and
//! surviving TLS-root adoption around those same libc owners. Foreign threads,
//! AIO, allocator-wide fork state, and arbitrary application locks remain
//! excluded. No user callback may recurse
//! into `fork`, `pthread_atfork`, `exit`, `atexit`, or `__funcs_on_exit`;
//! callbacks must return normally. Dynamic fork preserves the surviving FS
//! image and loader-owned runtime TLS view, while translating constructor
//! visitors and rejecting closures held by vanished constructor owners.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 pthread-atfork leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(feature = "x86-owned-static-runtime"))]
use core::sync::atomic::AtomicUsize;
#[cfg(feature = "x86-owned-static-runtime")]
use core::sync::atomic::AtomicPtr;

use super::c_status;
use super::{
    immediate_termination, pthread_create_join, pthread_identity, pthread_tsd,
    signal_execution, static_tls,
};

#[cfg(not(feature = "x86-owned-static-runtime"))]
const ATFORK_CAPACITY: usize = 32;
const ENOMEM: c_int = 12;
const EAGAIN: i64 = 11;
// Linux x86-64 has kept the legacy `fork` syscall at 57 throughout the
// selected Linux 5.10 baseline.  Keep it local: this leaf deliberately does
// not widen the shared raw-syscall surface into a general process API.
const LINUX_X86_64_SYS_FORK: i64 = 57;

type AtforkHook = unsafe extern "C" fn();

#[cfg(not(feature = "x86-owned-static-runtime"))]
#[derive(Clone, Copy)]
struct AtforkRegistration {
    prepare: Option<AtforkHook>,
    parent: Option<AtforkHook>,
    child: Option<AtforkHook>,
}

#[cfg(not(feature = "x86-owned-static-runtime"))]
impl AtforkRegistration {
    const EMPTY: Self = Self {
        prepare: None,
        parent: None,
        child: None,
    };
}

// Both registry representations retain this lock across raw fork. Owned
// allocation finishes before acquiring it; all links are published and read
// while held. Retain the existing paired lock even for an empty registry so
// a concurrent first registration cannot cross an unprotected fork snapshot.
static ATFORK_LOCK: AtomicBool = AtomicBool::new(false);
#[cfg(not(feature = "x86-owned-static-runtime"))]
static ATFORK_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "x86-owned-static-runtime"))]
static mut ATFORK_REGISTRATIONS: [AtforkRegistration; ATFORK_CAPACITY] =
    [AtforkRegistration::EMPTY; ATFORK_CAPACITY];

// Musl's atfork_funcs record: callbacks followed by previous/next links.
// While the lock is held, HEAD also acts as the source's traversal cursor:
// prepare leaves it at the oldest node, completion returns it to the newest.
// Nodes are never freed because pthread_atfork has no deregistration API.
#[cfg(feature = "x86-owned-static-runtime")]
#[repr(C)]
struct AtforkNode {
    prepare: Option<AtforkHook>,
    parent: Option<AtforkHook>,
    child: Option<AtforkHook>,
    previous: *mut AtforkNode,
    next: *mut AtforkNode,
}

#[cfg(feature = "x86-owned-static-runtime")]
static OWNED_ATFORK_HEAD: AtomicPtr<AtforkNode> = AtomicPtr::new(core::ptr::null_mut());

/// Perform only the selected Linux x86-64 `fork=57` transition.
///
/// The public `fork` boundary holds the private atfork registry lock across
/// this exact instruction. Keeping the syscall adjacent to that state change
/// prevents the process-transition proof from depending on generic raw-
/// syscall wrapper inlining after lifecycle composition changes elsewhere.
#[inline(always)]
unsafe fn raw_selected_fork() -> i64 {
    let result: i64;
    // SAFETY: SYS_fork has no argument registers. Linux returns the child's
    // PID in the parent, zero in the child, or one negative errno value.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") LINUX_X86_64_SYS_FORK => result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[inline]
unsafe fn lock_registry() {
    while ATFORK_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn unlock_registry() {
    ATFORK_LOCK.store(false, Ordering::Release);
}

#[cfg(not(feature = "x86-owned-static-runtime"))]
#[inline]
unsafe fn registrations() -> *mut AtforkRegistration {
    core::ptr::addr_of_mut!(ATFORK_REGISTRATIONS).cast::<AtforkRegistration>()
}

/// Dispatch the frozen private callback table around one raw process transition.
///
/// `who < 0` acquires the registry lock and runs prepare callbacks in
/// reverse registration order. `who == 0` runs parent callbacks forward;
/// `who > 0` runs child callbacks forward. Both post-fork paths release the
/// copied lock. This is the private `__fork_handler` shape used by musl's
/// `fork`; callers must preserve its paired prepare/post transition and never
/// invoke it reentrantly from a callback.
#[cfg(not(feature = "x86-owned-static-runtime"))]
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn __fork_handler(who: c_int) {
    if who < 0 {
        unsafe { lock_registry() };
        let count = ATFORK_COUNT.load(Ordering::Acquire);
        let registrations = unsafe { registrations() };
        let mut index = count;
        while index != 0 {
            index -= 1;
            let callback = unsafe { (*registrations.add(index)).prepare };
            if let Some(callback) = callback {
                unsafe { callback() };
            }
        }
        return;
    }

    let count = ATFORK_COUNT.load(Ordering::Acquire);
    let registrations = unsafe { registrations() };
    for index in 0..count {
        let callback = if who == 0 {
            unsafe { (*registrations.add(index)).parent }
        } else {
            unsafe { (*registrations.add(index)).child }
        };
        if let Some(callback) = callback {
            unsafe { callback() };
        }
    }
    unlock_registry();
}

/// Dispatch musl's allocated atfork list through its paired cursor reversal.
///
/// # Safety
/// A negative prepare call must have exactly one parent (zero) or child
/// (positive) completion. Callbacks return normally and never reenter the
/// registry while this task retains its lock.
#[cfg(feature = "x86-owned-static-runtime")]
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn __fork_handler(who: c_int) {
    if who < 0 {
        unsafe { lock_registry() };
        let mut node = OWNED_ATFORK_HEAD.load(Ordering::Relaxed);
        while !node.is_null() {
            if let Some(prepare) = unsafe { (*node).prepare } {
                unsafe { prepare() };
            }
            OWNED_ATFORK_HEAD.store(node, Ordering::Relaxed);
            node = unsafe { (*node).next };
        }
        return;
    }
    let mut node = OWNED_ATFORK_HEAD.load(Ordering::Relaxed);
    while !node.is_null() {
        let callback = if who == 0 { unsafe { (*node).parent } }
            else { unsafe { (*node).child } };
        if let Some(callback) = callback { unsafe { callback() }; }
        OWNED_ATFORK_HEAD.store(node, Ordering::Relaxed);
        node = unsafe { (*node).previous };
    }
    unlock_registry();
}

/// Static-archive fallback for musl's private loader-atfork hook.
///
/// Musl 1.2.6 `src/process/fork.c` publishes its inert `dummy(int)` through
/// `weak_alias(dummy, __ldso_atfork)`.  A dynamically linked musl process
/// instead gets the loader-owned locking body from `ldso/dynlink.c`, so a
/// static archive consumer must retain this default-visible weak spelling for
/// a stronger loader or application definition to replace.
///
/// This selected static runtime has no mutable loader lock graph.  Keep the
/// fallback inert and do not route `fork` through it: doing so would falsely
/// claim musl's dynamic-loader fork coordination.  The symbol is only the
/// exact static archive-binding boundary, not loader admission, mapping,
/// finalization, or a general atfork protocol.
#[inline(never)]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __ldso_atfork(_who: c_int) {}

/// Static-archive fallback for musl's private AIO-atfork hook.
///
/// Musl 1.2.6 `src/process/fork.c` exposes its inert `dummy(int)` through
/// `weak_alias(dummy, __aio_atfork)`. Its separate `src/aio/aio.c` object
/// supplies the strong AIO lock-and-task-coordination body only when that
/// optional AIO support is linked. Preserve the weak static binding next to
/// the selected `fork` owner so a stronger application or runtime spelling
/// can replace it.
///
/// This selected static fork path does not call the fallback. It therefore
/// does not select AIO queues, AIO locks, request cancellation, file-descriptor
/// coordination, loader state, or a general process/fork runtime.
#[inline(never)]
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn __aio_atfork(_who: c_int) {}

/// Register one callback triple in the frozen private fixed-capacity table.
///
/// Registration is private to this static process image.  Each optional
/// callback must remain executable until every admitted `fork` that can read
/// it has completed.  The callbacks must return normally and must not call
/// this leaf recursively while its registry lock is held.
#[cfg(not(feature = "x86-owned-static-runtime"))]
#[no_mangle]
pub unsafe extern "C" fn pthread_atfork(
    prepare: Option<AtforkHook>,
    parent: Option<AtforkHook>,
    child: Option<AtforkHook>,
) -> c_int {
    unsafe { lock_registry() };
    let count = ATFORK_COUNT.load(Ordering::Relaxed);
    if count == ATFORK_CAPACITY {
        unlock_registry();
        return ENOMEM;
    }

    let registrations = unsafe { registrations() };
    unsafe {
        *registrations.add(count) = AtforkRegistration {
            prepare,
            parent,
            child,
        };
    }
    ATFORK_COUNT.store(count + 1, Ordering::Release);
    unlock_registry();
    0
}

/// Register an owned atfork triple in a process-lifetime allocated record.
///
/// Allocation precedes locking, as in musl `pthread_atfork.c`, so failure
/// returns `ENOMEM` before any list mutation and allocation cannot reenter
/// while the atfork lock is held. The existing internal allocator supplies
/// storage; this registry introduces neither an allocator nor a capacity.
///
/// # Safety
/// Each non-null callback stays executable for every later fork that can
/// reach it, returns normally, and does not reenter this locked registry.
#[cfg(feature = "x86-owned-static-runtime")]
#[no_mangle]
pub unsafe extern "C" fn pthread_atfork(
    prepare: Option<AtforkHook>,
    parent: Option<AtforkHook>,
    child: Option<AtforkHook>,
) -> c_int {
    let node = unsafe {
        super::allocator::allocate_internal(core::mem::size_of::<AtforkNode>())
    }.cast::<AtforkNode>();
    if node.is_null() { return ENOMEM; }
    unsafe { lock_registry() };
    let head = OWNED_ATFORK_HEAD.load(Ordering::Relaxed);
    // SAFETY: allocation returned aligned unique storage. The lock excludes
    // every list mutator until this fully initialized node becomes its head.
    unsafe {
        node.write(AtforkNode { prepare, parent, child,
            previous: core::ptr::null_mut(), next: head });
        if !head.is_null() { (*head).previous = node; }
    }
    OWNED_ATFORK_HEAD.store(node, Ordering::Relaxed);
    unlock_registry();
    0
}

/// Fork one selected owned task through Linux `fork=57`.
///
/// Registered user callbacks run newest-first before internal locks. The
/// paired internal transaction then blocks application signals, holds the
/// selected worker list across the raw fork, and in a child transfers the
/// calling worker's TSD/TLS identity into child-main state before dropping all
/// inherited worker handles. The parent retains its untouched list. A raw
/// Linux error follows the same parent completion path before this wrapper
/// writes selected `errno` and returns `-1`.
///
/// The caller is the owned initial task or one selected worker. The dynamic
/// adapter first retains graph/callback ownership, then both linkage modes
/// follow musl's key -> stdio -> syslog -> timezone -> thread-list ->
/// process-creation order. Parent/error completion releases that ownership
/// before user hooks.
/// The child keeps its FS image, adopts TSD/cleanup/robust/main-task state and
/// then lets the loader re-root TLS/constructor ownership before any hook.
#[no_mangle]
pub unsafe extern "C" fn fork() -> c_int {
    let thread_pointer = pthread_identity::current_thread_pointer();
    if !static_tls::is_initial_thread_pointer(thread_pointer)
        && !pthread_create_join::is_current_selected_worker()
    {
        return c_status(-EAGAIN);
    }
    unsafe { __fork_handler(-1) };
    let mut saved_signal_mask = 0_u64;
    // SAFETY: this private fork transaction restores the exact one-word mask
    // on every parent, child, and raw-error completion path below.
    unsafe { signal_execution::block_application_signals(&mut saved_signal_mask) };
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    let loader_callback_lock = pthread_create_join::fork_has_other_runtime_tasks();
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    let Some(loader_fork) = (unsafe { static_tls::prepare_fork(loader_callback_lock) }) else {
        unsafe {
            signal_execution::restore_application_signals(&saved_signal_mask);
            __fork_handler(0);
        }
        return c_status(-EAGAIN);
    };
    // Musl's private pthread-key owner precedes the thread-list lock. Holding
    // it through raw fork makes the copied key metadata and caller values one
    // coherent child snapshot rather than clearing an inherited partial lock.
    pthread_tsd::pthread_fork_prepare();
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe {
        super::stdio_standard::pthread_fork_prepare();
        super::owned_syslog::pthread_fork_prepare();
        super::owned_timezone::pthread_fork_prepare();
    }
    pthread_create_join::pthread_fork_prepare();
    #[cfg(feature = "x86-owned-static-runtime")]
    let mut saved_all_signal_mask = 0_u64;
    #[cfg(feature = "x86-owned-static-runtime")]
    unsafe {
        // Musl `_Fork` nests an all-signal block around __abort_lock. The
        // outer transaction still retains its application-signal block while
        // this inner saved mask is restored after the raw process transition.
        signal_execution::block_all_signals(&mut saved_all_signal_mask);
        // The shared abort/process-creation lock is musl's inner `_Fork`
        // transaction. It follows every outer registry/thread-list lock and
        // contains no user callback or CLONE_VM spawn child.
        super::owned_process_lock::pthread_fork_prepare();
    }
    // SAFETY: this private leaf owns the fixed zero-argument Linux x86-64
    // `fork=57` transition while the selected worker list cannot mutate.
    let result = unsafe { raw_selected_fork() };
    if result == 0 {
        let child_tid = unsafe { pthread_create_join::register_fork_child_kernel_tid() };
        #[cfg(feature = "x86-owned-static-runtime")]
        unsafe {
            // `_Fork` completes its copied abort/process lock before the
            // enclosing fork transaction repairs any outer TSD/list state.
            // Restore only the nested all-signal snapshot here; the outer
            // application block remains in force until the full transaction
            // becomes callable below.
            super::owned_process_lock::pthread_fork_child();
            signal_execution::restore_application_signals(&saved_all_signal_mask);
        }
        // SAFETY: the copied list lock retains the inherited caller control
        // while this first child-only TSD transfer runs. It also clears the
        // copied TSD lock, whose parent owner cannot exist in this child.
        if !unsafe { pthread_tsd::adopt_current_values_after_fork() }
            || !static_tls::adopt_current_thread_after_fork()
        {
            immediate_termination::_Exit(127)
        }
        // SAFETY: the child now has its caller's main TSD/TLS identity. Drop
        // inherited worker handles and the copied list lock before callbacks.
        unsafe { pthread_create_join::pthread_fork_child(child_tid) };
        #[cfg(feature = "x86-owned-static-runtime")]
        unsafe {
            super::stdio_standard::pthread_fork_child();
            super::owned_syslog::pthread_fork_child();
            super::owned_timezone::pthread_fork_child();
        }
    } else {
        #[cfg(feature = "x86-owned-static-runtime")]
        unsafe {
            // A raw error follows the parent completion path. Complete the
            // inner lock before any outer registry or user callback sees it.
            super::owned_process_lock::pthread_fork_parent();
            // Restore `_Fork`'s nested all-signal mask before the outer
            // thread-list/registry completion, retaining its app-signal mask.
            signal_execution::restore_application_signals(&saved_all_signal_mask);
        }
        // SAFETY: this completes the parent side of the exact list-lock pair
        // on both a successful parent return and a raw fork failure.
        unsafe { pthread_create_join::pthread_fork_parent() };
        #[cfg(feature = "x86-owned-static-runtime")]
        unsafe {
            super::stdio_standard::pthread_fork_parent();
            super::owned_syslog::pthread_fork_parent();
            super::owned_timezone::pthread_fork_parent();
        }
        // SAFETY: this is the matching outer key-metadata completion after
        // every parent-side raw fork result.
        unsafe { pthread_tsd::pthread_fork_parent() };
    }
    #[cfg(feature = "x86-owned-dynamic-runtime")]
    unsafe { loader_fork.complete(result == 0) };
    // SAFETY: this restores the caller's saved application mask after all
    // child or parent internal state has reached a callable form.
    unsafe { signal_execution::restore_application_signals(&saved_signal_mask) };
    unsafe { __fork_handler(if result == 0 { 1 } else { 0 }) };
    c_status(result)
}
