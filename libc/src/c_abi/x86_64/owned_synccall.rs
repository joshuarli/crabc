//! Owned Linux/x86-64 all-thread synchronous call (`__synccall`) and the
//! thread-list lock it serializes against.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/thread/synccall.c::__synccall` supplies the signal-driven
//!   rendezvous: application signals are blocked before the thread-list lock
//!   and all signals after it, cancellation is disabled, `SIGSYNCCALL` (34)
//!   is installed with a full handler mask and `SA_RESTART | SA_ONSTACK`, and
//!   each other thread is caught in turn by `tkill`, runs the callback
//!   serially on the caller's release, and returns only after the caller has
//!   run it too. A failed `tkill` replaces the callback by a no-op for every
//!   thread, including the caller, and releases the threads already caught.
//! - `src/thread/pthread_create.c::{__tl_lock,__tl_unlock}` supplies the
//!   owner-TID futex lock that makes the thread set stable for the whole
//!   rendezvous; `src/process/_Fork.c::__post_Fork` clears it in the child.
//!
//! - `src/linux/membarrier.c::{__membarrier,bcast_barrier}` supplies the
//!   `MEMBARRIER_CMD_PRIVATE_EXPEDITED` emulation that shares this signal
//!   and lock: [`emulate_private_expedited_membarrier`].
//!
//! Musl's exiting thread keeps the thread-list lock until the kernel clears
//! it through its clear-child-TID address, so a listed thread is always
//! alive. Here the clear-child-TID word belongs to join/detached
//! reclamation, so a non-final task commits its exit under the lock, keeps it
//! through the rest of its retirement, and releases it itself immediately
//! before `SYS_exit`. A rendezvous signals only uncommitted tasks, which
//! cannot commit, be created, or vanish until it releases the lock.
//!
//! The lock is acquired only with application signals blocked, and never
//! while `SIGSYNCCALL` is blocked, so a holder can always take part in a
//! rendezvous it is waiting on and no application handler can reenter it.
//! It is not recursive: no holder calls back into a lock owner.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 synccall leaf requires little-endian Linux/x86-64");

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use super::{pthread_cancel, pthread_create_join, raw_syscall, signal_execution, signal_foundation};

/// Musl's private implementation signal for `__synccall`
/// (`pthread_impl.h`: `SIGTIMER` 32, `SIGCANCEL` 33, `SIGSYNCCALL` 34).
/// Public `sigaction` rejects all three.
pub(super) const SIGSYNCCALL: c_int = 34;

const EAGAIN: i64 = 11;
const SIGKILL: i64 = 9;
const PTHREAD_CANCEL_DISABLE: c_int = 1;
const SA_RESTART: u64 = 0x1000_0000;
const SA_ONSTACK: u64 = 0x0800_0000;
const SIG_IGN: usize = 1;
const FUTEX_WAIT_PRIVATE: i64 = 128;
const FUTEX_WAKE_PRIVATE: i64 = 129;

/// One callback the rendezvous runs on every thread.
///
/// It runs inside a signal handler with every signal blocked, so it must be
/// async-signal-safe and must not touch `errno`, locks, or allocation.
pub(super) type SynccallCallback = unsafe fn(*mut c_void);

// Musl's `__thread_list_lock`: zero or the owner's Linux TID.
static THREAD_LIST_LOCK: AtomicI32 = AtomicI32::new(0);
static THREAD_LIST_WAITERS: AtomicI32 = AtomicI32::new(0);

#[inline]
fn current_linux_thread_id() -> c_int {
    // SAFETY: gettid has no arguments and cannot fail.
    unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETTID) as c_int }
}

#[inline]
unsafe fn futex_wait(word: &AtomicI32, expected: c_int) {
    // SAFETY: `word` is a live process-lifetime or rendezvous-scoped aligned
    // futex word; EAGAIN/EINTR returns are retried by every caller.
    unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FUTEX,
            word.as_ptr() as i64,
            FUTEX_WAIT_PRIVATE,
            i64::from(expected),
            0,
        );
    }
}

#[inline]
unsafe fn futex_wake(word: &AtomicI32, count: c_int) {
    // SAFETY: waking a live aligned futex word has no memory effect.
    unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FUTEX,
            word.as_ptr() as i64,
            FUTEX_WAKE_PRIVATE,
            i64::from(count),
        );
    }
}

/// Acquire musl's thread-list lock (`__tl_lock`).
///
/// # Safety
///
/// The caller has blocked application signals, has not blocked
/// `SIGSYNCCALL`, does not already hold the lock, and pairs this with one
/// [`unlock_thread_list`] before it restores its mask.
pub(super) unsafe fn lock_thread_list() {
    let tid = current_linux_thread_id();
    loop {
        match THREAD_LIST_LOCK.compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return,
            Err(owner) => {
                // Musl's `__wait`: register as a waiter before sleeping on
                // the observed owner value.
                THREAD_LIST_WAITERS.fetch_add(1, Ordering::SeqCst);
                if THREAD_LIST_LOCK.load(Ordering::SeqCst) == owner {
                    unsafe { futex_wait(&THREAD_LIST_LOCK, owner) };
                }
                THREAD_LIST_WAITERS.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

/// Release musl's thread-list lock (`__tl_unlock`).
///
/// # Safety
///
/// The caller holds the lock from [`lock_thread_list`].
pub(super) unsafe fn unlock_thread_list() {
    THREAD_LIST_LOCK.store(0, Ordering::SeqCst);
    if THREAD_LIST_WAITERS.load(Ordering::SeqCst) != 0 {
        unsafe { futex_wake(&THREAD_LIST_LOCK, 1) };
    }
}

/// Clear a thread-list lock copied into a sole process child, as musl's
/// `__post_Fork` does. Its owner, if any, does not exist in the child.
pub(super) fn reset_thread_list_after_fork() {
    THREAD_LIST_LOCK.store(0, Ordering::Relaxed);
    THREAD_LIST_WAITERS.store(0, Ordering::Relaxed);
}

/// Musl's use of a private `sem_t` for the three rendezvous handoffs.
///
/// Posts and waits are raw private-futex operations: they are
/// async-signal-safe, never cancellation points, and never write `errno`.
struct RendezvousSemaphore(AtomicI32);

impl RendezvousSemaphore {
    const fn new() -> Self {
        Self(AtomicI32::new(0))
    }

    fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    fn post(&self) {
        self.0.fetch_add(1, Ordering::Release);
        // SAFETY: this process-lifetime word is a valid futex address.
        unsafe { futex_wake(&self.0, 1) };
    }

    fn wait(&self) {
        loop {
            let value = self.0.load(Ordering::Acquire);
            if value > 0 {
                if self
                    .0
                    .compare_exchange_weak(value, value - 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            // SAFETY: as above; a changed value returns immediately.
            unsafe { futex_wait(&self.0, value) };
        }
    }
}

// Rendezvous state, owned by the thread-list lock holder. Caught threads read
// it only between the caller's semaphore posts, which order every access.
static TARGET_TID: AtomicI32 = AtomicI32::new(0);
static CALLBACK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CONTEXT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static TARGET_SEM: RendezvousSemaphore = RendezvousSemaphore::new();
static CALLER_SEM: RendezvousSemaphore = RendezvousSemaphore::new();
static EXIT_SEM: RendezvousSemaphore = RendezvousSemaphore::new();

unsafe fn dummy(_context: *mut c_void) {}

#[inline]
fn load_callback() -> SynccallCallback {
    let callback = CALLBACK.load(Ordering::Acquire);
    // SAFETY: only `__synccall` stores this word, always from a
    // `SynccallCallback` value, before any handler can observe it.
    unsafe { core::mem::transmute::<*mut (), SynccallCallback>(callback) }
}

/// Musl's `SIGSYNCCALL` handler.
///
/// A signal meant for another thread (or a stray one) is ignored. Musl saves
/// and restores `errno` around the callback; every operation here is a raw
/// syscall that never publishes `errno`, so there is nothing to restore.
unsafe extern "C" fn handler(_signal: c_int) {
    if current_linux_thread_id() != TARGET_TID.load(Ordering::Acquire) {
        return;
    }
    // Inform the caller that this thread is caught, then wait to be told to
    // run the callback.
    CALLER_SEM.post();
    TARGET_SEM.wait();

    let callback = load_callback();
    // SAFETY: `__synccall`'s caller supplies a callback valid on every thread
    // for the rendezvous; its context outlives the rendezvous.
    unsafe { callback(CONTEXT.load(Ordering::Acquire)) };

    // Report completion and wait for release, then report that the shared
    // state may be destroyed.
    CALLER_SEM.post();
    EXIT_SEM.wait();
    CALLER_SEM.post();
}

unsafe fn set_synccall_disposition(handler: usize) -> i64 {
    let action = signal_foundation::KernelSigAction {
        handler,
        flags: SA_RESTART | SA_ONSTACK | signal_foundation::SA_RESTORER,
        restorer: signal_foundation::restorer_address(),
        // Block even implementation-internal signals, so that nothing
        // (in particular asynchronous cancellation) interrupts the handler.
        mask: u64::MAX,
    };
    // SAFETY: the compact kernel record is complete and the handler, when
    // installed, is a process-lifetime function with the x86 restorer.
    unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RT_SIGACTION,
            i64::from(SIGSYNCCALL),
            (&action as *const signal_foundation::KernelSigAction) as i64,
            0,
            8,
        )
    }
}

/// Targets held on the caller's stack before a mapping is needed.
const INLINE_TARGETS: usize = 64;
const PAGE_SIZE: usize = 4096;

/// The rendezvous targets, copied under the registry lock before any task
/// is caught (see `collect_other_live_runtime_tasks`). A larger process maps
/// its list with `mmap`, which remains async-signal-safe.
struct TargetList<'a> {
    targets: *const c_int,
    count: usize,
    mapping: usize,
    _inline: core::marker::PhantomData<&'a mut [c_int]>,
}

impl<'a> TargetList<'a> {
    fn collect(self_tid: c_int, inline: &'a mut [c_int; INLINE_TARGETS]) -> Option<Self> {
        let count = pthread_create_join::collect_other_live_runtime_tasks(self_tid, &mut inline[..]);
        if count <= INLINE_TARGETS {
            return Some(Self { targets: inline.as_ptr(), count, mapping: 0, _inline: core::marker::PhantomData });
        }
        let mapping = (count * core::mem::size_of::<c_int>()).div_ceil(PAGE_SIZE) * PAGE_SIZE;
        // SAFETY: a fresh private anonymous read/write mapping.
        let address = unsafe {
            raw_syscall::syscall6(raw_syscall::SYS_MMAP, 0, mapping as i64, 3, 0x22, -1, 0)
        };
        if (-4095..0).contains(&address) {
            return None;
        }
        // SAFETY: the mapping holds `count` aligned words and is exclusively
        // owned here until `drop`.
        let targets = unsafe { core::slice::from_raw_parts_mut(address as *mut c_int, count) };
        // The locked thread list keeps the set exact, so the count repeats.
        let again = pthread_create_join::collect_other_live_runtime_tasks(self_tid, targets);
        debug_assert_eq!(again, count);
        Some(Self { targets: address as *const c_int, count: again.min(count), mapping, _inline: core::marker::PhantomData })
    }

    fn as_slice(&self) -> &[c_int] {
        // SAFETY: `targets` names `count` initialized words owned by `self`.
        unsafe { core::slice::from_raw_parts(self.targets, self.count) }
    }
}

impl Drop for TargetList<'_> {
    fn drop(&mut self) {
        if self.mapping != 0 {
            // SAFETY: this list exclusively owns the mapping it created.
            unsafe { raw_syscall::syscall2(raw_syscall::SYS_MUNMAP, self.targets as i64, self.mapping as i64) };
        }
    }
}

/// Run `callback(context)` on every live thread of the process, serially,
/// with the calling thread last (musl `__synccall`).
///
/// Only when the caller is a registered owned task whose recorded TID is its
/// Linux TID are other threads involved; otherwise (a single-threaded
/// process, a raw-fork or vfork image, or a foreign task) the callback runs
/// only on the caller, as in musl.
///
/// # Safety
///
/// `callback` must be async-signal-safe, must not use `errno`, locks,
/// allocation, or cancellation points, and must tolerate running inside a
/// signal handler on each thread. `context` must stay valid until return.
/// The caller must not hold the thread-list lock or any lock another thread
/// can need before it can take `SIGSYNCCALL`.
pub(super) unsafe fn synccall(callback: SynccallCallback, context: *mut c_void) {
    let mut old_mask = 0_u64;
    let mut all_blocked = 0_u64;
    let mut cancel_state: c_int = 0;
    // Blocking in two steps is what makes this async-signal-safe: blocking
    // everything first would deadlock two concurrent callers, and waiting to
    // block until after the lock would allow same-thread reentry.
    unsafe {
        signal_execution::block_application_signals(&mut old_mask);
        lock_thread_list();
        signal_execution::block_all_signals(&mut all_blocked);
        pthread_cancel::pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &mut cancel_state);
    }

    TARGET_SEM.reset();
    CALLER_SEM.reset();
    EXIT_SEM.reset();

    let mut run = callback;
    let mut count = 0_usize;
    let self_tid = current_linux_thread_id();
    if pthread_create_join::current_runtime_task_linux_id() == Some(self_tid) {
        CALLBACK.store(callback as *mut (), Ordering::Release);
        CONTEXT.store(context, Ordering::Release);
        let _ = unsafe { set_synccall_disposition(handler as *const () as usize) };
        let mut inline_targets = [0 as c_int; INLINE_TARGETS];
        let targets = TargetList::collect(self_tid, &mut inline_targets);
        let targets_ok = targets.is_some();
        for &tid in targets.as_ref().map_or(&[][..], TargetList::as_slice) {
            TARGET_TID.store(tid, Ordering::Release);
            let result = loop {
                // SAFETY: the thread-list lock keeps `tid` a live task of
                // this process: it can neither commit exit nor be reused.
                let result = unsafe {
                    raw_syscall::syscall2(raw_syscall::SYS_TKILL, i64::from(tid), i64::from(SIGSYNCCALL))
                };
                if result != -EAGAIN {
                    break result;
                }
            };
            if result != 0 {
                // If any thread cannot be signaled, nop out the callback to
                // abort the rendezvous and just release those already caught.
                run = dummy;
                CALLBACK.store(dummy as *mut (), Ordering::Release);
                break;
            }
            CALLER_SEM.wait();
            count += 1;
        }
        drop(targets);
        if !targets_ok {
            // No target list could be mapped: nothing was caught, and the
            // rendezvous fails as if the first thread could not be signaled.
            run = dummy;
        }
        TARGET_TID.store(0, Ordering::Release);

        // Serialize the callback in caught threads, or just release them all
        // if the rendezvous was aborted.
        for _ in 0..count {
            TARGET_SEM.post();
            CALLER_SEM.wait();
        }
        let _ = unsafe { set_synccall_disposition(SIG_IGN) };
    }

    // SAFETY: the caller's obligations cover this final invocation.
    unsafe { run(context) };

    // Release the caught threads only after every thread, including this
    // one, has returned from the callback.
    for _ in 0..count {
        EXIT_SEM.post();
    }
    for _ in 0..count {
        CALLER_SEM.wait();
    }

    unsafe {
        pthread_cancel::pthread_setcancelstate(cancel_state, core::ptr::null_mut());
        unlock_thread_list();
        signal_execution::restore_application_signals(&old_mask);
    }
}

// Musl's `barrier_sem` in `membarrier.c`, owned by the thread-list lock holder.
static BARRIER_SEM: RendezvousSemaphore = RendezvousSemaphore::new();

/// Musl's `bcast_barrier`: receiving the signal is the barrier; the post
/// tells the caller this thread has passed it.
unsafe extern "C" fn broadcast_barrier(_signal: c_int) {
    BARRIER_SEM.post();
}

/// Musl `__membarrier`'s emulation of an unregistered or refused
/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED`: interrupt every other thread of the
/// process with `SIGSYNCCALL` and wait until each has taken it. A signal
/// delivery is a full barrier on the receiving thread, so on return every
/// other thread has executed one since the call began. Unlike the syscall it
/// does not reach other processes that share the address space, which musl
/// also does not support.
///
/// Returns whether the barrier was established; it fails only when the
/// handler cannot be installed or a large target list cannot be mapped.
///
/// Two deliberate differences from musl, neither visible to a valid program:
/// the caller blocks every signal after taking the lock, as `__synccall`
/// does, so asynchronous cancellation cannot unwind it while it holds that
/// lock (musl's `sem_wait` here is even a cancellation point); and it waits
/// only for threads the kernel accepted a signal for, retrying a full signal
/// queue as `synccall` does, where musl would wait forever for a thread
/// whose `tkill` failed (the locked list makes any other failure
/// impossible). It sets no `errno`.
pub(super) fn emulate_private_expedited_membarrier() -> bool {
    let mut old_mask = 0_u64;
    let mut all_blocked = 0_u64;
    // SAFETY: the same lock admission order as `synccall`.
    unsafe {
        signal_execution::block_application_signals(&mut old_mask);
        lock_thread_list();
        signal_execution::block_all_signals(&mut all_blocked);
    }
    BARRIER_SEM.reset();
    let mut established = false;
    // SAFETY: the handler is a process-lifetime async-signal-safe function.
    if unsafe { set_synccall_disposition(broadcast_barrier as *const () as usize) } == 0 {
        let self_tid = current_linux_thread_id();
        let mut inline_targets = [0 as c_int; INLINE_TARGETS];
        // Musl walks `self->next` back to itself; a caller outside the owned
        // registry (a raw-fork or vfork image) is alone in its list.
        let targets = if pthread_create_join::current_runtime_task_linux_id() == Some(self_tid) {
            TargetList::collect(self_tid, &mut inline_targets)
        } else {
            Some(TargetList { targets: inline_targets.as_ptr(), count: 0, mapping: 0, _inline: core::marker::PhantomData })
        };
        if let Some(targets) = targets {
            let mut signaled = 0_usize;
            for &tid in targets.as_slice() {
                let result = loop {
                    // SAFETY: the thread-list lock keeps `tid` a live task.
                    let result = unsafe {
                        raw_syscall::syscall2(raw_syscall::SYS_TKILL, i64::from(tid), i64::from(SIGSYNCCALL))
                    };
                    if result != -EAGAIN {
                        break result;
                    }
                };
                if result == 0 {
                    signaled += 1;
                }
            }
            for _ in 0..signaled {
                BARRIER_SEM.wait();
            }
            established = true;
        }
        let _ = unsafe { set_synccall_disposition(SIG_IGN) };
    }
    unsafe {
        unlock_thread_list();
        signal_execution::restore_application_signals(&old_mask);
    }
    established
}

/// Kill the whole process after a partial credential transition.
///
/// Musl's `do_setxid`/`do_setgroups` do this when one thread fails after
/// another has already succeeded: the process state would be inconsistent
/// and dangerous. `SIGKILL` is uncatchable.
pub(super) fn kill_process_after_partial_transition() -> ! {
    let mut ignored = 0_u64;
    unsafe {
        signal_execution::block_all_signals(&mut ignored);
        let process = raw_syscall::syscall0(raw_syscall::SYS_GETPID);
        raw_syscall::syscall2(raw_syscall::SYS_KILL, process, SIGKILL);
    }
    loop {
        core::hint::spin_loop();
    }
}
