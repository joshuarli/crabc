//! Private static Linux/x86-64 `pthread_atfork` and `fork` composition.
//!
//! This leaf admits one deliberately narrow process transition: a
//! single-threaded Static Initial TLS v1 caller may register up to 32 ordinary
//! `pthread_atfork` triples, then call `fork`.  Prepare hooks run in reverse
//! registration order while the fixed registry lock is held; parent and child
//! hooks run in registration order and release that lock after the raw Linux
//! fork result. A failed fork follows musl's parent path, so it still runs the
//! parent hooks before publishing the raw Linux error through the selected
//! initial-TLS `errno` slot. The child may then use the already-selected,
//! bounded ordinary-exit callback block; this leaf does not widen that block.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/thread/pthread_atfork.c` supplies the registration and
//!   reverse-prepare/forward-parent-or-child hook ordering.
//! - `src/process/fork.c` supplies the prepare -> raw fork -> parent/child
//!   handler transition, including the parent-handler route on raw failure.
//!
//! Musl grows an allocated handler list and coordinates all of its complete
//! pthread runtime around fork. This static archive deliberately owns neither
//! facility. Its 32-record no-allocation registry reports `ENOMEM` once full.
//! `fork` fails closed with `EAGAIN` before it runs any hook if the selected
//! worker registry is nonempty; the caller must additionally ensure that no
//! foreign thread or concurrent runtime state exists. No callback may recurse
//! into `fork`, `pthread_atfork`, `exit`, `atexit`, or `__funcs_on_exit`, and
//! callbacks must return normally without relying on signals, allocator, TSD,
//! cancellation, mutex/condition, once, dynamic-TLS, loader, CRT, or process-
//! exit state. In particular, callbacks must not create, join, or detach a
//! selected worker after `fork` has completed its worker-free admission check.
//! Concurrent selected-worker lifecycle calls are likewise caller-excluded.
//! This is a private static artifact, not a general fork, atfork, process-exit,
//! or pthread runtime.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("x86 pthread-atfork leaf requires little-endian Linux/x86-64");

use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::c_status;

const ATFORK_CAPACITY: usize = 32;
const ENOMEM: c_int = 12;
const EAGAIN: i64 = 11;
// Linux x86-64 has kept the legacy `fork` syscall at 57 throughout the
// selected Linux 5.10 baseline.  Keep it local: this leaf deliberately does
// not widen the shared raw-syscall surface into a general process API.
const LINUX_X86_64_SYS_FORK: i64 = 57;

type AtforkHook = unsafe extern "C" fn();

#[derive(Clone, Copy)]
struct AtforkRegistration {
    prepare: Option<AtforkHook>,
    parent: Option<AtforkHook>,
    child: Option<AtforkHook>,
}

impl AtforkRegistration {
    const EMPTY: Self = Self {
        prepare: None,
        parent: None,
        child: None,
    };
}

// The lock is intentionally a tiny no-allocation single-threaded admission
// boundary.  `fork` retains it across the raw syscall exactly so the copied
// child cannot observe a partially changed registry before its child hooks.
static ATFORK_LOCK: AtomicBool = AtomicBool::new(false);
static ATFORK_COUNT: AtomicUsize = AtomicUsize::new(0);
static mut ATFORK_REGISTRATIONS: [AtforkRegistration; ATFORK_CAPACITY] =
    [AtforkRegistration::EMPTY; ATFORK_CAPACITY];

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

#[inline]
unsafe fn registrations() -> *mut AtforkRegistration {
    core::ptr::addr_of_mut!(ATFORK_REGISTRATIONS).cast::<AtforkRegistration>()
}

/// Dispatch the selected atfork registry around one raw process transition.
///
/// `who < 0` acquires the fixed registry lock and runs prepare callbacks in
/// reverse registration order. `who == 0` runs parent callbacks forward;
/// `who > 0` runs child callbacks forward. Both post-fork paths release the
/// copied lock. This is the private `__fork_handler` shape used by musl's
/// `fork`; callers must preserve its paired prepare/post transition and never
/// invoke it reentrantly from a callback.
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

/// Register one fixed-capacity atfork callback triple.
///
/// Registration is private to this static process image.  Each optional
/// callback must remain executable until every admitted `fork` that can read
/// it has completed.  The callbacks must return normally and must not call
/// this leaf recursively while its registry lock is held.
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

/// Fork the selected single-threaded static process through Linux `fork=57`.
///
/// A live selected pthread/C11 worker is rejected before prepare callbacks
/// run, preventing this leaf from copying its private worker state into a
/// child. The caller must still ensure that no foreign thread or unselected
/// concurrent runtime state exists. Registered callbacks execute with the
/// fixed registry lock held: prepare callbacks run newest first, then the
/// resulting parent or child callbacks run oldest first. A raw Linux error
/// runs parent callbacks before this wrapper writes the selected initial-TLS
/// `errno` and returns `-1`. Concurrent selected-worker creation, join, and
/// detach are outside this check; the single-threaded caller must exclude them.
#[no_mangle]
pub unsafe extern "C" fn fork() -> c_int {
    if super::pthread_create_join::has_live_selected_workers() {
        return c_status(-EAGAIN);
    }
    unsafe { __fork_handler(-1) };
    // SAFETY: this private leaf owns the fixed zero-argument Linux x86-64
    // `fork=57` transition and its no-live-worker admission requirement.
    let result = unsafe { raw_selected_fork() };
    unsafe { __fork_handler(if result == 0 { 1 } else { 0 }) };
    c_status(result)
}
