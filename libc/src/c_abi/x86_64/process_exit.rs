//! Shared native x86 ordinary-exit registration for selected static and dynamic startup.
//!
//! Provenance: musl 1.2.6 revision 9fa28ece75d8a2191de7c5bb53bed224c5947417,
//! src/exit/atexit.c and src/exit/exit.c, MIT license. The registry is musl's
//! `struct fl` chain: a static builtin block of `COUNT == 32` entries is used
//! first, and each further block is zero-allocated through the private
//! `__libc_calloc` seam and pushed in front of it. Blocks are never freed.
//! Dispatch walks the head block from `slot` down, then each older block from
//! the top, releasing nothing, so a handler registered by a running handler
//! is appended at the current position and runs next. After dispatch,
//! registration fails, as musl's `finished_atexit` makes it.
//!
//! Only the owned products link the private allocator. The isolated fixture
//! roots without it keep the builtin block alone, so their 33rd registration
//! fails as musl's does when calloc fails. Each process composition includes
//! exactly one copy; CRT/main/loader ordering belongs to its startup owner.
//!
//! In the owned products, `LOCK`/`UNLOCK` of musl's private `lock` word
//! (published to fork as `__atexit_lockptr`) serialize registration and
//! dispatch through the shared `musl_lock` owner, and the fork transaction
//! holds it over raw fork like the other `atfork_locks`. The isolated fixture
//! roots have no threads or fork owner and keep the registry unlocked.

use core::ffi::{c_int, c_void};
use core::ptr::{addr_of_mut, null_mut};
#[cfg(crabc_x86_owned_runtime)]
use core::sync::atomic::{AtomicI32, Ordering};

// musl atexit.c `static volatile int lock[1]`, which fork reaches through
// the weak `__atexit_lockptr` so that linking fork never links atexit.o. The
// installed static archive keeps the word and its fork hooks in their own
// member for the same reason: an application's own `atexit` then replaces
// this registry without a duplicate definition.
static_archive_member! { atexit_lock {
    #[cfg(crabc_x86_owned_runtime)]
    static LOCK: AtomicI32 = AtomicI32::new(0);

    #[inline]
    pub(super) fn lock() {
        #[cfg(crabc_x86_owned_runtime)]
        crate::x86_64_static_c_abi::musl_lock::lock(&LOCK);
    }

    #[inline]
    pub(super) fn unlock() {
        #[cfg(crabc_x86_owned_runtime)]
        crate::x86_64_static_c_abi::musl_lock::unlock(&LOCK);
    }

    /// Take the registry lock before raw `fork` (musl's `__atexit_lockptr`).
    ///
    /// # Safety
    /// The caller makes exactly one matching parent/error or child completion
    /// before user callbacks resume.
    #[cfg(crabc_x86_owned_runtime)]
    pub(crate) unsafe fn pthread_fork_prepare() {
        lock();
    }

    /// Release the registry lock in the original process after raw `fork`.
    ///
    /// # Safety
    /// Completes one preceding `pthread_fork_prepare` in the parent or on failure.
    #[cfg(crabc_x86_owned_runtime)]
    pub(crate) unsafe fn pthread_fork_parent() {
        unlock();
    }

    /// Clear the copied registry lock in the sole `fork` child, as musl's fork
    /// zeroes each copied `atfork_locks` word.
    ///
    /// # Safety
    /// Runs once after the matching prepared raw fork, before user callbacks.
    #[cfg(crabc_x86_owned_runtime)]
    pub(crate) unsafe fn pthread_fork_child() {
        LOCK.store(0, Ordering::Relaxed);
    }
}}

const COUNT: usize = 32;
type ExitFunction = unsafe extern "C" fn(*mut c_void);
type PlainExitFunction = unsafe extern "C" fn();

/// musl's `struct fl`: one block of registrations and the older block.
#[repr(C)]
struct FunctionList {
    next: *mut FunctionList,
    functions: [Option<ExitFunction>; COUNT],
    arguments: [*mut c_void; COUNT],
}

static mut BUILTIN: FunctionList =
    FunctionList { next: null_mut(), functions: [None; COUNT], arguments: [null_mut(); COUNT] };
// Null until the first registration, as musl defers `head = &builtin`.
static mut HEAD: *mut FunctionList = null_mut();
// Used entries of the head block; COUNT means the head block is full.
static mut SLOT: usize = 0;
static mut FINISHED_ATEXIT: bool = false;

/// Zero-allocate one more block, or return null when none is available.
///
/// # Safety
/// Owned TLS is ready for the allocator's errno publication.
unsafe fn allocate_block() -> *mut FunctionList {
    #[cfg(crabc_x86_owned_runtime)]
    {
        // SAFETY: musl's `__libc_calloc` seam returns zeroed storage large
        // and aligned enough for the plain-data block; zero is its empty
        // state (null next, no functions, null arguments).
        unsafe {
            super::super::allocator::allocate_zeroed_internal(core::mem::size_of::<FunctionList>())
                .cast::<FunctionList>()
        }
    }
    #[cfg(not(crabc_x86_owned_runtime))]
    {
        null_mut()
    }
}

/// Register a C++-ABI-shaped ordinary-exit callback.
///
/// This registration owner does not implement per-DSO finalization. Its `_dso`
/// parameter is therefore retained only for ABI compatibility with the musl
/// entry point and does not select any DSO-specific semantics.
///
/// # Safety
/// The callback and its argument must remain valid through ordinary process
/// exit. Registration is serialized by the registry lock.
#[no_mangle]
pub unsafe extern "C" fn __cxa_atexit(
    callback: Option<ExitFunction>,
    argument: *mut c_void,
    _dso: *mut c_void,
) -> c_int {
    lock();
    // SAFETY: the registry lock serializes these process-lifetime statics,
    // which are touched only here and in dispatch.
    let result = unsafe {
        if FINISHED_ATEXIT {
            -1
        } else {
            register_held(callback, argument)
        }
    };
    unlock();
    result
}

/// Append one registration, chaining a new block when the head is full.
///
/// # Safety
/// The caller holds the registry lock and dispatch has not finished.
unsafe fn register_held(callback: Option<ExitFunction>, argument: *mut c_void) -> c_int {
    unsafe {
        if HEAD.is_null() {
            HEAD = addr_of_mut!(BUILTIN);
        }
        if SLOT == COUNT {
            let block = allocate_block();
            if block.is_null() {
                return -1;
            }
            (*block).next = HEAD;
            HEAD = block;
            SLOT = 0;
        }
        (*HEAD).functions[SLOT] = callback;
        (*HEAD).arguments[SLOT] = argument;
        SLOT += 1;
    }
    0
}

unsafe extern "C" fn invoke_plain_exit(argument: *mut c_void) {
    // SAFETY: `atexit` records only a non-null C ABI no-argument function
    // pointer in this machine-word slot.
    let callback: PlainExitFunction = unsafe { core::mem::transmute(argument) };
    unsafe { callback() };
}

/// Register a C `atexit` callback.
///
/// # Safety
/// Callers must serialize registration and dispatch, and retain the callback
/// mapping through ordinary process exit.
#[no_mangle]
pub unsafe extern "C" fn atexit(callback: Option<PlainExitFunction>) -> c_int {
    let Some(callback) = callback else {
        return -1;
    };
    unsafe {
        __cxa_atexit(
            Some(invoke_plain_exit),
            core::mem::transmute(callback),
            core::ptr::null_mut(),
        )
    }
}

/// Dispatch registered ordinary-exit callbacks in LIFO order.
///
/// musl's `for (; head; head=head->next, slot=COUNT) while(slot-->0)`: each
/// callback runs with the registry published, so one it registers lands at
/// the current slot and runs next. A null function cannot occur (atexit and
/// the C++ ABI never register one) but is skipped rather than called.
///
/// # Safety
/// The caller must exclusively own process exit; every registered callback
/// and argument must remain valid. Recursive dispatch is not admitted.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn __funcs_on_exit() {
    lock();
    loop {
        // SAFETY: the registry lock is held here; the head block is live.
        let (callback, argument) = unsafe {
            if HEAD.is_null() {
                // Unlock so a global destructor calling atexit fails rather
                // than deadlocks, as musl does.
                FINISHED_ATEXIT = true;
                unlock();
                return;
            }
            if SLOT == 0 {
                HEAD = (*HEAD).next;
                SLOT = COUNT;
                continue;
            }
            SLOT -= 1;
            ((*HEAD).functions[SLOT], (*HEAD).arguments[SLOT])
        };
        if let Some(callback) = callback {
            unlock();
            unsafe { callback(argument) };
            lock();
        }
    }
}

/// Compatibility no-op for the C++ ABI finalization entry point.
///
/// Like musl's corresponding entry point, this deliberately leaves ordinary
/// registrations for `exit`'s LIFO dispatch instead of adding DSO filtering.
///
/// # Safety
/// This process-only compatibility call must not be relied on to finalize a
/// DSO or release callback mappings before ordinary exit.
#[no_mangle]
pub unsafe extern "C" fn __cxa_finalize(_dso: *mut c_void) {}
