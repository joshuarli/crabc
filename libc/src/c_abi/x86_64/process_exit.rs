//! Shared native x86 ordinary-exit registration for selected static and dynamic startup.
//!
//! This retains the established 32-entry, allocation-free registration contract
//! and unchanged LIFO dispatch from static_startup.rs. Each process composition
//! includes exactly one copy; CRT/main/loader ordering belongs to its startup
//! owner. Concurrent registration and reentrant exit remain unqualified.
//!
//! Provenance: musl 1.2.6 revision 9fa28ece75d8a2191de7c5bb53bed224c5947417,
//! src/exit/atexit.c and src/exit/exit.c, MIT license. The fixed capacity is the
//! existing documented crabc limitation, not musl's dynamically growing registry.

use core::ffi::{c_int, c_void};
const ATEXIT_CAPACITY: usize = 32;
type ExitFunction = unsafe extern "C" fn(*mut c_void);
type PlainExitFunction = unsafe extern "C" fn();

/// One no-allocation ordinary-exit registration.
///
/// The data is private to the selected process composition. Registrations
/// occur during single-threaded startup/application setup; broader concurrent
/// and reentrant exit semantics remain outside this artifact's contract.
#[derive(Clone, Copy)]
struct ExitRegistration {
    callback: Option<ExitFunction>,
    argument: *mut c_void,
}

impl ExitRegistration {
    const EMPTY: Self = Self {
        callback: None,
        argument: core::ptr::null_mut(),
    };
}

static mut ATEXIT_REGISTRATIONS: [ExitRegistration; ATEXIT_CAPACITY] =
    [ExitRegistration::EMPTY; ATEXIT_CAPACITY];
static mut ATEXIT_COUNT: usize = 0;
static mut ATEXIT_FINISHED: bool = false;

/// Register a C++-ABI-shaped ordinary-exit callback in the fixed process block.
///
/// This registration owner does not implement per-DSO finalization. Its `_dso`
/// parameter is therefore retained only for ABI compatibility with the musl
/// entry point and does not select any DSO-specific semantics.
///
/// # Safety
/// Callers must serialize registration and dispatch. The callback and its
/// argument must remain valid through ordinary process exit.
#[no_mangle]
pub unsafe extern "C" fn __cxa_atexit(
    callback: Option<ExitFunction>,
    argument: *mut c_void,
    _dso: *mut c_void,
) -> c_int {
    if callback.is_none() || unsafe { ATEXIT_FINISHED || ATEXIT_COUNT == ATEXIT_CAPACITY } {
        return -1;
    }
    let count = unsafe { ATEXIT_COUNT };
    // SAFETY: `count` is bounded by the condition above. Function and data
    // pointers share the AMD64 machine-word calling representation used by
    // this musl-compatible ABI boundary.
    unsafe {
        ATEXIT_REGISTRATIONS[count] = ExitRegistration {
            callback,
            argument,
        };
        ATEXIT_COUNT = count + 1;
    }
    0
}

unsafe extern "C" fn invoke_plain_exit(argument: *mut c_void) {
    // SAFETY: `atexit` records only a non-null C ABI no-argument function
    // pointer in this machine-word slot.
    let callback: PlainExitFunction = unsafe { core::mem::transmute(argument) };
    unsafe { callback() };
}

/// Register a C `atexit` callback in the fixed process block.
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
/// Each entry is cleared before invocation. A normal handler that registers
/// another callback therefore adds it above the current consumed slot and it
/// is selected by the same reverse walk; no callback can be observed twice.
///
/// # Safety
/// The caller must exclusively own process exit; every registered callback
/// and argument must remain valid. Recursive dispatch is not admitted.
#[no_mangle]
pub unsafe extern "C" fn __funcs_on_exit() {
    loop {
        let registration = unsafe {
            if ATEXIT_COUNT == 0 {
                ATEXIT_FINISHED = true;
                return;
            }
            ATEXIT_COUNT -= 1;
            let index = ATEXIT_COUNT;
            let registration = ATEXIT_REGISTRATIONS[index];
            ATEXIT_REGISTRATIONS[index] = ExitRegistration::EMPTY;
            registration
        };
        if let Some(callback) = registration.callback {
            unsafe { callback(registration.argument) };
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
