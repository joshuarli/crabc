//! Runtime proof for 's native thread and TLS boundary.
//!
//! This archive is linked into a C fixture running under crabc's loader. It
//! uses the private singleton table rather than public pthread names or errno.

#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::runtime_thread::{
    current, set_cancellation_state, set_cancellation_type, spawn_raw, CancellationState,
    CancellationType, Key,
};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

static CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn worker(argument: *mut c_void) -> *mut c_void {
    CALLBACK_COUNT.fetch_add(1, Ordering::Release);
    argument
}

#[no_mangle]
pub extern "C" fn crabc_rs_runtime_thread_probe() -> i32 {
    if current().is_err() {
        return 1;
    }

    let argument = 0x4d37usize as *mut c_void;
    // SAFETY: The callback only returns its opaque argument and does not
    // borrow any stack state after this function leaves.
    let worker = match unsafe { spawn_raw(worker, argument) } {
        Ok(worker) => worker,
        Err(_) => return 2,
    };
    let result = match worker.join() {
        Ok(result) => result,
        Err(_) => return 3,
    };
    if result != argument || CALLBACK_COUNT.load(Ordering::Acquire) != 1 {
        return 4;
    }

    let key = match Key::new() {
        Ok(key) => key,
        Err(_) => return 5,
    };
    let value = NonNull::new(0x71usize as *mut c_void).expect("fixed non-null probe value");
    // SAFETY: This no-destructor key stores an opaque non-dereferenced marker
    // that remains valid for the duration of the probe.
    if unsafe { key.set(Some(value)) }.is_err() {
        return 6;
    }
    if key.get() != Some(value) {
        return 7;
    }
    if key.delete().is_err() {
        return 8;
    }

    // SAFETY: No cancellation request is pending in this probe. Temporarily
    // changing the current thread's settings therefore cannot interrupt a
    // Rust ownership or lock transition.
    let previous_state = match unsafe { set_cancellation_state(CancellationState::Disabled) } {
        Ok(state) => state,
        Err(_) => return 9,
    };
    let previous_type = match unsafe { set_cancellation_type(CancellationType::Deferred) } {
        Ok(kind) => kind,
        Err(_) => return 10,
    };
    // SAFETY: Same no-pending-cancellation contract as the transitions above.
    if unsafe { set_cancellation_type(previous_type) }.is_err() {
        return 11;
    }
    // SAFETY: Same no-pending-cancellation contract as the transitions above.
    if unsafe { set_cancellation_state(previous_state) }.is_err() {
        return 12;
    }
    0
}
