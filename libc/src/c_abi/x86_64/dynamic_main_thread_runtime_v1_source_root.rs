#![no_std]
#![feature(thread_local)]
#![allow(unexpected_cfgs)]

//! Isolated private x86 dynamic-main-thread RuntimeV1 libc root.
//!
//! This root is linked only into the focused native evidence DSO. It provides
//! the smallest real `__libc_start_main` and dynamic TLS `errno` boundary
//! needed after the Rust-produced Scrt1.o validates the main-resident loader
//! descriptor. It is never selected by `libc.a`, an installed sysroot, or a
//! public `libc.so` product.

#[allow(dead_code)]
#[path = "errno.rs"]
mod errno;
#[cfg(not(crabc_general_dynamic_lifecycle))]
#[path = "dynamic_main_thread_runtime_v1.rs"]
mod dynamic_main_thread_runtime_v1;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "dynamic_main_thread_runtime_v1_lifecycle.rs"]
mod dynamic_main_thread_runtime_v1;

// These are the same ABI/state owners used by the selected static runtime;
// the dynamic composition supplies a loader-owned TLS image instead.
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "process_exit.rs"]
mod process_exit;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "environment.rs"]
mod environment;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "auxv_observation.rs"]
mod auxv_observation;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "startup_security.rs"]
mod startup_security;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "issetugid.rs"]
mod issetugid;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "syscall.rs"]
#[allow(dead_code)]
mod raw_syscall;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "immediate_termination.rs"]
mod immediate_termination;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "posix_exit.rs"]
mod posix_exit;
#[cfg(crabc_general_dynamic_lifecycle)]
#[path = "stack_chk_fail.rs"]
mod stack_chk_fail;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

// Keep the direct source-root DSO self-contained. Rust may lower the small
// bounded startup/vector operations to these byte primitives even though this
// private runtime owns no allocator or ambient C runtime dependency.
#[no_mangle]
pub unsafe extern "C" fn memcpy(
    destination: *mut core::ffi::c_void,
    source: *const core::ffi::c_void,
    length: usize,
) -> *mut core::ffi::c_void {
    let destination = destination.cast::<u8>();
    let source = source.cast::<u8>();
    for offset in 0..length {
        unsafe {
            core::ptr::write_volatile(
                destination.add(offset),
                core::ptr::read_volatile(source.add(offset)),
            );
        }
    }
    destination.cast()
}

#[no_mangle]
pub unsafe extern "C" fn memset(
    destination: *mut core::ffi::c_void,
    value: core::ffi::c_int,
    length: usize,
) -> *mut core::ffi::c_void {
    let destination = destination.cast::<u8>();
    for offset in 0..length {
        unsafe { core::ptr::write_volatile(destination.add(offset), value as u8) };
    }
    destination.cast()
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(
    left: *const core::ffi::c_void,
    right: *const core::ffi::c_void,
    length: usize,
) -> core::ffi::c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for offset in 0..length {
        let left_byte = unsafe { core::ptr::read_volatile(left.add(offset)) };
        let right_byte = unsafe { core::ptr::read_volatile(right.add(offset)) };
        if left_byte != right_byte {
            return left_byte as core::ffi::c_int - right_byte as core::ffi::c_int;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bcmp(
    left: *const core::ffi::c_void,
    right: *const core::ffi::c_void,
    length: usize,
) -> core::ffi::c_int {
    unsafe { memcmp(left, right, length) }
}
