#![no_std]
#![allow(unexpected_cfgs)]

//! Isolated freestanding consumer root for the private x86 loader/libc TLS
//! RuntimeV1 handoff.
//!
//! The selected static `libc.a` does not include this root or its weak loader
//! record import. Static Initial TLS v1 remains the no-PT_INTERP owner. This
//! source is compiled only by the focused loader/libc handoff evidence, where
//! a PT_INTERP-selected x86 loader has already materialized its one bounded
//! initial TLS graph.

#[path = "loader_tls_runtime_v1.rs"]
mod loader_tls_runtime_v1;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// The freestanding proof builds with `panic=abort`; retain this terminal
// personality spelling so the isolated consumer never reaches for an ambient
// unwind runtime.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

// Rust may lower bounded record initialization and comparison to ordinary C
// byte primitives even though this source itself uses no allocator or libc
// runtime. Keep the one handoff consumer self-contained, as the adjacent
// fixed-graph bridge does, rather than pulling an ambient implementation into
// the evidence executable.
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
