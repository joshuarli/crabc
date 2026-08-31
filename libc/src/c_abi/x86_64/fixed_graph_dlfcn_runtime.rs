#![no_std]
#![feature(linkage)]

//! Isolated PIC build root for the fixed-graph public C dlfcn bridge.
//!
//! The canonical staged `libc.a` also composes this exact leaf and owns its
//! export ratchet. Dynamic evidence uses this root so the no-TLS loader graph
//! does not accidentally pull the canonical archive's independently selected
//! static-initial-TLS `errno` object through a shared Rust codegen unit.
//! It enables the same target-scoped weak-linkage support as `libc/src/lib.rs`
//! so the isolated bridge retains musl's static `dl_iterate_phdr` and
//! `dlopen` bindings.

#[path = "syscall.rs"]
#[allow(dead_code)]
mod raw_syscall;
#[path = "fixed_graph_dlfcn.rs"]
mod fixed_graph_dlfcn;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

// Rust lowers bounded record copies and zero-initialization to these ordinary
// C primitives. Keep the isolated bridge self-contained instead of reaching
// an ambient libc or pulling the canonical archive's TLS-bearing codegen unit.
#[no_mangle]
pub unsafe extern "C" fn memcpy(
    destination: *mut core::ffi::c_void,
    source: *const core::ffi::c_void,
    length: usize,
) -> *mut core::ffi::c_void {
    let destination_bytes = destination.cast::<u8>();
    let source_bytes = source.cast::<u8>();
    for index in 0..length {
        core::ptr::write_volatile(
            destination_bytes.add(index),
            core::ptr::read_volatile(source_bytes.add(index)),
        );
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn memset(
    destination: *mut core::ffi::c_void,
    value: core::ffi::c_int,
    length: usize,
) -> *mut core::ffi::c_void {
    let destination_bytes = destination.cast::<u8>();
    for index in 0..length {
        core::ptr::write_volatile(destination_bytes.add(index), value as u8);
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(
    left: *const core::ffi::c_void,
    right: *const core::ffi::c_void,
    length: usize,
) -> core::ffi::c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for index in 0..length {
        let left_byte = core::ptr::read_volatile(left.add(index));
        let right_byte = core::ptr::read_volatile(right.add(index));
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
    memcmp(left, right, length)
}
