//! Hidden environment accessor for the pinned C mimalloc backend.
//!
//! The product builders compile unedited upstream `src/prim/unix/prim.c` with
//! `-Denviron=(*__crabc_allocator_environ())`, so its `_mi_prim_getenv` scans
//! the vector this returns. Secure execution, as cached by
//! super::startup_security, supplies an empty vector so a privileged process
//! never honors caller-controlled `MIMALLOC_*` options; otherwise the live C
//! `environ` is returned. The symbol is hidden and never part of the C ABI.

use core::{ffi::c_char, ptr};

use super::startup_security;

core::arch::global_asm!(".hidden __crabc_allocator_environ");

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

static mut EMPTY_ENVIRONMENT: [*mut c_char; 1] = [ptr::null_mut()];
static mut EMPTY_ENVIRONMENT_POINTER: *mut *mut c_char = ptr::addr_of_mut!(EMPTY_ENVIRONMENT).cast();

/// Return the address of the environment vector the C allocator may scan.
#[no_mangle]
pub extern "C" fn __crabc_allocator_environ() -> *mut *mut *mut c_char {
    if startup_security::is_secure() {
        ptr::addr_of_mut!(EMPTY_ENVIRONMENT_POINTER)
    } else {
        ptr::addr_of_mut!(environ)
    }
}
