//! Private Linux/x86-64 selected-environment exec forwarding.
//!
//! This leaf owns only `execv` and the private snapshot of `__environ` it
//! forwards to the direct `execve` sibling. It is the pinned musl 1.2.6
//! `src/process/execv.c` mapping. It does not search PATH, inspect C varargs,
//! map argv storage, implement spawn/fork, or expand the bounded environment
//! substrate into a general process runtime.
//!
//! `execv` forwards the selected `__environ` pointer directly. `execvp` and
//! `__execvpe`/`execvpe` additionally use the default environment artifact's
//! 1,048,576-entry `getenv` lookup for PATH; all three observe its bounded
//! mutation contract. Ordinary valid finite environment forwarding is the
//! selected behavior; this opt-in leaf does not claim unrestricted musl
//! environment parity or select allocator-backed `x86-environment-runtime`.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 execv environment leaf requires little-endian Linux/x86-64");

use core::{ffi::{c_char, c_int}, ptr};

use super::{environment, process_exec};

/// Read the selected public environment-vector object without constructing a
/// reference to mutable static storage.
#[inline]
pub(super) unsafe fn current_environment() -> *const *const c_char {
    // SAFETY: the environment substrate owns the mutable global; this leaf
    // takes one machine-word snapshot just as musl reads `__environ`.
    let vector = unsafe { ptr::read(ptr::addr_of!(environment::__environ)) };
    vector.cast_const().cast()
}

/// Replace the current image with the selected process environment.
///
/// C callers must supply a Linux-valid pathname and null-terminated argv;
/// successful image replacement does not return.
#[no_mangle]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    let envp = unsafe { current_environment() };
    unsafe { process_exec::execve_result(path, argv, envp) }
}
