//! Private Linux/x86-64 `execl` entry.
//!
//! This is the pinned musl 1.2.6 `src/process/execl.c` C-variadic wrapper over
//! the selected environment-forwarding and direct-exec siblings. Its dynamic
//! argv-vector helper remains separate so direct/env/PATH consumers do not
//! extract mmap/munmap closure merely by using their own entry points.

use core::ffi::{c_char, c_int};

use super::{process_exec, process_exec_env, process_exec_variadic};

/// Construct argv from C varargs, then replace the current image with the
/// selected process environment.
///
/// The caller must provide `path`, `first`, and every non-null variadic
/// argument as valid null-terminated C strings, followed by a null pointer
/// sentinel. A successful image replacement does not return.
#[no_mangle]
pub unsafe extern "C" fn execl(
    path: *const c_char,
    first: *const c_char,
    mut args: ...,
) -> c_int {
    let argv = match unsafe { process_exec_variadic::variadic_argv(first, &mut args) } {
        Ok(argv) => argv,
        Err(()) => return -1,
    };
    let envp = unsafe { process_exec_env::current_environment() };
    unsafe { process_exec::execve_result(path, argv.as_argv(), envp) }
}
