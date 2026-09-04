//! Private Linux/x86-64 `execle` entry.
//!
//! This is the pinned musl 1.2.6 `src/process/execle.c` C-variadic wrapper over
//! the direct-exec sibling. Its explicit environment vector means this archive
//! member does not need the selected `__environ` or PATH-search closure.

use core::ffi::{c_char, c_int};

use super::{process_exec, process_exec_variadic};

/// Construct argv from C varargs and read the following explicit environment
/// vector.
///
/// The caller must provide `path`, `first`, and every non-null argv vararg as
/// valid null-terminated C strings, followed by a null pointer sentinel. The
/// immediately following `envp` argument must be a valid null-terminated C
/// pointer vector whose non-null entries are valid null-terminated C strings.
/// A successful image replacement does not return.
#[no_mangle]
pub unsafe extern "C" fn execle(
    path: *const c_char,
    first: *const c_char,
    mut args: ...,
) -> c_int {
    let argv = match unsafe { process_exec_variadic::variadic_argv(first, &mut args) } {
        Ok(argv) => argv,
        Err(()) => return -1,
    };
    // SAFETY: the C execle ABI places one `char *const[]` pointer immediately
    // after the argv list's terminal null.
    let envp: *const *const c_char = unsafe { args.next_arg() };
    unsafe { process_exec::execve_result(path, argv.as_argv(), envp) }
}
