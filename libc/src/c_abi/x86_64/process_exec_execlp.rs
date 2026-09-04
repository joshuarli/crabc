//! Private Linux/x86-64 `execlp` entry.
//!
//! This is the pinned musl 1.2.6 `src/process/execlp.c` C-variadic wrapper over
//! the selected PATH-search sibling. Its dynamic argv-vector helper stays in
//! a separate archive member so `execvp`/`__execvpe` do not acquire mmap/munmap
//! closure when linked ordinarily.

use core::ffi::{c_char, c_int};

use super::{process_exec_path, process_exec_variadic};

/// Construct argv from C varargs, search the selected process PATH, and
/// replace the current image.
///
/// The caller must provide `file`, `first`, and every non-null variadic
/// argument as valid null-terminated C strings, followed by a null pointer
/// sentinel. A successful image replacement does not return.
#[no_mangle]
pub unsafe extern "C" fn execlp(
    file: *const c_char,
    first: *const c_char,
    mut args: ...,
) -> c_int {
    let argv = match unsafe { process_exec_variadic::variadic_argv(first, &mut args) } {
        Ok(argv) => argv,
        Err(()) => return -1,
    };
    unsafe { process_exec_path::execvp(file, argv.as_argv()) }
}
