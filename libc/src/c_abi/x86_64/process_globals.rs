//! Static Linux/x86-64 program-name globals and option-parser compatibility.
//!
//! This ABI-only leaf publishes musl's same-address program-name aliases and
//! the shared short/GNU-long option parser. It composes the
//! already selected initial-TLS errno, fixed-locale multibyte, byte-string,
//! and permanent-standard-stream leaves. It does not own environment
//! mutation, secure-execution policy, timezone/network/signgam globals,
//! allocation, locale selection beyond the existing bounded profile, or a
//! dynamic loader handoff.
//!
//! ## Fixed source and license provenance
//!
//! The contract is mapped to musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//! `src/env/__libc_start_main.c`, `src/env/__init_libc.c`,
//! `src/misc/getopt.c`, and `src/misc/getopt_long.c`. The Rust option-parser
//! body remains shared with
//! the established AArch64 C ABI through `libc/src/getopt_exports.rs`; this
//! module owns only x86 composition and the stricter same-address aliases.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("x86 process globals require little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{
    byte_strings::strlen,
    errno,
    locale_multibyte::{mblen, mbtowc},
    stdio_standard::{fputc, fwrite, stderr, StandardStream},
};

const EINVAL: c_int = 22;
static EMPTY_PROGRAM_NAME: [u8; 1] = [0];

/// Select full and short process names from startup's argv and `AT_EXECFN`.
///
/// # Safety
///
/// `argc` and `argv` must be the validated initial process vector, with
/// readable NUL-terminated strings for non-null entries. `execfn` must be null
/// or a readable NUL-terminated kernel auxiliary-vector value. The returned
/// pointers are retained in process globals, so all selected storage must live
/// for the process lifetime.
unsafe fn select_program_names(
    argc: c_int,
    argv: *const *const c_char,
    execfn: *const c_char,
) -> (*const c_char, *const c_char) {
    let full = if argc > 0 && !argv.is_null() && !unsafe { *argv }.is_null() {
        unsafe { *argv }
    } else if !execfn.is_null() {
        execfn
    } else {
        EMPTY_PROGRAM_NAME.as_ptr().cast()
    };
    let mut short = full;
    let mut cursor = full;
    while unsafe { *cursor } != 0 {
        if unsafe { *cursor } as u8 == b'/' {
            short = unsafe { cursor.add(1) };
        }
        cursor = unsafe { cursor.add(1) };
    }
    (full, short)
}

// Musl exposes these compatibility spellings as weak aliases, not copied
// pointer values. The same-address property matters when a caller writes a
// program-name object or strongly overrides one public spelling at static
// link time.
core::arch::global_asm!(
    ".weak optreset",
    ".set optreset, __optreset",
    ".weak program_invocation_name",
    ".set program_invocation_name, __progname_full",
    ".weak program_invocation_short_name",
    ".set program_invocation_short_name, __progname",
    ".weak __posix_getopt",
    ".set __posix_getopt, getopt",
);

/// Minimal internal `fputs` adapter used only by getopt diagnostics.
///
/// The x86 permanent-stream leaf deliberately does not export `fputs`; this
/// private adapter retains the exact selected output path without promoting
/// another public stdio entry point.
unsafe fn fputs(string: *const c_char, stream: *mut StandardStream) -> c_int {
    let length = unsafe { strlen(string) };
    if unsafe { fwrite(string.cast::<c_void>(), 1, length, stream) } == length {
        0
    } else {
        -1
    }
}

include!("../../getopt_exports.rs");

/// Publish the process-name globals from the initial argv before callbacks.
///
/// If startup has no non-null `argv[0]`, use the validated kernel `AT_EXECFN`
/// value; if that tag is absent, use the empty program name as musl does.
///
/// # Safety
///
/// `argc` and `argv` must be the same validated initial process vector used by
/// the selected startup path, and `auxv_observation` must already own its
/// validated initial auxv pointer. The kernel-provided `AT_EXECFN` pointer is
/// retained for process lifetime, like pointers into the initial argv vector.
pub(super) unsafe fn install(argc: c_int, argv: *const *const c_char) {
    let execfn = super::auxv_observation::initial_execfn().unwrap_or(core::ptr::null());
    let (full, short) = unsafe { select_program_names(argc, argv, execfn) };
    // SAFETY: the selected pointers refer to the validated initial stack or
    // the leaf-owned static empty-name byte, and both globals are C ABI pointer slots.
    unsafe {
        __progname_full = full.cast_mut();
        __progname = short.cast_mut();
    }
}

#[cfg(test)]
mod tests {
    use super::select_program_names;
    use core::ffi::c_char;

    #[test]
    fn null_argv0_uses_execfn_and_extracts_basename() {
        static EXECFN: &[u8] = b"/srv/app/no-argv0\0";
        let argv = [core::ptr::null::<c_char>()];
        let (full, short) = unsafe {
            select_program_names(0, argv.as_ptr(), EXECFN.as_ptr().cast())
        };
        assert_eq!(full, EXECFN.as_ptr().cast());
        assert_eq!(short, unsafe { EXECFN.as_ptr().add(9) }.cast());
    }

    #[test]
    fn absent_execfn_uses_the_leaf_owned_empty_program_name() {
        let argv = [core::ptr::null::<c_char>()];
        let (full, short) = unsafe {
            select_program_names(0, argv.as_ptr(), core::ptr::null())
        };
        assert_eq!(unsafe { *full }, 0);
        assert_eq!(short, full);
        assert_eq!(full, EMPTY_PROGRAM_NAME.as_ptr().cast());
    }
}
