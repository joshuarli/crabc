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

/// Publish the validated startup vectors before constructors or `main` run.
pub(super) unsafe fn install(
    argc: c_int,
    argv: *const *const c_char,
) {
    let argv0 = if argc > 0 && !argv.is_null() && !unsafe { *argv }.is_null() {
        unsafe { *argv }
    } else {
        EMPTY_PROGRAM_NAME.as_ptr().cast::<c_char>()
    };
    unsafe { cabi_set_program_names(argv0) };
}
