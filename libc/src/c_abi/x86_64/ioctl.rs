//! Selected static Linux/x86-64 C generic ioctl boundary.
//!
//! This leaf owns the direct C `ioctl` syscall forwarder for a deliberately
//! narrow static artifact.  It accepts the public two fixed C words and an
//! opaque third machine word, preserves Linux's low-32-bit request contract,
//! and translates only Linux raw errors through the selected initial-TLS
//! `errno` boundary.  It does not select a request vocabulary, device policy,
//! terminal/session behavior, socket options, cancellation, a general C/POSIX
//! runtime, libc.so, CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/misc/ioctl.c` maps to the generic three-word Linux forwarding path
//!   in [`ioctl_word`].
//!
//! Musl's variadic implementation always reads and forwards one argument
//! word.  A C caller may legally omit that word for request forms such as
//! `FIOCLEX` and `FIONCLEX`, but SysV AMD64 leaves `%rdx` unspecified then.
//! The public assembly boundary intercepts exactly those two known two-word
//! forms and supplies a zero Linux argument before it reaches Rust. SysV AMD64
//! places fd/request/the first explicit vararg in rdi/rsi/rdx. Every other
//! selected call must provide an explicit third word; this preserves the
//! source ABI without inventing a generic request classifier.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

const FIONCLEX: c_int = 0x5450;
const FIOCLEX: c_int = 0x5451;

// Keep the public variadic spelling in assembly.  A two-word C call does not
// initialize rdx, so only the two named no-argument request words may tail
// branch to the helper that installs a known zero.  All other requests retain
// the incoming third SysV word for the musl-shaped three-word path.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global ioctl
    .type ioctl,@function
ioctl:
    cmp esi, {fioclex}
    je {no_argument}
    cmp esi, {fionclex}
    je {no_argument}
    jmp {word}
    .size ioctl, .-ioctl

    .section .note.GNU-stack,"",@progbits
"#,
    fioclex = const FIOCLEX,
    fionclex = const FIONCLEX,
    no_argument = sym ioctl_no_argument,
    word = sym ioctl_word,
);

/// Forward one admitted no-vararg Linux request with an explicit zero word.
///
/// The public assembly entry is the only caller.  Keeping this as a normal
/// two-argument function ensures Rust never observes an absent C vararg.
#[inline(never)]
unsafe extern "C" fn ioctl_no_argument(file_descriptor: c_int, request: c_int) -> c_int {
    if request != FIOCLEX && request != FIONCLEX {
        return unsafe { ioctl_word(file_descriptor, request, 0) };
    }
    // SAFETY: the named Linux requests ignore their third word.  The assembly
    // dispatcher admits only exactly these two source-defined two-word forms.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(file_descriptor),
            i64::from(request),
            0,
        )
    };
    c_status(result)
}

/// Forward one explicit third C vararg word through Linux `ioctl=16`.
///
/// The public declaration is variadic, while SysV AMD64 passes its first
/// opaque vararg word in the same `%rdx` register as this fixed helper.  This
/// helper is therefore called only from the public assembly three-word path;
/// callers of all other request forms must supply an explicit pointer or
/// integer word exactly as their chosen Linux request requires.
#[inline(never)]
unsafe extern "C" fn ioctl_word(
    file_descriptor: c_int,
    request: c_int,
    argument: usize,
) -> c_int {
    // SAFETY: the caller owns descriptor, request, pointer/integer-word, and
    // request-specific memory validity.  Linux consumes the request's low 32
    // bits; i64::from mirrors musl's signed-int register extension.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(file_descriptor),
            i64::from(request),
            argument as i64,
        )
    };
    c_status(result)
}
