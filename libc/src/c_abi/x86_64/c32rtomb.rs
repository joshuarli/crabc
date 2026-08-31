//! Linux/x86-64 selected static C `c32rtomb` adapter.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` maps
//! `src/multibyte/c32rtomb.c::c32rtomb` to this one tail-call adapter. Musl's
//! complete source body is `return wcrtomb(s, c32, ps);`: x86-64 passes the
//! `char *`, 32-bit `char32_t`/`wchar_t`, and `mbstate_t *` in the same
//! rdi/esi/rdx registers, so a tail jump preserves both the SysV ABI and the
//! exact selected C/POSIX/C.UTF-8 profile behavior of the established
//! `wcrtomb` owner.
//!
//! This leaf owns no UTF-16 surrogate state, decoding, locale selection or
//! objects, environment lookup, encoding database, allocation, errno/TLS
//! storage, syscall, CRT, loader, or public x86 support. Its one direct
//! dependency is the already selected fixed-profile `wcrtomb` core; error and
//! locale semantics remain owned there rather than copied here.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C c32rtomb adapter requires little-endian Linux/x86-64");

// `char32_t` and x86 `wchar_t` are both 32-bit values in esi, while the two
// pointer arguments remain rdi/rdx. A direct tail jump is therefore the exact
// ABI form of musl's one-call C body, including bit-preserving values above
// INT_MAX that `wcrtomb` subsequently interprets as `u32`.
core::arch::global_asm!(
    r#"
    .text

    .global c32rtomb
    .type c32rtomb,@function
c32rtomb:
    jmp wcrtomb
    .size c32rtomb, .-c32rtomb

    .section .note.GNU-stack,"",@progbits
    "#,
);
