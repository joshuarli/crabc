//! Linux/x86-64 selected static C legacy-memory adapters.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The exact source
//! closure is deliberately only two adapter functions:
//!
//! - `src/string/bcopy.c` maps `bcopy(source, destination, length)` to
//!   `memmove(destination, source, length)`.
//! - `src/string/bzero.c` maps `bzero(destination, length)` to
//!   `memset(destination, 0, length)`.
//!
//! The existing selected `memory.rs` leaf owns the musl-derived x86-64
//! `memmove` and `memset` implementations. These wrappers only arrange the
//! SysV AMD64 argument registers and tail-transfer to that established owner,
//! so they add no allocation, errno, TLS, syscall, locale, mutable state, or
//! compiler/runtime dependency. The assembly spelling differs lexically from
//! musl's C call-and-return wrappers while preserving their observable behavior.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C legacy-memory leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    r#"
    .text

    /* bcopy(source, destination, length) is musl's memmove(destination,
       source, length) adapter. Swapping rdi/rsi preserves rdx before the
       separately selected overlap-safe owner is called. */
    .global bcopy
    .type bcopy,@function
bcopy:
    xchg rdi, rsi
    jmp memmove
    .size bcopy, .-bcopy

    /* bzero(destination, length) is musl's memset(destination, 0, length)
       adapter. Move its second argument before memset consumes sil. */
    .global bzero
    .type bzero,@function
bzero:
    mov rdx, rsi
    xor esi, esi
    jmp memset
    .size bzero, .-bzero

    .section .note.GNU-stack,"",@progbits
    "#
);
