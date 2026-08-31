//! Linux/x86-64 selected static C `mempcpy` adapter.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The complete
//! source closure is `src/string/mempcpy.c`: it calls `memcpy(destination,
//! source, count)` and returns the destination byte immediately following the
//! copied range. This assembly preserves that exact adapter boundary while
//! making the SysV AMD64 call and return preservation explicit.
//! The delegated `memcpy` retains its C restrict non-overlap contract.
//!
//! This leaf owns neither a new bulk-memory algorithm nor a general memory
//! contract. It has exactly one direct dependency on the already selected
//! `memcpy` owner. It is stateless and allocation-free, with no errno, TLS,
//! syscall, locale, mutable-runtime, allocator, CRT, loader, or sysroot path.
//! It is a private selected static artifact, not `memory.bytes-basic`, general
//! bulk memory, libc.so, a public x86 support claim, or family promotion.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C mempcpy leaf requires little-endian Linux/x86-64");

// On entry rdi/rsi/rdx hold destination/source/count. Save the calculated
// one-past return in callee-saved rbx across the direct memcpy call; the push
// also restores the required 16-byte stack alignment before that call.
core::arch::global_asm!(
    r#"
    .text

    .global mempcpy
    .type mempcpy,@function
mempcpy:
    push rbx
    lea rbx, [rdi + rdx]
    call memcpy
    mov rax, rbx
    pop rbx
    ret
    .size mempcpy, .-mempcpy

    .section .note.GNU-stack,"",@progbits
    "#,
);
