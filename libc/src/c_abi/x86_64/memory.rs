//! Linux/x86-64 source-only C bulk-memory leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The exact source
//! mapping is deliberately narrow:
//!
//! - `src/string/x86_64/memcpy.s` maps to `memcpy` and hidden
//!   `__memcpy_fwd` below.
//! - `src/string/x86_64/memmove.s` maps to `memmove` below.
//! - `src/string/x86_64/memset.s` maps to `memset` below.
//!
//! The intentional difference is lexical only: the pinned AT&T assembly is
//! expressed through Rust `global_asm!`'s native Intel syntax. It remains a
//! source-only evidence leaf until x86 `crabc-libc` composition selects these
//! symbols. It is not a general x86 C runtime or public-support claim.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 C memory leaf requires little-endian Linux/x86-64");

// Preserve musl's exact algorithms, including `memcpy`'s non-overlap contract
// and `memmove`'s explicit direction-flag restoration after a backwards copy.
// The routines use only the established x86 string/GPR instructions; there is
// no feature dispatch, vector path, or alternate allocator/runtime dependency.
core::arch::global_asm!(
    r#"
    .text

    .global memcpy
    .global __memcpy_fwd
    .hidden __memcpy_fwd
    .type memcpy,@function
memcpy:
__memcpy_fwd:
    mov rax, rdi
    cmp rdx, 8
    jb .Lcrabc_x86_memcpy_words
    test edi, 7
    jz .Lcrabc_x86_memcpy_words
.Lcrabc_x86_memcpy_align:
    movsb
    dec rdx
    test edi, 7
    jnz .Lcrabc_x86_memcpy_align
.Lcrabc_x86_memcpy_words:
    mov rcx, rdx
    shr rcx, 3
    rep movsq
    and edx, 7
    jz .Lcrabc_x86_memcpy_done
.Lcrabc_x86_memcpy_tail:
    movsb
    dec edx
    jnz .Lcrabc_x86_memcpy_tail
.Lcrabc_x86_memcpy_done:
    ret
    .size memcpy, .-memcpy

    .global memset
    .type memset,@function
memset:
    movzx rax, sil
    mov r8, 0x0101010101010101
    imul rax, r8

    cmp rdx, 126
    ja .Lcrabc_x86_memset_long

    test edx, edx
    jz .Lcrabc_x86_memset_done

    mov byte ptr [rdi], sil
    mov byte ptr [rdi + rdx - 1], sil
    cmp edx, 2
    jbe .Lcrabc_x86_memset_done

    mov word ptr [rdi + 1], ax
    mov word ptr [rdi + rdx - 3], ax
    cmp edx, 6
    jbe .Lcrabc_x86_memset_done

    mov dword ptr [rdi + 3], eax
    mov dword ptr [rdi + rdx - 7], eax
    cmp edx, 14
    jbe .Lcrabc_x86_memset_done

    mov qword ptr [rdi + 7], rax
    mov qword ptr [rdi + rdx - 15], rax
    cmp edx, 30
    jbe .Lcrabc_x86_memset_done

    mov qword ptr [rdi + 15], rax
    mov qword ptr [rdi + 23], rax
    mov qword ptr [rdi + rdx - 31], rax
    mov qword ptr [rdi + rdx - 23], rax
    cmp edx, 62
    jbe .Lcrabc_x86_memset_done

    mov qword ptr [rdi + 31], rax
    mov qword ptr [rdi + 39], rax
    mov qword ptr [rdi + 47], rax
    mov qword ptr [rdi + 55], rax
    mov qword ptr [rdi + rdx - 63], rax
    mov qword ptr [rdi + rdx - 55], rax
    mov qword ptr [rdi + rdx - 47], rax
    mov qword ptr [rdi + rdx - 39], rax

.Lcrabc_x86_memset_done:
    mov rax, rdi
    ret

.Lcrabc_x86_memset_long:
    test edi, 15
    mov r8, rdi
    mov qword ptr [rdi + rdx - 8], rax
    mov rcx, rdx
    jnz .Lcrabc_x86_memset_unaligned

.Lcrabc_x86_memset_words:
    shr rcx, 3
    rep stosq
    mov rax, r8
    ret

.Lcrabc_x86_memset_unaligned:
    xor edx, edx
    sub edx, edi
    and edx, 15
    mov qword ptr [rdi], rax
    mov qword ptr [rdi + 8], rax
    sub rcx, rdx
    add rdi, rdx
    jmp .Lcrabc_x86_memset_words
    .size memset, .-memset

    .global memmove
    .type memmove,@function
memmove:
    mov rax, rdi
    sub rax, rsi
    cmp rax, rdx
    jae __memcpy_fwd
    mov rcx, rdx
    lea rdi, [rdi + rdx - 1]
    lea rsi, [rsi + rdx - 1]
    std
    rep movsb
    cld
    lea rax, [rdi + 1]
    ret
    .size memmove, .-memmove
"#,
);
