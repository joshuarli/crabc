//! Linux/x86-64 selected static C bulk-memory leaf.
//!
//! Provenance is fixed to musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`),
//! under musl's MIT license recorded in its `COPYRIGHT` file. The exact source
//! mapping is deliberately narrow:
//!
//! - `src/string/x86_64/memcpy.s` maps to `memcpy` and hidden
//!   `__memcpy_fwd` below.
//! - `src/string/x86_64/memmove.s` maps to `memmove` below.
//! - `src/string/x86_64/memset.s` maps to `memset` below.
//! - `src/string/memcmp.c` maps to the fixed unsigned-byte `memcmp` loop
//!   below, and `src/string/bcmp.c` maps to its direct `bcmp` forwarding
//!   alias.
//!
//! `memset` and the hidden `__memcpy_fwd` keep musl's exact algorithms; the
//! pinned AT&T assembly is expressed through Rust `global_asm!`'s native
//! Intel syntax. `memcpy`, `memmove` and `memcmp` keep musl's contracts and
//! results but use faster x86-64-baseline (SSE2, no CPU dispatch) forms,
//! chosen by cycle measurement on the development CPU:
//!
//! - `memcpy` copies up to 64 bytes with overlapping register loads and
//!   stores, and larger copies with an overlapping 64-byte head that aligns
//!   the destination to 64 bytes, musl's `rep movsq` bulk, and an overlapping
//!   16-byte tail (about 2x faster for short unaligned copies, 5% for 16 KiB
//!   unaligned; aligned bulk copies are already at `rep movsq`'s bandwidth).
//! - `memmove` performs every copy of at most 64 bytes with all loads before
//!   any store, takes musl's forward `__memcpy_fwd` when that is safe, and
//!   copies backwards with 16-byte SSE2 blocks instead of `std; rep movsb`
//!   (about 30x faster), leaving the direction flag untouched.
//! - `memcmp` compares 16-byte SSE2 blocks and, below 16 bytes, overlapping
//!   8-byte words, returning musl's first-differing-unsigned-byte
//!   difference (about 10x faster from 64 bytes up).
//!
//! Every access stays inside the requested ranges; the source-only memory
//! probe proves that at guard pages for every size, alignment and overlap
//! class. The selected x86 static archive exposes this exact small
//! bulk-memory surface only after its freestanding artifact fixture proves
//! it. It is not a general x86 C runtime or public-support claim.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 C memory leaf requires little-endian Linux/x86-64");

// Preserve musl's contracts, including `memcpy`'s non-overlap contract and a
// clear direction flag on return. The routines use only x86-64 baseline
// string, GPR and SSE2 instructions; there is no CPU feature dispatch or
// alternate allocator/runtime dependency.

// Each routine has its own static archive member, as musl's objects do, so an
// application may define any one of them and link against the rest.
// `memmove` reaches memcpy's hidden `__memcpy_fwd` and `bcmp` tail-calls
// `memcmp`, exactly as musl's objects do.

// Musl's `src/string/x86_64/memcpy.s` object: `memcpy` plus musl's exact
// hidden forward copy `__memcpy_fwd`, which `memmove` reaches.
static_archive_member! { memcpy_source {
    core::arch::global_asm!(
        r#"
    .text

    .global memcpy
    .global __memcpy_fwd
    .hidden __memcpy_fwd
    .type memcpy,@function
memcpy:
    mov rax, rdi
    cmp rdx, 64
    ja .Lcrabc_x86_memcpy_large
    cmp rdx, 16
    jb .Lcrabc_x86_memcpy_below16
    /* 16..64 bytes: overlapping 16-byte blocks, all loads first. */
    movdqu xmm0, xmmword ptr [rsi]
    movdqu xmm1, xmmword ptr [rsi + rdx - 16]
    cmp rdx, 32
    jbe .Lcrabc_x86_memcpy_store2
    movdqu xmm2, xmmword ptr [rsi + 16]
    movdqu xmm3, xmmword ptr [rsi + rdx - 32]
    movdqu xmmword ptr [rdi + 16], xmm2
    movdqu xmmword ptr [rdi + rdx - 32], xmm3
.Lcrabc_x86_memcpy_store2:
    movdqu xmmword ptr [rdi], xmm0
    movdqu xmmword ptr [rdi + rdx - 16], xmm1
    ret
.Lcrabc_x86_memcpy_below16:
    cmp edx, 8
    jb .Lcrabc_x86_memcpy_below8
    mov rcx, qword ptr [rsi]
    mov r8, qword ptr [rsi + rdx - 8]
    mov qword ptr [rdi], rcx
    mov qword ptr [rdi + rdx - 8], r8
    ret
.Lcrabc_x86_memcpy_below8:
    cmp edx, 4
    jb .Lcrabc_x86_memcpy_below4
    mov ecx, dword ptr [rsi]
    mov r8d, dword ptr [rsi + rdx - 4]
    mov dword ptr [rdi], ecx
    mov dword ptr [rdi + rdx - 4], r8d
    ret
.Lcrabc_x86_memcpy_below4:
    test edx, edx
    jz .Lcrabc_x86_memcpy_done
    /* 1..3 bytes: first, middle (n / 2) and last byte. */
    mov r9, rdx
    shr r9, 1
    movzx ecx, byte ptr [rsi]
    movzx r8d, byte ptr [rsi + rdx - 1]
    movzx r10d, byte ptr [rsi + r9]
    mov byte ptr [rdi], cl
    mov byte ptr [rdi + rdx - 1], r8b
    mov byte ptr [rdi + r9], r10b
.Lcrabc_x86_memcpy_done:
    ret
.Lcrabc_x86_memcpy_large:
    /* More than 64 bytes of non-overlapping ranges: an overlapping 64-byte
       head aligns the destination to 64 bytes for musl's `rep movsq` bulk,
       and a preloaded 16-byte tail covers its final 0-7 bytes. */
    movdqu xmm0, xmmword ptr [rsi]
    movdqu xmm1, xmmword ptr [rsi + 16]
    movdqu xmm2, xmmword ptr [rsi + 32]
    movdqu xmm3, xmmword ptr [rsi + 48]
    movdqu xmm4, xmmword ptr [rsi + rdx - 16]
    lea r9, [rdi + rdx - 16]
    mov rcx, rdi
    neg rcx
    and ecx, 63
    movdqu xmmword ptr [rdi], xmm0
    movdqu xmmword ptr [rdi + 16], xmm1
    movdqu xmmword ptr [rdi + 32], xmm2
    movdqu xmmword ptr [rdi + 48], xmm3
    add rdi, rcx
    add rsi, rcx
    sub rdx, rcx
    mov rcx, rdx
    shr rcx, 3
    rep movsq
    movdqu xmmword ptr [r9], xmm4
    ret
    .size memcpy, .-memcpy

    .type __memcpy_fwd,@function
__memcpy_fwd:
    mov rax, rdi
    cmp rdx, 8
    jb .Lcrabc_x86_memcpy_fwd_words
    test edi, 7
    jz .Lcrabc_x86_memcpy_fwd_words
.Lcrabc_x86_memcpy_fwd_align:
    movsb
    dec rdx
    test edi, 7
    jnz .Lcrabc_x86_memcpy_fwd_align
.Lcrabc_x86_memcpy_fwd_words:
    mov rcx, rdx
    shr rcx, 3
    rep movsq
    and edx, 7
    jz .Lcrabc_x86_memcpy_fwd_done
.Lcrabc_x86_memcpy_fwd_tail:
    movsb
    dec edx
    jnz .Lcrabc_x86_memcpy_fwd_tail
.Lcrabc_x86_memcpy_fwd_done:
    ret
    .size __memcpy_fwd, .-__memcpy_fwd
"#,
    );
}}

// Musl's `src/string/memcmp.c` object: the same first-different-unsigned-byte
// result, compared 16 bytes (SSE2) or 8 bytes at a time.
static_archive_member! { memcmp_source {
    core::arch::global_asm!(
        r#"
    .text

    .global memcmp
    .type memcmp,@function
memcmp:
    xor eax, eax
    test rdx, rdx
    jz .Lcrabc_x86_memcmp_done
    cmp rdx, 16
    jb .Lcrabc_x86_memcmp_below16
    xor ecx, ecx
    lea r8, [rdx - 16]
.Lcrabc_x86_memcmp_blocks:
    cmp rcx, r8
    jae .Lcrabc_x86_memcmp_last_block
    movdqu xmm0, xmmword ptr [rdi + rcx]
    movdqu xmm1, xmmword ptr [rsi + rcx]
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    xor eax, 0xffff
    jnz .Lcrabc_x86_memcmp_byte
    add rcx, 16
    jmp .Lcrabc_x86_memcmp_blocks
.Lcrabc_x86_memcmp_last_block:
    /* The final, possibly overlapping, block ends exactly at n; its lowest
       differing byte is the first difference overall. */
    mov rcx, r8
    movdqu xmm0, xmmword ptr [rdi + rcx]
    movdqu xmm1, xmmword ptr [rsi + rcx]
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    xor eax, 0xffff
    jnz .Lcrabc_x86_memcmp_byte
    ret
.Lcrabc_x86_memcmp_below16:
    cmp edx, 8
    jb .Lcrabc_x86_memcmp_bytes
    xor ecx, ecx
    mov rax, qword ptr [rdi]
    xor rax, qword ptr [rsi]
    jnz .Lcrabc_x86_memcmp_word
    lea rcx, [rdx - 8]
    mov rax, qword ptr [rdi + rcx]
    xor rax, qword ptr [rsi + rcx]
    jnz .Lcrabc_x86_memcmp_word
    xor eax, eax
    ret
.Lcrabc_x86_memcmp_word:
    bsf rax, rax
    shr eax, 3
.Lcrabc_x86_memcmp_byte:
    /* eax is a nonzero difference mask (bit per byte) or, from the word
       path, already the byte index. */
    cmp rdx, 16
    jb .Lcrabc_x86_memcmp_indexed
    bsf eax, eax
.Lcrabc_x86_memcmp_indexed:
    add rcx, rax
    movzx eax, byte ptr [rdi + rcx]
    movzx edx, byte ptr [rsi + rcx]
    sub eax, edx
    ret
.Lcrabc_x86_memcmp_bytes:
.Lcrabc_x86_memcmp_loop:
    movzx eax, byte ptr [rdi]
    movzx ecx, byte ptr [rsi]
    sub eax, ecx
    jne .Lcrabc_x86_memcmp_done
    inc rdi
    inc rsi
    dec rdx
    jne .Lcrabc_x86_memcmp_loop
.Lcrabc_x86_memcmp_done:
    ret
    .size memcmp, .-memcmp
"#,
    );
}}

// Musl's `src/string/bcmp.c` object.
static_archive_member! { bcmp_source {
    core::arch::global_asm!(
        r#"
    .text

    .global bcmp
    .type bcmp,@function
bcmp:
    jmp memcmp
    .size bcmp, .-bcmp
"#,
    );
}}

// Musl's `src/string/x86_64/memset.s` object.
static_archive_member! { memset_source {
    core::arch::global_asm!(
        r#"
    .text

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
"#,
    );
}}

// Musl's `src/string/x86_64/memmove.s` object.
static_archive_member! { memmove_source {
    core::arch::global_asm!(
        r#"
    .text

    .global memmove
    .type memmove,@function
memmove:
    mov rax, rdi
    cmp rdx, 64
    ja .Lcrabc_x86_memmove_large
    /* At most 64 bytes: every load precedes every store, so either overlap
       direction is exact. */
    cmp rdx, 16
    jb .Lcrabc_x86_memmove_below16
    movdqu xmm0, xmmword ptr [rsi]
    movdqu xmm1, xmmword ptr [rsi + rdx - 16]
    cmp rdx, 32
    jbe .Lcrabc_x86_memmove_store2
    movdqu xmm2, xmmword ptr [rsi + 16]
    movdqu xmm3, xmmword ptr [rsi + rdx - 32]
    movdqu xmmword ptr [rdi + 16], xmm2
    movdqu xmmword ptr [rdi + rdx - 32], xmm3
.Lcrabc_x86_memmove_store2:
    movdqu xmmword ptr [rdi], xmm0
    movdqu xmmword ptr [rdi + rdx - 16], xmm1
    ret
.Lcrabc_x86_memmove_below16:
    cmp edx, 8
    jb .Lcrabc_x86_memmove_below8
    mov rcx, qword ptr [rsi]
    mov r8, qword ptr [rsi + rdx - 8]
    mov qword ptr [rdi], rcx
    mov qword ptr [rdi + rdx - 8], r8
    ret
.Lcrabc_x86_memmove_below8:
    cmp edx, 4
    jb .Lcrabc_x86_memmove_below4
    mov ecx, dword ptr [rsi]
    mov r8d, dword ptr [rsi + rdx - 4]
    mov dword ptr [rdi], ecx
    mov dword ptr [rdi + rdx - 4], r8d
    ret
.Lcrabc_x86_memmove_below4:
    test edx, edx
    jz .Lcrabc_x86_memmove_done
    mov r9, rdx
    shr r9, 1
    movzx ecx, byte ptr [rsi]
    movzx r8d, byte ptr [rsi + rdx - 1]
    movzx r10d, byte ptr [rsi + r9]
    mov byte ptr [rdi], cl
    mov byte ptr [rdi + rdx - 1], r8b
    mov byte ptr [rdi + r9], r10b
.Lcrabc_x86_memmove_done:
    ret
.Lcrabc_x86_memmove_large:
    mov rcx, rdi
    sub rcx, rsi
    cmp rcx, rdx
    jae __memcpy_fwd
    /* Destination above an overlapping source: copy 16-byte blocks from the
       top down. Each block's source lies below every byte already stored,
       so it is still original; the preloaded head and tail are stored last. */
    movdqu xmm5, xmmword ptr [rsi]
    movdqu xmm4, xmmword ptr [rsi + rdx - 16]
    lea r11, [rdi + rdx - 16]
    lea r9, [rdi + rdx]
    lea rsi, [rsi + rdx]
    mov rcx, r9
    and ecx, 15
    sub r9, rcx
    sub rsi, rcx
    lea r10, [rdi + 80]
.Lcrabc_x86_memmove_back64:
    cmp r9, r10
    jb .Lcrabc_x86_memmove_back16_start
    movdqu xmm0, xmmword ptr [rsi - 16]
    movdqu xmm1, xmmword ptr [rsi - 32]
    movdqu xmm2, xmmword ptr [rsi - 48]
    movdqu xmm3, xmmword ptr [rsi - 64]
    movdqa xmmword ptr [r9 - 16], xmm0
    movdqa xmmword ptr [r9 - 32], xmm1
    movdqa xmmword ptr [r9 - 48], xmm2
    movdqa xmmword ptr [r9 - 64], xmm3
    sub rsi, 64
    sub r9, 64
    jmp .Lcrabc_x86_memmove_back64
.Lcrabc_x86_memmove_back16_start:
    lea r10, [rdi + 32]
.Lcrabc_x86_memmove_back16:
    cmp r9, r10
    jb .Lcrabc_x86_memmove_back_finish
    movdqu xmm0, xmmword ptr [rsi - 16]
    movdqa xmmword ptr [r9 - 16], xmm0
    sub rsi, 16
    sub r9, 16
    jmp .Lcrabc_x86_memmove_back16
.Lcrabc_x86_memmove_back_finish:
    /* dst + 16 <= r9 < dst + 32: one unaligned block below r9, then the
       head and tail. */
    movdqu xmm0, xmmword ptr [rsi - 16]
    movdqu xmmword ptr [r9 - 16], xmm0
    movdqu xmmword ptr [r11], xmm4
    movdqu xmmword ptr [rdi], xmm5
    ret
    .size memmove, .-memmove
"#,
    );
}}
