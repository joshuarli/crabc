#![no_std]

//! Self-relocating static-PIE application entry object.
//!
//! This file intentionally keeps the relocation bootstrap in Rust-hosted
//! `global_asm!`: it must execute before a normal Rust function can touch a
//! GOT entry or relocated global. It obtains the load bias from Linux's
//! `AT_PHDR` plus the executable `PT_PHDR` record, applies the AArch64
//! `RELA`/`RELR` relative forms emitted by the pinned linker, seals GNU RELRO,
//! and only then branches to the common Rust startup routine.

mod array_boundaries;
mod startup;

pub use startup::__crabc_start;

core::arch::global_asm!(
    r#"
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,%function
_start:
    // Preserve the initial stack before making the ABI's required alignment
    // explicit. x29/x30 are the conventional bottom-frame sentinel.
    mov x15, sp
    mov x29, xzr
    mov x30, xzr
    and sp, x15, #0xfffffffffffffff0

    // Parse the kernel stack through argv[] and envp[] to AT_PHDR, AT_PHENT,
    // and AT_PHNUM. These bounded scans use no relocated data or Rust code.
    ldr x10, [x15]
    mov x11, #0x100000
    cmp x10, x11
    b.hi .Lstatic_pie_fail
    add x11, x15, #8
    add x11, x11, x10, lsl #3
    add x11, x11, #8
    mov x17, #0x100000
.Lstatic_pie_env:
    cbz x17, .Lstatic_pie_fail
    ldr x12, [x11], #8
    sub x17, x17, #1
    cbnz x12, .Lstatic_pie_env

    mov x20, xzr
    mov x21, xzr
    mov x22, xzr
    mov x17, #4096
.Lstatic_pie_auxv:
    cbz x17, .Lstatic_pie_fail
    ldr x12, [x11]
    ldr x13, [x11, #8]
    add x11, x11, #16
    sub x17, x17, #1
    cbz x12, .Lstatic_pie_auxv_done
    cmp x12, #3
    b.ne .Lstatic_pie_not_phdr
    mov x20, x13
    b .Lstatic_pie_auxv
.Lstatic_pie_not_phdr:
    cmp x12, #4
    b.ne .Lstatic_pie_not_phent
    mov x21, x13
    b .Lstatic_pie_auxv
.Lstatic_pie_not_phent:
    cmp x12, #5
    b.ne .Lstatic_pie_auxv
    mov x22, x13
    b .Lstatic_pie_auxv
.Lstatic_pie_auxv_done:
    cbz x20, .Lstatic_pie_fail
    cmp x21, #56
    b.ne .Lstatic_pie_fail
    cbz x22, .Lstatic_pie_fail
    mov x10, #128
    cmp x22, x10
    b.hi .Lstatic_pie_fail

    // A valid PT_PHDR maps the runtime AT_PHDR address back to the ELF load
    // bias. The same checked table supplies the bounded PT_DYNAMIC record.
    // Every later dynamic/relocation range is checked against a PT_LOAD range;
    // relocation writes additionally require PF_W. Arithmetic alone cannot
    // establish that a malformed tag points into mapped writable memory.
    mov x23, x20
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x9, xzr
    mov x10, xzr
.Lstatic_pie_find_phdr:
    cmp x24, x22
    b.hs .Lstatic_pie_found_phdr
    ldr w11, [x23]
    cmp w11, #6
    b.ne .Lstatic_pie_not_program_header
    cbnz x9, .Lstatic_pie_fail
    ldr x25, [x23, #16]
    mov x9, #1
    b .Lstatic_pie_next_program_header
.Lstatic_pie_not_program_header:
    cmp w11, #2
    b.ne .Lstatic_pie_next_program_header
    cbnz x10, .Lstatic_pie_fail
    ldr x26, [x23, #16]
    ldr x27, [x23, #40]
    mov x10, #1
.Lstatic_pie_next_program_header:
    add x23, x23, #56
    add x24, x24, #1
    b .Lstatic_pie_find_phdr
.Lstatic_pie_found_phdr:
    cbz x9, .Lstatic_pie_fail
    cbz x10, .Lstatic_pie_fail
    cbz x27, .Lstatic_pie_fail
    cmp x20, x25
    b.lo .Lstatic_pie_fail
    sub x19, x20, x25
    adds x23, x19, x26
    b.cs .Lstatic_pie_fail
    adds x24, x23, x27
    b.cs .Lstatic_pie_fail
    mov x0, x23
    mov x1, x27
    adr x17, .Lstatic_pie_after_dynamic_range
    b .Lstatic_pie_require_load_range
.Lstatic_pie_after_dynamic_range:
    // The range verifier intentionally reuses x23/x24 for its PT_LOAD
    // traversal; reconstruct the validated PT_DYNAMIC cursor before reading
    // any dynamic tag.
    adds x23, x19, x26
    b.cs .Lstatic_pie_fail
    adds x24, x23, x27
    b.cs .Lstatic_pie_fail

    // Dynamic tags identify the only relocation encodings this bootstrap
    // accepts: AArch64 RELA relative entries and packed RELR entries.
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
    mov x18, xzr
.Lstatic_pie_dynamic:
    add x9, x23, #16
    cmp x9, x24
    b.hi .Lstatic_pie_fail
    ldr x10, [x23]
    ldr x11, [x23, #8]
    add x23, x23, #16
    cbz x10, .Lstatic_pie_dynamic_done
    cmp x10, #7
    b.ne .Lstatic_pie_not_rela
    mov x25, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_rela:
    cmp x10, #8
    b.ne .Lstatic_pie_not_relasz
    mov x26, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relasz:
    cmp x10, #36
    b.ne .Lstatic_pie_not_relr
    mov x27, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relr:
    cmp x10, #35
    b.ne .Lstatic_pie_not_relrsz
    mov x28, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relrsz:
    cmp x10, #37
    b.ne .Lstatic_pie_dynamic
    mov x18, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_dynamic_done:
    cbz x26, .Lstatic_pie_rela_done
    cbz x25, .Lstatic_pie_fail
    mov x9, #24
    udiv x10, x26, x9
    msub x11, x10, x9, x26
    cbnz x11, .Lstatic_pie_fail
    adds x25, x19, x25
    b.cs .Lstatic_pie_fail
    adds x26, x25, x26
    b.cs .Lstatic_pie_fail
    mov x0, x25
    sub x1, x26, x25
    adr x17, .Lstatic_pie_after_rela_table_range
    b .Lstatic_pie_require_load_range
.Lstatic_pie_after_rela_table_range:
.Lstatic_pie_rela:
    cmp x25, x26
    b.hs .Lstatic_pie_rela_done
    ldr x9, [x25]
    ldr x10, [x25, #8]
    ldr x11, [x25, #16]
    lsr x12, x10, #32
    cbnz x12, .Lstatic_pie_fail
    cbz w10, .Lstatic_pie_next_rela
    cmp w10, #1027
    b.ne .Lstatic_pie_fail
    tst x9, #7
    b.ne .Lstatic_pie_fail
    adds x12, x19, x9
    b.cs .Lstatic_pie_fail
    mov x0, x12
    mov x1, #8
    adr x17, .Lstatic_pie_after_rela_target_range
    b .Lstatic_pie_require_writable_load_range
.Lstatic_pie_after_rela_target_range:
    adds x11, x19, x11
    b.cs .Lstatic_pie_fail
    str x11, [x12]
.Lstatic_pie_next_rela:
    add x25, x25, #24
    b .Lstatic_pie_rela
.Lstatic_pie_rela_done:
    cbz x28, .Lstatic_pie_relr_done
    cbz x27, .Lstatic_pie_fail
    cmp x18, #8
    b.ne .Lstatic_pie_fail
    tst x28, #7
    b.ne .Lstatic_pie_fail
    adds x27, x19, x27
    b.cs .Lstatic_pie_fail
    adds x28, x27, x28
    b.cs .Lstatic_pie_fail
    mov x0, x27
    sub x1, x28, x27
    adr x17, .Lstatic_pie_after_relr_table_range
    b .Lstatic_pie_require_load_range
.Lstatic_pie_after_relr_table_range:
    mov x25, xzr
    mov x26, xzr
.Lstatic_pie_relr:
    cmp x27, x28
    b.hs .Lstatic_pie_relr_done
    ldr x9, [x27], #8
    tbnz x9, #0, .Lstatic_pie_relr_bitmap
    tst x9, #7
    b.ne .Lstatic_pie_fail
    adds x25, x19, x9
    b.cs .Lstatic_pie_fail
    mov x0, x25
    mov x1, #8
    adr x17, .Lstatic_pie_after_relr_target_range
    b .Lstatic_pie_require_writable_load_range
.Lstatic_pie_after_relr_target_range:
    ldr x10, [x25]
    adds x10, x10, x19
    b.cs .Lstatic_pie_fail
    str x10, [x25], #8
    mov x26, #1
    b .Lstatic_pie_relr
.Lstatic_pie_relr_bitmap:
    cbz x26, .Lstatic_pie_fail
    lsr x9, x9, #1
    mov x10, xzr
.Lstatic_pie_relr_bits:
    cmp x10, #63
    b.eq .Lstatic_pie_relr_bits_done
    tbz x9, #0, .Lstatic_pie_relr_next_bit
    adds x12, x25, x10, lsl #3
    b.cs .Lstatic_pie_fail
    mov x0, x12
    mov x1, #8
    adr x17, .Lstatic_pie_after_relr_bitmap_target_range
    b .Lstatic_pie_require_writable_load_range
.Lstatic_pie_after_relr_bitmap_target_range:
    ldr x11, [x12]
    adds x11, x11, x19
    b.cs .Lstatic_pie_fail
    str x11, [x12]
.Lstatic_pie_relr_next_bit:
    lsr x9, x9, #1
    add x10, x10, #1
    b .Lstatic_pie_relr_bits
.Lstatic_pie_relr_bits_done:
    adds x25, x25, #504
    b.cs .Lstatic_pie_fail
    b .Lstatic_pie_relr
.Lstatic_pie_relr_done:

    // Seal each recorded GNU_RELRO page span after all relocation writes.
    mov x23, x20
    mov x24, xzr
    movz w9, #0xe552
    movk w9, #0x6474, lsl #16
.Lstatic_pie_relro:
    cmp x24, x22
    b.hs .Lstatic_pie_enter_rust
    ldr w10, [x23]
    cmp w10, w9
    b.ne .Lstatic_pie_next_relro
    ldr x11, [x23, #16]
    ldr x12, [x23, #40]
    adds x0, x19, x11
    b.cs .Lstatic_pie_fail
    and x0, x0, #0xfffffffffffff000
    adds x1, x19, x11
    b.cs .Lstatic_pie_fail
    adds x1, x1, x12
    b.cs .Lstatic_pie_fail
    adds x1, x1, #4095
    b.cs .Lstatic_pie_fail
    and x1, x1, #0xfffffffffffff000
    sub x1, x1, x0
    cbz x1, .Lstatic_pie_next_relro
    mov x2, #1
    mov x8, #226
    svc #0
    tbnz x0, #63, .Lstatic_pie_fail
.Lstatic_pie_next_relro:
    add x23, x23, #56
    add x24, x24, #1
    b .Lstatic_pie_relro

.Lstatic_pie_enter_rust:
    mov x0, x15
    mov x1, xzr
    b {startup}

.Lstatic_pie_fail:
    mov x0, #127
    mov x8, #93
    svc #0
    brk #0
    .size _start, .-_start

    // Inputs: x0 = runtime address, x1 = nonzero byte length. This verifier
    // walks the already bounded program-header table and accepts only a
    // complete range inside one PT_LOAD. It uses no GOT, TLS, allocator, or
    // relocated state; callers may safely run it before the first relocation.
.Lstatic_pie_require_load_range:
    mov x7, xzr
    b .Lstatic_pie_require_load_range_common

    // The relocation target variant is identical except that the owning load
    // segment must have PF_W (bit 1) set. Do not infer writability from the
    // dynamic table or from a successful address calculation.
.Lstatic_pie_require_writable_load_range:
    mov x7, #1
.Lstatic_pie_require_load_range_common:
    cbz x1, .Lstatic_pie_fail
    adds x1, x0, x1
    b.cs .Lstatic_pie_fail
    mov x23, x20
    mov x24, xzr
.Lstatic_pie_require_load_range_next:
    cmp x24, x22
    b.hs .Lstatic_pie_fail
    ldr w2, [x23]
    cmp w2, #1
    b.ne .Lstatic_pie_require_load_range_advance
    cbz x7, .Lstatic_pie_require_load_range_bounds
    ldr w3, [x23, #4]
    tst w3, #2
    b.eq .Lstatic_pie_require_load_range_advance
.Lstatic_pie_require_load_range_bounds:
    ldr x3, [x23, #16]
    ldr x4, [x23, #40]
    adds x3, x19, x3
    b.cs .Lstatic_pie_fail
    adds x4, x3, x4
    b.cs .Lstatic_pie_fail
    cmp x0, x3
    b.lo .Lstatic_pie_require_load_range_advance
    cmp x1, x4
    b.hi .Lstatic_pie_require_load_range_advance
    br x17
.Lstatic_pie_require_load_range_advance:
    add x23, x23, #56
    add x24, x24, #1
    b .Lstatic_pie_require_load_range_next

    .section .note.GNU-stack,"",@progbits
"#,
    startup = sym __crabc_start,
);
