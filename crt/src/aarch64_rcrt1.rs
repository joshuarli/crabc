#![no_std]

//! AArch64 relocation entry ported from crt/src/rcrt1.rs; startup follows musl
//! 1.2.6 crt/rcrt1.c and arch/aarch64/crt_arch.h (MIT).


mod x86_64_array_boundaries;
mod x86_64_startup;

pub use x86_64_startup::__crabc_x86_64_static_pie_start;

core::arch::global_asm!(
    r#"
    .section .text._start,"ax",@progbits
    .global _start
    .type _start,%function
_start:
    mov x15, sp
    mov x29, xzr
    mov x30, xzr
    and sp, x15, #0xfffffffffffffff0

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

    mov x23, x20
    mov x24, xzr
    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x9, xzr
    mov x10, xzr
    mov x16, xzr
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
    movz w12, #0xe552
    movk w12, #0x6474, lsl #16
    cmp w11, w12
    b.ne .Lstatic_pie_not_relro_header
    cbnz x16, .Lstatic_pie_fail
    ldr x12, [x23, #40]
    cbz x12, .Lstatic_pie_fail
    mov x16, x23
    b .Lstatic_pie_next_program_header
.Lstatic_pie_not_relro_header:
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

    mov w0, {hardened}
    cbz w0, .Lstatic_pie_hardened_headers_done
    mov x0, xzr
    mov x1, x20
.Lstatic_pie_hardened_elf_header:
    cmp x0, x22
    b.hs .Lstatic_pie_fail
    ldr w2, [x1]
    cmp w2, #1
    b.ne .Lstatic_pie_hardened_elf_next
    ldr x2, [x1, #8]
    cbnz x2, .Lstatic_pie_hardened_elf_next
    ldr w2, [x1, #4]
    tbz w2, #2, .Lstatic_pie_hardened_elf_next
    ldr x2, [x1, #32]
    cmp x2, #64
    b.lo .Lstatic_pie_hardened_elf_next
    ldr x2, [x1, #40]
    cmp x2, #64
    b.lo .Lstatic_pie_hardened_elf_next
    ldr x3, [x1, #16]
    adds x3, x3, x19
    b.cs .Lstatic_pie_fail
    adds x2, x3, #64
    b.cs .Lstatic_pie_fail
    ldr w2, [x3]
    movz w4, #0x457f
    movk w4, #0x464c, lsl #16
    cmp w2, w4
    b.ne .Lstatic_pie_fail
    ldrh w2, [x3, #4]
    mov w4, #0x102
    cmp w2, w4
    b.ne .Lstatic_pie_fail
    ldrb w2, [x3, #6]
    cmp w2, #1
    b.ne .Lstatic_pie_fail
    ldrh w2, [x3, #16]
    cmp w2, #3
    b.ne .Lstatic_pie_fail
    ldrh w2, [x3, #18]
    cmp w2, #183
    b.ne .Lstatic_pie_fail
    ldr w2, [x3, #20]
    cmp w2, #1
    b.ne .Lstatic_pie_fail
    ldrh w2, [x3, #52]
    cmp w2, #64
    b.ne .Lstatic_pie_fail
    ldrh w2, [x3, #54]
    cmp w2, #56
    b.ne .Lstatic_pie_fail
    ldrh w2, [x3, #56]
    cmp x2, x22
    b.ne .Lstatic_pie_fail
    ldr x5, [x3, #32]
    mov x2, #56
    mul x6, x22, x2
    adds x6, x6, x5
    b.cs .Lstatic_pie_fail
    mov x8, x20
    mov x9, xzr
.Lstatic_pie_hardened_phdr_mapping:
    cmp x9, x22
    b.hs .Lstatic_pie_fail
    ldr w2, [x8]
    cmp w2, #1
    b.ne .Lstatic_pie_hardened_phdr_next
    ldr w2, [x8, #4]
    tbz w2, #2, .Lstatic_pie_hardened_phdr_next
    ldr x7, [x8, #8]
    cmp x5, x7
    b.lo .Lstatic_pie_hardened_phdr_next
    ldr x2, [x8, #32]
    adds x2, x2, x7
    b.cs .Lstatic_pie_fail
    cmp x6, x2
    b.hi .Lstatic_pie_hardened_phdr_next
    sub x2, x6, x7
    ldr x4, [x8, #40]
    cmp x2, x4
    b.hi .Lstatic_pie_hardened_phdr_next
    sub x2, x5, x7
    ldr x4, [x8, #16]
    adds x2, x2, x4
    b.cs .Lstatic_pie_fail
    adds x2, x2, x19
    b.cs .Lstatic_pie_fail
    cmp x2, x20
    b.eq .Lstatic_pie_hardened_elf_done
.Lstatic_pie_hardened_phdr_next:
    add x8, x8, #56
    add x9, x9, #1
    b .Lstatic_pie_hardened_phdr_mapping
.Lstatic_pie_hardened_elf_next:
    add x1, x1, #56
    add x0, x0, #1
    b .Lstatic_pie_hardened_elf_header
.Lstatic_pie_hardened_elf_done:
    mov x0, xzr
    mov x1, x20
    mov x2, xzr
.Lstatic_pie_hardened_headers:
    cmp x0, x22
    b.hs .Lstatic_pie_hardened_headers_end
    ldr w3, [x1]
    movz w4, #0xe551
    movk w4, #0x6474, lsl #16
    cmp w3, w4
    b.ne .Lstatic_pie_hardened_not_stack
    cbnz x2, .Lstatic_pie_fail
    ldr w4, [x1, #4]
    tbnz w4, #0, .Lstatic_pie_fail
    mov x2, #1
    b .Lstatic_pie_hardened_next
.Lstatic_pie_hardened_not_stack:
    cmp w3, #1
    b.ne .Lstatic_pie_hardened_next
    ldr w4, [x1, #4]
    and w3, w4, #3
    cmp w3, #3
    b.eq .Lstatic_pie_fail
    tbz w4, #1, .Lstatic_pie_hardened_next
    ldr x7, [x1, #40]
    cbz x7, .Lstatic_pie_hardened_next
    ldr x5, [x1, #16]
    adds x6, x5, x7
    b.cs .Lstatic_pie_fail
    adds x6, x6, #4095
    b.cs .Lstatic_pie_fail
    and x5, x5, #0xfffffffffffff000
    and x6, x6, #0xfffffffffffff000
    mov x8, x20
    mov x9, xzr
.Lstatic_pie_hardened_overlap:
    cmp x9, x22
    b.hs .Lstatic_pie_hardened_next
    ldr w3, [x8]
    cmp w3, #1
    b.ne .Lstatic_pie_hardened_overlap_next
    ldr w3, [x8, #4]
    tbz w3, #0, .Lstatic_pie_hardened_overlap_next
    ldr x7, [x8, #40]
    cbz x7, .Lstatic_pie_hardened_overlap_next
    ldr x11, [x8, #16]
    adds x12, x11, x7
    b.cs .Lstatic_pie_fail
    adds x12, x12, #4095
    b.cs .Lstatic_pie_fail
    and x11, x11, #0xfffffffffffff000
    and x12, x12, #0xfffffffffffff000
    cmp x5, x12
    b.hs .Lstatic_pie_hardened_overlap_next
    cmp x11, x6
    b.lo .Lstatic_pie_fail
.Lstatic_pie_hardened_overlap_next:
    add x8, x8, #56
    add x9, x9, #1
    b .Lstatic_pie_hardened_overlap
.Lstatic_pie_hardened_next:
    add x1, x1, #56
    add x0, x0, #1
    b .Lstatic_pie_hardened_headers
.Lstatic_pie_hardened_headers_end:
    cbz x2, .Lstatic_pie_fail
.Lstatic_pie_hardened_headers_done:
    cbz x16, .Lstatic_pie_relro_range_done
    ldr x0, [x16, #16]
    adds x0, x0, x19
    b.cs .Lstatic_pie_fail
    ldr x1, [x16, #40]
    adds x1, x1, x0
    b.cs .Lstatic_pie_fail
    adds x1, x1, #4095
    b.cs .Lstatic_pie_fail
    and x0, x0, #0xfffffffffffff000
    and x1, x1, #0xfffffffffffff000
    mov x8, x20
    mov x9, xzr
.Lstatic_pie_relro_range:
    cmp x9, x22
    b.hs .Lstatic_pie_fail
    ldr w2, [x8]
    cmp w2, #1
    b.ne .Lstatic_pie_relro_range_next
    ldr x4, [x8, #40]
    cbz x4, .Lstatic_pie_relro_range_next
    ldr w2, [x8, #4]
    and w2, w2, #3
    cmp w2, #2
    b.ne .Lstatic_pie_relro_range_next
    ldr x2, [x8, #16]
    adds x2, x2, x19
    b.cs .Lstatic_pie_fail
    adds x3, x2, x4
    b.cs .Lstatic_pie_fail
    adds x3, x3, #4095
    b.cs .Lstatic_pie_fail
    and x2, x2, #0xfffffffffffff000
    and x3, x3, #0xfffffffffffff000
    cmp x0, x2
    b.lo .Lstatic_pie_relro_range_next
    cmp x1, x3
    b.ls .Lstatic_pie_relro_executable_check
.Lstatic_pie_relro_range_next:
    add x8, x8, #56
    add x9, x9, #1
    b .Lstatic_pie_relro_range
.Lstatic_pie_relro_executable_check:
    mov x8, x20
    mov x9, xzr
.Lstatic_pie_relro_executable_next:
    cmp x9, x22
    b.hs .Lstatic_pie_relro_range_done
    ldr w2, [x8]
    cmp w2, #1
    b.ne .Lstatic_pie_relro_executable_advance
    ldr x4, [x8, #40]
    cbz x4, .Lstatic_pie_relro_executable_advance
    ldr w2, [x8, #4]
    tbz w2, #0, .Lstatic_pie_relro_executable_advance
    ldr x2, [x8, #16]
    adds x2, x2, x19
    b.cs .Lstatic_pie_fail
    adds x3, x2, x4
    b.cs .Lstatic_pie_fail
    adds x3, x3, #4095
    b.cs .Lstatic_pie_fail
    and x2, x2, #0xfffffffffffff000
    and x3, x3, #0xfffffffffffff000
    cmp x0, x3
    b.hs .Lstatic_pie_relro_executable_advance
    cmp x2, x1
    b.lo .Lstatic_pie_fail
.Lstatic_pie_relro_executable_advance:
    add x8, x8, #56
    add x9, x9, #1
    b .Lstatic_pie_relro_executable_next
.Lstatic_pie_relro_range_done:
    adds x23, x19, x26
    b.cs .Lstatic_pie_fail
    adds x24, x23, x27
    b.cs .Lstatic_pie_fail
    mov x0, x23
    mov x1, x27
    adr x17, .Lstatic_pie_after_dynamic_range
    b .Lstatic_pie_require_load_range
.Lstatic_pie_after_dynamic_range:
    adds x23, x19, x26
    b.cs .Lstatic_pie_fail
    adds x24, x23, x27
    b.cs .Lstatic_pie_fail

    mov x25, xzr
    mov x26, xzr
    mov x27, xzr
    mov x28, xzr
    mov x18, xzr
    mov x14, xzr
    mov x21, xzr
.Lstatic_pie_dynamic:
    add x9, x23, #16
    cmp x9, x24
    b.hi .Lstatic_pie_fail
    ldr x10, [x23]
    ldr x11, [x23, #8]
    add x23, x23, #16
    cbz x10, .Lstatic_pie_dynamic_done
    cmp x10, #1
    b.eq .Lstatic_pie_fail
    cmp x10, #2
    b.eq .Lstatic_pie_fail
    cmp x10, #17
    b.lo .Lstatic_pie_not_rel
    cmp x10, #20
    b.ls .Lstatic_pie_fail
.Lstatic_pie_not_rel:
    cmp x10, #22
    b.eq .Lstatic_pie_fail
    cmp x10, #23
    b.eq .Lstatic_pie_fail
    cmp x10, #30
    b.ne .Lstatic_pie_not_flags
    tbnz x11, #2, .Lstatic_pie_fail
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_flags:
    cmp x10, #3
    b.ne .Lstatic_pie_not_pltgot
    tbnz x14, #6, .Lstatic_pie_fail
    orr x14, x14, #64
    mov x21, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_pltgot:
    cmp x10, #7
    b.ne .Lstatic_pie_not_rela
    tbnz x14, #0, .Lstatic_pie_fail
    orr x14, x14, #1
    mov x25, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_rela:
    cmp x10, #8
    b.ne .Lstatic_pie_not_relasz
    tbnz x14, #1, .Lstatic_pie_fail
    orr x14, x14, #2
    mov x26, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relasz:
    cmp x10, #9
    b.ne .Lstatic_pie_not_relaent
    tbnz x14, #5, .Lstatic_pie_fail
    orr x14, x14, #32
    cmp x11, #24
    b.ne .Lstatic_pie_fail
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relaent:
    cmp x10, #36
    b.ne .Lstatic_pie_not_relr
    tbnz x14, #2, .Lstatic_pie_fail
    orr x14, x14, #4
    mov x27, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relr:
    cmp x10, #35
    b.ne .Lstatic_pie_not_relrsz
    tbnz x14, #3, .Lstatic_pie_fail
    orr x14, x14, #8
    mov x28, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_not_relrsz:
    cmp x10, #37
    b.ne .Lstatic_pie_dynamic
    tbnz x14, #4, .Lstatic_pie_fail
    orr x14, x14, #16
    mov x18, x11
    b .Lstatic_pie_dynamic
.Lstatic_pie_dynamic_done:
    and x9, x14, #3
    cbz x9, .Lstatic_pie_rela_tags_done
    cmp x9, #3
    b.ne .Lstatic_pie_fail
.Lstatic_pie_rela_tags_done:
    and x9, x14, #28
    cbz x9, .Lstatic_pie_relr_tags_done
    cmp x9, #28
    b.ne .Lstatic_pie_fail
.Lstatic_pie_relr_tags_done:
    mov w9, {hardened}
    cbz w9, .Lstatic_pie_got_done
    tbz x14, #6, .Lstatic_pie_got_done
    cbz x16, .Lstatic_pie_fail
    cbz x21, .Lstatic_pie_fail
    adds x0, x21, x19
    b.cs .Lstatic_pie_fail
    adds x9, x0, #24
    b.cs .Lstatic_pie_fail
    ldr x10, [x16, #16]
    adds x10, x10, x19
    b.cs .Lstatic_pie_fail
    ldr x11, [x16, #40]
    adds x11, x11, x10
    b.cs .Lstatic_pie_fail
    adds x11, x11, #4095
    b.cs .Lstatic_pie_fail
    and x10, x10, #0xfffffffffffff000
    and x11, x11, #0xfffffffffffff000
    cmp x0, x10
    b.lo .Lstatic_pie_fail
    cmp x9, x11
    b.hi .Lstatic_pie_fail
    mov x1, #24
    adr x17, .Lstatic_pie_got_done
    b .Lstatic_pie_require_writable_load_range
.Lstatic_pie_got_done:
    cbz x26, .Lstatic_pie_rela_done
    tbz x14, #5, .Lstatic_pie_fail
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

.Lstatic_pie_require_load_range:
    mov x7, xzr
    b .Lstatic_pie_require_load_range_common

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
    startup = sym __crabc_x86_64_static_pie_start,
    hardened = const cfg!(crabc_hardened) as u8,
);
