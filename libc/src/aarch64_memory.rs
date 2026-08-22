// AArch64 `memcpy` baseline kernel, adapted without algorithmic changes from
// musl 1.2.6 `src/string/aarch64/memcpy.S`.
//
// Copyright (c) 2012-2020, Arm Limited.
// SPDX-License-Identifier: MIT
//
// This is deliberately the only architecture-specific bulk-memory path. The
// preceding scalar implementation was differential-tested and measured first;
// its compiler lowering retained generic loop and overlap guards in all sizes.
// The musl routine retains C's non-overlap `memcpy` contract, uses no runtime
// feature dispatch, and covers its own short, aligned, unaligned, and long
// paths.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .text

    .global __crabc_aarch64_memcpy
    .hidden __crabc_aarch64_memcpy
    .type __crabc_aarch64_memcpy,%function
__crabc_aarch64_memcpy:
    add     x4, x1, x2
    add     x5, x0, x2
    cmp     x2, #128
    b.hi    .Lcrabc_memcpy_long
    cmp     x2, #32
    b.hi    .Lcrabc_memcpy_32_128

    // Small copies: 0..32 bytes.
    cmp     x2, #16
    b.lo    .Lcrabc_memcpy_16
    ldp     x6, x7, [x1]
    ldp     x12, x13, [x4, #-16]
    stp     x6, x7, [x0]
    stp     x12, x13, [x5, #-16]
    ret

.Lcrabc_memcpy_16:
    tbz     x2, #3, .Lcrabc_memcpy_8
    ldr     x6, [x1]
    ldr     x7, [x4, #-8]
    str     x6, [x0]
    str     x7, [x5, #-8]
    ret

    .p2align 3
.Lcrabc_memcpy_8:
    tbz     x2, #2, .Lcrabc_memcpy_4
    ldr     w6, [x1]
    ldr     w8, [x4, #-4]
    str     w6, [x0]
    str     w8, [x5, #-4]
    ret

    // Copy 0..3 bytes with the oracle's branchless middle-byte selection.
.Lcrabc_memcpy_4:
    cbz     x2, .Lcrabc_memcpy_done
    lsr     x14, x2, #1
    ldrb    w6, [x1]
    ldrb    w10, [x4, #-1]
    ldrb    w8, [x1, x14]
    strb    w6, [x0]
    strb    w8, [x0, x14]
    strb    w10, [x5, #-1]
.Lcrabc_memcpy_done:
    ret

    .p2align 4
    // Medium copies: 33..128 bytes. Loading both ends first is valid under
    // `memcpy`'s non-overlap contract and avoids a trip-counted loop here.
.Lcrabc_memcpy_32_128:
    ldp     x6, x7, [x1]
    ldp     x8, x9, [x1, #16]
    ldp     x10, x11, [x4, #-32]
    ldp     x12, x13, [x4, #-16]
    cmp     x2, #64
    b.hi    .Lcrabc_memcpy_128
    stp     x6, x7, [x0]
    stp     x8, x9, [x0, #16]
    stp     x10, x11, [x5, #-32]
    stp     x12, x13, [x5, #-16]
    ret

    .p2align 4
.Lcrabc_memcpy_128:
    ldp     x14, x15, [x1, #32]
    ldp     x16, x17, [x1, #48]
    cmp     x2, #96
    b.ls    .Lcrabc_memcpy_96
    ldp     x2, x3, [x4, #-64]
    ldp     x1, x4, [x4, #-48]
    stp     x2, x3, [x5, #-64]
    stp     x1, x4, [x5, #-48]
.Lcrabc_memcpy_96:
    stp     x6, x7, [x0]
    stp     x8, x9, [x0, #16]
    stp     x14, x15, [x0, #32]
    stp     x16, x17, [x0, #48]
    stp     x10, x11, [x5, #-32]
    stp     x12, x13, [x5, #-16]
    ret

    .p2align 4
    // Copy more than 128 bytes. Aligning only the destination permits all
    // source alignments while giving the pipelined stores a stable alignment.
.Lcrabc_memcpy_long:
    ldp     x12, x13, [x1]
    and     x14, x0, #15
    bic     x3, x0, #15
    sub     x1, x1, x14
    add     x2, x2, x14
    ldp     x6, x7, [x1, #16]
    stp     x12, x13, [x0]
    ldp     x8, x9, [x1, #32]
    ldp     x10, x11, [x1, #48]
    ldp     x12, x13, [x1, #64]!
    subs    x2, x2, #144
    b.ls    .Lcrabc_memcpy_64_from_end

.Lcrabc_memcpy_loop_64:
    stp     x6, x7, [x3, #16]
    ldp     x6, x7, [x1, #16]
    stp     x8, x9, [x3, #32]
    ldp     x8, x9, [x1, #32]
    stp     x10, x11, [x3, #48]
    ldp     x10, x11, [x1, #48]
    stp     x12, x13, [x3, #64]!
    ldp     x12, x13, [x1, #64]!
    subs    x2, x2, #64
    b.hi    .Lcrabc_memcpy_loop_64

.Lcrabc_memcpy_64_from_end:
    ldp     x14, x15, [x4, #-64]
    stp     x6, x7, [x3, #16]
    ldp     x6, x7, [x4, #-48]
    stp     x8, x9, [x3, #32]
    ldp     x8, x9, [x4, #-32]
    stp     x10, x11, [x3, #48]
    ldp     x10, x11, [x4, #-16]
    stp     x12, x13, [x3, #64]
    stp     x14, x15, [x5, #-64]
    stp     x6, x7, [x5, #-48]
    stp     x8, x9, [x5, #-32]
    stp     x10, x11, [x5, #-16]
    ret
    .size __crabc_aarch64_memcpy,.-__crabc_aarch64_memcpy
"#,
);
