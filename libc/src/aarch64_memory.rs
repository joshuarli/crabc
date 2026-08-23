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

// LLVM is free to vectorize ordinary typed writes on AArch64, including the
// fixed head/tail stores in a scalar schedule. These tiny veneers keep that
// schedule GPR-only until a separately proved SIMD decision is made. They
// carry no call boundary after inlining and have ordinary memory side effects,
// so no `nomem` option may be used.
#[inline(always)]
unsafe fn memset_store_byte(destination: *mut u8, value: u8) {
    // SAFETY: the caller proves `destination` names one writable byte.
    unsafe {
        core::arch::asm!(
            "strb {value:w}, [{destination}]",
            destination = in(reg) destination,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
unsafe fn memset_store_word(destination: *mut u8, value: u32) {
    // SAFETY: the caller proves `destination` names four writable bytes with
    // the alignment required by the scalar schedule.
    unsafe {
        core::arch::asm!(
            "str {value:w}, [{destination}]",
            destination = in(reg) destination,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
unsafe fn memset_store_32_bytes(destination: *mut u8, value: u64) {
    // SAFETY: the caller proves `destination` starts one aligned, writable
    // 32-byte scalar block. Each pair writes a distinct 16-byte subrange.
    unsafe {
        core::arch::asm!(
            "stp {value}, {value}, [{destination}]",
            "stp {value}, {value}, [{destination}, #16]",
            destination = in(reg) destination,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Fill an arbitrary writable byte range with one byte using aligned scalar
/// stores after bounded head and tail stores.
///
/// This preserves the schedule of musl 1.2.6 `src/string/memset.c`'s GNU C
/// path (MIT licensed) while expressing every typed store through a raw
/// pointer. The early writes establish that every later fixed offset lies
/// within the caller's `length`-byte range; the final loop can therefore omit
/// a scalar tail without writing beyond the supplied object.
#[inline]
unsafe fn memset_scalar(destination: *mut u8, value: u8, mut length: usize) {
    if length == 0 {
        return;
    }

    // SAFETY: `destination` designates `length > 0` writable bytes. These
    // stores are the first and last byte of that exact range.
    unsafe {
        memset_store_byte(destination, value);
        memset_store_byte(destination.add(length - 1), value);
    }
    if length <= 2 {
        return;
    }

    // SAFETY: reaching this point proves bytes 1, 2, `length - 2`, and
    // `length - 3` are all inside the caller-owned writable range.
    unsafe {
        memset_store_byte(destination.add(1), value);
        memset_store_byte(destination.add(2), value);
        memset_store_byte(destination.add(length - 2), value);
        memset_store_byte(destination.add(length - 3), value);
    }
    if length <= 6 {
        return;
    }

    // SAFETY: `length > 6` makes both fixed positions valid.
    unsafe {
        memset_store_byte(destination.add(3), value);
        memset_store_byte(destination.add(length - 4), value);
    }
    if length <= 8 {
        return;
    }

    // The head/tail byte stores make up to three bytes on either side already
    // initialized. Advance the raw pointer only inside the supplied range and
    // retain a four-byte central range for the typed scalar stores below.
    let head_bytes = destination.addr().wrapping_neg() & 3;
    let mut cursor = unsafe { destination.add(head_bytes) };
    length -= head_bytes;
    length &= !3;

    let repeated_u32 = u32::from_ne_bytes([value; 4]);
    // SAFETY: `cursor` is four-byte aligned and `length` is a positive
    // multiple of four. Each listed four-byte store lies in its central range.
    unsafe {
        memset_store_word(cursor, repeated_u32);
        memset_store_word(cursor.add(length - 4), repeated_u32);
    }
    if length <= 8 {
        return;
    }

    // SAFETY: `length > 8` after four-byte truncation means it is at least
    // twelve, making the head and tail word positions valid and aligned.
    unsafe {
        memset_store_word(cursor.add(4), repeated_u32);
        memset_store_word(cursor.add(8), repeated_u32);
        memset_store_word(cursor.add(length - 12), repeated_u32);
        memset_store_word(cursor.add(length - 8), repeated_u32);
    }
    if length <= 24 {
        return;
    }

    // SAFETY: `length > 24` after four-byte truncation means it is at least
    // twenty-eight, so the remaining fixed head and tail stores are valid.
    unsafe {
        memset_store_word(cursor.add(12), repeated_u32);
        memset_store_word(cursor.add(16), repeated_u32);
        memset_store_word(cursor.add(20), repeated_u32);
        memset_store_word(cursor.add(24), repeated_u32);
        memset_store_word(cursor.add(length - 28), repeated_u32);
        memset_store_word(cursor.add(length - 24), repeated_u32);
        memset_store_word(cursor.add(length - 20), repeated_u32);
        memset_store_word(cursor.add(length - 16), repeated_u32);
    }

    // A four-byte-aligned `cursor` needs either 24 or 28 bytes to become
    // eight-byte aligned. The head/tail schedule above has already written
    // these bytes and the final 28 bytes, leaving only whole 32-byte groups.
    let loop_head_bytes = 24 + (cursor.addr() & 4);
    cursor = unsafe { cursor.add(loop_head_bytes) };
    length -= loop_head_bytes;
    let repeated_u64 = u64::from_ne_bytes([value; 8]);
    while length >= 32 {
        // SAFETY: `cursor` is eight-byte aligned. This iteration owns the
        // next 32 bytes of the still-unwritten central range, and advances
        // only after all four non-overlapping scalar stores complete.
        unsafe {
            memset_store_32_bytes(cursor, repeated_u64);
            cursor = cursor.add(32);
        }
        length -= 32;
    }
}
