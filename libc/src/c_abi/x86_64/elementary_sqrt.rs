//! Selected static Linux/x86-64 square-root C ABI leaf.
//!
//! This target-private leaf maps the complete pinned musl 1.2.6
//! (`9fa28ece75d8a2191de7c5bb53bed224c5947417`) x86-64 implementation of
//! exactly three elementary functions, under musl's MIT license:
//!
//! - `src/math/x86_64/sqrt.c` maps to the scalar `sqrtsd` entry below;
//! - `src/math/x86_64/sqrtf.c` maps to the scalar `sqrtss` entry below;
//! - `src/math/x86_64/sqrtl.c` maps to the x87 `fsqrt` entry below.
//!
//! The instruction choice is observable C behavior. `sqrt` and `sqrtf`
//! consume MXCSR rounding and exception state, while the x87 binary80
//! `sqrtl` consumes the x87 control word and status state. Rust has no stable
//! C binary80 type, so the System V AMD64 stack-argument and `st0` return ABI
//! stays in assembly rather than borrowing AArch64's binary128 math code.
//!
//! The paired native fixture proves all four rounding modes, signed zero,
//! infinities, NaNs, negative-domain `FE_INVALID`, and inexact results against
//! pinned musl. This remains one selected static artifact inside the planned
//! math family: it does not select any other elementary operation, general
//! libm, complex math, errno policy, libc.so, CRT, loader, or sysroot.

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"), target_endian = "little")))]
compile_error!("the x86 square-root leaf requires little-endian Linux/x86-64");

// Each musl object below has its own static archive member, as in musl's
// libc.a; a chunk that shares local labels with another stays with it.
// Musl's `src/math/sqrt.c` object.
static_archive_member! { sqrt_source {
    // musl 1.2.6 src/math/aarch64/sqrt.c.
    #[cfg(target_arch = "aarch64")]
    core::arch::global_asm!(".text", ".global sqrt", ".type sqrt, %function", "sqrt:", "fsqrt d0, d0", "ret", ".size sqrt, .-sqrt");
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .text

    .p2align 4
    .global sqrt
    .type sqrt,@function
sqrt:
    sqrtsd xmm0, xmm0
    ret
    .size sqrt, .-sqrt
"#,
    );
}}

// Musl's `src/math/sqrtf.c` object.
static_archive_member! { sqrtf_source {
    // musl 1.2.6 src/math/aarch64/sqrtf.c.
    #[cfg(target_arch = "aarch64")]
    core::arch::global_asm!(".text", ".global sqrtf", ".type sqrtf, %function", "sqrtf:", "fsqrt s0, s0", "ret", ".size sqrtf, .-sqrtf");
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .text

    .p2align 4
    .global sqrtf
    .type sqrtf,@function
sqrtf:
    sqrtss xmm0, xmm0
    ret
    .size sqrtf, .-sqrtf

    /* System V AMD64 classifies long double as X87. The argument therefore
       occupies 16 bytes of stack storage beginning at rsp+8; the binary80
       result returns in st0. */
"#,
    );
}}

// Musl's `src/math/sqrtl.c` object.
static_archive_member! { sqrtl_source {
    // musl 1.2.6 src/math/sqrtl.c, src/math/sqrt_data.c and src/math/__math_invalidl.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn sqrtl(x: f128) -> f128 {
        unsafe extern "C" { fn feraiseexcept(mask: i32) -> i32; fn fegetround() -> i32; }
        const RSQRT: [u16; 128] = [
0xb451,0xb2f0,0xb196,0xb044,0xaef9,0xadb6,0xac79,0xab43,
0xaa14,0xa8eb,0xa7c8,0xa6aa,0xa592,0xa480,0xa373,0xa26b,
0xa168,0xa06a,0x9f70,0x9e7b,0x9d8a,0x9c9d,0x9bb5,0x9ad1,
0x99f0,0x9913,0x983a,0x9765,0x9693,0x95c4,0x94f8,0x9430,
0x936b,0x92a9,0x91ea,0x912e,0x9075,0x8fbe,0x8f0a,0x8e59,
0x8daa,0x8cfe,0x8c54,0x8bac,0x8b07,0x8a64,0x89c4,0x8925,
0x8889,0x87ee,0x8756,0x86c0,0x862b,0x8599,0x8508,0x8479,
0x83ec,0x8361,0x82d8,0x8250,0x81c9,0x8145,0x80c2,0x8040,
0xff02,0xfd0e,0xfb25,0xf947,0xf773,0xf5aa,0xf3ea,0xf234,
0xf087,0xeee3,0xed47,0xebb3,0xea27,0xe8a3,0xe727,0xe5b2,
0xe443,0xe2dc,0xe17a,0xe020,0xdecb,0xdd7d,0xdc34,0xdaf1,
0xd9b3,0xd87b,0xd748,0xd61a,0xd4f1,0xd3cd,0xd2ad,0xd192,
0xd07b,0xcf69,0xce5b,0xcd51,0xcc4a,0xcb48,0xca4a,0xc94f,
0xc858,0xc764,0xc674,0xc587,0xc49d,0xc3b7,0xc2d4,0xc1f4,
0xc116,0xc03c,0xbf65,0xbe90,0xbdbe,0xbcef,0xbc23,0xbb59,
0xba91,0xb9cc,0xb90a,0xb84a,0xb78c,0xb6d0,0xb617,0xb560,
];
        fn mul32(a: u32, b: u32) -> u32 { ((a as u64 * b as u64) >> 32) as u32 }
        fn mul64(a: u64, b: u64) -> u64 {
            let (ahi, alo) = (a >> 32, a & 0xffff_ffff);
            let (bhi, blo) = (b >> 32, b & 0xffff_ffff);
            (ahi * bhi).wrapping_add(ahi * blo >> 32).wrapping_add(alo * bhi >> 32)
        }
        fn mul128(a: u128, b: u128) -> u128 {
            let hi = (a >> 64) * (b >> 64);
            hi.wrapping_add(mul64((a >> 64) as u64, b as u64) as u128)
                .wrapping_add(mul64(a as u64, (b >> 64) as u64) as u128)
        }
        fn mkldbl(top: u64, bits: u128) -> f128 {
            f128::from_bits((bits & ((1u128 << 112) - 1)) | ((top as u128) << 112))
        }
        let mut ix = x.to_bits();
        let mut top = (ix >> 112) as u64;
        if top.wrapping_sub(1) >= 0x7fff - 1 {
            if ix << 1 == 0 { return x; }
            if ix == (0x7fffu128 << 112) { return x; }
            if ix >> 127 != 0 && (ix & ((1u128 << 127) - 1)) <= (0x7fffu128 << 112) {
                unsafe { feraiseexcept(1); }
                return f128::from_bits((0x7fffu128 << 112) | ((1u128 << 112) - 1));
            }
            if top >= 0x7fff { return (x - x) / (x - x); }
            ix = (x * f128::from_bits((0x3fffu128 + 112) << 112)).to_bits();
            top = (ix >> 112) as u64;
            top = top.wrapping_sub(112);
        }
        let even = top & 1;
        let mut ml = ix << 15;
        ml |= 1u128 << 127;
        if even != 0 { ml >>= 1; }
        top = top.wrapping_add(0x3fff) >> 1;
        let three = 0xc0000000u64;
        let i = ((ix >> 106) % 128) as usize;
        let mut r = (RSQRT[i] as u32) << 16;
        let ss = mul32((ml >> 96) as u32, r);
        let d = mul32(ss, r);
        let u = (three as u32).wrapping_sub(d);
        r = mul32(u, r) << 1;
        let mut rr = (r as u64) << 32;
        let mut s64 = mul64((ml >> 64) as u64, rr);
        let mut d64 = mul64(s64, rr);
        let mut u64v = (three << 32).wrapping_sub(d64);
        rr = mul64(u64v, rr) << 1;
        s64 = mul64(u64v, s64) << 1;
        d64 = mul64(s64, rr);
        u64v = (three << 32).wrapping_sub(d64);
        rr = mul64(u64v, rr) << 1;
        let threel = (three as u128) << 96;
        let rl = (rr as u128) << 64;
        let mut sl = mul128(ml, rl);
        let dl = mul128(sl, rl);
        let ul = threel.wrapping_sub(dl);
        sl = mul128(ul, sl);
        sl = sl.wrapping_sub(4) >> 13;
        let d0 = (ml << 98).wrapping_sub(sl.wrapping_mul(sl));
        let d1 = sl.wrapping_sub(d0);
        let d2 = sl.wrapping_add(1).wrapping_add(d1);
        sl = sl.wrapping_add(d1 >> 127);
        let mut bits = mkldbl(top, sl).to_bits();
        if d2 != 0 {
            unsafe { feraiseexcept(16); }
            let negative = (d1 ^ d2) >> 127 != 0;
            match unsafe { fegetround() } {
                0x400000 if !negative => bits += 1,
                0x800000 | 0xc00000 if negative => bits -= 1,
                _ => (),
            }
        }
        f128::from_bits(bits)
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .text
    .p2align 4
    .global sqrtl
    .type sqrtl,@function
sqrtl:
    fld tbyte ptr [rsp + 8]
    fsqrt
    ret
    .size sqrtl, .-sqrtl

    .section .note.GNU-stack, "", @progbits
"#,
    );
}}
