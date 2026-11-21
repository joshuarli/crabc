//! Selected static Linux/x86-64 long-double classification and complex ABI foundation.
//!
//! This is a deliberately small x87 ABI foundation, not a scalar or complex
//! math implementation. It owns only `__fpclassify*`, `__signbit*`, and the C99
//! `creal*`, `cimag*`, and `conj*` function symbols. The adjacent
//! `math_complex_complete.rs` leaf supplies the remaining 57 symbols, including
//! `cproj*`, to close the private 66-symbol `math.complex` capability without
//! blurring this source map. Scalar elementary exports, errno, fenv behavior
//! beyond classification, libm, libc.so, CRT, loader, and sysroot remain
//! outside this foundation's contract.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/math/__fpclassify*.c` and `src/math/__signbit*.c` define the exact
//!   binary32/binary64/x87 extended-precision classification/sign contracts.
//! - `src/complex/{creal,crealf,creall,cimag,cimagf,cimagl}.c` map to the six
//!   real/imaginary accessors.
//! - `src/complex/{conj,conjf,conjl}.c` map to the three sign-flipping
//!   conjugation entries.
//!
//! The intentional difference is representation only. Rust has no native
//! stable C `long double`/`_Complex long double` type, so this source carries
//! the fixed System V AMD64 x87 calling convention in one private assembly
//! leaf: 80-bit long-double inputs arrive in stack storage, complex-long-double
//! returns use `st0`/`st1`, and float/double complex values use their psABI SSE
//! registers. The focused freestanding C fixture proves those boundaries
//! against pinned musl before this leaf is treated as selected archive work.
//! `__fpclassifyl` occupies its own text section because
//! `math_long_double_completion.rs` uses that classifier; section GC may
//! retain that one ABI dependency without retaining unrelated classification,
//! sign, and complex entries.

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little"
)))]
compile_error!("the x86 math/complex leaf requires little-endian Linux/x86-64");

// musl 1.2.6 src/complex uses C complex pairs with the AArch64 homogeneous aggregate ABI.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct Complex32 { real: f32, imag: f32 }
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct Complex64 { real: f64, imag: f64 }
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct Complex128 { real: f128, imag: f128 }

// Each musl object below has its own static archive member, as in musl's
// libc.a; a chunk that shares local labels with another stays with it.
// Musl's `src/math/__fpclassifyl.c` object.
static_archive_member! { __fpclassifyl_source {
    // musl 1.2.6 src/math/__fpclassifyl.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn __fpclassifyl(x: f128) -> i32 {
        let bits = x.to_bits();
        let e = (bits >> 112) & 0x7fff;
        if e == 0 { return if (bits << 1) != 0 { 3 } else { 2 }; }
        if e == 0x7fff { return if (bits << 16) != 0 { 0 } else { 1 }; }
        4
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.__fpclassifyl,"ax",@progbits
    .p2align 4
    .global __fpclassifyl
    .type __fpclassifyl,@function
__fpclassifyl:
    movzx ecx, word ptr [rsp + 16]
    mov rdx, qword ptr [rsp + 8]
    mov eax, ecx
    and eax, 0x7fff
    mov r8, rdx
    shr r8, 63
    test eax, eax
    jne .Lcrabc_x86_fpclassify_nonzero_exponent
    test r8d, r8d
    jne .Lcrabc_x86_fpclassify_normal
    test rdx, rdx
    mov eax, 3
    jne .Lcrabc_x86_fpclassify_done
    mov eax, 2
    ret
.Lcrabc_x86_fpclassify_nonzero_exponent:
    cmp eax, 0x7fff
    jne .Lcrabc_x86_fpclassify_finite
    test r8d, r8d
    jz .Lcrabc_x86_fpclassify_nan
    add rdx, rdx
    mov eax, 0
    jne .Lcrabc_x86_fpclassify_done
    mov eax, 1
    ret
.Lcrabc_x86_fpclassify_finite:
    test r8d, r8d
    jz .Lcrabc_x86_fpclassify_nan
.Lcrabc_x86_fpclassify_normal:
    mov eax, 4
.Lcrabc_x86_fpclassify_done:
    ret
.Lcrabc_x86_fpclassify_nan:
    xor eax, eax
    ret
    .size __fpclassifyl, .-__fpclassifyl

    .section .text.crabc_x86_math_complex_rest,"ax",@progbits
    /* musl src/math/__fpclassifyf.c and __fpclassify.c. These are public
       external ABI entries, including for consumers that name the symbols
       directly rather than through the classification macros. */
"#,
    );
}}

// Musl's `src/math/__fpclassifyf.c` object.
static_archive_member! { __fpclassifyf_source {
    // musl 1.2.6 src/math/__fpclassifyf.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn __fpclassifyf(x: f32) -> i32 {
        let bits: u32;
        // SAFETY: FMOV copies the argument bits without changing floating-point state.
        unsafe { core::arch::asm!("fmov {bits:w}, {value:s}", bits = out(reg) bits, value = in(vreg) x, options(pure, nomem, nostack)); }
        let e = (bits >> 23) & 0xff;
        if e == 0 { return if (bits << 1) != 0 { 3 } else { 2 }; }
        if e == 0xff { return if (bits << 9) != 0 { 0 } else { 1 }; }
        4
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits
    .p2align 4
    .global __fpclassifyf
    .type __fpclassifyf,@function
__fpclassifyf:
    movd eax, xmm0
    mov ecx, eax
    shr ecx, 23
    and ecx, 0xff
    test ecx, ecx
    jne .Lcrabc_x86_fpclassifyf_nonzero_exponent
    shl eax, 9
    jnz .Lcrabc_x86_fpclassifyf_subnormal
    mov eax, 2
    ret
.Lcrabc_x86_fpclassifyf_subnormal:
    mov eax, 3
    ret
.Lcrabc_x86_fpclassifyf_nonzero_exponent:
    cmp ecx, 0xff
    jne .Lcrabc_x86_fpclassifyf_normal
    shl eax, 9
    jnz .Lcrabc_x86_fpclassifyf_nan
    mov eax, 1
    ret
.Lcrabc_x86_fpclassifyf_normal:
    mov eax, 4
.Lcrabc_x86_fpclassifyf_done:
    ret
.Lcrabc_x86_fpclassifyf_nan:
    xor eax, eax
    ret
    .size __fpclassifyf, .-__fpclassifyf
"#,
    );
}}

// Musl's `src/math/__fpclassify.c` object.
static_archive_member! { __fpclassify_source {
    // musl 1.2.6 src/math/__fpclassify.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn __fpclassify(x: f64) -> i32 {
        let bits: u64;
        // SAFETY: FMOV copies the argument bits without changing floating-point state.
        unsafe { core::arch::asm!("fmov {bits}, {value:d}", bits = out(reg) bits, value = in(vreg) x, options(pure, nomem, nostack)); }
        let e = (bits >> 52) & 0x7ff;
        if e == 0 { return if (bits << 1) != 0 { 3 } else { 2 }; }
        if e == 0x7ff { return if (bits << 12) != 0 { 0 } else { 1 }; }
        4
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global __fpclassify
    .type __fpclassify,@function
__fpclassify:
    movq rax, xmm0
    mov rcx, rax
    shr rcx, 52
    and ecx, 0x7ff
    shl rax, 12
    test ecx, ecx
    jne .Lcrabc_x86_fpclassify64_nonzero_exponent
    test rax, rax
    mov eax, 2
    jne .Lcrabc_x86_fpclassify64_done
    ret
.Lcrabc_x86_fpclassify64_nonzero_exponent:
    cmp ecx, 0x7ff
    jne .Lcrabc_x86_fpclassify64_normal
    test rax, rax
    mov eax, 1
    jne .Lcrabc_x86_fpclassify64_nan
    ret
.Lcrabc_x86_fpclassify64_normal:
    mov eax, 4
    ret
.Lcrabc_x86_fpclassify64_done:
    mov eax, 3
    ret
.Lcrabc_x86_fpclassify64_nan:
    xor eax, eax
    ret
    .size __fpclassify, .-__fpclassify
"#,
    );
}}

// Musl's `src/math/__signbitf.c` object.
static_archive_member! { __signbitf_source {
    // musl 1.2.6 src/math/__signbitf.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn __signbitf(x: f32) -> i32 { (x.to_bits() >> 31) as i32 }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    /* musl src/math/__signbitf.c and __signbit.c. */
    .p2align 4
    .global __signbitf
    .type __signbitf,@function
__signbitf:
    movd eax, xmm0
    shr eax, 31
    ret
    .size __signbitf, .-__signbitf
"#,
    );
}}

// Musl's `src/math/__signbit.c` object.
static_archive_member! { __signbit_source {
    // musl 1.2.6 src/math/__signbit.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn __signbit(x: f64) -> i32 { (x.to_bits() >> 63) as i32 }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global __signbit
    .type __signbit,@function
__signbit:
    movq rax, xmm0
    shr rax, 63
    ret
    .size __signbit, .-__signbit

    .section .text.__signbitl,"ax",@progbits
"#,
    );
}}

// Musl's `src/math/__signbitl.c` object.
static_archive_member! { __signbitl_source {
    // musl 1.2.6 src/math/__signbitl.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn __signbitl(x: f128) -> i32 { (x.to_bits() >> 127) as i32 }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.__signbitl,"ax",@progbits
    .p2align 4
    .global __signbitl
    .type __signbitl,@function
__signbitl:
    movzx eax, word ptr [rsp + 16]
    shr eax, 15
    ret
    .size __signbitl, .-__signbitl

    .section .text.crabc_x86_math_complex_rest,"ax",@progbits
    /* C99 real/imaginary accessor ABI: complex float is one SSE eightbyte;
       complex double is real in xmm0 and imaginary in xmm1. */
"#,
    );
}}

// Musl's `src/complex/crealf.c` object.
static_archive_member! { crealf_source {
    // musl 1.2.6 src/complex/crealf.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn crealf(z: Complex32) -> f32 { z.real }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits
    .p2align 4
    .global crealf
    .type crealf,@function
crealf:
    ret
    .size crealf, .-crealf
"#,
    );
}}

// Musl's `src/complex/cimagf.c` object.
static_archive_member! { cimagf_source {
    // musl 1.2.6 src/complex/cimagf.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn cimagf(z: Complex32) -> f32 { z.imag }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global cimagf
    .type cimagf,@function
cimagf:
    shufps xmm0, xmm0, 0x55
    ret
    .size cimagf, .-cimagf
"#,
    );
}}

// Musl's `src/complex/creal.c` object.
static_archive_member! { creal_source {
    // musl 1.2.6 src/complex/creal.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn creal(z: Complex64) -> f64 { z.real }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global creal
    .type creal,@function
creal:
    ret
    .size creal, .-creal
"#,
    );
}}

// Musl's `src/complex/cimag.c` object.
static_archive_member! { cimag_source {
    // musl 1.2.6 src/complex/cimag.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn cimag(z: Complex64) -> f64 { z.imag }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global cimag
    .type cimag,@function
cimag:
    movapd xmm0, xmm1
    ret
    .size cimag, .-cimag

    /* A complex long double is passed in 32 stack bytes. Its real component
       starts at +8 and its imaginary component at +24; scalar long-double
       results return in st0. */
"#,
    );
}}

// Musl's `src/complex/creall.c` object.
static_archive_member! { creall_source {
    // musl 1.2.6 src/complex/creall.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn creall(z: Complex128) -> f128 { z.real }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits
    .p2align 4
    .global creall
    .type creall,@function
creall:
    fld tbyte ptr [rsp + 8]
    ret
    .size creall, .-creall
"#,
    );
}}

// Musl's `src/complex/cimagl.c` object.
static_archive_member! { cimagl_source {
    // musl 1.2.6 src/complex/cimagl.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn cimagl(z: Complex128) -> f128 { z.imag }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global cimagl
    .type cimagl,@function
cimagl:
    fld tbyte ptr [rsp + 24]
    ret
    .size cimagl, .-cimagl
"#,
    );
}}

// Musl's `src/complex/conjf.c` object.
static_archive_member! { conjf_source {
    // musl 1.2.6 src/complex/conjf.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn conjf(z: Complex32) -> Complex32 {
        Complex32 { real: z.real, imag: -z.imag }
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global conjf
    .type conjf,@function
conjf:
    xorps xmm0, xmmword ptr [rip + .Lcrabc_x86_conjf_sign_conjf_source]
    ret
    .size conjf, .-conjf
    .section .rodata
    .p2align 4
.Lcrabc_x86_conjf_sign_conjf_source:
    .long 0, 0x80000000, 0, 0
"#,
    );
}}

// Musl's `src/complex/conj.c` object.
static_archive_member! { conj_source {
    // musl 1.2.6 src/complex/conj.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn conj(z: Complex64) -> Complex64 {
        Complex64 { real: z.real, imag: -z.imag }
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits

    .p2align 4
    .global conj
    .type conj,@function
conj:
    xorpd xmm1, xmmword ptr [rip + .Lcrabc_x86_conj_sign_conj_source]
    ret
    .size conj, .-conj

    /* COMPLEX_X87 returns its real component in st0 and its imaginary
       component in st1. Loading the negated imaginary first then the real
       creates that exact ordered pair without a Rust f80 representation. */
    .section .rodata
    .p2align 4
.Lcrabc_x86_conj_sign_conj_source:
    .quad 0x8000000000000000, 0
"#,
    );
}}

// Musl's `src/complex/conjl.c` object.
static_archive_member! { conjl_source {
    // musl 1.2.6 src/complex/conjl.c.
    #[cfg(target_arch = "aarch64")]
    #[no_mangle]
    pub extern "C" fn conjl(z: Complex128) -> Complex128 {
        Complex128 { real: z.real, imag: -z.imag }
    }
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
    .section .text.crabc_x86_math_complex_rest,"ax",@progbits
    .p2align 4
    .global conjl
    .type conjl,@function
conjl:
    fld tbyte ptr [rsp + 24]
    fchs
    fld tbyte ptr [rsp + 8]
    ret
    .size conjl, .-conjl

    .section .rodata
    .p2align 4
.Lcrabc_x86_conjf_sign:
    .long 0, 0x80000000, 0, 0
    .p2align 4
.Lcrabc_x86_conj_sign:
    .quad 0x8000000000000000, 0

    .section .note.GNU-stack, "", @progbits
"#,
    );
}}
