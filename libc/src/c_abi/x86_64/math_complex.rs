//! Selected static Linux/x86-64 long-double classification and complex ABI foundation.
//!
//! This is a deliberately small x87 ABI foundation, not a scalar or complex
//! math implementation. It owns only `__fpclassify*`, `__signbit*`, and the
//! C99 `creal*`, `cimag*`, and `conj*` function symbols. The public header
//! still declares many further math/complex APIs; none of them are selected by
//! this leaf. The separately mapped `complex_projection.rs` sibling composes
//! `cproj*` into the same native artifact without blurring this source map.
//! `cabs*`, `carg*`, powers, transcendentals, errno, fenv behavior beyond
//! classification, libm, libc.so, CRT, loader, sysroot, and public x86 support
//! all remain outside its contract.
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

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 math/complex leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    r#"
    .text

    /* musl src/math/__fpclassifyl.c for x87 extended precision. The argument
       occupies 16 stack bytes after the return address: low 64-bit mantissa
       at +8 and the little-endian sign/exponent word at +16. */
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

    /* musl src/math/__fpclassifyf.c and __fpclassify.c. These are public
       external ABI entries, including for consumers that name the symbols
       directly rather than through the classification macros. */
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

    /* musl src/math/__signbitf.c and __signbit.c. */
    .p2align 4
    .global __signbitf
    .type __signbitf,@function
__signbitf:
    movd eax, xmm0
    shr eax, 31
    ret
    .size __signbitf, .-__signbitf

    .p2align 4
    .global __signbit
    .type __signbit,@function
__signbit:
    movq rax, xmm0
    shr rax, 63
    ret
    .size __signbit, .-__signbit

    .p2align 4
    .global __signbitl
    .type __signbitl,@function
__signbitl:
    movzx eax, word ptr [rsp + 16]
    shr eax, 15
    ret
    .size __signbitl, .-__signbitl

    /* C99 real/imaginary accessor ABI: complex float is one SSE eightbyte;
       complex double is real in xmm0 and imaginary in xmm1. */
    .p2align 4
    .global crealf
    .type crealf,@function
crealf:
    ret
    .size crealf, .-crealf

    .p2align 4
    .global cimagf
    .type cimagf,@function
cimagf:
    shufps xmm0, xmm0, 0x55
    ret
    .size cimagf, .-cimagf

    .p2align 4
    .global creal
    .type creal,@function
creal:
    ret
    .size creal, .-creal

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
    .p2align 4
    .global creall
    .type creall,@function
creall:
    fld tbyte ptr [rsp + 8]
    ret
    .size creall, .-creall

    .p2align 4
    .global cimagl
    .type cimagl,@function
cimagl:
    fld tbyte ptr [rsp + 24]
    ret
    .size cimagl, .-cimagl

    .p2align 4
    .global conjf
    .type conjf,@function
conjf:
    xorps xmm0, xmmword ptr [rip + .Lcrabc_x86_conjf_sign]
    ret
    .size conjf, .-conjf

    .p2align 4
    .global conj
    .type conj,@function
conj:
    xorpd xmm1, xmmword ptr [rip + .Lcrabc_x86_conj_sign]
    ret
    .size conj, .-conj

    /* COMPLEX_X87 returns its real component in st0 and its imaginary
       component in st1. Loading the negated imaginary first then the real
       creates that exact ordered pair without a Rust f80 representation. */
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
