//! Legacy Linux/x86-64 C99 complex-projection ABI source.
//!
//! The active static root now obtains `cproj*` from the complete
//! `math_complex_complete.rs` source-faithful musl translation. This retained
//! narrow implementation documents the prior focused projection proof but is
//! intentionally not compiled alongside that complete leaf, which would
//! duplicate the public C ABI symbols.
//!
//! This target-private leaf maps pinned musl 1.2.6 commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`
//! `src/complex/{cproj,cprojf,cprojl}.c`, under musl's MIT license. For each C
//! real width, a complex value with either component equal to infinity maps to
//! positive real infinity plus an imaginary zero carrying the input imaginary
//! sign; every finite/NaN-only pair is returned bit-for-bit unchanged.
//!
//! AArch64 owns the same contract in `complex_basic_exports.rs`, using its
//! binary128 `ComplexLong` record. System V AMD64 instead passes float/double
//! complex values in SSE registers and long-double complex in 32 bytes of
//! stack storage, returning binary80 components through `st0`/`st1`. Keeping
//! that representation here avoids pretending the two long-double ABIs share
//! a Rust type. The paired native fixture proves ordinary, signed-zero,
//! infinity, and NaN projection behavior against pinned musl.
//!
//! This leaf selects no `cabs*`, `carg*`, complex power/transcendental,
//! general libm, family completion, promotion, or public x86 support.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_endian = "little")))]
compile_error!("the x86 complex-projection leaf requires little-endian Linux/x86-64");

core::arch::global_asm!(
    r#"
    .section .text.cprojf, "ax", @progbits
    .p2align 4
    .global cprojf
    .type cprojf,@function
cprojf:
    movq rax, xmm0
    mov edx, eax
    and edx, 0x7fffffff
    cmp edx, 0x7f800000
    je .Lcrabc_x86_cprojf_project
    mov rdx, rax
    shr rdx, 32
    mov ecx, edx
    and ecx, 0x7fffffff
    cmp ecx, 0x7f800000
    jne .Lcrabc_x86_cprojf_return
.Lcrabc_x86_cprojf_project:
    mov rdx, rax
    shr rdx, 32
    and edx, 0x80000000
    shl rdx, 32
    mov eax, 0x7f800000
    or rax, rdx
    movq xmm0, rax
.Lcrabc_x86_cprojf_return:
    ret
    .size cprojf, .-cprojf

    .section .text.cproj, "ax", @progbits
    .p2align 4
    .global cproj
    .type cproj,@function
cproj:
    movq rax, xmm0
    shl rax, 1
    movabs rcx, 0xffe0000000000000
    cmp rax, rcx
    je .Lcrabc_x86_cproj_project
    movq rax, xmm1
    shl rax, 1
    cmp rax, rcx
    jne .Lcrabc_x86_cproj_return
.Lcrabc_x86_cproj_project:
    movsd xmm0, qword ptr [rip + .Lcrabc_x86_cproj_infinity]
    movq rax, xmm1
    shr rax, 63
    shl rax, 63
    movq xmm1, rax
.Lcrabc_x86_cproj_return:
    ret
    .size cproj, .-cproj

    .section .text.cprojl, "ax", @progbits
    .p2align 4
    .global cprojl
    .type cprojl,@function
cprojl:
    movzx eax, word ptr [rsp + 16]
    and eax, 0x7fff
    cmp eax, 0x7fff
    jne .Lcrabc_x86_cprojl_check_imaginary
    mov rax, qword ptr [rsp + 8]
    movabs rdx, 0x8000000000000000
    cmp rax, rdx
    je .Lcrabc_x86_cprojl_project
.Lcrabc_x86_cprojl_check_imaginary:
    movzx eax, word ptr [rsp + 32]
    and eax, 0x7fff
    cmp eax, 0x7fff
    jne .Lcrabc_x86_cprojl_return_input
    mov rax, qword ptr [rsp + 24]
    movabs rdx, 0x8000000000000000
    cmp rax, rdx
    jne .Lcrabc_x86_cprojl_return_input
.Lcrabc_x86_cprojl_project:
    fldz
    test word ptr [rsp + 32], 0x8000
    jz .Lcrabc_x86_cprojl_load_infinity
    fchs
.Lcrabc_x86_cprojl_load_infinity:
    fld tbyte ptr [rip + .Lcrabc_x86_cprojl_infinity]
    ret
.Lcrabc_x86_cprojl_return_input:
    fld tbyte ptr [rsp + 24]
    fld tbyte ptr [rsp + 8]
    ret
    .size cprojl, .-cprojl

    .section .rodata.complex_projection, "a", @progbits
    .p2align 4
.Lcrabc_x86_cproj_infinity:
    .quad 0x7ff0000000000000
.Lcrabc_x86_cprojl_infinity:
    .quad 0x8000000000000000
    .word 0x7fff
    .zero 6

    .section .note.GNU-stack, "", @progbits
"#,
);
