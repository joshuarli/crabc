/*
 * Fixed musl 1.2.6 x86-64 support assembly translations for the private
 * floating scanner. See float_parse.rs for source, license, compiler-codegen
 * provenance, and the string-only pseudo-FILE boundary.
 */

/* musl src/internal/shgetc.c */
	.text
	.section	.text.crabc_x86_float_parse_shlim,"ax",@progbits
	.type	crabc_x86_float_parse_shlim, @function
crabc_x86_float_parse_shlim:
	movq	8(%rdi), %rax
	movq	88(%rdi), %rdx
	movq	%rsi, 192(%rdi)
	subq	%rax, %rdx
	movq	%rdx, 200(%rdi)
	movq	16(%rdi), %rdx
	testq	%rsi, %rsi
	je	.Lcrabc_x86_float_parse_src_internal_shgetc_c_2
	movq	%rdx, %rcx
	subq	%rax, %rcx
	addq	%rsi, %rax
	cmpq	%rsi, %rcx
	cmovg	%rax, %rdx
.Lcrabc_x86_float_parse_src_internal_shgetc_c_2:
	movq	%rdx, 184(%rdi)
	ret
	.size	crabc_x86_float_parse_shlim, .-crabc_x86_float_parse_shlim
	.section	.text.crabc_x86_float_parse_shgetc,"ax",@progbits
	.type	crabc_x86_float_parse_shgetc, @function
crabc_x86_float_parse_shgetc:
	pushq	%rbp
	pushq	%rbx
	movq	%rdi, %rbx
	subq	$8, %rsp
	movq	8(%rdi), %rdx
	movq	88(%rdi), %rcx
	movq	192(%rdi), %rax
	movq	%rdx, %rbp
	subq	%rcx, %rbp
	addq	200(%rdi), %rbp
	testq	%rax, %rax
	je	.Lcrabc_x86_float_parse_src_internal_shgetc_c_15
	cmpq	%rbp, %rax
	jle	.Lcrabc_x86_float_parse_src_internal_shgetc_c_8
.Lcrabc_x86_float_parse_src_internal_shgetc_c_15:
	movq	%rbx, %rdi
	call	crabc_x86_float_parse_uflow
	movq	8(%rbx), %rdx
	movq	88(%rbx), %rcx
	testl	%eax, %eax
	js	.Lcrabc_x86_float_parse_src_internal_shgetc_c_8
	movq	192(%rbx), %rsi
	movq	16(%rbx), %rdi
	addq	$1, %rbp
	testq	%rsi, %rsi
	je	.Lcrabc_x86_float_parse_src_internal_shgetc_c_12
	movq	%rdi, %r9
	subq	%rbp, %rsi
	subq	%rdx, %r9
	leaq	(%rdx,%rsi), %r8
	cmpq	%rsi, %r9
	cmovg	%r8, %rdi
.Lcrabc_x86_float_parse_src_internal_shgetc_c_12:
	movq	%rcx, %rsi
	movq	%rdi, 184(%rbx)
	subq	%rdx, %rsi
	addq	%rbp, %rsi
	movq	%rsi, 200(%rbx)
	cmpq	%rdx, %rcx
	jb	.Lcrabc_x86_float_parse_src_internal_shgetc_c_7
	movb	%al, -1(%rdx)
.Lcrabc_x86_float_parse_src_internal_shgetc_c_7:
	addq	$8, %rsp
	popq	%rbx
	popq	%rbp
	ret
.Lcrabc_x86_float_parse_src_internal_shgetc_c_8:
	subq	%rdx, %rcx
	movq	%rdx, 184(%rbx)
	movq	$-1, 192(%rbx)
	leaq	(%rcx,%rbp), %rax
	movq	%rax, 200(%rbx)
	movl	$-1, %eax
	jmp	.Lcrabc_x86_float_parse_src_internal_shgetc_c_7
	.size	crabc_x86_float_parse_shgetc, .-crabc_x86_float_parse_shgetc
	.section	.note.GNU-stack,"",@progbits

/* musl src/math/scalbn.c */
	.text
	.section	.text.crabc_x86_float_parse_scalbn,"ax",@progbits
	.type	crabc_x86_float_parse_scalbn, @function
crabc_x86_float_parse_scalbn:
	cmpl	$1023, %edi
	jle	.Lcrabc_x86_float_parse_src_math_scalbn_c_2
	movsd	.Lcrabc_x86_float_parse_src_math_scalbn_c_C0(%rip), %xmm1
	mulsd	%xmm1, %xmm0
	cmpl	$2046, %edi
	jle	.Lcrabc_x86_float_parse_src_math_scalbn_c_3
	mulsd	%xmm1, %xmm0
	subl	$2046, %edi
	movl	$1023, %eax
	cmpl	%eax, %edi
	cmovg	%eax, %edi
	addl	$1023, %edi
	jmp	.Lcrabc_x86_float_parse_src_math_scalbn_c_3
.Lcrabc_x86_float_parse_src_math_scalbn_c_2:
	cmpl	$-1022, %edi
	jl	.Lcrabc_x86_float_parse_src_math_scalbn_c_4
.Lcrabc_x86_float_parse_src_math_scalbn_c_6:
	addl	$1023, %edi
.Lcrabc_x86_float_parse_src_math_scalbn_c_3:
	salq	$52, %rdi
	movq	%rdi, %xmm2
	mulsd	%xmm2, %xmm0
	ret
.Lcrabc_x86_float_parse_src_math_scalbn_c_4:
	movsd	.Lcrabc_x86_float_parse_src_math_scalbn_c_C1(%rip), %xmm1
	mulsd	%xmm1, %xmm0
	cmpl	$-1991, %edi
	jl	.Lcrabc_x86_float_parse_src_math_scalbn_c_5
	addl	$1992, %edi
	jmp	.Lcrabc_x86_float_parse_src_math_scalbn_c_3
.Lcrabc_x86_float_parse_src_math_scalbn_c_5:
	mulsd	%xmm1, %xmm0
	addl	$1938, %edi
	movl	$-1022, %eax
	cmpl	%eax, %edi
	cmovl	%eax, %edi
	jmp	.Lcrabc_x86_float_parse_src_math_scalbn_c_6
	.size	crabc_x86_float_parse_scalbn, .-crabc_x86_float_parse_scalbn
	.section	.rodata.cst8,"aM",@progbits,8
	.align 8
.Lcrabc_x86_float_parse_src_math_scalbn_c_C0:
	.long	0
	.long	2145386496
	.align 8
.Lcrabc_x86_float_parse_src_math_scalbn_c_C1:
	.long	0
	.long	56623104
	.section	.note.GNU-stack,"",@progbits

/* musl src/math/scalbnl.c */
	.text
	.section	.text.crabc_x86_float_parse_scalbnl,"ax",@progbits
	.type	crabc_x86_float_parse_scalbnl, @function
crabc_x86_float_parse_scalbnl:
	fldt	8(%rsp)
	cmpl	$16383, %edi
	jle	.Lcrabc_x86_float_parse_src_math_scalbnl_c_2
	leal	-16383(%rdi), %eax
	fldt	.Lcrabc_x86_float_parse_src_math_scalbnl_c_C0(%rip)
	fmul	%st, %st(1)
	cmpl	$16383, %eax
	jle	.Lcrabc_x86_float_parse_src_math_scalbnl_c_6
	leal	-32766(%rdi), %eax
	fmulp	%st, %st(1)
	movl	$16383, %edx
	cmpl	%edx, %eax
	cmovg	%edx, %eax
	jmp	.Lcrabc_x86_float_parse_src_math_scalbnl_c_3
.Lcrabc_x86_float_parse_src_math_scalbnl_c_6:
	fstp	%st(0)
	jmp	.Lcrabc_x86_float_parse_src_math_scalbnl_c_3
.Lcrabc_x86_float_parse_src_math_scalbnl_c_7:
	fstp	%st(0)
.Lcrabc_x86_float_parse_src_math_scalbnl_c_3:
	fld1
	addw	$16383, %ax
	fstpt	-24(%rsp)
	movw	%ax, -16(%rsp)
	fldt	-24(%rsp)
	fmulp	%st, %st(1)
	ret
.Lcrabc_x86_float_parse_src_math_scalbnl_c_2:
	movl	%edi, %eax
	cmpl	$-16382, %edi
	jge	.Lcrabc_x86_float_parse_src_math_scalbnl_c_3
	fldt	.Lcrabc_x86_float_parse_src_math_scalbnl_c_C1(%rip)
	addl	$16269, %eax
	fmul	%st, %st(1)
	cmpl	$-16382, %eax
	jge	.Lcrabc_x86_float_parse_src_math_scalbnl_c_7
	leal	32538(%rdi), %eax
	fmulp	%st, %st(1)
	movl	$-16382, %edx
	cmpl	%edx, %eax
	cmovl	%edx, %eax
	jmp	.Lcrabc_x86_float_parse_src_math_scalbnl_c_3
	.size	crabc_x86_float_parse_scalbnl, .-crabc_x86_float_parse_scalbnl
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.Lcrabc_x86_float_parse_src_math_scalbnl_c_C0:
	.long	0
	.long	-2147483648
	.long	32766
	.long	0
	.align 16
.Lcrabc_x86_float_parse_src_math_scalbnl_c_C1:
	.long	0
	.long	-2147483648
	.long	114
	.long	0
	.section	.note.GNU-stack,"",@progbits

/* musl src/math/copysignl.c */
	.text
	.section	.text.crabc_x86_float_parse_copysignl,"ax",@progbits
	.type	crabc_x86_float_parse_copysignl, @function
crabc_x86_float_parse_copysignl:
	movl	16(%rsp), %edx
	movq	8(%rsp), %rax
	movl	%edx, -16(%rsp)
	movq	%rax, -24(%rsp)
	movq	%rdx, %rax
	movzwl	32(%rsp), %edx
	andw	$32767, %ax
	andw	$-32768, %dx
	orl	%edx, %eax
	movw	%ax, -16(%rsp)
	fldt	-24(%rsp)
	ret
	.size	crabc_x86_float_parse_copysignl, .-crabc_x86_float_parse_copysignl
	.section	.note.GNU-stack,"",@progbits

/* musl src/math/x86_64/fabsl.c */
	.text
	.section	.text.crabc_x86_float_parse_fabsl,"ax",@progbits
	.type	crabc_x86_float_parse_fabsl, @function
crabc_x86_float_parse_fabsl:
	fldt	8(%rsp)
#APP
# 5 "src/math/x86_64/fabsl.c" 1
	fabs
# 0 "" 2
#NO_APP
	ret
	.size	crabc_x86_float_parse_fabsl, .-crabc_x86_float_parse_fabsl
	.section	.note.GNU-stack,"",@progbits

/* musl src/math/x86_64/fmodl.c */
	.text
	.section	.text.crabc_x86_float_parse_fmodl,"ax",@progbits
	.type	crabc_x86_float_parse_fmodl, @function
crabc_x86_float_parse_fmodl:
	fldt	24(%rsp)
	fldt	8(%rsp)
.Lcrabc_x86_float_parse_src_math_x86_64_fmodl_c_2:
#APP
# 6 "src/math/x86_64/fmodl.c" 1
	fprem; fnstsw %ax
# 0 "" 2
#NO_APP
	testb	$4, %ah
	jne	.Lcrabc_x86_float_parse_src_math_x86_64_fmodl_c_2
	fstp	%st(1)
	ret
	.size	crabc_x86_float_parse_fmodl, .-crabc_x86_float_parse_fmodl
	.section	.note.GNU-stack,"",@progbits

/* The pseudo-string scanner never reaches __shgetc's refill route: strtox
 * installs rend = (void *)-1 and input is required to be NUL terminated. The
 * selected wide scanner, however, installs one private read callback at FILE
 * offset 64. This local __uflow subset invokes exactly that callback for one
 * byte; it does not import __toread, expose FILE, or admit public stdio. */
    .text
    .type crabc_x86_float_parse_uflow,@function
crabc_x86_float_parse_uflow:
    movq 64(%rdi), %rax
    testq %rax, %rax
    je .Lcrabc_x86_float_parse_uflow_eof
    subq $24, %rsp
    movq %rdi, 8(%rsp)
    leaq 7(%rsp), %rsi
    movl $1, %edx
    call *%rax
    cmpq $1, %rax
    jne .Lcrabc_x86_float_parse_uflow_stack_eof
    movzbl 7(%rsp), %eax
    addq $24, %rsp
    ret
.Lcrabc_x86_float_parse_uflow_stack_eof:
    addq $24, %rsp
.Lcrabc_x86_float_parse_uflow_eof:
    movl $-1, %eax
    ret
    .size crabc_x86_float_parse_uflow, .-crabc_x86_float_parse_uflow
    .section .note.GNU-stack,"",@progbits
