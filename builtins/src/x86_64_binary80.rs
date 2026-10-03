// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception AND MIT
// The parent Rust module selects this x87 ABI only on x86-64.
core::arch::global_asm!(r#"
/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception AND MIT
 * Faithful binary80 compiler kernels with a local musl math closure.
 * The six public entries use the System V AMD64 x87 calling convention.
 */
/* LLVM 22.1.3 floattixf.c */
	.text
	.section	.text.__floattixf,"ax",@progbits
	.p2align 4
	.globl	__floattixf
	.type	__floattixf, @function
__floattixf:
	xchgq	%rdi, %rsi
	movq	%rsi, %rax
	orq	%rdi, %rax
	jne	.Lbinary80_floattixf_21
	fldz
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_floattixf_21:
	pushq	%r14
	movq	%rdi, %r11
	pushq	%rbx
	sarq	$63, %r11
	movl	$128, %ebx
	xorq	%r11, %rsi
	xorq	%r11, %rdi
	subq	$40, %rsp
	subq	%r11, %rsi
	sbbq	%r11, %rdi
	movq	%rsi, %r8
	movq	%r11, 16(%rsp)
	movq	%rdi, %r9
	movq	%rsi, %rdi
	movq	%r8, (%rsp)
	movq	%r9, %rsi
	movq	%r9, 8(%rsp)
	movq	%r11, 24(%rsp)
	call	__clzti2@PLT
	movl	$127, %edx
	movq	(%rsp), %r8
	movq	8(%rsp), %r9
	subl	%eax, %ebx
	subl	%eax, %edx
	movq	16(%rsp), %r10
	cmpl	$64, %ebx
	movl	%ebx, %r14d
	jle	.Lbinary80_floattixf_3
	cmpl	$63, %eax
	je	.Lbinary80_floattixf_4
	cmpl	$62, %eax
	je	.Lbinary80_floattixf_5
	movq	$-1, %rsi
	leal	66(%rax), %ecx
	xorl	%r11d, %r11d
	movq	%rsi, %rdi
	shrdq	%cl, %rsi, %rsi
	shrq	%cl, %rdi
	testb	$64, %cl
	cmovne	%rdi, %rsi
	cmovne	%r11, %rdi
	andq	%r8, %rsi
	andq	%r9, %rdi
	movq	%rsi, %rcx
	xorl	%esi, %esi
	orq	%rdi, %rcx
	movl	$62, %ecx
	setne	%sil
	subl	%eax, %ecx
	xorl	%edi, %edi
	xorl	%ebx, %ebx
	shrdq	%cl, %r9, %r8
	shrq	%cl, %r9
	andl	$64, %ecx
	cmovne	%r9, %r8
	cmovne	%rbx, %r9
	orq	%rsi, %r8
	orq	%rdi, %r9
.Lbinary80_floattixf_5:
	movq	%r8, %rsi
	xorl	%edi, %edi
	shrq	$2, %rsi
	orq	%r9, %rdi
	andl	$1, %esi
	orq	%r8, %rsi
	addq	$1, %rsi
	adcq	$0, %rdi
	xorl	%ecx, %ecx
	movq	%rsi, %r8
	movq	%rdi, %r9
	movq	%rcx, %rax
	shrdq	$2, %rdi, %r8
	sarq	$2, %r9
	movq	%r9, %rbx
	andl	$1, %ebx
	orq	%rbx, %rax
	je	.Lbinary80_floattixf_7
	shrdq	$3, %rdi, %rsi
	movl	%r14d, %edx
	movq	%rsi, %r8
	jmp	.Lbinary80_floattixf_7
	.p2align 4,,10
	.p2align 3
.Lbinary80_floattixf_3:
	leal	-64(%rax), %ecx
	xorl	%eax, %eax
	salq	%cl, %r8
	andl	$64, %ecx
	cmovne	%rax, %r8
.Lbinary80_floattixf_7:
	movl	%r10d, %eax
	addl	$16383, %edx
	movq	%r8, (%rsp)
	andl	$32768, %eax
	orl	%edx, %eax
	movl	%eax, 8(%rsp)
	fldt	(%rsp)
	addq	$40, %rsp
	popq	%rbx
	popq	%r14
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_floattixf_4:
	addq	%r8, %r8
	adcq	%r9, %r9
	jmp	.Lbinary80_floattixf_5
	.size	__floattixf, .-__floattixf

/* LLVM 22.1.3 floatuntixf.c */
	.text
	.section	.text.__floatuntixf,"ax",@progbits
	.p2align 4
	.globl	__floatuntixf
	.type	__floatuntixf, @function
__floatuntixf:
	movq	%rdi, %rax
	orq	%rsi, %rax
	jne	.Lbinary80_floatuntixf_21
	fldz
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_floatuntixf_21:
	subq	$24, %rsp
	movq	%rdi, (%rsp)
	movq	%rsi, 8(%rsp)
	call	__clzti2@PLT
	movl	$128, %edi
	movl	$127, %esi
	movq	(%rsp), %r8
	subl	%eax, %edi
	subl	%eax, %esi
	movq	8(%rsp), %r9
	cmpl	$64, %edi
	jle	.Lbinary80_floatuntixf_3
	cmpl	$63, %eax
	je	.Lbinary80_floatuntixf_4
	cmpl	$62, %eax
	je	.Lbinary80_floatuntixf_5
	movl	$62, %ecx
	movq	%r8, %r10
	movq	%r9, %r11
	xorl	%edx, %edx
	subl	%eax, %ecx
	shrq	%cl, %r11
	shrdq	%cl, %r9, %r10
	testb	$64, %cl
	leal	66(%rax), %ecx
	movq	$-1, %rax
	cmovne	%r11, %r10
	cmovne	%rdx, %r11
	movq	%rax, %rdx
	shrdq	%cl, %rdx, %rax
	shrq	%cl, %rdx
	testb	$64, %cl
	je	.Lbinary80_floatuntixf_22
	movq	%rdx, %rax
	xorl	%edx, %edx
.Lbinary80_floatuntixf_22:
	andq	%r8, %rax
	andq	%r9, %rdx
	xorl	%r8d, %r8d
	orq	%rdx, %rax
	setne	%r8b
	xorl	%r9d, %r9d
	orq	%r10, %r8
	orq	%r11, %r9
.Lbinary80_floatuntixf_5:
	movq	%r8, %rax
	xorl	%edx, %edx
	shrq	$2, %rax
	orq	%r9, %rdx
	andl	$1, %eax
	orq	%r8, %rax
	addq	$1, %rax
	adcq	$0, %rdx
	xorl	%r10d, %r10d
	movq	%rax, %r8
	movq	%rdx, %r9
	movq	%r10, %rcx
	shrdq	$2, %rdx, %r8
	shrq	$2, %r9
	movq	%r9, %r11
	andl	$1, %r11d
	orq	%r11, %rcx
	je	.Lbinary80_floatuntixf_7
	shrdq	$3, %rdx, %rax
	movl	%edi, %esi
	movq	%rax, %r8
	jmp	.Lbinary80_floatuntixf_7
	.p2align 4,,10
	.p2align 3
.Lbinary80_floatuntixf_3:
	leal	-64(%rax), %ecx
	xorl	%eax, %eax
	salq	%cl, %r8
	andl	$64, %ecx
	cmovne	%rax, %r8
.Lbinary80_floatuntixf_7:
	leal	16383(%rsi), %eax
	movq	%r8, (%rsp)
	movl	%eax, 8(%rsp)
	fldt	(%rsp)
	addq	$24, %rsp
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_floatuntixf_4:
	addq	%r8, %r8
	adcq	%r9, %r9
	jmp	.Lbinary80_floatuntixf_5
	.size	__floatuntixf, .-__floatuntixf

/* LLVM 22.1.3 fixxfti.c */
	.text
	.section	.text.__fixxfti,"ax",@progbits
	.p2align 4
	.globl	__fixxfti
	.type	__fixxfti, @function
__fixxfti:
	movq	16(%rsp), %rsi
	xorl	%eax, %eax
	xorl	%edx, %edx
	movl	%esi, %ecx
	andl	$32767, %ecx
	movl	%ecx, %r8d
	subl	$16383, %r8d
	js	.Lbinary80_fixxfti_1
	cmpl	$127, %r8d
	ja	.Lbinary80_fixxfti_8
	shrl	$15, %esi
	movq	8(%rsp), %rax
	xorl	%edx, %edx
	andl	$1, %esi
	negl	%esi
	movslq	%esi, %rsi
	movq	%rsi, %rdi
	sarq	$63, %rdi
	cmpl	$63, %r8d
	jle	.Lbinary80_fixxfti_4
	subl	$16446, %ecx
	xorl	%r9d, %r9d
	shldq	%cl, %rax, %rdx
	salq	%cl, %rax
	andl	$64, %ecx
	cmovne	%rax, %rdx
	cmovne	%r9, %rax
.Lbinary80_fixxfti_5:
	xorq	%rsi, %rax
	xorq	%rdi, %rdx
	subq	%rsi, %rax
	sbbq	%rdi, %rdx
.Lbinary80_fixxfti_1:
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_fixxfti_8:
	movabsq	$-9223372036854775808, %rdx
	fldz
	xorl	%ecx, %ecx
	fldt	8(%rsp)
	fcomip	%st(1), %st
	fstp	%st(0)
	seta	%cl
	xorl	%eax, %eax
	subq	%rcx, %rax
	sbbq	$0, %rdx
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_fixxfti_4:
	movl	$63, %ecx
	subl	%r8d, %ecx
	shrdq	%cl, %rdx, %rax
	sarq	%cl, %rdx
	movq	%rdx, %r8
	sarq	$63, %r8
	andl	$64, %ecx
	cmovne	%rdx, %rax
	cmovne	%r8, %rdx
	jmp	.Lbinary80_fixxfti_5
	.size	__fixxfti, .-__fixxfti

/* LLVM 22.1.3 fixunsxfti.c */
	.text
	.section	.text.__fixunsxfti,"ax",@progbits
	.p2align 4
	.globl	__fixunsxfti
	.type	__fixunsxfti, @function
__fixunsxfti:
	movq	16(%rsp), %rsi
	xorl	%eax, %eax
	xorl	%edx, %edx
	movl	%esi, %ecx
	andl	$32767, %ecx
	movl	%ecx, %edi
	subl	$16383, %edi
	js	.Lbinary80_fixunsxfti_1
	testl	$32768, %esi
	jne	.Lbinary80_fixunsxfti_1
	movq	$-1, %rax
	movq	%rax, %rdx
	cmpl	$128, %edi
	ja	.Lbinary80_fixunsxfti_1
	movq	8(%rsp), %rax
	xorl	%edx, %edx
	cmpl	$63, %edi
	jle	.Lbinary80_fixunsxfti_3
	subl	$16446, %ecx
	xorl	%edi, %edi
	shldq	%cl, %rax, %rdx
	salq	%cl, %rax
	andl	$64, %ecx
	cmovne	%rax, %rdx
	cmovne	%rdi, %rax
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_fixunsxfti_3:
	movl	$63, %ecx
	xorl	%esi, %esi
	subl	%edi, %ecx
	shrdq	%cl, %rdx, %rax
	shrq	%cl, %rdx
	andl	$64, %ecx
	cmovne	%rdx, %rax
	cmovne	%rsi, %rdx
.Lbinary80_fixunsxfti_1:
	ret
	.size	__fixunsxfti, .-__fixunsxfti

/* LLVM 22.1.3 mulxc3.c */
	.text
	.section	.text.__mulxc3,"ax",@progbits
	.p2align 4
	.globl	__mulxc3
	.type	__mulxc3, @function
__mulxc3:
	fldt	8(%rsp)
	fldt	40(%rsp)
	fmul	%st(1), %st
	fldt	24(%rsp)
	fldt	56(%rsp)
	fmul	%st, %st(1)
	fmul	%st(3), %st
	fldt	40(%rsp)
	fldt	24(%rsp)
	fmulp	%st, %st(1)
	fld	%st(0)
	fstpt	-72(%rsp)
	fld	%st(3)
	fsub	%st(3), %st
	fld	%st(2)
	faddp	%st, %st(2)
	fld	%st(1)
	fxch	%st(1)
	fucomi	%st(0), %st
	jnp	.Lbinary80_mulxc3_96
	fxch	%st(2)
	fucomip	%st(0), %st
	jp	.Lbinary80_mulxc3_89
	fstp	%st(5)
	fstp	%st(3)
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_1
	.p2align 4,,10
	.p2align 3
.Lbinary80_mulxc3_96:
	fstp	%st(5)
	fstp	%st(5)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_1
.Lbinary80_mulxc3_105:
	fstp	%st(2)
	fxch	%st(1)
.Lbinary80_mulxc3_1:
	ret
.Lbinary80_mulxc3_89:
	fld	%st(5)
	fabs
	fld	%st(0)
	fstpt	-40(%rsp)
	fldt	24(%rsp)
	fabs
	fstpt	-56(%rsp)
	fldt	-56(%rsp)
	fstpt	-24(%rsp)
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fxch	%st(1)
	fucomip	%st(1), %st
	fstp	%st(0)
	ja	.Lbinary80_mulxc3_97
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fldt	-56(%rsp)
	fucomip	%st(1), %st
	fstp	%st(0)
	ja	.Lbinary80_mulxc3_98
	fldt	56(%rsp)
	fabs
	fstpt	-56(%rsp)
	fldt	40(%rsp)
	fabs
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fxch	%st(1)
	fucomip	%st(1), %st
	fstp	%st(0)
	ja	.Lbinary80_mulxc3_99
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fldt	-56(%rsp)
	fucomip	%st(1), %st
	fstp	%st(0)
	jbe	.Lbinary80_mulxc3_8
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	flds	.Lbinary80_mulxc3_C0(%rip)
	fstpt	-56(%rsp)
	fldt	-56(%rsp)
	fldz
	fxch	%st(1)
.Lbinary80_mulxc3_6:
	fldt	40(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fxch	%st(1)
	fabs
	testb	$2, %ah
	fld	%st(0)
	fchs
	fcmove	%st(1), %st
	fstp	%st(1)
	xorl	%eax, %eax
	fstpt	40(%rsp)
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fldt	-56(%rsp)
	fucomip	%st(1), %st
	fstp	%st(0)
	seta	%al
	movl	%eax, -72(%rsp)
	fildl	-72(%rsp)
	fldt	56(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fabs
	testb	$2, %ah
	fld	%st(0)
	fchs
	fcmove	%st(1), %st
	fstp	%st(1)
	fstpt	56(%rsp)
	fxch	%st(1)
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_90
.Lbinary80_mulxc3_19:
	fldt	24(%rsp)
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_91
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_15
.Lbinary80_mulxc3_101:
	fxch	%st(1)
	jmp	.Lbinary80_mulxc3_15
.Lbinary80_mulxc3_106:
	fstp	%st(1)
	fxch	%st(1)
	.p2align 4
	.p2align 3
.Lbinary80_mulxc3_15:
	fldt	40(%rsp)
	fmul	%st(1), %st
	fldt	56(%rsp)
	fldt	24(%rsp)
	fmul	%st, %st(1)
	fxch	%st(2)
	fsubp	%st, %st(1)
	fldt	56(%rsp)
	fmulp	%st, %st(3)
	fldt	40(%rsp)
	fmulp	%st, %st(2)
	fxch	%st(2)
	faddp	%st, %st(1)
	fxch	%st(1)
	fmul	%st(2), %st
	fxch	%st(2)
	fmulp	%st, %st(1)
	fxch	%st(1)
	jmp	.Lbinary80_mulxc3_1
.Lbinary80_mulxc3_97:
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_3
.Lbinary80_mulxc3_98:
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
.Lbinary80_mulxc3_3:
	fldt	.Lbinary80_mulxc3_C3(%rip)
	xorl	%eax, %eax
	fldt	-40(%rsp)
	fucomip	%st(1), %st
	seta	%al
	movl	%eax, -72(%rsp)
	fildl	-72(%rsp)
	fxch	%st(2)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fxch	%st(1)
	fabs
	testb	$2, %ah
	fld	%st(0)
	fchs
	fcmove	%st(1), %st
	fstp	%st(1)
	xorl	%eax, %eax
	fldt	-24(%rsp)
	fucomip	%st(2), %st
	fstp	%st(1)
	seta	%al
	movl	%eax, -72(%rsp)
	fildl	-72(%rsp)
	fldt	24(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fabs
	testb	$2, %ah
	fld	%st(0)
	fchs
	fcmove	%st(1), %st
	fstp	%st(1)
	fstpt	24(%rsp)
	fldt	40(%rsp)
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_92
	fstp	%st(0)
.Lbinary80_mulxc3_11:
	fldt	40(%rsp)
	fabs
	fldt	56(%rsp)
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_13
	fabs
	fld	%st(0)
	fstpt	-56(%rsp)
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fxch	%st(2)
	fucomip	%st(2), %st
	ja	.Lbinary80_mulxc3_100
	fucomip	%st(1), %st
	fstp	%st(0)
	flds	.Lbinary80_mulxc3_C0(%rip)
	jbe	.Lbinary80_mulxc3_101
	fstpt	-56(%rsp)
	fldt	-56(%rsp)
	fldz
	fxch	%st(1)
	jmp	.Lbinary80_mulxc3_6
.Lbinary80_mulxc3_99:
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_84
.Lbinary80_mulxc3_100:
	fstp	%st(0)
	fstp	%st(0)
.Lbinary80_mulxc3_84:
	fld1
	flds	.Lbinary80_mulxc3_C0(%rip)
	jmp	.Lbinary80_mulxc3_6
.Lbinary80_mulxc3_8:
	fxch	%st(4)
	fabs
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fxch	%st(1)
	fucomip	%st(1), %st
	ja	.Lbinary80_mulxc3_102
	fxch	%st(3)
	fabs
	fucomip	%st(3), %st
	ja	.Lbinary80_mulxc3_103
	fxch	%st(1)
	fabs
	fucomip	%st(2), %st
	fstp	%st(1)
	ja	.Lbinary80_mulxc3_104
	fldt	-72(%rsp)
	fabs
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fxch	%st(1)
	fucomip	%st(1), %st
	fstp	%st(0)
	jbe	.Lbinary80_mulxc3_105
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_22
.Lbinary80_mulxc3_102:
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_22
.Lbinary80_mulxc3_103:
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_mulxc3_22
.Lbinary80_mulxc3_104:
	fstp	%st(0)
	fstp	%st(0)
.Lbinary80_mulxc3_22:
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_93
.Lbinary80_mulxc3_26:
	fldt	24(%rsp)
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_94
	fstp	%st(0)
.Lbinary80_mulxc3_28:
	fldt	40(%rsp)
	fucomi	%st(0), %st
	jp	.Lbinary80_mulxc3_95
	fstp	%st(0)
.Lbinary80_mulxc3_30:
	fldt	56(%rsp)
	fucomi	%st(0), %st
	flds	.Lbinary80_mulxc3_C0(%rip)
	jnp	.Lbinary80_mulxc3_106
	fstp	%st(0)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_32
	fstp	%st(0)
	fldz
	fchs
.Lbinary80_mulxc3_32:
	fstpt	56(%rsp)
.Lbinary80_mulxc3_87:
	flds	.Lbinary80_mulxc3_C0(%rip)
	fxch	%st(1)
	jmp	.Lbinary80_mulxc3_15
.Lbinary80_mulxc3_91:
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_21
	fstp	%st(0)
	fldz
	fchs
.Lbinary80_mulxc3_21:
	fstpt	24(%rsp)
	jmp	.Lbinary80_mulxc3_15
.Lbinary80_mulxc3_90:
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_19
	fstp	%st(0)
	fldz
	fchs
	jmp	.Lbinary80_mulxc3_19
.Lbinary80_mulxc3_13:
	fstp	%st(0)
	fldt	56(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_16
	fstp	%st(0)
	fldz
	fchs
.Lbinary80_mulxc3_16:
	fstpt	56(%rsp)
	fldt	.Lbinary80_mulxc3_C3(%rip)
	fxch	%st(1)
	fucomip	%st(1), %st
	fstp	%st(0)
	jbe	.Lbinary80_mulxc3_87
	xorl	%eax, %eax
	fld1
	xorl	%edx, %edx
	flds	.Lbinary80_mulxc3_C0(%rip)
	movq	%rax, -56(%rsp)
	movl	%edx, -48(%rsp)
	jmp	.Lbinary80_mulxc3_6
.Lbinary80_mulxc3_92:
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_12
	fstp	%st(0)
	fldz
	fchs
.Lbinary80_mulxc3_12:
	fstpt	40(%rsp)
	jmp	.Lbinary80_mulxc3_11
.Lbinary80_mulxc3_95:
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_31
	fstp	%st(0)
	fldz
	fchs
.Lbinary80_mulxc3_31:
	fstpt	40(%rsp)
	jmp	.Lbinary80_mulxc3_30
.Lbinary80_mulxc3_94:
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_29
	fstp	%st(0)
	fldz
	fchs
.Lbinary80_mulxc3_29:
	fstpt	24(%rsp)
	jmp	.Lbinary80_mulxc3_28
.Lbinary80_mulxc3_93:
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fldz
	testb	$2, %ah
	je	.Lbinary80_mulxc3_26
	fstp	%st(0)
	fldz
	fchs
	jmp	.Lbinary80_mulxc3_26
	.size	__mulxc3, .-__mulxc3
	.section	.rodata.cst4,"aM",@progbits,4
	.align 4
.Lbinary80_mulxc3_C0:
	.long	2139095040
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.Lbinary80_mulxc3_C3:
	.long	-1
	.long	-1
	.long	32766
	.long	0

/* LLVM 22.1.3 divxc3.c */
	.text
	.section	.text.__divxc3,"ax",@progbits
	.p2align 4
	.globl	__divxc3
	.type	__divxc3, @function
__divxc3:
	pushq	%rbx
	subq	$112, %rsp
	fldt	160(%rsp)
	fabs
	fstpt	16(%rsp)
	fldt	176(%rsp)
	fabs
	fstpt	(%rsp)
	call	__crabc_binary80_fmaxl@PLT
	popq	%rax
	popq	%rdx
	fstpt	(%rsp)
	call	__crabc_binary80_logbl@PLT
	fld	%st(0)
	fstpt	48(%rsp)
	fabs
	fld	%st(0)
	fstpt	64(%rsp)
	fldt	.Lbinary80_divxc3_C0(%rip)
	popq	%rcx
	popq	%rsi
	fucomip	%st(1), %st
	fstp	%st(0)
	jnb	.Lbinary80_divxc3_45
	xorl	%ebx, %ebx
.Lbinary80_divxc3_2:
	fldt	144(%rsp)
	subq	$16, %rsp
	movl	%ebx, %edi
	fmul	%st(0), %st
	fldt	144(%rsp)
	fld	%st(0)
	fmul	%st(0), %st
	faddp	%st, %st(2)
	fldt	112(%rsp)
	fmulp	%st, %st(1)
	fldt	160(%rsp)
	fldt	128(%rsp)
	fmulp	%st, %st(1)
	faddp	%st, %st(1)
	fxch	%st(1)
	fld	%st(0)
	fstpt	16(%rsp)
	fdivrp	%st, %st(1)
	fstpt	(%rsp)
	call	__crabc_binary80_scalbnl@PLT
	subq	$16, %rsp
	movl	%ebx, %edi
	fstpt	48(%rsp)
	fldt	160(%rsp)
	fldt	144(%rsp)
	fmulp	%st, %st(1)
	fldt	176(%rsp)
	fldt	128(%rsp)
	fmulp	%st, %st(1)
	fsubrp	%st, %st(1)
	fldt	32(%rsp)
	fdivrp	%st, %st(1)
	fstpt	(%rsp)
	call	__crabc_binary80_scalbnl@PLT
	fldt	48(%rsp)
	addq	$32, %rsp
	fld	%st(1)
	fucomip	%st(0), %st
	jnp	.Lbinary80_divxc3_1
	fucomi	%st(0), %st
	jp	.Lbinary80_divxc3_46
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_48:
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_49:
	fstp	%st(0)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_53:
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_54:
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_55:
	fstp	%st(0)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_56:
	fstp	%st(0)
.Lbinary80_divxc3_1:
	addq	$80, %rsp
	popq	%rbx
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_divxc3_45:
	fnstcw	78(%rsp)
	fldt	32(%rsp)
	movzwl	78(%rsp), %eax
	orb	$12, %ah
	movw	%ax, 76(%rsp)
	fldcw	76(%rsp)
	fistpl	(%rsp)
	fldcw	78(%rsp)
	movl	(%rsp), %ebx
	pushq	136(%rsp)
	pushq	136(%rsp)
	negl	%ebx
	movl	%ebx, %edi
	call	__crabc_binary80_scalbnl@PLT
	movl	%ebx, %edi
	fstpt	144(%rsp)
	pushq	168(%rsp)
	pushq	168(%rsp)
	call	__crabc_binary80_scalbnl@PLT
	fstpt	176(%rsp)
	addq	$32, %rsp
	jmp	.Lbinary80_divxc3_2
.Lbinary80_divxc3_46:
	fldz
	fldt	(%rsp)
	fucomip	%st(1), %st
	fstp	%st(0)
	jp	.Lbinary80_divxc3_4
	jne	.Lbinary80_divxc3_4
	fldt	96(%rsp)
	fucomip	%st(0), %st
	jnp	.Lbinary80_divxc3_47
	fldt	112(%rsp)
	fucomip	%st(0), %st
	jp	.Lbinary80_divxc3_1
	fstp	%st(0)
	fstp	%st(0)
	jmp	.Lbinary80_divxc3_18
.Lbinary80_divxc3_47:
	fstp	%st(0)
	fstp	%st(0)
.Lbinary80_divxc3_18:
	fldt	128(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	flds	.Lbinary80_divxc3_C2(%rip)
	testb	$2, %ah
	je	.Lbinary80_divxc3_7
	fstp	%st(0)
	flds	.Lbinary80_divxc3_C3(%rip)
.Lbinary80_divxc3_7:
	fldt	96(%rsp)
	fmul	%st(1), %st
	fldt	112(%rsp)
	fmulp	%st, %st(2)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_4:
	fldt	96(%rsp)
	fabs
	fldt	.Lbinary80_divxc3_C0(%rip)
	fxch	%st(1)
	fucomi	%st(1), %st
	jbe	.Lbinary80_divxc3_8
	fldt	128(%rsp)
	fabs
	fxch	%st(2)
	fucomi	%st(2), %st
	fstp	%st(2)
	jb	.Lbinary80_divxc3_48
	fldt	144(%rsp)
	fabs
	fxch	%st(2)
	fucomip	%st(2), %st
	fstp	%st(1)
	jb	.Lbinary80_divxc3_49
	fstp	%st(1)
	fstp	%st(1)
	jmp	.Lbinary80_divxc3_9
.Lbinary80_divxc3_52:
	fstp	%st(1)
	fstp	%st(1)
.Lbinary80_divxc3_9:
	fldt	.Lbinary80_divxc3_C0(%rip)
	fxch	%st(1)
	xorl	%eax, %eax
	fucomip	%st(1), %st
	seta	%al
	movl	%eax, (%rsp)
	fildl	(%rsp)
	fldt	96(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fabs
	testb	$2, %ah
	fld	%st(0)
	fchs
	fcmove	%st(1), %st
	fstp	%st(1)
	xorl	%eax, %eax
	fldt	112(%rsp)
	fabs
	fucomip	%st(2), %st
	fstp	%st(1)
	seta	%al
	movl	%eax, (%rsp)
	fildl	(%rsp)
	fldt	112(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fabs
	testb	$2, %ah
	fld	%st(0)
	fchs
	fcmove	%st(1), %st
	fstp	%st(1)
	fldt	128(%rsp)
	fmul	%st(2), %st
	fldt	144(%rsp)
	fmul	%st(2), %st
	faddp	%st, %st(1)
	flds	.Lbinary80_divxc3_C2(%rip)
	fldt	128(%rsp)
	fmulp	%st, %st(3)
	fldt	144(%rsp)
	fmulp	%st, %st(4)
	fxch	%st(2)
	fsubp	%st, %st(3)
	fmul	%st(1), %st
	fxch	%st(2)
	fmulp	%st, %st(1)
	fxch	%st(1)
	jmp	.Lbinary80_divxc3_1
.Lbinary80_divxc3_8:
	fldt	112(%rsp)
	fabs
	fucomip	%st(2), %st
	jbe	.Lbinary80_divxc3_50
	fldt	128(%rsp)
	fabs
	fxch	%st(2)
	fucomi	%st(2), %st
	fstp	%st(2)
	jb	.Lbinary80_divxc3_51
	fldt	144(%rsp)
	fabs
	fxch	%st(2)
	fucomip	%st(2), %st
	fstp	%st(1)
	jnb	.Lbinary80_divxc3_52
	jmp	.Lbinary80_divxc3_10
.Lbinary80_divxc3_50:
	fstp	%st(1)
	jmp	.Lbinary80_divxc3_10
.Lbinary80_divxc3_51:
	fstp	%st(1)
.Lbinary80_divxc3_10:
	fldt	.Lbinary80_divxc3_C0(%rip)
	fldt	48(%rsp)
	fucomip	%st(1), %st
	jbe	.Lbinary80_divxc3_53
	fldz
	fldt	32(%rsp)
	fcomip	%st(1), %st
	fstp	%st(0)
	jbe	.Lbinary80_divxc3_54
	fucomi	%st(1), %st
	fstp	%st(1)
	jb	.Lbinary80_divxc3_55
	fldt	112(%rsp)
	fabs
	fxch	%st(1)
	fucomi	%st(1), %st
	fstp	%st(1)
	jb	.Lbinary80_divxc3_56
	fstp	%st(1)
	fstp	%st(1)
	fldt	128(%rsp)
	xorl	%eax, %eax
	fabs
	fucomip	%st(1), %st
	fstp	%st(0)
	seta	%al
	movl	%eax, (%rsp)
	fildl	(%rsp)
	fldt	128(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fabs
	testb	$2, %ah
	je	.Lbinary80_divxc3_14
	fchs
.Lbinary80_divxc3_14:
	fldt	144(%rsp)
	xorl	%eax, %eax
	fabs
	fldt	.Lbinary80_divxc3_C0(%rip)
	fxch	%st(1)
	fucomip	%st(1), %st
	fstp	%st(0)
	seta	%al
	movl	%eax, (%rsp)
	fildl	(%rsp)
	fldt	144(%rsp)
	fxam
	fnstsw	%ax
	fstp	%st(0)
	fabs
	testb	$2, %ah
	je	.Lbinary80_divxc3_15
	fchs
.Lbinary80_divxc3_15:
	fldt	96(%rsp)
	fmul	%st(2), %st
	fldt	112(%rsp)
	fmul	%st(2), %st
	faddp	%st, %st(1)
	fldz
	fldt	112(%rsp)
	fmulp	%st, %st(4)
	fldt	96(%rsp)
	fmulp	%st, %st(3)
	fxch	%st(2)
	fsubrp	%st, %st(3)
	fmul	%st(1), %st
	fxch	%st(1)
	fmulp	%st, %st(2)
	jmp	.Lbinary80_divxc3_1
	.size	__divxc3, .-__divxc3
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.Lbinary80_divxc3_C0:
	.long	-1
	.long	-1
	.long	32766
	.long	0
	.section	.rodata.cst4,"aM",@progbits,4
	.align 4
.Lbinary80_divxc3_C2:
	.long	2139095040
	.align 4
.Lbinary80_divxc3_C3:
	.long	-8388608

/* musl 1.2.6 fmaxl.c */
	.text
	.section	.text.fmaxl,"ax",@progbits
	.p2align 4
.local __crabc_binary80_fmaxl
	.type	__crabc_binary80_fmaxl, @function
__crabc_binary80_fmaxl:
	pushq	%rbx
	pushq	24(%rsp)
	pushq	24(%rsp)
	call	__crabc_binary80___fpclassifyl@PLT
	popq	%r8
	popq	%r9
	testl	%eax, %eax
	jne	.Lbinary80_fmaxl_2
.Lbinary80_fmaxl_6:
	fldt	32(%rsp)
	popq	%rbx
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_fmaxl_2:
	pushq	40(%rsp)
	pushq	40(%rsp)
	call	__crabc_binary80___fpclassifyl@PLT
	popq	%rsi
	popq	%rdi
	testl	%eax, %eax
	je	.Lbinary80_fmaxl_4
	pushq	24(%rsp)
	pushq	24(%rsp)
	call	__crabc_binary80___signbitl@PLT
	pushq	56(%rsp)
	pushq	56(%rsp)
	movl	%eax, %ebx
	call	__crabc_binary80___signbitl@PLT
	addq	$32, %rsp
	cmpl	%eax, %ebx
	jne	.Lbinary80_fmaxl_14
	fldt	16(%rsp)
	fldt	32(%rsp)
	popq	%rbx
	fcomi	%st(1), %st
	fcmovbe	%st(1), %st
	fstp	%st(1)
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_fmaxl_14:
	pushq	24(%rsp)
	pushq	24(%rsp)
	call	__crabc_binary80___signbitl@PLT
	popq	%rdx
	popq	%rcx
	testl	%eax, %eax
	jne	.Lbinary80_fmaxl_6
.Lbinary80_fmaxl_4:
	fldt	16(%rsp)
	popq	%rbx
	ret
	.size	__crabc_binary80_fmaxl, .-__crabc_binary80_fmaxl

/* musl 1.2.6 logbl.c */
	.text
	.section	.text.logbl,"ax",@progbits
	.p2align 4
.local __crabc_binary80_logbl
	.type	__crabc_binary80_logbl, @function
__crabc_binary80_logbl:
	subq	$40, %rsp
	fldt	48(%rsp)
	fstpt	(%rsp)
	call	__crabc_binary80___fpclassifyl@PLT
	popq	%rcx
	popq	%rsi
	fldt	32(%rsp)
	cmpl	$1, %eax
	jle	.Lbinary80_logbl_9
	fldz
	fxch	%st(1)
	fucomi	%st(1), %st
	fstp	%st(1)
	jp	.Lbinary80_logbl_4
	jne	.Lbinary80_logbl_4
	fmul	%st(0), %st
	addq	$24, %rsp
	fld1
	fchs
	fdivp	%st, %st(1)
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_logbl_4:
	subq	$16, %rsp
	fstpt	(%rsp)
	call	__crabc_binary80_ilogbl@PLT
	movl	%eax, 28(%rsp)
	fildl	28(%rsp)
	popq	%rax
	popq	%rdx
	addq	$24, %rsp
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_logbl_9:
	fmul	%st(0), %st
	addq	$24, %rsp
	ret
	.size	__crabc_binary80_logbl, .-__crabc_binary80_logbl

/* musl 1.2.6 ilogbl.c */
	.text
	.section	.text.ilogbl,"ax",@progbits
	.p2align 4
.local __crabc_binary80_ilogbl
	.type	__crabc_binary80_ilogbl, @function
__crabc_binary80_ilogbl:
	movzwl	16(%rsp), %ecx
	movq	8(%rsp), %rdx
	andw	$32767, %cx
	jne	.Lbinary80_ilogbl_2
	testq	%rdx, %rdx
	je	.Lbinary80_ilogbl_3
	movl	$-16382, %eax
	js	.Lbinary80_ilogbl_11
	.p2align 3
	.p2align 4
	.p2align 3
.Lbinary80_ilogbl_4:
	subl	$1, %eax
	addq	%rdx, %rdx
	jns	.Lbinary80_ilogbl_4
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_ilogbl_2:
	movzwl	%cx, %eax
	subl	$16383, %eax
	cmpw	$32767, %cx
	je	.Lbinary80_ilogbl_12
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_ilogbl_12:
	pxor	%xmm0, %xmm0
	xorl	%eax, %eax
	addq	%rdx, %rdx
	divss	%xmm0, %xmm0
	setne	%al
	negl	%eax
	xorl	$2147483647, %eax
	movss	%xmm0, -12(%rsp)
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_ilogbl_11:
	ret
.Lbinary80_ilogbl_3:
	pxor	%xmm0, %xmm0
	movl	$-2147483648, %eax
	divss	%xmm0, %xmm0
	movss	%xmm0, -16(%rsp)
	ret
	.size	__crabc_binary80_ilogbl, .-__crabc_binary80_ilogbl

/* musl 1.2.6 scalbnl.c */
	.text
	.section	.text.scalbnl,"ax",@progbits
	.p2align 4
.local __crabc_binary80_scalbnl
	.type	__crabc_binary80_scalbnl, @function
__crabc_binary80_scalbnl:
	fldt	8(%rsp)
	cmpl	$16383, %edi
	jle	.Lbinary80_scalbnl_2
	leal	-16383(%rdi), %eax
	fldt	.Lbinary80_scalbnl_C0(%rip)
	fmul	%st, %st(1)
	cmpl	$16383, %eax
	jle	.Lbinary80_scalbnl_6
	leal	-32766(%rdi), %eax
	fmulp	%st, %st(1)
	movl	$16383, %edx
	cmpl	%edx, %eax
	cmovg	%edx, %eax
	jmp	.Lbinary80_scalbnl_3
	.p2align 4,,10
	.p2align 3
.Lbinary80_scalbnl_6:
	fstp	%st(0)
	jmp	.Lbinary80_scalbnl_3
	.p2align 4,,10
	.p2align 3
.Lbinary80_scalbnl_7:
	fstp	%st(0)
.Lbinary80_scalbnl_3:
	fld1
	addw	$16383, %ax
	fstpt	-24(%rsp)
	movw	%ax, -16(%rsp)
	fldt	-24(%rsp)
	fmulp	%st, %st(1)
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80_scalbnl_2:
	movl	%edi, %eax
	cmpl	$-16382, %edi
	jge	.Lbinary80_scalbnl_3
	fldt	.Lbinary80_scalbnl_C1(%rip)
	addl	$16269, %eax
	fmul	%st, %st(1)
	cmpl	$-16382, %eax
	jge	.Lbinary80_scalbnl_7
	leal	32538(%rdi), %eax
	fmulp	%st, %st(1)
	movl	$-16382, %edx
	cmpl	%edx, %eax
	cmovl	%edx, %eax
	jmp	.Lbinary80_scalbnl_3
	.size	__crabc_binary80_scalbnl, .-__crabc_binary80_scalbnl
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.Lbinary80_scalbnl_C0:
	.long	0
	.long	-2147483648
	.long	32766
	.long	0
	.align 16
.Lbinary80_scalbnl_C1:
	.long	0
	.long	-2147483648
	.long	114
	.long	0

/* musl 1.2.6 __fpclassifyl.c */
	.text
	.section	.text.__fpclassifyl,"ax",@progbits
	.p2align 4
.local __crabc_binary80___fpclassifyl
	.type	__crabc_binary80___fpclassifyl, @function
__crabc_binary80___fpclassifyl:
	movq	8(%rsp), %rcx
	movq	16(%rsp), %rax
	movq	%rcx, %rdx
	movl	%eax, %esi
	andl	$32767, %eax
	shrq	$63, %rdx
	andw	$32767, %si
	orl	%edx, %eax
	je	.Lbinary80___fpclassifyl_9
	leal	0(,%rdx,4), %eax
	cmpw	$32767, %si
	je	.Lbinary80___fpclassifyl_10
.Lbinary80___fpclassifyl_1:
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80___fpclassifyl_10:
	xorl	%eax, %eax
	testq	%rdx, %rdx
	je	.Lbinary80___fpclassifyl_1
	xorl	%eax, %eax
	addq	%rcx, %rcx
	sete	%al
	ret
	.p2align 4,,10
	.p2align 3
.Lbinary80___fpclassifyl_9:
	cmpq	$1, %rcx
	movl	$2, %eax
	sbbl	$-1, %eax
	ret
	.size	__crabc_binary80___fpclassifyl, .-__crabc_binary80___fpclassifyl

/* musl 1.2.6 __signbitl.c */
	.text
	.section	.text.__signbitl,"ax",@progbits
	.p2align 4
.local __crabc_binary80___signbitl
	.type	__crabc_binary80___signbitl, @function
__crabc_binary80___signbitl:
	movzwl	16(%rsp), %eax
	shrw	$15, %ax
	movzwl	%ax, %eax
	ret
	.size	__crabc_binary80___signbitl, .-__crabc_binary80___signbitl

.section .note.GNU-stack,"",@progbits

"#, options(att_syntax));
