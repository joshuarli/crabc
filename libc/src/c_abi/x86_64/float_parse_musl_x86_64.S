/*
 * Fixed musl 1.2.6 x86-64 src/internal/floatscan.c assembly
 * translation. See float_parse.rs for source, pin, license, compiler-codegen
 * provenance, and the intentional boundary. This is an owned source
 * translation, not a linked foreign object.
 */
	.text
	.section	.text.crabc_x86_float_parse_scanexp,"ax",@progbits
	.type	crabc_x86_float_parse_scanexp, @function
crabc_x86_float_parse_scanexp:
	pushq	%r13
	pushq	%r12
	movq	%rdi, %r12
	pushq	%rbp
	pushq	%rbx
	subq	$24, %rsp
	movq	8(%rdi), %rax
	cmpq	184(%rdi), %rax
	je	.Lcrabc_x86_float_parse_scan_2
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rdi)
	movzbl	(%rax), %edx
.Lcrabc_x86_float_parse_scan_3:
	leal	-43(%rdx), %eax
	andl	$-3, %eax
	jne	.Lcrabc_x86_float_parse_scan_4
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_5
	leaq	1(%rax), %rcx
	movq	%rcx, 8(%r12)
	movzbl	(%rax), %ecx
.Lcrabc_x86_float_parse_scan_6:
	leal	-48(%rcx), %eax
	cmpl	$9, %eax
	ja	.Lcrabc_x86_float_parse_scan_7
	xorl	%ebp, %ebp
	cmpl	$45, %edx
	movslq	%ecx, %rdx
	sete	%bpl
	jmp	.Lcrabc_x86_float_parse_scan_8
.Lcrabc_x86_float_parse_scan_2:
	movl	%esi, 8(%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	8(%rsp), %esi
	movslq	%eax, %rdx
	jmp	.Lcrabc_x86_float_parse_scan_3
.Lcrabc_x86_float_parse_scan_5:
	movq	%r12, %rdi
	movl	%esi, 12(%rsp)
	movl	%edx, 8(%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	12(%rsp), %esi
	movl	8(%rsp), %edx
	movl	%eax, %ecx
	jmp	.Lcrabc_x86_float_parse_scan_6
.Lcrabc_x86_float_parse_scan_7:
	testl	%esi, %esi
	je	.Lcrabc_x86_float_parse_scan_9
	cmpq	$0, 192(%r12)
	js	.Lcrabc_x86_float_parse_scan_11
	movq	8(%r12), %rax
	subq	$1, %rax
.Lcrabc_x86_float_parse_scan_12:
	subq	$1, %rax
	movq	%rax, 8(%r12)
.Lcrabc_x86_float_parse_scan_11:
	movabsq	$-9223372036854775808, %rbx
	jmp	.Lcrabc_x86_float_parse_scan_1
.Lcrabc_x86_float_parse_scan_4:
	leal	-48(%rdx), %eax
	cmpl	$9, %eax
	ja	.Lcrabc_x86_float_parse_scan_9
	xorl	%ebp, %ebp
.Lcrabc_x86_float_parse_scan_8:
	xorl	%ebx, %ebx
	jmp	.Lcrabc_x86_float_parse_scan_13
.Lcrabc_x86_float_parse_scan_9:
	cmpq	$0, 192(%r12)
	js	.Lcrabc_x86_float_parse_scan_11
	movq	8(%r12), %rax
	jmp	.Lcrabc_x86_float_parse_scan_12
.Lcrabc_x86_float_parse_scan_16:
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shgetc
	movslq	%eax, %rdx
.Lcrabc_x86_float_parse_scan_17:
	leal	-48(%rdx), %eax
.Lcrabc_x86_float_parse_scan_13:
	cmpl	$9, %eax
	ja	.Lcrabc_x86_float_parse_scan_30
	cmpl	$214748363, %ebx
	jg	.Lcrabc_x86_float_parse_scan_30
	leal	(%rbx,%rbx,4), %eax
	leal	-48(%rdx,%rax,2), %ebx
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_16
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%r12)
	movzbl	(%rax), %edx
	jmp	.Lcrabc_x86_float_parse_scan_17
.Lcrabc_x86_float_parse_scan_30:
	movabsq	$92233720368547757, %r13
	movslq	%ebx, %rbx
	jmp	.Lcrabc_x86_float_parse_scan_20
.Lcrabc_x86_float_parse_scan_21:
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shgetc
	movslq	%eax, %rdx
.Lcrabc_x86_float_parse_scan_22:
	leal	-48(%rdx), %eax
.Lcrabc_x86_float_parse_scan_20:
	cmpl	$9, %eax
	ja	.Lcrabc_x86_float_parse_scan_43
	cmpq	%r13, %rbx
	jg	.Lcrabc_x86_float_parse_scan_25
	leaq	(%rbx,%rbx,4), %rax
	leaq	-48(%rdx,%rax,2), %rbx
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_21
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%r12)
	movzbl	(%rax), %edx
	jmp	.Lcrabc_x86_float_parse_scan_22
.Lcrabc_x86_float_parse_scan_26:
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shgetc
	movl	%eax, %edx
.Lcrabc_x86_float_parse_scan_27:
	leal	-48(%rdx), %eax
.Lcrabc_x86_float_parse_scan_25:
	cmpl	$9, %eax
	ja	.Lcrabc_x86_float_parse_scan_43
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_26
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%r12)
	movzbl	(%rax), %edx
	jmp	.Lcrabc_x86_float_parse_scan_27
.Lcrabc_x86_float_parse_scan_43:
	cmpq	$0, 192(%r12)
	js	.Lcrabc_x86_float_parse_scan_29
	subq	$1, 8(%r12)
.Lcrabc_x86_float_parse_scan_29:
	movq	%rbx, %rax
	negq	%rax
	testl	%ebp, %ebp
	cmovne	%rax, %rbx
.Lcrabc_x86_float_parse_scan_1:
	addq	$24, %rsp
	movq	%rbx, %rax
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	ret
	.size	crabc_x86_float_parse_scanexp, .-crabc_x86_float_parse_scanexp
	.section	.text.crabc_x86_float_parse_decfloat,"ax",@progbits
	.type	crabc_x86_float_parse_decfloat, @function
crabc_x86_float_parse_decfloat:
	pushq	%r15
	movl	%esi, %eax
	pushq	%r14
	pushq	%r13
	xorl	%r13d, %r13d
	pushq	%r12
	movq	%rdi, %r12
	pushq	%rbp
	pushq	%rbx
	subq	$8280, %rsp
	movl	%edx, 68(%rsp)
	movl	%ecx, 32(%rsp)
	movl	%r8d, 16(%rsp)
	movl	%r9d, 48(%rsp)
	jmp	.Lcrabc_x86_float_parse_scan_47
.Lcrabc_x86_float_parse_scan_48:
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shgetc
.Lcrabc_x86_float_parse_scan_49:
	movl	$1, %r13d
.Lcrabc_x86_float_parse_scan_47:
	cmpl	$48, %eax
	jne	.Lcrabc_x86_float_parse_scan_218
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_48
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%r12)
	movzbl	(%rax), %eax
	jmp	.Lcrabc_x86_float_parse_scan_49
.Lcrabc_x86_float_parse_scan_218:
	xorl	%esi, %esi
	xorl	%ebx, %ebx
	cmpl	$46, %eax
	je	.Lcrabc_x86_float_parse_scan_219
.Lcrabc_x86_float_parse_scan_51:
	movl	$0, 80(%rsp)
	xorl	%r8d, %r8d
	xorl	%r15d, %r15d
	xorl	%ebp, %ebp
	xorl	%r14d, %r14d
	jmp	.Lcrabc_x86_float_parse_scan_58
.Lcrabc_x86_float_parse_scan_219:
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_52
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%r12)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_53:
	xorl	%ebx, %ebx
	jmp	.Lcrabc_x86_float_parse_scan_54
.Lcrabc_x86_float_parse_scan_52:
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shgetc
	jmp	.Lcrabc_x86_float_parse_scan_53
.Lcrabc_x86_float_parse_scan_55:
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shgetc
.Lcrabc_x86_float_parse_scan_56:
	movl	$1, %r13d
.Lcrabc_x86_float_parse_scan_54:
	cmpl	$48, %eax
	jne	.Lcrabc_x86_float_parse_scan_220
	movq	8(%r12), %rax
	subq	$1, %rbx
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_55
	leaq	1(%rax), %rcx
	movq	%rcx, 8(%r12)
	movzbl	(%rax), %eax
	jmp	.Lcrabc_x86_float_parse_scan_56
.Lcrabc_x86_float_parse_scan_220:
	movl	$1, %esi
	jmp	.Lcrabc_x86_float_parse_scan_51
.Lcrabc_x86_float_parse_scan_68:
	cmpl	$46, %eax
	je	.Lcrabc_x86_float_parse_scan_212
	addq	$1, %r15
	cmpl	$2044, %r14d
	jg	.Lcrabc_x86_float_parse_scan_62
	cmpl	$48, %eax
	movslq	%r14d, %rax
	cmovne	%r15d, %r8d
	testl	%ebp, %ebp
	je	.Lcrabc_x86_float_parse_scan_64
	movl	80(%rsp,%rax,4), %ecx
	addl	$1, %ebp
	movl	$1, %r13d
	leal	(%rcx,%rcx,4), %ecx
	leal	(%rdi,%rcx,2), %ecx
	movl	%ecx, 80(%rsp,%rax,4)
	cmpl	$9, %ebp
	jne	.Lcrabc_x86_float_parse_scan_61
	addl	$1, %r14d
	movl	$1, %r13d
	xorl	%ebp, %ebp
	jmp	.Lcrabc_x86_float_parse_scan_61
.Lcrabc_x86_float_parse_scan_64:
	movl	%edi, 80(%rsp,%rax,4)
	movl	$1, %r13d
	movl	$1, %ebp
	jmp	.Lcrabc_x86_float_parse_scan_61
.Lcrabc_x86_float_parse_scan_62:
	cmpl	$48, %eax
	je	.Lcrabc_x86_float_parse_scan_61
	orl	$1, 8256(%rsp)
	movl	$18396, %r8d
.Lcrabc_x86_float_parse_scan_61:
	movq	8(%r12), %rax
	cmpq	184(%r12), %rax
	je	.Lcrabc_x86_float_parse_scan_66
	leaq	1(%rax), %rdi
	movq	%rdi, 8(%r12)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_58:
	leal	-48(%rax), %edi
	cmpl	$9, %edi
	jbe	.Lcrabc_x86_float_parse_scan_68
	cmpl	$46, %eax
	jne	.Lcrabc_x86_float_parse_scan_221
.Lcrabc_x86_float_parse_scan_212:
	testl	%esi, %esi
	jne	.Lcrabc_x86_float_parse_scan_60
	movq	%r15, %rbx
	movl	$1, %esi
	jmp	.Lcrabc_x86_float_parse_scan_61
.Lcrabc_x86_float_parse_scan_66:
	movq	%r12, %rdi
	movl	%esi, 64(%rsp)
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	64(%rsp), %esi
	movl	(%rsp), %r8d
	jmp	.Lcrabc_x86_float_parse_scan_58
.Lcrabc_x86_float_parse_scan_221:
	testl	%esi, %esi
	cmove	%r15, %rbx
	testl	%r13d, %r13d
	je	.Lcrabc_x86_float_parse_scan_70
	movl	%eax, %ecx
	orl	$32, %ecx
	cmpl	$101, %ecx
	je	.Lcrabc_x86_float_parse_scan_222
	testl	%eax, %eax
	js	.Lcrabc_x86_float_parse_scan_77
.Lcrabc_x86_float_parse_scan_173:
	cmpq	$0, 192(%r12)
	js	.Lcrabc_x86_float_parse_scan_77
	subq	$1, 8(%r12)
.Lcrabc_x86_float_parse_scan_77:
	movl	80(%rsp), %eax
	testl	%eax, %eax
	je	.Lcrabc_x86_float_parse_scan_223
	cmpq	%rbx, %r15
	jne	.Lcrabc_x86_float_parse_scan_84
	cmpq	$9, %r15
	jg	.Lcrabc_x86_float_parse_scan_84
	movl	68(%rsp), %esi
	cmpl	$30, %esi
	jg	.Lcrabc_x86_float_parse_scan_217
	movl	%eax, %edi
	movl	%esi, %ecx
	shrl	%cl, %edi
	testl	%edi, %edi
	je	.Lcrabc_x86_float_parse_scan_217
.Lcrabc_x86_float_parse_scan_84:
	movl	32(%rsp), %esi
	movl	%esi, %eax
	shrl	$31, %eax
	addl	%esi, %eax
	sarl	%eax
	negl	%eax
	cltq
	cmpq	%rbx, %rax
	jl	.Lcrabc_x86_float_parse_scan_224
	movl	32(%rsp), %eax
	addl	$-128, %eax
	cltq
	cmpq	%rbx, %rax
	jg	.Lcrabc_x86_float_parse_scan_225
	movslq	%r14d, %rcx
	testl	%ebp, %ebp
	jne	.Lcrabc_x86_float_parse_scan_88
.Lcrabc_x86_float_parse_scan_89:
	movl	$8, %eax
	movl	%ebx, %r11d
	cmpl	%eax, %ebx
	cmovle	%ebx, %eax
	cmpl	%eax, %r8d
	jg	.Lcrabc_x86_float_parse_scan_91
	cmpl	$17, %ebx
	jle	.Lcrabc_x86_float_parse_scan_226
.Lcrabc_x86_float_parse_scan_91:
	movl	32(%rsp), %eax
	leal	-1(%r14), %edx
	leaq	80(%rsp), %rdi
	negl	%eax
	subl	68(%rsp), %eax
	movl	%eax, 64(%rsp)
	movslq	%edx, %rax
	leaq	(%rdi,%rax,4), %rax
	.p2align 5
.Lcrabc_x86_float_parse_scan_95:
	movl	(%rax), %r8d
	movl	%r14d, %r9d
	subq	$4, %rax
	movl	%edx, %r14d
	testl	%r8d, %r8d
	jne	.Lcrabc_x86_float_parse_scan_213
	subl	$1, %edx
	jmp	.Lcrabc_x86_float_parse_scan_95
.Lcrabc_x86_float_parse_scan_222:
	movl	48(%rsp), %esi
	movq	%r12, %rdi
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_scanexp
	movl	(%rsp), %r8d
	movabsq	$-9223372036854775808, %rcx
	cmpq	%rcx, %rax
	je	.Lcrabc_x86_float_parse_scan_227
	addq	%rax, %rbx
	jmp	.Lcrabc_x86_float_parse_scan_77
.Lcrabc_x86_float_parse_scan_227:
	movl	48(%rsp), %r9d
	testl	%r9d, %r9d
	jne	.Lcrabc_x86_float_parse_scan_173
	jmp	.Lcrabc_x86_float_parse_scan_215
.Lcrabc_x86_float_parse_scan_70:
	testl	%eax, %eax
	jns	.Lcrabc_x86_float_parse_scan_144
.Lcrabc_x86_float_parse_scan_80:
	call	__errno_location
	movl	$22, (%rax)
.Lcrabc_x86_float_parse_scan_215:
	xorl	%esi, %esi
	movq	%r12, %rdi
	call	crabc_x86_float_parse_shlim
	fldz
	jmp	.Lcrabc_x86_float_parse_scan_46
.Lcrabc_x86_float_parse_scan_223:
	pxor	%xmm0, %xmm0
	pxor	%xmm1, %xmm1
	cvtsi2sdl	16(%rsp), %xmm1
	mulsd	%xmm0, %xmm1
	movsd	%xmm1, (%rsp)
	fldl	(%rsp)
.Lcrabc_x86_float_parse_scan_46:
	addq	$8280, %rsp
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
.Lcrabc_x86_float_parse_scan_224:
	call	__errno_location
	fildl	16(%rsp)
	movl	$34, (%rax)
	fldt	.Lcrabc_x86_float_parse_scan_C2(%rip)
	fmul	%st, %st(1)
	fmulp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_46
.Lcrabc_x86_float_parse_scan_225:
	call	__errno_location
	fildl	16(%rsp)
	movl	$34, (%rax)
	fldt	.Lcrabc_x86_float_parse_scan_C3(%rip)
	fmul	%st, %st(1)
	fmulp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_46
	.p2align 5
.Lcrabc_x86_float_parse_scan_90:
	movl	80(%rsp,%rcx,4), %eax
	addl	$1, %ebp
	leal	(%rax,%rax,4), %eax
	addl	%eax, %eax
	movl	%eax, 80(%rsp,%rcx,4)
.Lcrabc_x86_float_parse_scan_88:
	cmpl	$8, %ebp
	jle	.Lcrabc_x86_float_parse_scan_90
	addl	$1, %r14d
	jmp	.Lcrabc_x86_float_parse_scan_89
.Lcrabc_x86_float_parse_scan_226:
	movl	80(%rsp), %eax
	cmpl	$9, %ebx
	je	.Lcrabc_x86_float_parse_scan_217
	cmpl	$8, %ebx
	jle	.Lcrabc_x86_float_parse_scan_228
	leal	-9(%rbx), %edx
	movl	68(%rsp), %ebx
	leal	0(,%rdx,4), %ecx
	subl	%ecx, %edx
	leal	(%rdx,%rbx), %ecx
	cmpl	$30, %ecx
	jg	.Lcrabc_x86_float_parse_scan_94
	movl	%eax, %edx
	shrl	%cl, %edx
	testl	%edx, %edx
	jne	.Lcrabc_x86_float_parse_scan_91
.Lcrabc_x86_float_parse_scan_94:
	movq	%rax, (%rsp)
	fildl	16(%rsp)
	leal	-10(%r11), %eax
	leaq	crabc_x86_float_parse_p10s_1(%rip), %rdx
	cltq
	fildq	(%rsp)
	fmulp	%st, %st(1)
	fildl	(%rdx,%rax,4)
	fmulp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_46
.Lcrabc_x86_float_parse_scan_217:
	fildl	16(%rsp)
	movq	%rax, (%rsp)
	fildq	(%rsp)
	fmulp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_46
.Lcrabc_x86_float_parse_scan_228:
	movq	%rax, (%rsp)
	fildl	16(%rsp)
	movl	$8, %eax
	leaq	crabc_x86_float_parse_p10s_1(%rip), %rdx
	subl	%ebx, %eax
	fildq	(%rsp)
	cltq
	fmulp	%st, %st(1)
	fildl	(%rdx,%rax,4)
	fdivrp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_46
.Lcrabc_x86_float_parse_scan_213:
	movslq	%r11d, %rsi
	movl	%r11d, %eax
	imulq	$954437177, %rsi, %rsi
	sarl	$31, %eax
	sarq	$33, %rsi
	subl	%eax, %esi
	leal	(%rsi,%rsi,8), %eax
	movl	%r11d, %esi
	subl	%eax, %esi
	je	.Lcrabc_x86_float_parse_scan_96
	testl	%r11d, %r11d
	leal	9(%rsi), %eax
	leaq	crabc_x86_float_parse_p10s_1(%rip), %rdx
	cmovs	%eax, %esi
	movl	$8, %eax
	xorl	%r8d, %r8d
	xorl	%r14d, %r14d
	xorl	%r10d, %r10d
	subl	%esi, %eax
	cltq
	movl	(%rdx,%rax,4), %r12d
	jmp	.Lcrabc_x86_float_parse_scan_98
	.p2align 6
.Lcrabc_x86_float_parse_scan_99:
	addl	$1, %r10d
	addq	$4, %rdi
.Lcrabc_x86_float_parse_scan_98:
	cmpl	%r9d, %r10d
	je	.Lcrabc_x86_float_parse_scan_229
	movl	(%rdi), %eax
	xorl	%edx, %edx
	divl	%r12d
	leal	(%rax,%r8), %ecx
	movl	%edx, %r13d
	movl	$1000000000, %eax
	xorl	%edx, %edx
	idivl	%r12d
	movl	%ecx, (%rdi)
	imull	%r13d, %eax
	movl	%eax, %r8d
	cmpl	%r14d, %r10d
	jne	.Lcrabc_x86_float_parse_scan_99
	testl	%ecx, %ecx
	jne	.Lcrabc_x86_float_parse_scan_99
	addl	$1, %r14d
	subl	$9, %r11d
	andl	$2047, %r14d
	jmp	.Lcrabc_x86_float_parse_scan_99
.Lcrabc_x86_float_parse_scan_229:
	testl	%r8d, %r8d
	je	.Lcrabc_x86_float_parse_scan_101
	movslq	%r9d, %rax
	addl	$1, %r9d
	movl	%r8d, 80(%rsp,%rax,4)
.Lcrabc_x86_float_parse_scan_101:
	subl	%esi, %r11d
	movl	%r14d, %esi
	addl	$9, %r11d
.Lcrabc_x86_float_parse_scan_96:
	movabsq	$19342813113834067, %r13
	xorl	%r12d, %r12d
	jmp	.Lcrabc_x86_float_parse_scan_102
.Lcrabc_x86_float_parse_scan_103:
	movl	%r10d, %edx
	movl	%ecx, 80(%rsp,%r8,4)
	andl	$2047, %edx
	cmpl	%edi, %edx
	je	.Lcrabc_x86_float_parse_scan_230
	cmpl	%esi, %edi
	je	.Lcrabc_x86_float_parse_scan_105
	subl	$1, %edi
	andl	$2047, %edi
.Lcrabc_x86_float_parse_scan_107:
	movslq	%edi, %r8
	movl	80(%rsp,%r8,4), %ecx
	salq	$29, %rcx
	addq	%rax, %rcx
	xorl	%eax, %eax
	cmpq	$1000000000, %rcx
	jbe	.Lcrabc_x86_float_parse_scan_103
	movq	%rcx, %rdx
	shrq	$9, %rdx
	movq	%rdx, %rax
	mulq	%r13
	shrq	$11, %rdx
	movl	%edx, %eax
	imulq	$1000000000, %rdx, %rdx
	subq	%rdx, %rcx
	jmp	.Lcrabc_x86_float_parse_scan_103
.Lcrabc_x86_float_parse_scan_230:
	cmpl	%esi, %edi
	je	.Lcrabc_x86_float_parse_scan_105
	testq	%rcx, %rcx
	jne	.Lcrabc_x86_float_parse_scan_148
	movl	%edi, %r9d
	subl	$1, %edi
	leal	-1(%rdx), %r10d
	andl	$2047, %edi
	jmp	.Lcrabc_x86_float_parse_scan_107
.Lcrabc_x86_float_parse_scan_148:
	subl	$1, %edi
	andl	$2047, %edi
	jmp	.Lcrabc_x86_float_parse_scan_107
.Lcrabc_x86_float_parse_scan_105:
	testl	%eax, %eax
	jne	.Lcrabc_x86_float_parse_scan_108
	cmpl	$26, %r11d
	jle	.Lcrabc_x86_float_parse_scan_109
.Lcrabc_x86_float_parse_scan_110:
	movslq	%esi, %rax
	cmpl	$17, 80(%rsp,%rax,4)
	ja	.Lcrabc_x86_float_parse_scan_113
.Lcrabc_x86_float_parse_scan_112:
	leal	-1(%r9), %r10d
.Lcrabc_x86_float_parse_scan_109:
	movl	%r10d, %edi
	subl	$29, %r12d
	xorl	%eax, %eax
	andl	$2047, %edi
	jmp	.Lcrabc_x86_float_parse_scan_107
.Lcrabc_x86_float_parse_scan_108:
	subl	$1, %esi
	addl	$9, %r11d
	andl	$2047, %esi
	cmpl	%esi, %r9d
	je	.Lcrabc_x86_float_parse_scan_231
.Lcrabc_x86_float_parse_scan_111:
	movslq	%esi, %rdx
	movl	%eax, 80(%rsp,%rdx,4)
.Lcrabc_x86_float_parse_scan_102:
	cmpl	$26, %r11d
	jle	.Lcrabc_x86_float_parse_scan_112
	cmpl	$27, %r11d
	je	.Lcrabc_x86_float_parse_scan_110
.Lcrabc_x86_float_parse_scan_113:
	leaq	crabc_x86_float_parse_th_0(%rip), %r15
	movl	$1000000000, %ebp
	jmp	.Lcrabc_x86_float_parse_scan_114
.Lcrabc_x86_float_parse_scan_231:
	leal	-1(%rdx), %ecx
	movslq	%edx, %r8
	movl	%edx, %r9d
	andl	$2047, %ecx
	movl	80(%rsp,%rcx,4), %edi
	orl	80(%rsp,%r8,4), %edi
	movl	%edi, 80(%rsp,%rcx,4)
	jmp	.Lcrabc_x86_float_parse_scan_111
.Lcrabc_x86_float_parse_scan_150:
	movl	$1, %eax
.Lcrabc_x86_float_parse_scan_116:
	cmpl	$27, %r11d
	jne	.Lcrabc_x86_float_parse_scan_118
	testb	%al, %al
	jne	.Lcrabc_x86_float_parse_scan_232
.Lcrabc_x86_float_parse_scan_118:
	xorl	%ecx, %ecx
	cmpl	$36, %r11d
	movl	$1, %r13d
	movl	%ebp, %r14d
	setg	%cl
	movl	%esi, %eax
	xorl	%r10d, %r10d
	leal	1(,%rcx,8), %ecx
	sall	%cl, %r13d
	addl	%ecx, %r12d
	sarl	%cl, %r14d
	subl	$1, %r13d
	jmp	.Lcrabc_x86_float_parse_scan_121
.Lcrabc_x86_float_parse_scan_232:
	movl	%esi, %edx
	fldz
	leal	3(%rsi), %r14d
	jmp	.Lcrabc_x86_float_parse_scan_119
	.p2align 6
.Lcrabc_x86_float_parse_scan_122:
	addl	$1, %eax
	andl	$2047, %eax
.Lcrabc_x86_float_parse_scan_121:
	cmpl	%r9d, %eax
	je	.Lcrabc_x86_float_parse_scan_233
	movslq	%eax, %r8
	movl	80(%rsp,%r8,4), %edx
	movl	%edx, %edi
	andl	%r13d, %edx
	imull	%r14d, %edx
	shrl	%cl, %edi
	addl	%r10d, %edi
	movl	%edi, 80(%rsp,%r8,4)
	movl	%edx, %r10d
	cmpl	%esi, %eax
	jne	.Lcrabc_x86_float_parse_scan_122
	testl	%edi, %edi
	jne	.Lcrabc_x86_float_parse_scan_122
	addl	$1, %esi
	subl	$9, %r11d
	andl	$2047, %esi
	jmp	.Lcrabc_x86_float_parse_scan_122
.Lcrabc_x86_float_parse_scan_233:
	testl	%r10d, %r10d
	je	.Lcrabc_x86_float_parse_scan_114
	leal	1(%r9), %eax
	andl	$2047, %eax
	cmpl	%esi, %eax
	je	.Lcrabc_x86_float_parse_scan_125
	movslq	%r9d, %r9
	movl	%r10d, 80(%rsp,%r9,4)
	movl	%eax, %r9d
.Lcrabc_x86_float_parse_scan_114:
	xorl	%edx, %edx
.Lcrabc_x86_float_parse_scan_115:
	cmpq	$3, %rdx
	je	.Lcrabc_x86_float_parse_scan_150
	leal	(%rsi,%rdx), %eax
	andl	$2047, %eax
	cmpl	%eax, %r9d
	je	.Lcrabc_x86_float_parse_scan_150
	movl	80(%rsp,%rax,4), %eax
	movl	(%r15,%rdx,4), %ecx
	cmpl	%ecx, %eax
	jb	.Lcrabc_x86_float_parse_scan_150
	addq	$1, %rdx
	cmpl	%eax, %ecx
	jnb	.Lcrabc_x86_float_parse_scan_115
	xorl	%eax, %eax
	jmp	.Lcrabc_x86_float_parse_scan_116
.Lcrabc_x86_float_parse_scan_125:
	leal	-1(%r9), %eax
	andl	$2047, %eax
	orl	$1, 80(%rsp,%rax,4)
	jmp	.Lcrabc_x86_float_parse_scan_114
	.p2align 6
.Lcrabc_x86_float_parse_scan_127:
	movl	80(%rsp,%rax,4), %eax
	fmuls	.Lcrabc_x86_float_parse_scan_C4(%rip)
	addl	$1, %edx
	movq	%rax, (%rsp)
	fildq	(%rsp)
	faddp	%st, %st(1)
	cmpl	%r14d, %edx
	je	.Lcrabc_x86_float_parse_scan_234
.Lcrabc_x86_float_parse_scan_119:
	movl	%edx, %eax
	andl	$2047, %eax
	cmpl	%r9d, %eax
	jne	.Lcrabc_x86_float_parse_scan_127
	addl	$1, %r9d
	andl	$2047, %r9d
	leal	-1(%r9), %ecx
	movslq	%ecx, %rcx
	movl	$0, 80(%rsp,%rcx,4)
	jmp	.Lcrabc_x86_float_parse_scan_127
.Lcrabc_x86_float_parse_scan_234:
	fildl	16(%rsp)
	leal	64(%r12), %r15d
	movl	%r15d, %ebx
	subl	32(%rsp), %ebx
	fmulp	%st, %st(1)
	cmpl	68(%rsp), %ebx
	jge	.Lcrabc_x86_float_parse_scan_153
	testl	%ebx, %ebx
	js	.Lcrabc_x86_float_parse_scan_154
	movl	%ebx, 68(%rsp)
	movl	$1, %r13d
	jmp	.Lcrabc_x86_float_parse_scan_128
.Lcrabc_x86_float_parse_scan_153:
	xorl	%r13d, %r13d
.Lcrabc_x86_float_parse_scan_128:
	movl	68(%rsp), %ecx
	cmpl	$63, %ecx
	jg	.Lcrabc_x86_float_parse_scan_155
	movl	$64, %eax
	movl	$127, %edi
	subl	%ecx, %eax
	subl	%ecx, %edi
	movl	%eax, %ebp
.Lcrabc_x86_float_parse_scan_129:
	movsd	.Lcrabc_x86_float_parse_scan_C5(%rip), %xmm0
	movl	%r9d, 76(%rsp)
	movl	%esi, 72(%rsp)
	fstpt	32(%rsp)
	call	crabc_x86_float_parse_scalbn@PLT
	fldt	32(%rsp)
	subq	$32, %rsp
	movsd	%xmm0, 32(%rsp)
	fld	%st(0)
	fstpt	16(%rsp)
	fstpt	80(%rsp)
	fldl	32(%rsp)
	fstpt	(%rsp)
	call	crabc_x86_float_parse_copysignl@PLT
	movsd	.Lcrabc_x86_float_parse_scan_C5(%rip), %xmm0
	movl	%ebp, %edi
	fstpt	64(%rsp)
	addq	$32, %rsp
	call	crabc_x86_float_parse_scalbn@PLT
	movsd	%xmm0, (%rsp)
	fldl	(%rsp)
	subq	$32, %rsp
	fstpt	16(%rsp)
	fldt	80(%rsp)
	fld	%st(0)
	fstpt	(%rsp)
	fstpt	32(%rsp)
	call	crabc_x86_float_parse_fmodl@PLT
	fld	%st(0)
	fldt	32(%rsp)
	fsubp	%st, %st(2)
	fldt	64(%rsp)
	movl	104(%rsp), %esi
	addq	$32, %rsp
	movl	76(%rsp), %r9d
	fadd	%st, %st(2)
.Lcrabc_x86_float_parse_scan_130:
	andl	$2047, %r14d
	cmpl	%r9d, %r14d
	je	.Lcrabc_x86_float_parse_scan_239
	movl	80(%rsp,%r14,4), %eax
	cmpl	$499999999, %eax
	ja	.Lcrabc_x86_float_parse_scan_132
	testl	%eax, %eax
	jne	.Lcrabc_x86_float_parse_scan_240
	leal	4(%rsi), %eax
	andl	$2047, %eax
	cmpl	%r9d, %eax
	je	.Lcrabc_x86_float_parse_scan_241
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_133
.Lcrabc_x86_float_parse_scan_240:
	fxch	%st(1)
.Lcrabc_x86_float_parse_scan_133:
	pxor	%xmm0, %xmm0
	cvtsi2sdl	16(%rsp), %xmm0
	mulsd	.Lcrabc_x86_float_parse_scan_C6(%rip), %xmm0
	movsd	%xmm0, (%rsp)
	faddl	(%rsp)
	jmp	.Lcrabc_x86_float_parse_scan_134
.Lcrabc_x86_float_parse_scan_241:
	fxch	%st(1)
.Lcrabc_x86_float_parse_scan_134:
	cmpl	$62, 68(%rsp)
	jle	.Lcrabc_x86_float_parse_scan_235
	jmp	.Lcrabc_x86_float_parse_scan_131
.Lcrabc_x86_float_parse_scan_239:
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_131
.Lcrabc_x86_float_parse_scan_243:
	fxch	%st(1)
	fxch	%st(2)
	jmp	.Lcrabc_x86_float_parse_scan_131
.Lcrabc_x86_float_parse_scan_244:
	fxch	%st(1)
	fxch	%st(2)
.Lcrabc_x86_float_parse_scan_131:
	movl	64(%rsp), %eax
	fadd	%st, %st(2)
	fxch	%st(2)
	leal	-1(%rax), %ecx
	movl	%r15d, %eax
	andl	$2147483647, %eax
	fsubp	%st, %st(1)
	cmpl	%eax, %ecx
	jle	.Lcrabc_x86_float_parse_scan_236
	fstp	%st(1)
.Lcrabc_x86_float_parse_scan_139:
	subq	$16, %rsp
	movl	%r12d, %edi
	fstpt	(%rsp)
	call	crabc_x86_float_parse_scalbnl@PLT
	popq	%rax
	popq	%rdx
	jmp	.Lcrabc_x86_float_parse_scan_46
.Lcrabc_x86_float_parse_scan_154:
	movl	$64, %ebp
	movl	$0, 68(%rsp)
	movl	$127, %edi
	movl	$1, %r13d
	jmp	.Lcrabc_x86_float_parse_scan_129
.Lcrabc_x86_float_parse_scan_155:
	fldz
	fldz
	jmp	.Lcrabc_x86_float_parse_scan_130
.Lcrabc_x86_float_parse_scan_132:
	pxor	%xmm0, %xmm0
	cvtsi2sdl	16(%rsp), %xmm0
	cmpl	$500000000, %eax
	jne	.Lcrabc_x86_float_parse_scan_242
	leal	4(%rsi), %eax
	andl	$2047, %eax
	cmpl	%r9d, %eax
	je	.Lcrabc_x86_float_parse_scan_237
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_135
.Lcrabc_x86_float_parse_scan_242:
	fxch	%st(1)
.Lcrabc_x86_float_parse_scan_135:
	mulsd	.Lcrabc_x86_float_parse_scan_C8(%rip), %xmm0
	movsd	%xmm0, (%rsp)
	faddl	(%rsp)
	jmp	.Lcrabc_x86_float_parse_scan_134
.Lcrabc_x86_float_parse_scan_237:
	fxch	%st(1)
	mulsd	.Lcrabc_x86_float_parse_scan_C7(%rip), %xmm0
	movsd	%xmm0, (%rsp)
	faddl	(%rsp)
	jmp	.Lcrabc_x86_float_parse_scan_134
.Lcrabc_x86_float_parse_scan_235:
	fxch	%st(1)
	fstpt	32(%rsp)
	fxch	%st(1)
	subq	$32, %rsp
	fstpt	48(%rsp)
	fld1
	fstpt	16(%rsp)
	fld	%st(0)
	fstpt	(%rsp)
	fstpt	32(%rsp)
	call	crabc_x86_float_parse_fmodl@PLT
	addq	$32, %rsp
	fldz
	fxch	%st(1)
	fucomip	%st(1), %st
	fstp	%st(0)
	fldt	(%rsp)
	fldt	16(%rsp)
	fldt	32(%rsp)
	jp	.Lcrabc_x86_float_parse_scan_243
	jne	.Lcrabc_x86_float_parse_scan_244
	fld1
	faddp	%st, %st(3)
	fxch	%st(1)
	fxch	%st(2)
	jmp	.Lcrabc_x86_float_parse_scan_131
.Lcrabc_x86_float_parse_scan_236:
	fxch	%st(1)
	fstpt	16(%rsp)
	movl	64(%rsp), %ebp
	subq	$16, %rsp
	addl	$3, %ebp
	fld	%st(0)
	fstpt	(%rsp)
	fstpt	16(%rsp)
	call	crabc_x86_float_parse_fabsl@PLT
	popq	%rcx
	popq	%rsi
	flds	.Lcrabc_x86_float_parse_scan_C10(%rip)
	fxch	%st(1)
	fcomip	%st(1), %st
	fstp	%st(0)
	fldt	(%rsp)
	fldt	16(%rsp)
	jnb	.Lcrabc_x86_float_parse_scan_140
	leal	63(%r12), %r15d
.Lcrabc_x86_float_parse_scan_141:
	cmpl	%r15d, %ebp
	jle	.Lcrabc_x86_float_parse_scan_245
	fldz
	movl	$1, %edx
	fucomip	%st(1), %st
	fstp	%st(0)
	setp	%al
	cmovne	%edx, %eax
	testb	%al, %al
	je	.Lcrabc_x86_float_parse_scan_139
	testl	%r13d, %r13d
	je	.Lcrabc_x86_float_parse_scan_139
	jmp	.Lcrabc_x86_float_parse_scan_142
.Lcrabc_x86_float_parse_scan_245:
	fstp	%st(0)
.Lcrabc_x86_float_parse_scan_142:
	fstpt	(%rsp)
	call	__errno_location
	fldt	(%rsp)
	movl	$34, (%rax)
	jmp	.Lcrabc_x86_float_parse_scan_139
.Lcrabc_x86_float_parse_scan_140:
	fxch	%st(1)
	fmuls	.Lcrabc_x86_float_parse_scan_C11(%rip)
	addl	$1, %r12d
	testl	%r13d, %r13d
	je	.Lcrabc_x86_float_parse_scan_246
	cmpl	68(%rsp), %ebx
	jne	.Lcrabc_x86_float_parse_scan_238
	fstp	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_143
.Lcrabc_x86_float_parse_scan_246:
	fstp	%st(1)
.Lcrabc_x86_float_parse_scan_143:
	cmpl	%ebp, %r15d
	jge	.Lcrabc_x86_float_parse_scan_142
	jmp	.Lcrabc_x86_float_parse_scan_139
.Lcrabc_x86_float_parse_scan_238:
	fxch	%st(1)
	movl	$1, %r13d
	jmp	.Lcrabc_x86_float_parse_scan_141
.Lcrabc_x86_float_parse_scan_60:
	testl	%r13d, %r13d
	jne	.Lcrabc_x86_float_parse_scan_173
.Lcrabc_x86_float_parse_scan_144:
	cmpq	$0, 192(%r12)
	js	.Lcrabc_x86_float_parse_scan_80
	subq	$1, 8(%r12)
	jmp	.Lcrabc_x86_float_parse_scan_80
	.size	crabc_x86_float_parse_decfloat, .-crabc_x86_float_parse_decfloat
	.section	.rodata.crabc_x86_float_parse_floatscan.str1.1,"aMS",@progbits,1
.Lcrabc_x86_float_parse_scan_C14:
	.string	"infinity"
.Lcrabc_x86_float_parse_scan_C16:
	.string	"nan"
	.section	.text.crabc_x86_float_parse_floatscan,"ax",@progbits
	.type	crabc_x86_float_parse_floatscan, @function
crabc_x86_float_parse_floatscan:
	cmpl	$2, %esi
	ja	.Lcrabc_x86_float_parse_scan_437
	pushq	%r15
	movl	%esi, %esi
	leaq	crabc_x86_float_parse_CSW16(%rip), %rax
	pushq	%r14
	movl	%edx, %r14d
	pushq	%r13
	pushq	%r12
	pushq	%rbp
	pushq	%rbx
	movq	%rdi, %rbx
	subq	$120, %rsp
	movl	(%rax,%rsi,4), %r15d
	leaq	crabc_x86_float_parse_CSW17(%rip), %rax
	movl	(%rax,%rsi,4), %ebp
	.p2align 5
.Lcrabc_x86_float_parse_scan_409:
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_249
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %esi
.Lcrabc_x86_float_parse_scan_250:
	leal	-9(%rsi), %eax
	cmpl	$4, %eax
	jbe	.Lcrabc_x86_float_parse_scan_409
	cmpl	$32, %esi
	je	.Lcrabc_x86_float_parse_scan_409
	leal	-43(%rsi), %eax
	movl	$1, %r8d
	andl	$-3, %eax
	jne	.Lcrabc_x86_float_parse_scan_252
	xorl	%eax, %eax
	cmpl	$45, %esi
	sete	%al
	addl	%eax, %eax
	subl	%eax, %r8d
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_253
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %esi
.Lcrabc_x86_float_parse_scan_252:
	xorl	%edx, %edx
	leaq	.Lcrabc_x86_float_parse_scan_C14(%rip), %r9
.Lcrabc_x86_float_parse_scan_254:
	movl	%esi, %ecx
	movsbl	(%r9,%rdx), %eax
	orl	$32, %ecx
	cmpl	%eax, %ecx
	jne	.Lcrabc_x86_float_parse_scan_446
	cmpq	$7, %rdx
	je	.Lcrabc_x86_float_parse_scan_255
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_256
	leaq	1(%rax), %rcx
	addq	$1, %rdx
	movq	%rcx, 8(%rbx)
	movzbl	(%rax), %esi
	jmp	.Lcrabc_x86_float_parse_scan_254
.Lcrabc_x86_float_parse_scan_249:
	movq	%rbx, %rdi
	call	crabc_x86_float_parse_shgetc
	movl	%eax, %esi
	jmp	.Lcrabc_x86_float_parse_scan_250
.Lcrabc_x86_float_parse_scan_253:
	movq	%rbx, %rdi
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	(%rsp), %r8d
	movl	%eax, %esi
	jmp	.Lcrabc_x86_float_parse_scan_252
.Lcrabc_x86_float_parse_scan_256:
	movq	%rbx, %rdi
	movl	%r8d, 16(%rsp)
	movq	%rdx, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movq	(%rsp), %rdx
	movl	16(%rsp), %r8d
	leaq	.Lcrabc_x86_float_parse_scan_C14(%rip), %r9
	movl	%eax, %esi
	addq	$1, %rdx
	jmp	.Lcrabc_x86_float_parse_scan_254
.Lcrabc_x86_float_parse_scan_446:
	movl	$264, %eax
	btq	%rdx, %rax
	jc	.Lcrabc_x86_float_parse_scan_259
	cmpq	$3, %rdx
	jbe	.Lcrabc_x86_float_parse_scan_260
	testl	%r14d, %r14d
	je	.Lcrabc_x86_float_parse_scan_260
	movq	192(%rbx), %rax
	testq	%rax, %rax
	js	.Lcrabc_x86_float_parse_scan_262
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_262:
	cmpq	$3, %rdx
	je	.Lcrabc_x86_float_parse_scan_255
	testq	%rax, %rax
	js	.Lcrabc_x86_float_parse_scan_269
.Lcrabc_x86_float_parse_scan_266:
	movq	8(%rbx), %rax
	cmpq	$4, %rdx
	je	.Lcrabc_x86_float_parse_scan_447
	subq	$2, %rax
	subq	$2, %rdx
	movq	%rax, 8(%rbx)
	cmpq	$3, %rdx
	jne	.Lcrabc_x86_float_parse_scan_266
	jmp	.Lcrabc_x86_float_parse_scan_255
.Lcrabc_x86_float_parse_scan_259:
	movq	192(%rbx), %rax
	testq	%rax, %rax
	js	.Lcrabc_x86_float_parse_scan_265
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_265:
	testl	%r14d, %r14d
	jne	.Lcrabc_x86_float_parse_scan_262
.Lcrabc_x86_float_parse_scan_255:
	pxor	%xmm0, %xmm0
	cvtsi2ssl	%r8d, %xmm0
	mulss	.Lcrabc_x86_float_parse_scan_C15(%rip), %xmm0
	movss	%xmm0, (%rsp)
	flds	(%rsp)
.Lcrabc_x86_float_parse_scan_247:
	addq	$120, %rsp
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
.Lcrabc_x86_float_parse_scan_269:
	cmpq	$4, %rdx
	je	.Lcrabc_x86_float_parse_scan_255
	subq	$2, %rdx
	cmpq	$3, %rdx
	jne	.Lcrabc_x86_float_parse_scan_269
	jmp	.Lcrabc_x86_float_parse_scan_255
.Lcrabc_x86_float_parse_scan_447:
	subq	$1, %rax
	movq	%rax, 8(%rbx)
	jmp	.Lcrabc_x86_float_parse_scan_255
.Lcrabc_x86_float_parse_scan_260:
	leaq	.Lcrabc_x86_float_parse_scan_C16(%rip), %r9
	testq	%rdx, %rdx
	jne	.Lcrabc_x86_float_parse_scan_299
.Lcrabc_x86_float_parse_scan_270:
	movl	%esi, %ecx
	movsbl	(%r9,%rdx), %eax
	orl	$32, %ecx
	cmpl	%eax, %ecx
	jne	.Lcrabc_x86_float_parse_scan_448
	movq	8(%rbx), %rax
	cmpq	$2, %rdx
	je	.Lcrabc_x86_float_parse_scan_273
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_274
	leaq	1(%rax), %rcx
	addq	$1, %rdx
	movq	%rcx, 8(%rbx)
	movzbl	(%rax), %esi
	jmp	.Lcrabc_x86_float_parse_scan_270
.Lcrabc_x86_float_parse_scan_299:
	cmpq	$0, 192(%rbx)
	js	.Lcrabc_x86_float_parse_scan_441
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_441:
	call	__errno_location
	movl	$22, (%rax)
.Lcrabc_x86_float_parse_scan_440:
	xorl	%esi, %esi
	movq	%rbx, %rdi
	call	crabc_x86_float_parse_shlim
	fldz
	jmp	.Lcrabc_x86_float_parse_scan_247
.Lcrabc_x86_float_parse_scan_274:
	movq	%rbx, %rdi
	movl	%r8d, 16(%rsp)
	movq	%rdx, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movq	(%rsp), %rdx
	movl	16(%rsp), %r8d
	leaq	.Lcrabc_x86_float_parse_scan_C16(%rip), %r9
	movl	%eax, %esi
	addq	$1, %rdx
	jmp	.Lcrabc_x86_float_parse_scan_270
.Lcrabc_x86_float_parse_scan_273:
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_449
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	cmpb	$40, (%rax)
	setne	%al
.Lcrabc_x86_float_parse_scan_280:
	movl	$1, %edx
	testb	%al, %al
	jne	.Lcrabc_x86_float_parse_scan_450
.Lcrabc_x86_float_parse_scan_290:
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_283
	leaq	1(%rax), %rcx
	movq	%rcx, 8(%rbx)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_284:
	cmpl	$57, %eax
	jle	.Lcrabc_x86_float_parse_scan_451
	subl	$65, %eax
	cmpl	$57, %eax
	ja	.Lcrabc_x86_float_parse_scan_288
	movabsq	$288230372997595135, %rcx
	btq	%rax, %rcx
	jnc	.Lcrabc_x86_float_parse_scan_288
.Lcrabc_x86_float_parse_scan_286:
	addq	$1, %rdx
	jmp	.Lcrabc_x86_float_parse_scan_290
.Lcrabc_x86_float_parse_scan_449:
	movq	%rbx, %rdi
	call	crabc_x86_float_parse_shgetc
	cmpl	$40, %eax
	setne	%al
	jmp	.Lcrabc_x86_float_parse_scan_280
.Lcrabc_x86_float_parse_scan_450:
	cmpq	$0, 192(%rbx)
	js	.Lcrabc_x86_float_parse_scan_282
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_282:
	flds	.Lcrabc_x86_float_parse_scan_C13(%rip)
	jmp	.Lcrabc_x86_float_parse_scan_247
.Lcrabc_x86_float_parse_scan_283:
	movq	%rbx, %rdi
	movq	%rdx, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movq	(%rsp), %rdx
	jmp	.Lcrabc_x86_float_parse_scan_284
.Lcrabc_x86_float_parse_scan_451:
	cmpl	$47, %eax
	jg	.Lcrabc_x86_float_parse_scan_286
	cmpl	$41, %eax
	je	.Lcrabc_x86_float_parse_scan_282
.Lcrabc_x86_float_parse_scan_288:
	movq	192(%rbx), %rcx
	testq	%rcx, %rcx
	js	.Lcrabc_x86_float_parse_scan_292
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_292:
	testl	%r14d, %r14d
	je	.Lcrabc_x86_float_parse_scan_441
	testq	%rdx, %rdx
	je	.Lcrabc_x86_float_parse_scan_282
	leaq	-1(%rdx), %rax
	testq	%rcx, %rcx
	js	.Lcrabc_x86_float_parse_scan_297
.Lcrabc_x86_float_parse_scan_294:
	movq	8(%rbx), %rdx
	testq	%rax, %rax
	je	.Lcrabc_x86_float_parse_scan_452
	subq	$2, %rdx
	movq	%rdx, 8(%rbx)
	cmpq	$1, %rax
	je	.Lcrabc_x86_float_parse_scan_282
	subq	$2, %rax
	jmp	.Lcrabc_x86_float_parse_scan_294
.Lcrabc_x86_float_parse_scan_297:
	testq	%rax, %rax
	je	.Lcrabc_x86_float_parse_scan_282
	cmpq	$1, %rax
	je	.Lcrabc_x86_float_parse_scan_282
	subq	$2, %rax
	jmp	.Lcrabc_x86_float_parse_scan_297
.Lcrabc_x86_float_parse_scan_452:
	subq	$1, %rdx
	movq	%rdx, 8(%rbx)
	jmp	.Lcrabc_x86_float_parse_scan_282
.Lcrabc_x86_float_parse_scan_448:
	testq	%rdx, %rdx
	jne	.Lcrabc_x86_float_parse_scan_299
	cmpl	$48, %esi
	jne	.Lcrabc_x86_float_parse_scan_302
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_303
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_304:
	orl	$32, %eax
	cmpl	$120, %eax
	je	.Lcrabc_x86_float_parse_scan_453
	cmpq	$0, 192(%rbx)
	js	.Lcrabc_x86_float_parse_scan_302
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_302:
	addq	$120, %rsp
	movl	%r14d, %r9d
	movl	%ebp, %ecx
	movl	%r15d, %edx
	movq	%rbx, %rdi
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	jmp	crabc_x86_float_parse_decfloat
.Lcrabc_x86_float_parse_scan_303:
	movq	%rbx, %rdi
	movl	%esi, 16(%rsp)
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	16(%rsp), %esi
	movl	(%rsp), %r8d
	jmp	.Lcrabc_x86_float_parse_scan_304
.Lcrabc_x86_float_parse_scan_453:
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_306
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_307:
	xorl	%esi, %esi
	jmp	.Lcrabc_x86_float_parse_scan_310
.Lcrabc_x86_float_parse_scan_306:
	movq	%rbx, %rdi
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	(%rsp), %r8d
	jmp	.Lcrabc_x86_float_parse_scan_307
.Lcrabc_x86_float_parse_scan_308:
	movq	%rbx, %rdi
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	(%rsp), %r8d
.Lcrabc_x86_float_parse_scan_309:
	movl	$1, %esi
.Lcrabc_x86_float_parse_scan_310:
	cmpl	$48, %eax
	jne	.Lcrabc_x86_float_parse_scan_454
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_308
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %eax
	jmp	.Lcrabc_x86_float_parse_scan_309
.Lcrabc_x86_float_parse_scan_454:
	xorl	%r12d, %r12d
	xorl	%r10d, %r10d
	cmpl	$46, %eax
	je	.Lcrabc_x86_float_parse_scan_455
.Lcrabc_x86_float_parse_scan_312:
	fld1
	xorl	%edx, %edx
	xorl	%r13d, %r13d
	xorl	%ecx, %ecx
	fldz
	jmp	.Lcrabc_x86_float_parse_scan_328
.Lcrabc_x86_float_parse_scan_455:
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_313
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_314:
	xorl	%r12d, %r12d
	jmp	.Lcrabc_x86_float_parse_scan_317
.Lcrabc_x86_float_parse_scan_313:
	movq	%rbx, %rdi
	movl	%esi, 16(%rsp)
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	(%rsp), %r8d
	movl	16(%rsp), %esi
	jmp	.Lcrabc_x86_float_parse_scan_314
.Lcrabc_x86_float_parse_scan_315:
	movq	%rbx, %rdi
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	(%rsp), %r8d
.Lcrabc_x86_float_parse_scan_316:
	subq	$1, %r12
	movl	$1, %esi
.Lcrabc_x86_float_parse_scan_317:
	cmpl	$48, %eax
	jne	.Lcrabc_x86_float_parse_scan_456
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_315
	leaq	1(%rax), %rdx
	movq	%rdx, 8(%rbx)
	movzbl	(%rax), %eax
	jmp	.Lcrabc_x86_float_parse_scan_316
.Lcrabc_x86_float_parse_scan_456:
	movl	$1, %r10d
	jmp	.Lcrabc_x86_float_parse_scan_312
.Lcrabc_x86_float_parse_scan_329:
	cmpl	$46, %eax
	je	.Lcrabc_x86_float_parse_scan_330
	subl	$87, %r11d
	cmpl	$57, %eax
	cmovg	%r11d, %edi
.Lcrabc_x86_float_parse_scan_322:
	cmpq	$7, %rdx
	jg	.Lcrabc_x86_float_parse_scan_323
	sall	$4, %ecx
	addl	%edi, %ecx
.Lcrabc_x86_float_parse_scan_324:
	addq	$1, %rdx
	movl	$1, %esi
.Lcrabc_x86_float_parse_scan_321:
	movq	8(%rbx), %rax
	cmpq	184(%rbx), %rax
	je	.Lcrabc_x86_float_parse_scan_326
	leaq	1(%rax), %rdi
	movq	%rdi, 8(%rbx)
	movzbl	(%rax), %eax
.Lcrabc_x86_float_parse_scan_328:
	leal	-48(%rax), %edi
	cmpl	$9, %edi
	jbe	.Lcrabc_x86_float_parse_scan_322
	movl	%eax, %r11d
	orl	$32, %r11d
	leal	-97(%r11), %r9d
	cmpl	$5, %r9d
	jbe	.Lcrabc_x86_float_parse_scan_329
	cmpl	$46, %eax
	jne	.Lcrabc_x86_float_parse_scan_457
.Lcrabc_x86_float_parse_scan_330:
	testl	%r10d, %r10d
	jne	.Lcrabc_x86_float_parse_scan_320
	movq	%rdx, %r12
	movl	$1, %r10d
	jmp	.Lcrabc_x86_float_parse_scan_321
.Lcrabc_x86_float_parse_scan_323:
	cmpq	$16, %rdx
	jg	.Lcrabc_x86_float_parse_scan_325
	fxch	%st(1)
	fmuls	.Lcrabc_x86_float_parse_scan_C17(%rip)
	movl	%edi, (%rsp)
	fildl	(%rsp)
	fmul	%st(1), %st
	faddp	%st, %st(2)
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_324
.Lcrabc_x86_float_parse_scan_325:
	testl	%edi, %edi
	je	.Lcrabc_x86_float_parse_scan_324
	testl	%r13d, %r13d
	jne	.Lcrabc_x86_float_parse_scan_324
	flds	.Lcrabc_x86_float_parse_scan_C11(%rip)
	movl	$1, %r13d
	fmul	%st(2), %st
	faddp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_324
.Lcrabc_x86_float_parse_scan_326:
	fstpt	80(%rsp)
	movq	%rbx, %rdi
	movl	%esi, 108(%rsp)
	fstpt	64(%rsp)
	movl	%ecx, 48(%rsp)
	movq	%rdx, 32(%rsp)
	movl	%r10d, 16(%rsp)
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shgetc
	movl	(%rsp), %r8d
	fldt	64(%rsp)
	movl	16(%rsp), %r10d
	fldt	80(%rsp)
	movq	32(%rsp), %rdx
	movl	48(%rsp), %ecx
	movl	108(%rsp), %esi
	jmp	.Lcrabc_x86_float_parse_scan_328
.Lcrabc_x86_float_parse_scan_457:
	fstp	%st(1)
	movq	%r12, %rax
	testl	%r10d, %r10d
	cmove	%rdx, %rax
	movq	%rax, %r12
	testl	%esi, %esi
	jne	.Lcrabc_x86_float_parse_scan_410
	fstp	%st(0)
	cmpq	$0, 192(%rbx)
	js	.Lcrabc_x86_float_parse_scan_332
	movq	8(%rbx), %rax
	testl	%r14d, %r14d
	je	.Lcrabc_x86_float_parse_scan_334
	testl	%r10d, %r10d
	jne	.Lcrabc_x86_float_parse_scan_337
	subq	$2, %rax
	movq	%rax, 8(%rbx)
	jmp	.Lcrabc_x86_float_parse_scan_443
.Lcrabc_x86_float_parse_scan_332:
	testl	%r14d, %r14d
	jne	.Lcrabc_x86_float_parse_scan_443
	jmp	.Lcrabc_x86_float_parse_scan_335
.Lcrabc_x86_float_parse_scan_334:
	subq	$1, %rax
	movq	%rax, 8(%rbx)
.Lcrabc_x86_float_parse_scan_335:
	xorl	%esi, %esi
	movq	%rbx, %rdi
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_shlim
	movl	(%rsp), %r8d
	jmp	.Lcrabc_x86_float_parse_scan_443
.Lcrabc_x86_float_parse_scan_462:
	fstp	%st(0)
.Lcrabc_x86_float_parse_scan_443:
	pxor	%xmm1, %xmm1
	pxor	%xmm0, %xmm0
	cvtsi2sdl	%r8d, %xmm1
	mulsd	%xmm0, %xmm1
	movsd	%xmm1, (%rsp)
	fldl	(%rsp)
	jmp	.Lcrabc_x86_float_parse_scan_247
.Lcrabc_x86_float_parse_scan_342:
	sall	$8, %ecx
	addq	$2, %rdx
.Lcrabc_x86_float_parse_scan_341:
	cmpq	$7, %rdx
	jle	.Lcrabc_x86_float_parse_scan_342
.Lcrabc_x86_float_parse_scan_435:
	cmpl	$112, %r11d
	je	.Lcrabc_x86_float_parse_scan_458
.Lcrabc_x86_float_parse_scan_445:
	cmpq	$0, 192(%rbx)
	js	.Lcrabc_x86_float_parse_scan_347
	subq	$1, 8(%rbx)
.Lcrabc_x86_float_parse_scan_347:
	xorl	%eax, %eax
.Lcrabc_x86_float_parse_scan_344:
	testl	%ecx, %ecx
	je	.Lcrabc_x86_float_parse_scan_462
	leaq	-32(%rax,%r12,4), %rbx
	movl	%ebp, %eax
	negl	%eax
	cltq
	cmpq	%rax, %rbx
	jg	.Lcrabc_x86_float_parse_scan_459
	leal	-128(%rbp), %eax
	cltq
	cmpq	%rax, %rbx
	jl	.Lcrabc_x86_float_parse_scan_433
	fld1
	jmp	.Lcrabc_x86_float_parse_scan_351
.Lcrabc_x86_float_parse_scan_458:
	movl	%r14d, %esi
	movq	%rbx, %rdi
	fstpt	32(%rsp)
	movl	%ecx, 16(%rsp)
	movl	%r8d, (%rsp)
	call	crabc_x86_float_parse_scanexp
	movl	$1, %edx
	movl	(%rsp), %r8d
	movl	16(%rsp), %ecx
	fldt	32(%rsp)
	salq	$63, %rdx
	cmpq	%rdx, %rax
	jne	.Lcrabc_x86_float_parse_scan_344
	testl	%r14d, %r14d
	jne	.Lcrabc_x86_float_parse_scan_445
	fstp	%st(0)
	jmp	.Lcrabc_x86_float_parse_scan_440
.Lcrabc_x86_float_parse_scan_459:
	fstp	%st(0)
	movl	%r8d, (%rsp)
	call	__errno_location
	fildl	(%rsp)
	movl	$34, (%rax)
	fldt	.Lcrabc_x86_float_parse_scan_C2(%rip)
	fmul	%st, %st(1)
	fmulp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_247
.Lcrabc_x86_float_parse_scan_433:
	fstp	%st(0)
	movl	%r8d, (%rsp)
	call	__errno_location
	fildl	(%rsp)
	movl	$34, (%rax)
	fldt	.Lcrabc_x86_float_parse_scan_C3(%rip)
	fmul	%st, %st(1)
	fmulp	%st, %st(1)
	jmp	.Lcrabc_x86_float_parse_scan_247
.Lcrabc_x86_float_parse_scan_434:
	fxch	%st(1)
	fadd	%st(0), %st
.Lcrabc_x86_float_parse_scan_354:
	fxch	%st(1)
	subq	$1, %rbx
.Lcrabc_x86_float_parse_scan_351:
	testl	%ecx, %ecx
	js	.Lcrabc_x86_float_parse_scan_460
	flds	.Lcrabc_x86_float_parse_scan_C11(%rip)
	fxch	%st(2)
	addl	%ecx, %ecx
	fcomi	%st(2), %st
	fstp	%st(2)
	jb	.Lcrabc_x86_float_parse_scan_434
	fld	%st(1)
	addl	$1, %ecx
	fsub	%st(1), %st
	faddp	%st, %st(2)
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_354
.Lcrabc_x86_float_parse_scan_460:
	fstp	%st(0)
	leaq	32(%rbx), %rax
	movslq	%ebp, %rsi
	movslq	%r15d, %rdx
	subq	%rsi, %rax
	cmpq	%rax, %rdx
	jle	.Lcrabc_x86_float_parse_scan_356
	movl	%ebx, %eax
	subl	%ebp, %eax
	addl	$32, %eax
	movl	%eax, %r15d
	js	.Lcrabc_x86_float_parse_scan_366
.Lcrabc_x86_float_parse_scan_356:
	cmpl	$63, %r15d
	jg	.Lcrabc_x86_float_parse_scan_367
.Lcrabc_x86_float_parse_scan_357:
	fstpt	48(%rsp)
	movsd	.Lcrabc_x86_float_parse_scan_C5(%rip), %xmm0
	movl	$95, %edi
	subl	%r15d, %edi
	movl	%r8d, (%rsp)
	fildl	(%rsp)
	movl	%ecx, 32(%rsp)
	fstpt	16(%rsp)
	call	crabc_x86_float_parse_scalbn@PLT
	fldt	16(%rsp)
	subq	$32, %rsp
	movsd	%xmm0, 32(%rsp)
	fstpt	16(%rsp)
	fldl	32(%rsp)
	fstpt	(%rsp)
	call	crabc_x86_float_parse_copysignl@PLT
	addq	$32, %rsp
	cmpl	$31, %r15d
	movl	32(%rsp), %ecx
	fldt	16(%rsp)
	fldt	48(%rsp)
	jg	.Lcrabc_x86_float_parse_scan_463
	fldz
	movl	$1, %edx
	fucomip	%st(1), %st
	setp	%al
	cmovne	%edx, %eax
	testb	%al, %al
	je	.Lcrabc_x86_float_parse_scan_464
	testb	$1, %cl
	jne	.Lcrabc_x86_float_parse_scan_465
	fstp	%st(0)
	addl	$1, %ecx
	fldz
	fxch	%st(2)
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_358
.Lcrabc_x86_float_parse_scan_366:
	xorl	%r15d, %r15d
	jmp	.Lcrabc_x86_float_parse_scan_357
.Lcrabc_x86_float_parse_scan_367:
	movl	%r8d, (%rsp)
	fldz
	fildl	(%rsp)
	jmp	.Lcrabc_x86_float_parse_scan_358
.Lcrabc_x86_float_parse_scan_463:
	fxch	%st(2)
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_358
.Lcrabc_x86_float_parse_scan_464:
	fxch	%st(2)
	fxch	%st(1)
	jmp	.Lcrabc_x86_float_parse_scan_358
.Lcrabc_x86_float_parse_scan_465:
	fxch	%st(2)
	fxch	%st(1)
.Lcrabc_x86_float_parse_scan_358:
	fmul	%st, %st(2)
	movq	%rcx, (%rsp)
	fildq	(%rsp)
	fmulp	%st, %st(1)
	fadd	%st(1), %st
	faddp	%st, %st(2)
	fsubrp	%st, %st(1)
	fldz
	fxch	%st(1)
	fucomi	%st(1), %st
	fstp	%st(1)
	jp	.Lcrabc_x86_float_parse_scan_359
	jne	.Lcrabc_x86_float_parse_scan_359
	fstpt	(%rsp)
	call	__errno_location
	fldt	(%rsp)
	movl	$34, (%rax)
.Lcrabc_x86_float_parse_scan_359:
	subq	$16, %rsp
	movl	%ebx, %edi
	fstpt	(%rsp)
	call	crabc_x86_float_parse_scalbnl@PLT
	popq	%rax
	popq	%rdx
	jmp	.Lcrabc_x86_float_parse_scan_247
.Lcrabc_x86_float_parse_scan_320:
	fstp	%st(1)
	movl	$46, %r11d
	testl	%esi, %esi
	je	.Lcrabc_x86_float_parse_scan_461
.Lcrabc_x86_float_parse_scan_410:
	testb	$1, %dl
	je	.Lcrabc_x86_float_parse_scan_341
	cmpq	$7, %rdx
	jg	.Lcrabc_x86_float_parse_scan_435
	sall	$4, %ecx
	addq	$1, %rdx
	jmp	.Lcrabc_x86_float_parse_scan_341
.Lcrabc_x86_float_parse_scan_461:
	fstp	%st(0)
	cmpq	$0, 192(%rbx)
	js	.Lcrabc_x86_float_parse_scan_332
	movq	8(%rbx), %rax
	testl	%r14d, %r14d
	je	.Lcrabc_x86_float_parse_scan_334
.Lcrabc_x86_float_parse_scan_337:
	subq	$3, %rax
	movq	%rax, 8(%rbx)
	jmp	.Lcrabc_x86_float_parse_scan_443
.Lcrabc_x86_float_parse_scan_437:
	fldz
	ret
	.size	crabc_x86_float_parse_floatscan, .-crabc_x86_float_parse_floatscan
	.section	.rodata.crabc_x86_float_parse_CSW17,"a"
	.align 8
	.type	crabc_x86_float_parse_CSW17, @object
	.size	crabc_x86_float_parse_CSW17, 12
crabc_x86_float_parse_CSW17:
	.long	-149
	.long	-1074
	.long	-16445
	.section	.rodata.crabc_x86_float_parse_CSW16,"a"
	.align 8
	.type	crabc_x86_float_parse_CSW16, @object
	.size	crabc_x86_float_parse_CSW16, 12
crabc_x86_float_parse_CSW16:
	.long	24
	.long	53
	.long	64
	.section	.rodata.crabc_x86_float_parse_th_0,"a"
	.align 8
	.type	crabc_x86_float_parse_th_0, @object
	.size	crabc_x86_float_parse_th_0, 12
crabc_x86_float_parse_th_0:
	.long	18
	.long	446744073
	.long	709551615
	.section	.rodata.crabc_x86_float_parse_p10s_1,"a"
	.align 32
	.type	crabc_x86_float_parse_p10s_1, @object
	.size	crabc_x86_float_parse_p10s_1, 32
crabc_x86_float_parse_p10s_1:
	.long	10
	.long	100
	.long	1000
	.long	10000
	.long	100000
	.long	1000000
	.long	10000000
	.long	100000000
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.Lcrabc_x86_float_parse_scan_C2:
	.long	-1
	.long	-1
	.long	32766
	.long	0
	.align 16
.Lcrabc_x86_float_parse_scan_C3:
	.long	0
	.long	-2147483648
	.long	1
	.long	0
	.section	.rodata.cst4,"aM",@progbits,4
	.align 4
.Lcrabc_x86_float_parse_scan_C4:
	.long	1315859240
	.section	.rodata.cst8,"aM",@progbits,8
	.align 8
.Lcrabc_x86_float_parse_scan_C5:
	.long	0
	.long	1072693248
	.align 8
.Lcrabc_x86_float_parse_scan_C6:
	.long	0
	.long	1070596096
	.align 8
.Lcrabc_x86_float_parse_scan_C7:
	.long	0
	.long	1071644672
	.align 8
.Lcrabc_x86_float_parse_scan_C8:
	.long	0
	.long	1072168960
	.section	.rodata.cst4
	.align 4
.Lcrabc_x86_float_parse_scan_C10:
	.long	1602224128
	.align 4
.Lcrabc_x86_float_parse_scan_C11:
	.long	1056964608
	.align 4
.Lcrabc_x86_float_parse_scan_C13:
	.long	2143289344
	.align 4
.Lcrabc_x86_float_parse_scan_C15:
	.long	2139095040
	.align 4
.Lcrabc_x86_float_parse_scan_C17:
	.long	1031798784
	.section	.note.GNU-stack,"",@progbits
