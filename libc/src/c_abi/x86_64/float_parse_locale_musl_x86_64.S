/*
 * Fixed musl 1.2.6 src/stdlib/wcstod.c x86-64 assembly translation.
 *
 * The public wrappers retain the SysV float/double/x87 return split.  The
 * private 60-byte refill buffer maps non-ASCII wchar_t values to '@', exactly
 * as the pinned source does, and reuses the already owned floatscan/shgetc
 * translation. See float_parse_locale.rs for source and generation provenance.
 */
    .text
    .section .rodata.crabc_x86_wide_parse,"a",@progbits
    .align 4
.Lcrabc_x86_wide_parse_at:
    .long 64, 0
.Lcrabc_x86_wide_parse_spaces:
    .long 32, 9, 10, 13, 11, 12, 0x0085
    .long 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005
    .long 0x2006, 0x2008, 0x2009, 0x200a
    .long 0x2028, 0x2029, 0x205f, 0x3000, 0

    .text
    .type crabc_x86_wide_parse_iswspace,@function
crabc_x86_wide_parse_iswspace:
    testl %edi, %edi
    je .Lcrabc_x86_wide_parse_not_space
    leaq .Lcrabc_x86_wide_parse_spaces(%rip), %rax
.Lcrabc_x86_wide_parse_space_loop:
    movl (%rax), %edx
    testl %edx, %edx
    je .Lcrabc_x86_wide_parse_not_space
    cmpl %edx, %edi
    je .Lcrabc_x86_wide_parse_space
    addq $4, %rax
    jmp .Lcrabc_x86_wide_parse_space_loop
.Lcrabc_x86_wide_parse_space:
    movl $1, %eax
    ret
.Lcrabc_x86_wide_parse_not_space:
    xorl %eax, %eax
    ret
    .size crabc_x86_wide_parse_iswspace, .-crabc_x86_wide_parse_iswspace

    .p2align 4
    .type crabc_x86_wide_parse_do_read,@function
crabc_x86_wide_parse_do_read:
    movq 152(%rdi), %r9
    movq %rdx, %r10
    movq %rsi, %r11
    movl $64, %r8d
    movl (%r9), %eax
    testl %eax, %eax
    leaq .Lcrabc_x86_wide_parse_at(%rip), %rax
    cmovne %r9, %rax
    movq %rax, %r9
    xorl %ecx, %ecx
    movq %r9, %rdx
    cmpq $0, 96(%rdi)
    jne .Lcrabc_x86_wide_parse_fill_test
    jmp .Lcrabc_x86_wide_parse_empty_buffer
    .p2align 4
.Lcrabc_x86_wide_parse_fill:
    cmpl $128, %eax
    movq 88(%rdi), %rsi
    cmovge %r8d, %eax
    addq $4, %rdx
    movb %al, (%rsi,%rcx)
    addq $1, %rcx
    cmpq 96(%rdi), %rcx
    jnb .Lcrabc_x86_wide_parse_full_buffer
.Lcrabc_x86_wide_parse_fill_test:
    movl (%rdx), %eax
    testl %eax, %eax
    jne .Lcrabc_x86_wide_parse_fill
    testq %rcx, %rcx
    setne %sil
.Lcrabc_x86_wide_parse_publish:
    movq 88(%rdi), %rax
    movq %rdx, 152(%rdi)
    addq %rax, %rcx
    movq %rax, %xmm0
    movq %rcx, %xmm1
    punpcklqdq %xmm1, %xmm0
    movups %xmm0, 8(%rdi)
    testq %r10, %r10
    je .Lcrabc_x86_wide_parse_no_read
    testb %sil, %sil
    je .Lcrabc_x86_wide_parse_no_read
    leaq 1(%rax), %rdx
    movq %rdx, 8(%rdi)
    movzbl (%rax), %eax
    movb %al, (%r11)
    movl $1, %eax
    ret
.Lcrabc_x86_wide_parse_full_buffer:
    leaq (%r9,%rcx,4), %rdx
    movl $1, %esi
    jmp .Lcrabc_x86_wide_parse_publish
.Lcrabc_x86_wide_parse_empty_buffer:
    movq 88(%rdi), %xmm0
    movq %r9, 152(%rdi)
    punpcklqdq %xmm0, %xmm0
    movups %xmm0, 8(%rdi)
.Lcrabc_x86_wide_parse_no_read:
    xorl %eax, %eax
    ret
    .size crabc_x86_wide_parse_do_read, .-crabc_x86_wide_parse_do_read

    .p2align 4
    .type crabc_x86_wide_parse_wcstox,@function
crabc_x86_wide_parse_wcstox:
    pushq %r14
    movl %edx, %r14d
    movl $29, %ecx
    xorl %eax, %eax
    pushq %r13
    movq %rdi, %r13
    pushq %r12
    movq %rsi, %r12
    pushq %rbp
    pushq %rbx
    movq %r13, %rbx
    subq $304, %rsp
    leaq 4(%rsp), %rdx
    leaq 64(%rsp), %rbp
    movq %rdx, %xmm0
    movq %rbp, %rdi
    rep stosq
    punpcklqdq %xmm0, %xmm0
    movq %rdx, 152(%rsp)
    movq $60, 160(%rsp)
    movl $-1, 204(%rsp)
    leaq crabc_x86_wide_parse_do_read(%rip), %rax
    movq %rax, 128(%rsp)
    movups %xmm0, 72(%rsp)
    jmp .Lcrabc_x86_wide_parse_skip_test
    .p2align 4
.Lcrabc_x86_wide_parse_skip:
    addq $4, %rbx
.Lcrabc_x86_wide_parse_skip_test:
    movl (%rbx), %edi
    call crabc_x86_wide_parse_iswspace
    testl %eax, %eax
    jne .Lcrabc_x86_wide_parse_skip
    xorl %esi, %esi
    movq %rbp, %rdi
    movq %rbx, 216(%rsp)
    call crabc_x86_float_parse_shlim
    movl $1, %edx
    movl %r14d, %esi
    movq %rbp, %rdi
    call crabc_x86_float_parse_floatscan
    testq %r12, %r12
    je .Lcrabc_x86_wide_parse_return
    movq 72(%rsp), %rax
    subq 152(%rsp), %rax
    addq 264(%rsp), %rax
    leaq (%rbx,%rax,4), %rdx
    movq %r13, %rax
    cmovne %rdx, %rax
    movq %rax, (%r12)
.Lcrabc_x86_wide_parse_return:
    addq $304, %rsp
    popq %rbx
    popq %rbp
    popq %r12
    popq %r13
    popq %r14
    ret
    .size crabc_x86_wide_parse_wcstox, .-crabc_x86_wide_parse_wcstox

    .section .text.wcstof,"ax",@progbits
    .globl wcstof
    .type wcstof,@function
wcstof:
    subq $24, %rsp
    xorl %edx, %edx
    call crabc_x86_wide_parse_wcstox
    fstps 12(%rsp)
    movss 12(%rsp), %xmm0
    addq $24, %rsp
    ret
    .size wcstof, .-wcstof

    .section .text.wcstod,"ax",@progbits
    .globl wcstod
    .type wcstod,@function
wcstod:
    subq $24, %rsp
    movl $1, %edx
    call crabc_x86_wide_parse_wcstox
    fstpl 8(%rsp)
    movsd 8(%rsp), %xmm0
    addq $24, %rsp
    ret
    .size wcstod, .-wcstod

    .section .text.wcstold,"ax",@progbits
    .globl wcstold
    .type wcstold,@function
wcstold:
    movl $2, %edx
    jmp crabc_x86_wide_parse_wcstox
    .size wcstold, .-wcstold

    .hidden crabc_x86_float_parse_floatscan
    .hidden crabc_x86_float_parse_shlim
    .section .note.GNU-stack,"",@progbits
