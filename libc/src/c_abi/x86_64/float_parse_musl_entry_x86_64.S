/*
 * Fixed musl 1.2.6 x86-64 src/stdlib/strtod.c and atof.c assembly translation.
 * The public entries intentionally retain the System V binary32/binary64 and
 * x87 binary80 return ABIs. The private pseudo-FILE stack image and scanner
 * calls are the exact pinned-source form; see float_parse.rs for provenance.
 */
    .text
    .section .text.crabc_x86_float_parse_strtox,"ax",@progbits
    .type crabc_x86_float_parse_strtox,@function
crabc_x86_float_parse_strtox:
    pushq %r13
    movq %rdi, %xmm0
    movl %edx, %r13d
    pushq %r12
    movq %rsi, %r12
    xorl %esi, %esi
    pushq %rbp
    pushq %rbx
    movq %rdi, %rbx
    subq $248, %rsp
    movhps .Lcrabc_x86_float_parse_entry_C0(%rip), %xmm0
    movq %rdi, 88(%rsp)
    movq %rsp, %rdi
    movups %xmm0, 8(%rsp)
    call crabc_x86_float_parse_shlim
    movl $1, %edx
    movl %r13d, %esi
    movq %rsp, %rdi
    call crabc_x86_float_parse_floatscan
    testq %r12, %r12
    je .Lcrabc_x86_float_parse_entry_1
    movq 8(%rsp), %rax
    subq 88(%rsp), %rax
    addq 200(%rsp), %rax
    addq %rax, %rbx
    movq %rbx, (%r12)
.Lcrabc_x86_float_parse_entry_1:
    addq $248, %rsp
    popq %rbx
    popq %rbp
    popq %r12
    popq %r13
    ret
    .size crabc_x86_float_parse_strtox, .-crabc_x86_float_parse_strtox

    .section .text.strtof,"ax",@progbits
    .globl strtof
    .type strtof,@function
strtof:
    subq $24, %rsp
    xorl %edx, %edx
    call crabc_x86_float_parse_strtox
    fstps 12(%rsp)
    movss 12(%rsp), %xmm0
    addq $24, %rsp
    ret
    .size strtof, .-strtof

    .section .text.strtod,"ax",@progbits
    .globl strtod
    .type strtod,@function
strtod:
    subq $24, %rsp
    movl $1, %edx
    call crabc_x86_float_parse_strtox
    fstpl 8(%rsp)
    movsd 8(%rsp), %xmm0
    addq $24, %rsp
    ret
    .size strtod, .-strtod

    .section .text.strtold,"ax",@progbits
    .globl strtold
    .type strtold,@function
strtold:
    movl $2, %edx
    jmp crabc_x86_float_parse_strtox
    .size strtold, .-strtold

    .section .text.atof,"ax",@progbits
    .globl atof
    .type atof,@function
atof:
    xorl %esi, %esi
    jmp strtod
    .size atof, .-atof

    .section .rodata.cst8,"aM",@progbits,8
    .align 8
.Lcrabc_x86_float_parse_entry_C0:
    .quad -1
    .section .note.GNU-stack,"",@progbits
