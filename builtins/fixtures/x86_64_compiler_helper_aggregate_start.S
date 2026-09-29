.text
.globl _start
.type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_compiler_helper_aggregate_probe
    testl %eax, %eax
    jne 1f
    call crabc_x86_64_int128_cast_registers
    testl %eax, %eax
    jne 1f
    movl $1, %edi
    leaq transcript(%rip), %rsi
    movl $29, %edx
    movl $1, %eax
    syscall
    xorl %edi, %edi
    jmp 2f
1:
    movl %eax, %edi
2:
    movl $60, %eax
    syscall
.size _start, .-_start
.section .rodata
transcript:
    .ascii "compiler-helper-aggregate-ok\n"
.section .note.GNU-stack,"",@progbits

.text
.type crabc_x86_64_int128_cast_registers,@function
crabc_x86_64_int128_cast_registers:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8,%rsp
    movq %rsp,(%rsp)
    movl $0x1234,%ebp
    movl $0x2345,%ebx
    movl $0x3456,%r12d
    movl $0x4567,%r13d
    movl $0x5678,%r14d
    movl $0x6789,%r15d
    xorl %edi,%edi
    movl $1,%esi
    call __floatuntidf
    movq %xmm0,%rax
    movabsq $0x43f0000000000000,%rdx
    cmpq %rdx,%rax
    jne 3f
    xorl %edi,%edi
    movq $-1,%rsi
    call __floattidf
    movq %xmm0,%rax
    movabsq $0xc3f0000000000000,%rdx
    cmpq %rdx,%rax
    jne 3f
    call __fixdfti
    testq %rax,%rax
    jne 3f
    cmpq $-1,%rdx
    jne 3f
    movabsq $0x43f0000000000000,%rax
    movq %rax,%xmm0
    call __fixunsdfti
    testq %rax,%rax
    jne 3f
    cmpq $1,%rdx
    jne 3f
    cmpq (%rsp),%rsp
    jne 3f
    cmpl $0x1234,%ebp
    jne 3f
    cmpl $0x2345,%ebx
    jne 3f
    cmpl $0x3456,%r12d
    jne 3f
    cmpl $0x4567,%r13d
    jne 3f
    cmpl $0x5678,%r14d
    jne 3f
    cmpl $0x6789,%r15d
    jne 3f
    xorl %eax,%eax
    jmp 4f
3:  movl $97,%eax
4:  addq $8,%rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size crabc_x86_64_int128_cast_registers,.-crabc_x86_64_int128_cast_registers
