.text
.globl _start
.type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_compiler_helper_aggregate_probe
    testl %eax, %eax
    jne 1f
    call crabc_x86_64_compiler_helper_registers
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
.type crabc_x86_64_compiler_helper_registers,@function
crabc_x86_64_compiler_helper_registers:
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
    # Complex-double arguments occupy XMM0 through XMM3, and its real and
    # imaginary result occupies XMM0 and XMM1. Use asymmetric components so
    # swapped arguments or a single-register return cannot pass.
    movabsq $0x4008000000000000,%rax
    movq %rax,%xmm0
    movabsq $0x4010000000000000,%rax
    movq %rax,%xmm1
    movabsq $0x4000000000000000,%rax
    movq %rax,%xmm2
    movabsq $0xbff0000000000000,%rax
    movq %rax,%xmm3
    call __muldc3
    movq %xmm0,%rax
    movabsq $0x4024000000000000,%rdx
    cmpq %rdx,%rax
    jne 3f
    movq %xmm1,%rax
    movabsq $0x4014000000000000,%rdx
    cmpq %rdx,%rax
    jne 3f
    # Binary80 uses integer word pairs for integer128 and ST0 for scalar
    # results. The low ten bytes carry the value; padding is not compared.
    subq $32,%rsp
    xorl %edi,%edi
    movabsq $0xfffffff000000000,%rsi
    call __floattixf
    fstpt (%rsp)
    movabsq $0x8000000000000000,%rax
    cmpq %rax,(%rsp)
    jne 5f
    cmpw $0xc063,8(%rsp)
    jne 5f
    call __fixxfti
    testq %rax,%rax
    jne 5f
    movabsq $0xfffffff000000000,%rcx
    cmpq %rcx,%rdx
    jne 5f
    xorl %edi,%edi
    movabsq $0x1000000000,%rsi
    call __floatuntixf
    fstpt (%rsp)
    movabsq $0x8000000000000000,%rax
    cmpq %rax,(%rsp)
    jne 5f
    cmpw $0x4063,8(%rsp)
    jne 5f
    call __fixunsxfti
    testq %rax,%rax
    jne 5f
    movabsq $0x1000000000,%rcx
    cmpq %rcx,%rdx
    jne 5f
    addq $32,%rsp
    jmp 6f
5:  addq $32,%rsp
    jmp 3f
6:
    # Four binary80 arguments occupy consecutive sixteen-byte stack slots.
    # Complex results return real then imaginary in ST0 and ST1.
    subq $64,%rsp
    movabsq $0x8000000000000000,%rax
    movq %rax,0(%rsp)
    movq %rax,16(%rsp)
    movq %rax,32(%rsp)
    movq $0,48(%rsp)
    movq $0,8(%rsp)
    movq $0,24(%rsp)
    movq $0,40(%rsp)
    movq $0,56(%rsp)
    movw $0x4001,8(%rsp)
    movw $0x4000,24(%rsp)
    movw $0x4000,40(%rsp)
    call __mulxc3
    fstpt 0(%rsp)
    fstpt 16(%rsp)
    movabsq $0x8000000000000000,%rax
    cmpq %rax,0(%rsp)
    jne 7f
    cmpq %rax,16(%rsp)
    jne 7f
    cmpw $0x4002,8(%rsp)
    jne 7f
    cmpw $0x4001,24(%rsp)
    jne 7f
    movw $0x4001,8(%rsp)
    movw $0x4000,24(%rsp)
    call __divxc3
    fstpt 0(%rsp)
    fstpt 16(%rsp)
    movabsq $0x8000000000000000,%rax
    cmpq %rax,0(%rsp)
    jne 7f
    cmpq %rax,16(%rsp)
    jne 7f
    cmpw $0x4000,8(%rsp)
    jne 7f
    cmpw $0x3fff,24(%rsp)
    jne 7f
    addq $64,%rsp
    jmp 8f
7:  addq $64,%rsp
    jmp 3f
8:  cmpq (%rsp),%rsp
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
.size crabc_x86_64_compiler_helper_registers,.-crabc_x86_64_compiler_helper_registers
