/* Freestanding Linux/x86-64 entry and exact binary80 record writer. */
    .text
    .globl _start
    .type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_math_sincosl_probe
    testl %eax, %eax
    jnz .Lfail
    lea crabc_x86_64_math_sincosl_records(%rip), %rsi
    mov $16384, %edx
.Lwrite:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lfail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lwrite
    xorl %edi, %edi
.Lfail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
