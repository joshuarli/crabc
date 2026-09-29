/* Write all 360 raw edge records from the freestanding exp2 probe. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_exp2_probe
    .extern crabc_x86_64_math_exp2_records
_start:
    call crabc_x86_64_math_exp2_probe
    testl %eax, %eax
    jnz .Lfail
    lea crabc_x86_64_math_exp2_records(%rip), %rsi
    mov $11520, %edx
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
