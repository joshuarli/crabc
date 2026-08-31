/* Freestanding Linux/x86-64 start and raw record writer for sin/sinf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_sin_probe
    .extern crabc_x86_64_math_sin_records
_start:
    call crabc_x86_64_math_sin_probe
    testl %eax, %eax
    jnz .Lcrabc_sin_fail
    lea crabc_x86_64_math_sin_records(%rip), %rsi
    mov $8192, %edx
.Lcrabc_sin_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_sin_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_sin_write
    xorl %edi, %edi
.Lcrabc_sin_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
