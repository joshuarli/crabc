/* Freestanding Linux/x86-64 start and raw record writer for pow/powf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_pow_probe
    .extern crabc_x86_64_math_pow_records
_start:
    call crabc_x86_64_math_pow_probe
    testl %eax, %eax
    jnz .Lcrabc_pow_fail
    lea crabc_x86_64_math_pow_records(%rip), %rsi
    mov $10240, %edx
.Lcrabc_pow_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_pow_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_pow_write
    xorl %edi, %edi
.Lcrabc_pow_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
