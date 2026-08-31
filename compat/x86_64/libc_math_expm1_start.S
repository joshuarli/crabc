/* Freestanding Linux/x86-64 start and raw record writer for expm1/expm1f. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_expm1_probe
    .extern crabc_x86_64_math_expm1_records
_start:
    call crabc_x86_64_math_expm1_probe
    testl %eax, %eax
    jnz .Lcrabc_expm1_fail
    lea crabc_x86_64_math_expm1_records(%rip), %rsi
    mov $7936, %edx
.Lcrabc_expm1_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_expm1_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_expm1_write
    xorl %edi, %edi
.Lcrabc_expm1_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
