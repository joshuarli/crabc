/* Freestanding Linux/x86-64 start and raw record writer for log10/log10f. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_log10_probe
    .extern crabc_x86_64_math_log10_records
_start:
    call crabc_x86_64_math_log10_probe
    testl %eax, %eax
    jnz .Lcrabc_log10_fail
    lea crabc_x86_64_math_log10_records(%rip), %rsi
    mov $7168, %edx
.Lcrabc_log10_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_log10_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_log10_write
    xorl %edi, %edi
.Lcrabc_log10_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
