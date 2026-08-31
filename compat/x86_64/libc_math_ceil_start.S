/* Freestanding Linux/x86-64 start and raw record writer for ceil/ceilf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_ceil_probe
    .extern crabc_x86_64_math_ceil_records
_start:
    call crabc_x86_64_math_ceil_probe
    testl %eax, %eax
    jnz .Lcrabc_ceil_fail
    lea crabc_x86_64_math_ceil_records(%rip), %rsi
    mov $6912, %edx
.Lcrabc_ceil_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_ceil_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_ceil_write
    xorl %edi, %edi
.Lcrabc_ceil_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
