/* Freestanding Linux/x86-64 entry for the all-provider math aggregate. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_math_elementary_fenv_sensitive_aggregate_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
