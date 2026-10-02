/* Freestanding entry for the ordinary power-identity C consumer. */
    .text
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_math_pow_identity110_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
