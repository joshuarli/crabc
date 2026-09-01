/* Freestanding Linux/x86-64 entry for the binary80 math differential. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_long_double_completion_probe
_start:
    call crabc_x86_64_math_long_double_completion_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
