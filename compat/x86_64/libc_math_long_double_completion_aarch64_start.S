/* Freestanding ARM64 entry for the binary128 math differential. */
    .text
    .global _start
    .type _start,%function
_start:
    bl crabc_x86_64_math_long_double_completion_probe
    mov x8, #93
    svc #0
    .size _start,.-_start
    .section .note.GNU-stack,"",%progbits
