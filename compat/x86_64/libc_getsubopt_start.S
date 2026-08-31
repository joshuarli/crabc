/* Freestanding static entry for libc_getsubopt_probe.c. */
    .text
#ifdef CRABC_GETSUBOPT_FREESTANDING
    .global _start
    .type _start,@function
_start:
    call crabc_x86_64_getsubopt_probe
    mov %eax, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
