/* Freestanding static entry for libc_hstrerror_probe.c. */
    .text
#ifdef CRABC_HSTRERROR_FREESTANDING
    .global _start
    .type _start,@function
_start:
    call crabc_x86_64_hstrerror_probe
    mov %eax, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
