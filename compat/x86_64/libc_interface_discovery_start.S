/* Freestanding static entry for libc_interface_discovery_probe.c. */
    .text
#ifdef CRABC_INTERFACE_DISCOVERY_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_interface_discovery_probe
    mov %eax, %edi
    mov $231, %eax
    syscall
1:
    mov $127, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
