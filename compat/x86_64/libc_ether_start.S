/* Freestanding static entry for libc_ether_probe.c.
 *
 * The ether_aton parser deliberately composes the selected strtoul errno
 * boundary. Set up that archive's initial TLS storage before the C fixture;
 * this is test-only glue, not CRT or a general TLS runtime.
 */
    .text
#ifdef CRABC_ETHER_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_ether_probe
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
