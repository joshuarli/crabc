/* Freestanding static entry for libc_inet_address_probe.c.
 *
 * The selected archive owns initial-TLS errno storage. Delegate first-thread
 * setup to its private bootstrap before the project-header C fixture; this is
 * evidence-only glue, not a CRT or general TLS runtime.
 */
    .text
#ifdef CRABC_INET_ADDRESS_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_inet_address_probe
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
