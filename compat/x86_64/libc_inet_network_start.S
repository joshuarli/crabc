/* Freestanding static entry for libc_inet_network_probe.c.
 *
 * inet_network itself is a pure wrapper, but its explicit selected inet_addr
 * dependency retains the numeric parser's initial-TLS errno slot. Delegate
 * that fixed first-thread setup to its private bootstrap; this is evidence
 * glue, not a CRT or a resolver/TLS runtime.
 */
    .text
#ifdef CRABC_INET_NETWORK_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_inet_network_probe
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
