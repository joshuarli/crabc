/* Freestanding static entry for libc_in6addr_loopback_probe.c.
 *
 * in6addr_loopback is an immutable, dependency-free data object. This only
 * establishes the stack alignment needed by the C fixture and exits through
 * Linux; it is evidence glue, not CRT, TLS, resolver, or socket runtime.
 */
    .text
#ifdef CRABC_IN6ADDR_LOOPBACK_FREESTANDING
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_in6addr_loopback_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
