/* Freestanding static entry for libc_ns_flagdata_probe.c.
 *
 * _ns_flagdata is immutable nameserver accessor data. This only establishes
 * the C fixture stack alignment and exits through Linux; it is evidence glue,
 * not CRT, TLS, parser, resolver, or socket runtime behavior.
 */
    .text
#ifdef CRABC_NS_FLAGDATA_FREESTANDING
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_ns_flagdata_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
