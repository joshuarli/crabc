/* Freestanding static entry for libc_ns_get16_probe.c.
 *
 * ns_get16 reads only two caller-owned bytes. This fixture supplies stack
 * alignment and Linux exit plumbing; it is evidence glue, not CRT, resolver,
 * DNS, socket, or byte-order runtime behavior.
 */
    .text
#ifdef CRABC_NS_GET16_FREESTANDING
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_ns_get16_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
