/* Freestanding static entry for libc_dn_skipname_probe.c.
 *
 * The selected leaf examines only caller-owned bytes. This fixture supplies
 * stack alignment and Linux exit plumbing; it is not CRT, TLS, resolver, or
 * socket runtime behavior.
 */
    .text
#ifdef CRABC_DN_SKIPNAME_FREESTANDING
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_dn_skipname_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
#endif
    .section .note.GNU-stack,"",@progbits
