/* Freestanding static entry for libc_nameser_message_parser_probe.c.
 *
 * The selected malformed DNS-message paths publish errno through the existing
 * initial-TLS x86 slot. Materialize only that selected TLS image before this
 * caller-owned parser transaction; this is not a CRT or resolver runtime.
 */
    .text
#ifdef CRABC_NAMESER_MESSAGE_PARSER_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_nameser_message_parser_probe
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
