/* Freestanding static entry for libc_nameser_wire_aggregate_probe.c.
 *
 * The composed ns_skiprr malformed-RR path publishes EMSGSIZE through the
 * selected initial-TLS errno slot. Materialize only that static TLS image
 * before the caller-owned nameser transaction; this is evidence glue, not a
 * CRT, resolver runtime, or general TLS implementation.
 */
    .text
#ifdef CRABC_NAMESER_WIRE_AGGREGATE_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_nameser_wire_aggregate_probe
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
