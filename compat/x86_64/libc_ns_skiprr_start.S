/* Freestanding static entry for libc_ns_skiprr_probe.c.
 *
 * ns_skiprr preserves musl's EMSGSIZE publication through the selected
 * initial-TLS errno slot. Materialize only that project-owned static TLS image
 * before calling the caller-owned wire-span fixture; this is evidence glue,
 * not a CRT, resolver runtime, or general TLS implementation.
 */
    .text
#ifdef CRABC_NS_SKIPRR_FREESTANDING
    .global _start
    .type _start,@function
_start:
    mov %rsp, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne 1f
    call crabc_x86_64_ns_skiprr_probe
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
