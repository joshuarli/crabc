/* Test-only static x86-64 entry shim for libc_ioctl_probe.c.
 *
 * The selected archive owns Static Initial TLS v1. This shim passes the
 * untouched Linux entry stack to the hidden owner before any C entry can touch
 * errno/TLS, then exits through Linux directly. It is not a CRT handoff.
 */

    .text
    .p2align 4
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* __crabc_x86_static_tls_bootstrap(original_rsp) == 0 on success. */
    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Ltls_failure

    call crabc_x86_64_ioctl_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
