/* Test-only static x86-64 entry shim for deferred pthread cancellation.
 *
 * The libc-owned Static Initial TLS v1 hook consumes the untouched Linux entry
 * stack and establishes the main Variant-II %fs base before this fixture calls
 * any selected pthread or errno entry point. This is neither a CRT nor a
 * fallback TLS implementation.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    js .Ltls_failure

    call crabc_x86_64_pthread_cancel_deferred_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
