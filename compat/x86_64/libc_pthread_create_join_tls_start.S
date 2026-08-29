/* Test-only static x86-64 entry shim for the bounded pthread worker slice.
 *
 * Keep the kernel entry stack intact long enough for the libc-owned Static
 * Initial TLS v1 hook to validate and materialize this final executable's
 * PT_TLS image. The hook, rather than fixture-local arithmetic, establishes
 * the main Variant-II %fs base and retains the template that workers receive
 * through CLONE_SETTLS. This remains a fixture, not a general CRT or loader.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* Pass the untouched Linux initial stack to the hidden libc TLS hook. */
    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    js .Ltls_failure

    call crabc_x86_64_pthread_create_join_tls_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
