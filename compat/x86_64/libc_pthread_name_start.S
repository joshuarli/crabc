/* Test-only static x86-64 entry shim for bounded pthread task-name evidence.
 *
 * The libc-owned Static Initial TLS v1 hook establishes the one admitted
 * process-main pthread_self() identity. This shim deliberately owns no TCB,
 * generic TLS, task-name policy, or application-startup behavior of its own.
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

    call crabc_x86_64_pthread_name_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
