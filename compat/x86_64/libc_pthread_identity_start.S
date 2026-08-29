/* Test-only static x86-64 entry shim for public pthread identity evidence.
 *
 * The libc-owned Static Initial TLS v1 hook installs the main thread image;
 * this shim deliberately does not construct an FS base or CRT state itself.
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

    call crabc_x86_64_pthread_identity_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
