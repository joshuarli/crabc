/* Test-only static x86-64 entry shim for psignal/psiginfo.
 *
 * The reporting leaf preserves C errno, so this fixture uses the selected
 * Static Initial TLS v1 bootstrap before entering its C body.  This is not a
 * general CRT or signal/stdio runtime transition.
 */

    .text
    .p2align 4
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Ltls_failure

    call crabc_x86_64_psignal_probe
    mov %eax, %edi
    mov $231, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
