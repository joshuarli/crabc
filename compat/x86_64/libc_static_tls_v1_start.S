/* Test-only entry shim for x86 Static Initial TLS v1.
 *
 * Unlike older errno fixture shims, this does not synthesize a BSS TLS block.
 * It passes the untouched initial stack to the hidden libc owner so the
 * candidate validates and copies its real final-executable PT_TLS template.
 * It is not a general CRT, loader, dynamic TLS, or sysroot startup path.
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

    call crabc_x86_64_static_tls_v1_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
