/* Test-only static x86-64 entry shim for libc_stdio_standard_probe.c.
 *
 * The permanent stream candidate owns initial TLS and the process-local
 * standard FILE state.  Keep the kernel entry stack intact long enough to
 * hand it to the hidden libc owner, then exit the one-process fixture through
 * Linux exit_group rather than a CRT or stdio-exit path.
 */

    .text
    .p2align 4
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* Pass the untouched Linux entry stack before realigning for calls. */
    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Ltls_failure

    call crabc_x86_64_stdio_standard_probe
    mov %eax, %edi
    mov $231, %eax                 /* Linux x86-64 exit_group(2). */
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
