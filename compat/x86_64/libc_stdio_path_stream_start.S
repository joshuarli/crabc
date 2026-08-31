/* Test-only static x86-64 entry shim for libc_stdio_path_stream_probe.c.
 *
 * It hands the untouched Linux entry stack to the archive-owned initial TLS
 * bootstrap, then exits the one-process fixture through Linux exit_group.
 * No CRT, dynamic loader, or stdio ordinary-exit route is selected here.
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

    call crabc_x86_64_stdio_path_stream_probe
    mov %eax, %edi
    mov $231, %eax                 /* Linux x86-64 exit_group(2). */
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
