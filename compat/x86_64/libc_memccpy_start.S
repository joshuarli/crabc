/* Test-only static x86-64 entry shim for libc_memccpy_probe.c.
 *
 * The selected bounded byte-transfer leaf has no state, errno, TLS, CRT, or
 * runtime initialization. This shim only calls the probe and exits through
 * the Linux x86-64 exit syscall; it is not application startup.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_memccpy_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
