/* Test-only static x86-64 entry shim for libc_sync_probe.c.
 *
 * The selected void sync request has no errno or TLS state. This aligns the
 * initial stack, runs the C probe, and exits; it is not CRT, a filesystem
 * policy layer, or application-startup code.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_sync_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
