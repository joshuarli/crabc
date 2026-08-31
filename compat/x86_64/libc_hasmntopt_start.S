/* Test-only static x86-64 entry shim for libc_hasmntopt_probe.c.
 *
 * The selected caller-owned mntent option scan has no state, errno, or TLS.
 * This aligns the initial stack, runs the C probe, and exits; it is not CRT,
 * stdio, mount parsing, pathname policy, or application-startup code.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_hasmntopt_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
