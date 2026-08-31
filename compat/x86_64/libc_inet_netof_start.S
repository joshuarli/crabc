/* Test-only static x86-64 entry shim for libc_inet_netof_probe.c.
 *
 * The selected classful IPv4 network-part leaf has no state, errno, or TLS.
 * This aligns the initial stack, runs the C probe, and exits; it is not CRT,
 * pthread/TLS lifecycle, resolver, or application-startup code.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_inet_netof_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
