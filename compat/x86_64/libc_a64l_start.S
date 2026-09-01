/* Test-only static x86-64 entry shim for libc_a64l_probe.c.
 *
 * The selected decoder and its strchr owner are stateless: no errno or TLS
 * setup is required. This aligns the initial stack, calls the C probe, and
 * exits directly; it is not CRT, pthread/TLS lifecycle, or application-startup
 * code.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_a64l_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
