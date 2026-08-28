/* Test-only static x86-64 entry shim for libc_byte_strings_probe.c.
 *
 * The closed byte-string leaf selects no errno or TLS state. This shim only
 * aligns the initial stack, calls the probe, and exits. It is not a CRT,
 * pthread/TLS lifecycle, dynamic loader, or application-startup
 * implementation.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_byte_strings_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
