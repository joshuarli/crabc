/* Test-only static x86-64 entry shim for libc_memory_search_probe.c.
 *
 * The selected bounded search functions are stateless and require no errno,
 * TLS, CRT, or runtime initialization.  This shim only calls the probe and
 * exits through the Linux x86-64 exit syscall.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_memory_search_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
