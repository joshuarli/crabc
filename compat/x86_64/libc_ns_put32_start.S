/* Freestanding static entry for libc_ns_put32_probe.c.
 *
 * ns_put32 writes only four caller-owned bytes. This fixture supplies stack
 * storage through its C body and exits directly, so it needs no CRT, TLS, or
 * libc startup path.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %rbp, %rbp
    and $-16, %rsp
    call crabc_x86_64_ns_put32_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
