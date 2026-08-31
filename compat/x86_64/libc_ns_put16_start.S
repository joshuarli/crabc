/* Freestanding static entry for libc_ns_put16_probe.c.
 *
 * ns_put16 writes only two caller-owned bytes. This fixture supplies stack
 * alignment and Linux exit plumbing; it is evidence glue, not CRT, resolver,
 * DNS, socket, or byte-order runtime behavior.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_ns_put16_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
