/* Freestanding static entry for libc_ns_get32_probe.c.
 *
 * ns_get32 reads only four caller-owned bytes. This fixture supplies stack
 * alignment and Linux exit plumbing; it is evidence glue, not CRT, resolver,
 * DNS, socket, or byte-order runtime behavior.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_ns_get32_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
