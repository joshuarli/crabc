/* Freestanding static entry for libc_dn_expand_probe.c.
 *
 * The selected leaf uses only caller-owned input/output byte spans. This
 * fixture requires no errno or TLS bootstrap and exits directly through the
 * Linux x86-64 syscall ABI.
 */
    .text
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_dn_expand_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
