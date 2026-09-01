/* Freestanding entry for the x86-64 fopen64 macro-alias fixture.
 *
 * The macro routes only to the existing bounded `fopen` owner, whose error
 * results use Static Initial TLS errno. The archive owns that bootstrap; this
 * fixture preserves the kernel entry stack until the bootstrap consumes it.
 */
    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp,%ebp
    mov %rsp,%rdi
    and $-16,%rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax,%eax
    jne .Ltls_failure
    call crabc_x86_64_fopen64_alias_probe
    mov %eax,%edi
    mov $231,%eax
    syscall
.Ltls_failure:
    mov $127,%edi
    mov $231,%eax
    syscall
    .size _start,.-_start

    .section .note.GNU-stack,"",@progbits
