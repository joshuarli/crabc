/* Freestanding entry for the bounded x86-64 tmpfile fixture.
 * The archive owns the Static Initial TLS v1 bootstrap; this fixture retains
 * the kernel entry stack unchanged until that helper consumes it.
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
    call crabc_x86_64_stdio_tmpfile_probe
    mov %eax,%edi
    mov $231,%eax
    syscall
.Ltls_failure:
    mov $127,%edi
    mov $231,%eax
    syscall
    .size _start,.-_start

    .section .note.GNU-stack,"",@progbits
