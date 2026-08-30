/* Test-only x86-64 entry shim for the static text/math/locale/stdio
 * composition fixture.  It gives the untouched Linux entry stack to the
 * archive-owned Static Initial TLS v1 bootstrap; it is not a CRT claim. */

    .text
    .p2align 4
    .global _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Ltls_failure
    call crabc_x86_64_text_math_locale_stdio_composition_probe
    mov %eax, %edi
    mov $231, %eax                 /* Linux x86-64 exit_group(2). */
    syscall
.Ltls_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
