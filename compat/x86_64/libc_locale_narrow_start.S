/* Test-only static entry for fixed-locale narrow text evidence. */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    mov %rsp, %rdi
    and $-16, %rsp
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Lfailure
    call crabc_x86_64_locale_narrow_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.Lfailure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
