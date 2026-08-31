/* Test-only static x86-64 entry shim for permanent-stdin __freadable. */

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

    call crabc_x86_64_stdio_permanent_freadable_stdin_probe
    mov %eax, %edi
    mov $231, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $231, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
