/* Candidate-only static x86-64 startup for native-mimalloc teardown evidence.
 *
 * libc owns the real initial TLS setup and the normal process startup. The
 * one pre-start call deliberately happens after that TLS setup but before
 * __libc_start_main so the fixture can exercise Inactive attach rejection.
 */

    .text
    .globl _start
    .type _start,@function
_start:
    mov %rsp, %r12
    xor %ebp, %ebp
    and $-16, %rsp

    mov %r12, %rdi
    call __crabc_x86_static_tls_bootstrap
    test %eax, %eax
    jne .Lstartup_failure

    call crabc_x86_64_native_mimalloc_shadow_prestart_rejection
    test %eax, %eax
    jne .Lprestart_failure

    lea main(%rip), %rdi
    mov (%r12), %esi
    lea 8(%r12), %rdx
    xor %ecx, %ecx
    xor %r8d, %r8d
    xor %r9d, %r9d
    call __libc_start_main
    ud2

.Lstartup_failure:
    mov $127, %edi
    jmp .Lexit_group

.Lprestart_failure:
    mov $126, %edi
.Lexit_group:
    mov $231, %eax
    syscall
    ud2
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
