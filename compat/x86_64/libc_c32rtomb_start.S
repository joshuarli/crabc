/* Test-only static x86-64 entry shim for libc_c32rtomb_probe.c.
 *
 * c32rtomb delegates to the established fixed-profile wcrtomb owner, whose
 * EILSEQ paths use the selected initial-exec errno slot. This fixture supplies
 * only bounded scratch initial TLS; it is not a CRT or general TLS proof.
 */

    .section .bss
    .balign 64
crabc_x86_64_c32rtomb_initial_tls:
    .zero 4096
crabc_x86_64_c32rtomb_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_c32rtomb_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* Initial-exec errno code reads its thread pointer from %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_c32rtomb_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
