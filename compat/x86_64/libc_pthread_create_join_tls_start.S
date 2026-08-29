/* Test-only static x86-64 entry shim for the bounded pthread worker slice.
 *
 * The selected archive owns one initial-TLS errno datum. The full x86 CRT and
 * loader remain unselected, so this fixture establishes only the main
 * thread's Variant-II %fs:0 self word before it invokes the C body. Workers
 * receive their own equivalent private TLS images through CLONE_SETTLS in the
 * selected artifact; this file is not a CRT or pthread lifecycle.
 */

    .section .bss
    .balign 64
crabc_x86_64_pthread_create_join_tls_initial_tls:
    .zero 4096
crabc_x86_64_pthread_create_join_tls_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_pthread_create_join_tls_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* x86 initial-exec errno code reads its thread pointer from %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_pthread_create_join_tls_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
