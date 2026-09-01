/* Test-only static x86-64 entry shim for legacy signal aliases.
 *
 * signal() retains the selected initial-TLS errno path. This fixture creates
 * only enough Variant-II TLS scratch to execute that bounded candidate; it is
 * not a CRT, loader, or general TLS lifecycle.
 */

    .section .bss
    .balign 64
crabc_x86_64_signal_legacy_aliases_initial_tls:
    .zero 4096
crabc_x86_64_signal_legacy_aliases_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_signal_legacy_aliases_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* The selected initial-exec errno accessor reads %fs:0. */
    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_signal_legacy_aliases_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
