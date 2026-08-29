/* Test-only static x86-64 entry shim for selected signal execution.
 *
 * The archive owns one initial-TLS errno datum while CRT/loader remain
 * unselected. This fixture-only entry creates a zeroed x86 Variant-II scratch
 * block and writes its self pointer at %fs:0 before entering the C probe.
 * It is not general startup or a pthread/TLS lifecycle.
 */

    .section .bss
    .balign 64
crabc_x86_64_signal_execution_initial_tls:
    .zero 4096
crabc_x86_64_signal_execution_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_signal_execution_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* x86 initial-exec errno code reads its thread pointer from %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_signal_execution_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
