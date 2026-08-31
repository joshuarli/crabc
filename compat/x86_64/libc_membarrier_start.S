/* Test-only static x86-64 entry shim for libc_membarrier_probe.c.
 *
 * The direct error result requires the selected initial-TLS errno datum. This
 * fixture-local Variant-II scratch initializes only that slot; it supplies no
 * CRT, thread lifecycle, command registry, or barrier policy.
 */

    .section .bss
    .balign 64
crabc_x86_64_membarrier_initial_tls:
    .zero 4096
crabc_x86_64_membarrier_thread_pointer:
    .zero 64

    .text
    .p2align 4
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_membarrier_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* The selected initial-exec errno slot reads through %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_membarrier_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
