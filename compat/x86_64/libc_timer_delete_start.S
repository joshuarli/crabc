/* Test-only static x86-64 entry shim for libc_timer_delete_probe.c.
 *
 * The timer_delete leaf itself has no errno/TLS path. This fixture needs the
 * initial-TLS errno slot only to prove that its sentinel is unchanged, so it
 * supplies a scratch Variant-II %fs thread-pointer self word before its C
 * body. It is not a CRT, dynamic-TLS, pthread, timer, loader, or startup
 * runtime.
 */

    .section .bss
    .balign 64
crabc_x86_64_timer_delete_initial_tls:
    .zero 4096
crabc_x86_64_timer_delete_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_timer_delete_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    /* x86 initial-exec errno reads the self word from %fs:0. */
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_timer_delete_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
