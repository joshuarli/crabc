/* Test-only static x86-64 entry shim for libc_socket_messages_probe.c.
 *
 * This fixture supplies the selected archive's initial-exec errno TLS scratch
 * image. It is not a CRT, pthread/TLS lifecycle, dynamic TLS, loader, or
 * application-startup implementation.
 */

    .section .bss
    .balign 64
crabc_x86_64_socket_messages_initial_tls:
    .zero 4096
crabc_x86_64_socket_messages_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_socket_messages_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_socket_messages_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
