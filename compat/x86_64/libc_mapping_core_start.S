/* Test-only static x86-64 entry shim for libc_mapping_core_probe.c.
 *
 * This selected archive currently provides only one initial-TLS errno datum.
 * The fixture supplies a scratch Variant-II %fs thread-pointer self word
 * before running its C body. It is not a CRT, dynamic-TLS, pthread, loader,
 * auxv, or application-startup implementation.
 */

    .section .bss
    .balign 64
crabc_x86_64_mapping_core_initial_tls:
    .zero 4096
crabc_x86_64_mapping_core_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    /* arch_prctl(ARCH_SET_FS, thread_pointer) = syscall 158. */
    lea crabc_x86_64_mapping_core_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure

    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_mapping_core_probe
    mov %eax, %edi
    mov $60, %eax
    syscall

.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
