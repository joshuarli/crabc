/* Fixture-only initial-TLS entry for the static getpass candidate.
 * Linux ARCH_SET_FS is 0x1002 for the x86-64 arch_prctl syscall. */

    .section .bss
    .balign 64
crabc_x86_64_getpass_initial_tls:
    .zero 4096
crabc_x86_64_getpass_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    lea crabc_x86_64_getpass_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure
    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_getpass_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
