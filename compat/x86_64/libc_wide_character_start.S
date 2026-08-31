/* Test-only freestanding x86-64 entry for libc_wide_character_probe.c.
 * The fixture's selected write(2) result path shares the archive's initial
 * errno TLS slot. This scratch block is not a CRT or general TLS lifecycle.
 */

    .section .bss
    .balign 64
crabc_x86_64_wide_character_initial_tls:
    .zero 4096
crabc_x86_64_wide_character_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp

    lea crabc_x86_64_wide_character_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Ltls_failure
    mov %rsi, %fs:0

    and $-16, %rsp
    call crabc_x86_64_wide_character_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.Ltls_failure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
