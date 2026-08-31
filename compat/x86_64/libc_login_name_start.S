/* Test-only static x86-64 entry for the login-name differential fixture. */
    .section .bss
    .balign 64
crabc_x86_64_login_name_initial_tls:
    .zero 4096
crabc_x86_64_login_name_thread_pointer:
    .zero 64

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    lea crabc_x86_64_login_name_thread_pointer(%rip), %rsi
    mov $0x1002, %edi
    mov $158, %eax
    syscall
    test %rax, %rax
    js .Lfailure
    mov %rsi, %fs:0
    and $-16, %rsp
    call crabc_x86_64_login_name_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.Lfailure:
    mov $127, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
