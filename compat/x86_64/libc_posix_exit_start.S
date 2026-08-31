/* Freestanding x86-64 entry for the static POSIX _exit fixture. */

    .text
    .globl _start
    .type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_posix_exit_probe
    movl %eax, %edi
    movl $60, %eax
    syscall
    .size _start, .-_start
