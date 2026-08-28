/* Freestanding x86-64 entry for the static C11 immediate-termination fixture. */

    .text
    .globl _start
    .type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_immediate_termination_probe
    movl %eax, %edi
    movl $60, %eax
    syscall
    .size _start, .-_start
