    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_atomic_addressable_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
