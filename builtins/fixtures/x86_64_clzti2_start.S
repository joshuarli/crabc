.text
.globl _start
.type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_clzti2_probe
    movl %eax, %edi
    movl $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
