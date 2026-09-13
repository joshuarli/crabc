.text
.globl _start
.type _start,@function
_start:
    andq $-16, %rsp
    call crabc_x86_64_compiler_helper_aggregate_probe
    testl %eax, %eax
    jne 1f
    movl $1, %edi
    leaq transcript(%rip), %rsi
    movl $29, %edx
    movl $1, %eax
    syscall
    xorl %edi, %edi
    jmp 2f
1:
    movl %eax, %edi
2:
    movl $60, %eax
    syscall
.size _start, .-_start
.section .rodata
transcript:
    .ascii "compiler-helper-aggregate-ok\n"
.section .note.GNU-stack,"",@progbits
