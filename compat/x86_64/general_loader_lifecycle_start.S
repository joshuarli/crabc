.text
.global _start
.type _start,@function
_start:
    xor %ebp, %ebp
    mov %rdx, %rdi
    and $-16, %rsp
    call lifecycle_main
    mov %eax, %edi
    mov $231, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
