.text
.global _start
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_binary32_casts_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.section .note.GNU-stack,"",@progbits
