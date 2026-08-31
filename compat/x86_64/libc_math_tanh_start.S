/* Freestanding Linux/x86-64 start and raw record writer for tanh/tanhf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_tanh_probe
    .extern crabc_x86_64_math_tanh_records
_start:
    call crabc_x86_64_math_tanh_probe
    testl %eax, %eax
    jnz .Lcrabc_tanh_fail
    lea crabc_x86_64_math_tanh_records(%rip), %rsi
    mov $8192, %edx
.Lcrabc_tanh_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_tanh_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_tanh_write
    xorl %edi, %edi
.Lcrabc_tanh_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
