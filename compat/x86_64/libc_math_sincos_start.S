/* Freestanding Linux/x86-64 start and raw record writer for sincos/sincosf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_sincos_probe
    .extern crabc_x86_64_math_sincos_records
_start:
    call crabc_x86_64_math_sincos_probe
    testl %eax, %eax
    jnz .Lcrabc_sincos_fail
    lea crabc_x86_64_math_sincos_records(%rip), %rsi
    mov $20480, %edx
.Lcrabc_sincos_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_sincos_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_sincos_write
    xorl %edi, %edi
.Lcrabc_sincos_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
