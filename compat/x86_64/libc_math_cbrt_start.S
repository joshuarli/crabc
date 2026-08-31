/* Freestanding Linux/x86-64 start and raw record writer for cbrt/cbrtf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_cbrt_probe
    .extern crabc_x86_64_math_cbrt_records
_start:
    call crabc_x86_64_math_cbrt_probe
    testl %eax, %eax
    jnz .Lcrabc_cbrt_fail
    lea crabc_x86_64_math_cbrt_records(%rip), %rsi
    mov $5376, %edx
.Lcrabc_cbrt_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_cbrt_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_cbrt_write
    xorl %edi, %edi
.Lcrabc_cbrt_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
