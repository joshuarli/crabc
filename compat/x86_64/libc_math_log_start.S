/* Freestanding Linux/x86-64 start and raw record writer for log/logf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_log_probe
    .extern crabc_x86_64_math_log_records
_start:
    call crabc_x86_64_math_log_probe
    testl %eax, %eax
    jnz .Lcrabc_log_fail
    lea crabc_x86_64_math_log_records(%rip), %rsi
    mov $7168, %edx
.Lcrabc_log_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_log_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_log_write
    xorl %edi, %edi
.Lcrabc_log_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
