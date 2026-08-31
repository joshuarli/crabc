/* Freestanding Linux/x86-64 start and raw record writer for round/roundf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_round_probe
    .extern crabc_x86_64_math_round_records
_start:
    call crabc_x86_64_math_round_probe
    testl %eax, %eax
    jnz .Lcrabc_round_fail
    lea crabc_x86_64_math_round_records(%rip), %rsi
    mov $6912, %edx
.Lcrabc_round_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_round_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_round_write
    xorl %edi, %edi
.Lcrabc_round_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
