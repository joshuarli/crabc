/* Freestanding writer for the exact pow edge record stream. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_pow_probe
    .extern crabc_x86_64_math_pow_records
    .extern crabc_x86_64_math_pow_record_bytes
_start:
    call crabc_x86_64_math_pow_probe
    testl %eax, %eax
    jnz .Lfail
    lea crabc_x86_64_math_pow_records(%rip), %rsi
    mov crabc_x86_64_math_pow_record_bytes(%rip), %rdx
.Lwrite:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lfail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lwrite
    xorl %edi, %edi
.Lfail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
