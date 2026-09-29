/* Write the complete raw record stream from the freestanding exp2 probe. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_exp2_probe
    .extern crabc_x86_64_math_exp2_records
    .extern crabc_x86_64_math_exp2_record_bytes
_start:
    /* Rust's local-exec errno accessor loads the self pointer at fs:0. */
    lea .Ltls_end(%rip), %rsi
    movq %rsi, (%rsi)
    mov $158, %eax
    mov $0x1002, %edi
    syscall
    testq %rax, %rax
    jnz .Lfail
    call crabc_x86_64_math_exp2_probe
    testl %eax, %eax
    jnz .Lfail
    lea crabc_x86_64_math_exp2_records(%rip), %rsi
    mov crabc_x86_64_math_exp2_record_bytes(%rip), %rdx
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
    .bss
    .balign 16
.Ltls:
    .skip 16
.Ltls_end:
    .skip 8
    .section .note.GNU-stack,"",@progbits
