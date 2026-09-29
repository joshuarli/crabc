/* Freestanding Linux/x86-64 start and raw record writer for exp2/exp2f. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_exp2_probe
    .extern crabc_x86_64_math_exp2_records
    .extern crabc_x86_64_math_exp2_record_bytes
_start:
    /* Rust's local-exec errno accessor loads the self pointer at fs:0. */
    lea .Lcrabc_exp2_tls_end(%rip), %rsi
    movq %rsi, (%rsi)
    mov $158, %eax
    mov $0x1002, %edi
    syscall
    testq %rax, %rax
    jnz .Lcrabc_exp2_fail
    call crabc_x86_64_math_exp2_probe
    testl %eax, %eax
    jnz .Lcrabc_exp2_fail
    lea crabc_x86_64_math_exp2_records(%rip), %rsi
    mov crabc_x86_64_math_exp2_record_bytes(%rip), %rdx
.Lcrabc_exp2_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_exp2_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_exp2_write
    xorl %edi, %edi
.Lcrabc_exp2_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .bss
    .balign 16
.Lcrabc_exp2_tls:
    .skip 16
.Lcrabc_exp2_tls_end:
    .skip 8
    .section .note.GNU-stack,"",@progbits
