/* Freestanding Linux/x86-64 output shim for the owned inverse-trig probe. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_owned_inverse_trig_probe
    .extern crabc_x86_64_owned_inverse_trig_records
    .extern crabc_x86_64_owned_inverse_trig_records_bytes
_start:
    call crabc_x86_64_owned_inverse_trig_probe
    testl %eax, %eax
    jnz .Lcrabc_owned_inverse_trig_exit
    lea crabc_x86_64_owned_inverse_trig_records(%rip), %rsi
    mov crabc_x86_64_owned_inverse_trig_records_bytes(%rip), %rdx
.Lcrabc_owned_inverse_trig_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_owned_inverse_trig_exit
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_owned_inverse_trig_write
    xorl %edi, %edi
.Lcrabc_owned_inverse_trig_exit:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
