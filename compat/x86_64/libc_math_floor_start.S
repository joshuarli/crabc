/* Freestanding Linux/x86-64 start and raw record writer for floor/floorf. */
    .text
    .global _start
    .type _start,@function
    .extern crabc_x86_64_math_floor_probe
    .extern crabc_x86_64_math_floor_records
_start:
    call crabc_x86_64_math_floor_probe
    testl %eax, %eax
    jnz .Lcrabc_floor_fail
    lea crabc_x86_64_math_floor_records(%rip), %rsi
    mov $6912, %edx
.Lcrabc_floor_write:
    mov $1, %eax
    mov $1, %edi
    syscall
    testq %rax, %rax
    jle .Lcrabc_floor_fail
    addq %rax, %rsi
    subq %rax, %rdx
    jne .Lcrabc_floor_write
    xorl %edi, %edi
.Lcrabc_floor_fail:
    mov $60, %eax
    syscall
    ud2
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
