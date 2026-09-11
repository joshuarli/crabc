/* Raw process boundary: no CRT, TLS, host libc, or allocator. */
.text
.global _start
.type _start,@function
_start:
    call math_scalar_corrections_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
