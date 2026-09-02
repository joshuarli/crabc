/* Test-only static x86-64 entry shim for the stateful byte-string fixture. */
    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_stateful_byte_strings_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start
    .section .note.GNU-stack,"",@progbits
