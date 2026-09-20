/* Test-only static x86-64 entry shim for libc_bsd_random_probe.c. */

    .text
    .globl _start
    .type _start,@function
_start:
    xor %ebp, %ebp
    and $-16, %rsp
    call crabc_x86_64_bsd_random_probe
    test %eax, %eax
    jne 1f
    mov $1, %eax
    mov $1, %edi
    lea crabc_x86_64_bsd_random_trace(%rip), %rsi
    mov $4096, %edx
    syscall
    cmp $4096, %eax
    je 2f
    mov $22, %edi
    jmp 3f
1:
    mov %eax, %edi
    jmp 3f
2:
    xor %edi, %edi
3:
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
