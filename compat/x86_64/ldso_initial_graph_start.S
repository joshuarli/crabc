#if defined(__aarch64__)
.global _start
.type _start,%function
_start:
    mov x29, xzr
    ldr x0, [sp]
    add x1, sp, #8
    bl main
    mov x8, #93
    svc #0
#else
.global _start
.type _start,@function
_start:
    xor %rbp, %rbp
    mov (%rsp), %rdi
    lea 8(%rsp), %rsi
    call main
    mov %eax, %edi
    mov $60, %eax
    syscall
#endif
