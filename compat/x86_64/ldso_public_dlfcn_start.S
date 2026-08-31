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

/*
 * Start one TLS-free Linux thread on caller-owned storage. The kernel writes
 * and later clears child_tid, so the fixture can prove the child has exited
 * without selecting pthread/TLS or an ambient libc.
 */
.global crabc_spawn_dlfcn_thread
.type crabc_spawn_dlfcn_thread,@function
crabc_spawn_dlfcn_thread:
    and $-16, %rdx
    sub $16, %rdx
    mov %rdi, (%rdx)
    mov %rsi, 8(%rdx)
    mov %rcx, %r10
    mov %rdx, %rsi
    xor %edx, %edx
    xor %r8d, %r8d
    mov $0x350f00, %edi
    mov $56, %eax
    syscall
    test %rax, %rax
    jne 1f
    xor %ebp, %ebp
    mov 8(%rsp), %rdi
    call *(%rsp)
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
1:
    ret
