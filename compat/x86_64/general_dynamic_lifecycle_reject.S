/* Negative entry shims only. Production Scrt1 is unchanged. */
.text
.global lifecycle_null_finalizer
.type lifecycle_null_finalizer,@function
lifecycle_null_finalizer:
    xor %edx,%edx
    jmp _start
.size lifecycle_null_finalizer,.-lifecycle_null_finalizer

.global lifecycle_missing_random
.type lifecycle_missing_random,@function
lifecycle_missing_random:
    mov (%rsp),%rax
    lea 16(%rsp,%rax,8),%rax
1:  cmpq $0,(%rax)
    lea 8(%rax),%rax
    jne 1b
2:  cmpq $0,(%rax)
    je 4f
    cmpq $25,(%rax)
    je 3f
    add $16,%rax
    jmp 2b
3:  movq $0,8(%rax)
4:  jmp _start
.size lifecycle_missing_random,.-lifecycle_missing_random
.section .note.GNU-stack,"",@progbits
