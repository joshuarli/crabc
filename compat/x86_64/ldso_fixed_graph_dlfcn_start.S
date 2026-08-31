#if !defined(CRABC_FIXED_GRAPH_DLFCN_STRONG_IMPORT)
.weak __crabc_x86_64_fixed_graph_dlfcn_v1
#endif

.global crabc_fixed_graph_dlfcn_record
.type crabc_fixed_graph_dlfcn_record,@function
crabc_fixed_graph_dlfcn_record:
    mov __crabc_x86_64_fixed_graph_dlfcn_v1@GOTPCREL(%rip), %rax
    ret

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
