.weak __crabc_x86_64_fixed_graph_introspection_v1

.global crabc_fixed_graph_introspection_record
.type crabc_fixed_graph_introspection_record,@function
crabc_fixed_graph_introspection_record:
    mov __crabc_x86_64_fixed_graph_introspection_v1@GOTPCREL(%rip), %rax
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
