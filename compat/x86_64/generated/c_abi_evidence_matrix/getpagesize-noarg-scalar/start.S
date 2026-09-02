# Generated from c_abi_evidence_matrix.toml and family fragments; do not edit.
.text
.globl _start
.type _start,@function
_start:
    call getpagesize
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start, .-_start
