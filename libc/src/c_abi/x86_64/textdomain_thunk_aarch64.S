
    .text
    .p2align 4
    .globl __crabc_x86_textdomain_cabi_malloc
    .hidden __crabc_x86_textdomain_cabi_malloc
    .type __crabc_x86_textdomain_cabi_malloc,%function
__crabc_x86_textdomain_cabi_malloc:
    b malloc
    .size __crabc_x86_textdomain_cabi_malloc, .-__crabc_x86_textdomain_cabi_malloc

.section .note.GNU-stack,"",%progbits
