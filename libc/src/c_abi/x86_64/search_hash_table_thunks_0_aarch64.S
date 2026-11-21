
    .text
    .p2align 4
    .globl __crabc_x86_hsearch_cabi_calloc
    .hidden __crabc_x86_hsearch_cabi_calloc
    .type __crabc_x86_hsearch_cabi_calloc,%function
__crabc_x86_hsearch_cabi_calloc:
    b calloc
    .size __crabc_x86_hsearch_cabi_calloc, .-__crabc_x86_hsearch_cabi_calloc

    .p2align 4
    .globl __crabc_x86_hsearch_cabi_free
    .hidden __crabc_x86_hsearch_cabi_free
    .type __crabc_x86_hsearch_cabi_free,%function
__crabc_x86_hsearch_cabi_free:
    b free
    .size __crabc_x86_hsearch_cabi_free, .-__crabc_x86_hsearch_cabi_free

.section .note.GNU-stack,"",%progbits
