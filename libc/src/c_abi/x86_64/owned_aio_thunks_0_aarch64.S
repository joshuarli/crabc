
    .text
    .p2align 4
    .globl __crabc_x86_aio_cabi_malloc
    .hidden __crabc_x86_aio_cabi_malloc
    .type __crabc_x86_aio_cabi_malloc,%function
__crabc_x86_aio_cabi_malloc:
    b malloc
    .size __crabc_x86_aio_cabi_malloc, .-__crabc_x86_aio_cabi_malloc

    .p2align 4
    .globl __crabc_x86_aio_cabi_free
    .hidden __crabc_x86_aio_cabi_free
    .type __crabc_x86_aio_cabi_free,%function
__crabc_x86_aio_cabi_free:
    b free
    .size __crabc_x86_aio_cabi_free, .-__crabc_x86_aio_cabi_free

.section .note.GNU-stack,"",%progbits
