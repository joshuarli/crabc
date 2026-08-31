/* Pinned musl 1.2.6 src/locale/strtod_l.c wrapper and weak-alias shape. */
    .text
    .section .text.strtof_l,"ax",@progbits
    .globl strtof_l
    .type strtof_l,@function
strtof_l:
    jmp strtof
    .size strtof_l, .-strtof_l
    .weak __strtof_l
    .set __strtof_l, strtof_l

    .section .text.strtod_l,"ax",@progbits
    .globl strtod_l
    .type strtod_l,@function
strtod_l:
    jmp strtod
    .size strtod_l, .-strtod_l
    .weak __strtod_l
    .set __strtod_l, strtod_l

    .section .text.strtold_l,"ax",@progbits
    .globl strtold_l
    .type strtold_l,@function
strtold_l:
    jmp strtold
    .size strtold_l, .-strtold_l
    .weak __strtold_l
    .set __strtold_l, strtold_l

    .section .note.GNU-stack,"",@progbits
