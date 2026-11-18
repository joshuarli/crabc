// musl 1.2.6 src/signal/siglongjmp.c; MIT license.
.text
.global siglongjmp
.type siglongjmp,%function
siglongjmp:
    b longjmp
.size siglongjmp, .-siglongjmp
.section .note.GNU-stack,"",%progbits
