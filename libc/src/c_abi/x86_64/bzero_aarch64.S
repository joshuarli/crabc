// musl 1.2.6 src/string/bzero.c; MIT license.
.text
.global bzero
.type bzero,%function
bzero:
 mov x2, x1
 mov x1, xzr
 b memset
.size bzero, .-bzero
.section .note.GNU-stack,"",%progbits
