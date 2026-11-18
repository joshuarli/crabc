// musl 1.2.6 src/multibyte/c32rtomb.c; MIT license.
.text
.global c32rtomb
.type c32rtomb,%function
c32rtomb:
 b wcrtomb
.size c32rtomb, .-c32rtomb
.section .note.GNU-stack,"",%progbits
