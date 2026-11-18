// musl 1.2.6 src/string/bcmp.c; MIT license.
.text
.global bcmp
.type bcmp,%function
bcmp:
 b memcmp
.size bcmp, .-bcmp
.section .note.GNU-stack,"",%progbits
