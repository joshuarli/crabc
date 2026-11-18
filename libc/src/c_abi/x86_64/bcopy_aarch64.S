// musl 1.2.6 src/string/bcopy.c; MIT license.
.text
.global bcopy
.type bcopy,%function
bcopy:
 mov x3, x0
 mov x0, x1
 mov x1, x3
 b memmove
.size bcopy, .-bcopy
.section .note.GNU-stack,"",%progbits
