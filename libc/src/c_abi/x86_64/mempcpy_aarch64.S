// musl 1.2.6 src/string/mempcpy.c; MIT license.
.text
.global mempcpy
.type mempcpy,%function
mempcpy:
 stp x19, x30, [sp, #-16]!
 add x19, x0, x2
 bl memcpy
 mov x0, x19
 ldp x19, x30, [sp], #16
 ret
.size mempcpy, .-mempcpy
.section .note.GNU-stack,"",%progbits
