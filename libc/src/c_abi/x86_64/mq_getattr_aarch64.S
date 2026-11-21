// musl 1.2.6 src/mq/mq_getattr.c; MIT license.
.text
.global mq_getattr
.type mq_getattr,%function
mq_getattr:
mov x2, x1
mov x1, xzr
b mq_setattr
.size mq_getattr, .-mq_getattr
.section .note.GNU-stack,"",%progbits
