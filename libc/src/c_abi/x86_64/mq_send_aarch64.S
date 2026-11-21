// musl 1.2.6 src/mq/mq_send.c; MIT license.
.text
.global mq_send
.type mq_send,%function
mq_send:
mov x4, xzr
b mq_timedsend
.size mq_send, .-mq_send
.section .note.GNU-stack,"",%progbits
