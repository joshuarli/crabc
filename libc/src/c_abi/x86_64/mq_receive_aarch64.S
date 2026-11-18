// musl 1.2.6 src/mq/mq_receive.c; MIT license.
.text
.global mq_receive
.type mq_receive,%function
mq_receive:
mov x4, xzr
b mq_timedreceive
.size mq_receive, .-mq_receive
.section .note.GNU-stack,"",%progbits
