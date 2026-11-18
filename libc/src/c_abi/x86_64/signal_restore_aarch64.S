// musl 1.2.6 src/signal/aarch64/restore.s; MIT license.
.text
.global crabc_x86_64_signal_restorer
.hidden crabc_x86_64_signal_restorer
.type crabc_x86_64_signal_restorer,%function
crabc_x86_64_signal_restorer:
 mov x8, #139
 svc 0
