// musl 1.2.6 src/misc/syscall.c; MIT license.
.text
.global syscall
.type syscall,%function
.hidden __crabc_aarch64_syscall
syscall:
 b __crabc_aarch64_syscall
.size syscall, .-syscall
.section .note.GNU-stack,"",%progbits
