// musl 1.2.6 src/linux/prctl.c; MIT license.
.text
.global prctl
.type prctl,%function
.hidden __crabc_aarch64_prctl
prctl:
 b __crabc_aarch64_prctl
.size prctl, .-prctl
.section .note.GNU-stack,"",%progbits
