.text
.global ioctl
.type ioctl,%function
.hidden ioctl_no_argument
.hidden ioctl_word
ioctl:
 mov w3, #0x5450
 cmp w1, w3
 b.eq ioctl_no_argument
 mov w3, #0x5451
 cmp w1, w3
 b.eq ioctl_no_argument
 b ioctl_word
.size ioctl, .-ioctl
.section .note.GNU-stack,"",%progbits
