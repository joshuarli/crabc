.text
.global ioctl
.type ioctl,%function
.hidden {no_argument}
.hidden {word}
ioctl:
 mov w3, #0x5450
 cmp w1, w3
 b.eq {no_argument}
 mov w3, #0x5451
 cmp w1, w3
 b.eq {no_argument}
 b {word}
.size ioctl, .-ioctl
.section .note.GNU-stack,"",%progbits
