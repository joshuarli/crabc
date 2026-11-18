.text
.global semctl
.type semctl,%function
.hidden semctl_word
.hidden semctl_no_argument
semctl:
 cmp w2, #16
 b.eq semctl_word
 cmp w2, #13
 b.eq semctl_word
 cmp w2, #17
 b.eq semctl_word
 cmp w2, #1
 b.eq semctl_word
 cmp w2, #3
 b.eq semctl_word
 cmp w2, #19
 b.eq semctl_word
 cmp w2, #2
 b.eq semctl_word
 cmp w2, #18
 b.eq semctl_word
 cmp w2, #20
 b.eq semctl_word
 b semctl_no_argument
.size semctl, .-semctl
.section .note.GNU-stack,"",%progbits
