.text
.global semctl
.type semctl,%function
.hidden {word}
.hidden {no_argument}
semctl:
 cmp w2, #16
 b.eq {word}
 cmp w2, #13
 b.eq {word}
 cmp w2, #17
 b.eq {word}
 cmp w2, #1
 b.eq {word}
 cmp w2, #3
 b.eq {word}
 cmp w2, #19
 b.eq {word}
 cmp w2, #2
 b.eq {word}
 cmp w2, #18
 b.eq {word}
 cmp w2, #20
 b.eq {word}
 b {no_argument}
.size semctl, .-semctl
.section .note.GNU-stack,"",%progbits
