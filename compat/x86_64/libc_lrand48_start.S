.text
.globl _start
.type _start,@function
_start:
 call crabc_x86_64_lrand48_probe
 mov %eax,%edi
 mov $60,%eax
 syscall
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
