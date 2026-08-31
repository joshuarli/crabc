/* Freestanding x86-64 entry for the selected strsignal fixture. */

.section .text
.globl _start
.type _start,@function
_start:
    call crabc_x86_64_strsignal_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.size _start, .-_start
