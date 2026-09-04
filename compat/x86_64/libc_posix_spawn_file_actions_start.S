/* Freestanding entry for the x86 POSIX spawn file-actions fixture. */
.text
.globl _start
.type _start,@function
_start:
    call crabc_x86_64_posix_spawn_file_actions_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
