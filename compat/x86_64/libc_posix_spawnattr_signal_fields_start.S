/* Freestanding Linux/x86-64 entry for spawn-attribute signal-field evidence. */

    .text
    .globl _start
    .type _start,@function
_start:
    call crabc_x86_64_posix_spawnattr_signal_fields_probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
