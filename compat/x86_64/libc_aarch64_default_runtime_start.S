.section .bss
.balign 64
.Ltls:
    .zero 4096
.text
.global _start
.type _start,%function
_start:
    adrp x0, .Ltls
    add x0, x0, :lo12:.Ltls
    msr tpidr_el0, x0
    bl crabc_aarch64_default_runtime_probe
    mov x8, #93
    svc #0
.size _start, .-_start
.section .note.GNU-stack,"",%progbits
