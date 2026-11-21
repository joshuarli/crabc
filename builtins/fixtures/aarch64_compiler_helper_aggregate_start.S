.text
.globl _start
.type _start,%function
_start:
    bl crabc_x86_64_compiler_helper_aggregate_probe
    cbnz w0, .Lexit
    mov x19, #19
    mov x20, #20
    mov x21, #21
    mov x22, #22
    mov x23, #23
    mov x24, #24
    mov x25, #25
    mov x26, #26
    mov x27, #27
    mov x28, #28
    mov x0, #0
    mov x1, #1
    bl __floatuntidf
    fmov x9, d0
    mov x10, #0x43f0
    lsl x10, x10, #48
    cmp x9, x10
    b.ne .Lbad
    cmp x19, #19
    b.ne .Lbad
    cmp x20, #20
    b.ne .Lbad
    cmp x21, #21
    b.ne .Lbad
    cmp x22, #22
    b.ne .Lbad
    cmp x23, #23
    b.ne .Lbad
    cmp x24, #24
    b.ne .Lbad
    cmp x25, #25
    b.ne .Lbad
    cmp x26, #26
    b.ne .Lbad
    cmp x27, #27
    b.ne .Lbad
    cmp x28, #28
    b.ne .Lbad
    mov x0, #1
    adr x1, .Ltranscript
    mov x2, #29
    mov x8, #64
    svc #0
    mov x0, #0
    b .Lexit
.Lbad:
    mov x0, #97
.Lexit:
    mov x8, #93
    svc #0
    udf #0
.size _start, .-_start
.section .rodata
.Ltranscript:
    .ascii "compiler-helper-aggregate-ok\n"
.section .note.GNU-stack,"",%progbits
