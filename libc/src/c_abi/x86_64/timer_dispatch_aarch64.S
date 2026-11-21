.text
.hidden __crabc_x86_timer_invoke
.hidden __crabc_x86_timer_dispatch
.global __crabc_x86_timer_dispatch
.type __crabc_x86_timer_dispatch,%function
__crabc_x86_timer_dispatch:
 stp x19, x30, [sp, #-192]!
 mov x19, x0
 add x0, sp, #16
 bl setjmp
 cbnz w0, 1f
 mov x0, x19
 add x1, sp, #16
 bl __crabc_x86_timer_invoke
1:
 ldp x19, x30, [sp], #192
 ret
.size __crabc_x86_timer_dispatch, .-__crabc_x86_timer_dispatch
.section .note.GNU-stack,"",%progbits
