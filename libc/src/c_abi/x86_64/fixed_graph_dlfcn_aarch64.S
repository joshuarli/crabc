.section .text.__crabc_x86_fixed_graph_dlfcn_record,"ax",%progbits
.weak __crabc_x86_64_fixed_graph_dlfcn_v1
.hidden __crabc_x86_fixed_graph_dlfcn_record
.global __crabc_x86_fixed_graph_dlfcn_record
.type __crabc_x86_fixed_graph_dlfcn_record,%function
__crabc_x86_fixed_graph_dlfcn_record:
 adrp x0, :got:__crabc_x86_64_fixed_graph_dlfcn_v1
 ldr x0, [x0, :got_lo12:__crabc_x86_64_fixed_graph_dlfcn_v1]
 ret
.size __crabc_x86_fixed_graph_dlfcn_record, .-__crabc_x86_fixed_graph_dlfcn_record
