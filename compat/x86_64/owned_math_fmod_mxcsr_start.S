	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp,%ebp
	and $-16,%rsp
	call main
	mov %eax,%edi
	mov $60,%eax
	syscall
	.size _start,.-_start
	.section .note.GNU-stack,"",@progbits
