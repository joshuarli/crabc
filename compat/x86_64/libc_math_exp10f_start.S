	.text
	.globl _start
	.type _start,@function
	.extern crabc_x86_64_math_exp10f_probe
	.extern crabc_x86_64_math_exp10f_records
_start:
	call crabc_x86_64_math_exp10f_probe
	test %eax, %eax
	jne .Lfailure
	mov $1, %rax
	mov $1, %rdi
	lea crabc_x86_64_math_exp10f_records(%rip), %rsi
	mov $8192, %rdx
	syscall
	cmp $8192, %rax
	jne .Lfailure
	xor %rdi, %rdi
	mov $60, %rax
	syscall
.Lfailure:
	mov $1, %rdi
	mov $60, %rax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
