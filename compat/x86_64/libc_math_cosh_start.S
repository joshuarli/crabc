	.text
	.globl _start
	.type _start,@function
	.extern crabc_x86_64_math_cosh_probe
	.extern crabc_x86_64_math_cosh_records
	.extern crabc_x86_64_math_cosh_record_bytes
_start:
	call crabc_x86_64_math_cosh_probe
	test %eax, %eax
	jne .Lfailure
	mov $1, %rax
	mov $1, %rdi
	lea crabc_x86_64_math_cosh_records(%rip), %rsi
	mov crabc_x86_64_math_cosh_record_bytes(%rip), %rdx
	mov %rdx, %r8
	syscall
	cmp %r8, %rax
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
