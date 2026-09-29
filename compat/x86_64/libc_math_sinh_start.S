	.text
	.globl _start
	.type _start,@function
	.extern crabc_x86_64_math_sinh_probe
	.extern crabc_x86_64_math_sinh_records
	.extern crabc_x86_64_math_sinh_record_bytes
_start:
	call crabc_x86_64_math_sinh_probe
	test %eax, %eax
	jne .Lfailure
	mov $1, %rax
	mov $1, %rdi
	lea crabc_x86_64_math_sinh_records(%rip), %rsi
	mov crabc_x86_64_math_sinh_record_bytes(%rip), %rdx
	syscall
	cmp crabc_x86_64_math_sinh_record_bytes(%rip), %rax
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
