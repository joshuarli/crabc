/* Direct Linux x86-64 entry for the stateless pthread attribute lifecycle
 * candidate. No CRT, TLS, errno, mutex, condition, or thread setup is needed.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_pthread_attr_lifecycle_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
