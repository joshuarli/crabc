/* Direct Linux x86-64 entry for the pthread-attribute metadata candidate.
 *
 * This owns no CRT, TLS, errno, thread, lifecycle, scheduler, or allocation
 * setup. The selected record operations return direct pthread status codes,
 * then this shim exits through Linux x86-64 syscall 60.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_pthread_attr_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
