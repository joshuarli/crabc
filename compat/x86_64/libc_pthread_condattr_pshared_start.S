/* Direct Linux x86-64 entry for the bounded condattr pshared candidate.
 *
 * This intentionally owns no CRT, TLS, errno, thread, lifecycle, condition,
 * or clock setup. The selected pair only observes or updates caller-owned
 * attribute storage, then this shim exits through Linux x86-64 syscall 60.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_pthread_condattr_pshared_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
