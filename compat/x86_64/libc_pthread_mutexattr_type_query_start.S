/* Direct Linux x86-64 entry for the bounded mutexattr type-query candidate.
 *
 * This intentionally owns no CRT, TLS, errno, thread, lifecycle, mutex, or
 * type setup. The selected getter only observes caller-owned attribute
 * storage, then this shim exits through Linux x86-64 syscall 60.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_pthread_mutexattr_type_query_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
