/* Direct Linux x86-64 entry for the bounded mutex priority-ceiling query.
 *
 * This owns no CRT, TLS, errno, thread, lifecycle, mutex, or scheduler setup.
 * The selected getter returns its fixed direct status, then this shim exits
 * through Linux x86-64 syscall 60.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	and $-16, %rsp
	call crabc_x86_64_pthread_mutex_prioceiling_query_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start

	.section .note.GNU-stack,"",@progbits
