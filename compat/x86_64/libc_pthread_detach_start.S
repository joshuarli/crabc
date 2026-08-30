/* Test-only static x86-64 entry for the bounded detach lifecycle fixture.
 *
 * libc alone owns Static Initial TLS v1 installation.  This shim keeps the
 * initial Linux stack available to that hook, then exits the process through
 * the raw x86-64 exit syscall; it is neither a general CRT nor a loader.
 */
	.text
	.globl _start
	.type _start,@function
_start:
	xor %ebp, %ebp
	mov %rsp, %rdi
	and $-16, %rsp
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne .Ltls_failure
	call crabc_x86_64_pthread_detach_probe
	mov %eax, %edi
	mov $60, %eax
	syscall

.Ltls_failure:
	mov $127, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
