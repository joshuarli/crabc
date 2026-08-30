/* Test-only static x86-64 entry for the bounded normal pthread-mutex fixture.
 *
 * libc owns Static Initial TLS v1 installation. This shim retains the Linux
 * initial stack for that hook, then exits through the raw x86-64 exit syscall;
 * it is neither a general CRT nor a loader.
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
	call crabc_x86_64_pthread_mutex_normal_probe
	mov %eax, %edi
	mov $60, %eax
	syscall

.Ltls_failure:
	mov $127, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
