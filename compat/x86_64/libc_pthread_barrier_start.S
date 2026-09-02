/* Test-only static x86-64 entry for the pthread-barrier fixture. libc owns
 * Static Initial TLS v1 installation; this shim retains the Linux entry stack
 * for that hook, then exits through raw syscall 60. It is not a CRT or loader.
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
	call crabc_x86_64_pthread_barrier_probe
	mov %eax, %edi
	mov $60, %eax
	syscall

.Ltls_failure:
	mov $127, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
