/* Freestanding static entry for libc_pthread_c11_tsd_probe.c. */
	.text
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_pthread_c11_tsd_probe
	mov %eax, %edi
	/* exit_group also closes a failed join path without leaving a selected
	 * worker alive after the probe reports failure. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
