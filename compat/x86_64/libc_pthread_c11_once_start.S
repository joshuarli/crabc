/*
 * Freestanding static entry for libc_pthread_c11_once_probe.c.
 *
 * libc owns the actual Static Initial TLS v1 installation. Keep this tiny
 * shim free of fixture-local TLS-base setup so the selected pthread/C11 once
 * candidate proves the same first-thread owner as its worker siblings.
 */
	.text
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_pthread_c11_once_probe
	mov %eax, %edi
	/* exit_group also closes a deliberately failed join path without leaving a
	 * blocked selected worker alive after the probe reports its failure. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
