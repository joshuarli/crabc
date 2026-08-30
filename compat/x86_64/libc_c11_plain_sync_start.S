/*
 * Freestanding static entry for libc_c11_plain_sync_probe.c.
 *
 * libc owns the actual Static Initial TLS v1 installation. Keep this tiny
 * shim free of fixture-local TLS-base setup so the C11 synchronization
 * candidate proves the same first-thread owner as its pthread/C11 lifecycle
 * siblings.
 */
	.text
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_c11_plain_sync_probe
	mov %eax, %edi
	mov $60, %eax
	syscall
1:
	mov $127, %edi
	mov $60, %eax
	syscall
	.size _start, .-_start
	.section .note.GNU-stack,"",@progbits
