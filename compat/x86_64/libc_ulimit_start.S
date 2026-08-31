/* Freestanding static entry for libc_ulimit_probe.c.
 *
 * The selected archive owns the direct initial-TLS errno slot observed by the
 * fixture. This evidence-only shim invokes its private bootstrap; it is not a
 * general CRT, resource-policy owner, or TLS runtime.
 */
	.text
#ifdef CRABC_ULIMIT_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_ulimit_probe
	mov %eax, %edi
	/* exit_group ends the disposable process with its changed soft limit. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
