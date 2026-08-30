/* Freestanding static entry for libc_pathname_lifecycle_probe.c.
 *
 * The selected archive owns initial-TLS errno. This evidence-only entry
 * delegates first-thread setup to that private bootstrap; it is not a CRT or
 * general TLS runtime.
 */
	.text
#ifdef CRABC_PATHNAME_LIFECYCLE_FREESTANDING
	.global _start
	.type _start,@function
_start:
	mov %rsp, %rdi
	call __crabc_x86_static_tls_bootstrap
	test %eax, %eax
	jne 1f
	call crabc_x86_64_pathname_lifecycle_probe
	mov %eax, %edi
	/* exit_group closes unexpected fixture paths after local cleanup. */
	mov $231, %eax
	syscall
1:
	mov $127, %edi
	mov $231, %eax
	syscall
	.size _start, .-_start
#endif
	.section .note.GNU-stack,"",@progbits
